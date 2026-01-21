#include "poaceaefs.h"

static void poaceae_d_release(struct dentry *dentry) {
  struct dentry *lower_dentry = dentry->d_fsdata;
  if (lower_dentry)
    dput(lower_dentry);
}

const struct dentry_operations poaceae_dops = {
    .d_release = poaceae_d_release,
};

static int poaceae_getattr(struct mnt_idmap *idmap, const struct path *path,
                           struct kstat *stat, u32 request_mask,
                           unsigned int flags) {
  struct inode *inode = d_inode(path->dentry);
  struct poaceae_inode_info *pi = POACEAE_I(inode);
  struct poaceae_sb_info *sbi = POACEAE_SB(inode->i_sb);
  struct poaceae_spoof_entry *s_entry;
  int err;

  if (!pi->lower_path.dentry)
    return -EIO;

  err = vfs_getattr(&pi->lower_path, stat, request_mask, flags);
  if (err)
    return err;

  if (gid_valid(sbi->trusted_gid) && gid_eq(current_gid(), sbi->trusted_gid))
    return 0;

  if (!poaceae_bloom_check(sbi, path->dentry->d_name.name))
    return 0;

  rcu_read_lock();
  list_for_each_entry_rcu(s_entry, &sbi->spoof_list, list) {
    if (strcmp(path->dentry->d_name.name, s_entry->name) == 0) {
      stat->uid = s_entry->uid;
      stat->gid = s_entry->gid;
      stat->mode = (stat->mode & S_IFMT) | (s_entry->mode & ~S_IFMT);
      stat->mtime.tv_sec = s_entry->mtime;
      stat->mtime.tv_nsec = 0;
      stat->atime.tv_sec = s_entry->mtime;
      stat->atime.tv_nsec = 0;
      stat->ctime.tv_sec = s_entry->mtime;
      stat->ctime.tv_nsec = 0;
      break;
    }
  }
  rcu_read_unlock();

  return 0;
}

static int poaceae_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
                           struct iattr *attr) {
  struct inode *inode = d_inode(dentry);
  struct poaceae_inode_info *pi = POACEAE_I(inode);
  struct inode *lower_inode;
  int err;

  if (!pi->lower_path.dentry)
    return -EIO;

  lower_inode = d_inode(pi->lower_path.dentry);

  setattr_copy(idmap, inode, attr);
  mark_inode_dirty(inode);

  inode_lock(lower_inode);
  err = notify_change(mnt_idmap(pi->lower_path.mnt), pi->lower_path.dentry,
                      attr, NULL);
  inode_unlock(lower_inode);

  return err;
}

static ssize_t poaceae_listxattr(struct dentry *dentry, char *list,
                                 size_t size) {
  struct inode *inode = d_inode(dentry);
  struct poaceae_inode_info *pi = POACEAE_I(inode);
  struct poaceae_sb_info *sbi = POACEAE_SB(dentry->d_sb);
  ssize_t ret;
  char *buf;
  ssize_t buf_len;

  if (!pi->lower_path.dentry)
    return -EIO;

  if (gid_valid(sbi->trusted_gid) && gid_eq(current_gid(), sbi->trusted_gid))
    return vfs_listxattr(pi->lower_path.dentry, list, size);

  buf_len = vfs_listxattr(pi->lower_path.dentry, NULL, 0);
  if (buf_len <= 0)
    return buf_len;

  buf = kmalloc(buf_len, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  buf_len = vfs_listxattr(pi->lower_path.dentry, buf, buf_len);
  if (buf_len > 0) {
    char *p = buf;
    char *end = buf + buf_len;
    char *out = buf;

    while (p < end) {
      size_t len = strlen(p) + 1;
      if (strncmp(p, "trusted.overlay.", 16) != 0) {
        if (out != p)
          memmove(out, p, len);
        out += len;
      }
      p += len;
    }
    buf_len = out - buf;
  }

  if (list) {
    if (size >= buf_len) {
      memcpy(list, buf, buf_len);
      ret = buf_len;
    } else {
      ret = -ERANGE;
    }
  } else {
    ret = buf_len;
  }

  kfree(buf);
  return ret;
}

static int poaceae_interpose(struct dentry *dentry, struct super_block *sb,
                             struct path *lower_path) {
  struct inode *lower_inode = d_inode(lower_path->dentry);
  struct inode *inode;

  inode = new_inode(sb);
  if (!inode)
    return -ENOMEM;

  inode->i_ino = lower_inode->i_ino;
  inode->i_mode = lower_inode->i_mode;
  inode->i_op = &poaceae_dir_iops;
  inode->i_fop = &poaceae_dir_fops;

  path_get(lower_path);
  POACEAE_I(inode)->lower_path = *lower_path;

  d_add(dentry, inode);
  return 0;
}

static struct dentry *poaceae_lookup(struct inode *dir, struct dentry *dentry,
                                     unsigned int flags) {
  struct poaceae_inode_info *dir_pi = POACEAE_I(dir);
  struct dentry *lower_dir_dentry = dir_pi->lower_path.dentry;
  struct dentry *lower_dentry = NULL;
  struct poaceae_sb_info *sbi = POACEAE_SB(dir->i_sb);
  struct poaceae_hide_entry *h_entry;
  struct poaceae_redirect_entry *r_entry;
  struct poaceae_merge_entry *m_entry;
  struct path target_path;
  struct path merge_target_path;
  char *redirect_target = NULL;
  bool is_trusted =
      gid_valid(sbi->trusted_gid) && gid_eq(current_gid(), sbi->trusted_gid);
  bool found_redirect = false;
  bool found_merge = false;
  int err;

  if (!is_trusted && poaceae_bloom_check(sbi, dentry->d_name.name)) {
    rcu_read_lock();
    list_for_each_entry_rcu(h_entry, &sbi->hide_list, list) {
      if (strcmp(dentry->d_name.name, h_entry->name) == 0) {
        rcu_read_unlock();
        d_add(dentry, NULL);
        return NULL;
      }
    }

    list_for_each_entry_rcu(r_entry, &sbi->redirect_list, list) {
      if (strcmp(dentry->d_name.name, r_entry->name) == 0) {
        redirect_target = kstrdup(r_entry->target, GFP_ATOMIC);
        found_redirect = true;
        break;
      }
    }
    rcu_read_unlock();

    if (found_redirect && redirect_target) {
      err = kern_path(redirect_target, LOOKUP_FOLLOW, &target_path);
      kfree(redirect_target);
      if (err)
        return ERR_PTR(err);
      goto do_interpose;
    }
  }

  rcu_read_lock();
  list_for_each_entry_rcu(m_entry, &sbi->merge_list, list) {
    char *buf, *path_str;
    buf = (char *)__get_free_page(GFP_ATOMIC);
    if (!buf)
      continue;

    path_str = d_path(&dir_pi->lower_path, buf, PAGE_SIZE);
    if (!IS_ERR(path_str)) {
      if (strcmp(path_str, m_entry->src) == 0) {
        merge_target_path = m_entry->target_path;
        path_get(&merge_target_path);
        found_merge = true;
      }
    }
    free_page((unsigned long)buf);
    if (found_merge)
      break;
  }
  rcu_read_unlock();

  if (found_merge) {
    struct dentry *merge_dentry;
    inode_lock(d_inode(merge_target_path.dentry));
    merge_dentry = lookup_one_len(dentry->d_name.name, merge_target_path.dentry,
                                  dentry->d_name.len);
    inode_unlock(d_inode(merge_target_path.dentry));

    if (!IS_ERR(merge_dentry)) {
      if (d_really_is_positive(merge_dentry)) {
        target_path.dentry = merge_dentry;
        target_path.mnt = merge_target_path.mnt;
        path_get(&target_path);
        path_put(&merge_target_path);
        goto do_interpose;
      }
      dput(merge_dentry);
    }
    path_put(&merge_target_path);
  }

  inode_lock(d_inode(lower_dir_dentry));
  lower_dentry =
      lookup_one_len(dentry->d_name.name, lower_dir_dentry, dentry->d_name.len);
  inode_unlock(d_inode(lower_dir_dentry));

  if (IS_ERR(lower_dentry))
    return ERR_CAST(lower_dentry);

  target_path.dentry = lower_dentry;
  target_path.mnt = dir_pi->lower_path.mnt;
  path_get(&target_path);

  if (!d_really_is_positive(lower_dentry)) {
    path_put(&target_path);
    dentry->d_fsdata = lower_dentry;
    d_set_d_op(dentry, &poaceae_dops);
    d_add(dentry, NULL);
    return NULL;
  }

do_interpose:
  dentry->d_fsdata = target_path.dentry;
  dget(target_path.dentry);

  d_set_d_op(dentry, &poaceae_dops);

  err = poaceae_interpose(dentry, dir->i_sb, &target_path);

  path_put(&target_path);

  return ERR_PTR(err);
}

static int poaceae_create(struct mnt_idmap *idmap, struct inode *dir,
                          struct dentry *dentry, umode_t mode, bool excl) {
  struct poaceae_inode_info *dir_pi = POACEAE_I(dir);
  struct dentry *lower_dentry = dentry->d_fsdata;
  struct inode *lower_dir_inode = d_inode(dir_pi->lower_path.dentry);
  struct path new_lower_path;
  int err;

  inode_lock(lower_dir_inode);
  err = vfs_create(mnt_idmap(dir_pi->lower_path.mnt), lower_dir_inode,
                   lower_dentry, mode, excl);
  inode_unlock(lower_dir_inode);

  if (err)
    return err;

  new_lower_path.dentry = lower_dentry;
  new_lower_path.mnt = dir_pi->lower_path.mnt;

  return poaceae_interpose(dentry, dir->i_sb, &new_lower_path);
}

static int poaceae_unlink(struct inode *dir, struct dentry *dentry) {
  struct poaceae_inode_info *dir_pi = POACEAE_I(dir);
  struct dentry *lower_dentry = dentry->d_fsdata;
  struct inode *lower_dir_inode = d_inode(dir_pi->lower_path.dentry);
  int err;

  inode_lock(lower_dir_inode);
  err = vfs_unlink(mnt_idmap(dir_pi->lower_path.mnt), lower_dir_inode,
                   lower_dentry, NULL);
  inode_unlock(lower_dir_inode);

  return err;
}

static int poaceae_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                         struct dentry *dentry, umode_t mode) {
  struct poaceae_inode_info *dir_pi = POACEAE_I(dir);
  struct dentry *lower_dentry = dentry->d_fsdata;
  struct inode *lower_dir_inode = d_inode(dir_pi->lower_path.dentry);
  struct path new_lower_path;
  int err;

  inode_lock(lower_dir_inode);
  err = vfs_mkdir(mnt_idmap(dir_pi->lower_path.mnt), lower_dir_inode,
                  lower_dentry, mode);
  inode_unlock(lower_dir_inode);

  if (err)
    return err;

  new_lower_path.dentry = lower_dentry;
  new_lower_path.mnt = dir_pi->lower_path.mnt;

  return poaceae_interpose(dentry, dir->i_sb, &new_lower_path);
}

static int poaceae_rmdir(struct inode *dir, struct dentry *dentry) {
  struct poaceae_inode_info *dir_pi = POACEAE_I(dir);
  struct dentry *lower_dentry = dentry->d_fsdata;
  struct inode *lower_dir_inode = d_inode(dir_pi->lower_path.dentry);
  int err;

  inode_lock(lower_dir_inode);
  err = vfs_rmdir(mnt_idmap(dir_pi->lower_path.mnt), lower_dir_inode,
                  lower_dentry);
  inode_unlock(lower_dir_inode);

  return err;
}

static int poaceae_rename(struct mnt_idmap *idmap, struct inode *old_dir,
                          struct dentry *old_dentry, struct inode *new_dir,
                          struct dentry *new_dentry, unsigned int flags) {
  struct poaceae_inode_info *old_dir_pi = POACEAE_I(old_dir);
  struct poaceae_inode_info *new_dir_pi = POACEAE_I(new_dir);
  struct dentry *lower_old_dentry = old_dentry->d_fsdata;
  struct dentry *lower_new_dentry = new_dentry->d_fsdata;
  int err;

  struct renamedata rd = {
      .old_mnt_idmap = mnt_idmap(old_dir_pi->lower_path.mnt),
      .old_dir = d_inode(old_dir_pi->lower_path.dentry),
      .old_dentry = lower_old_dentry,
      .new_mnt_idmap = mnt_idmap(new_dir_pi->lower_path.mnt),
      .new_dir = d_inode(new_dir_pi->lower_path.dentry),
      .new_dentry = lower_new_dentry,
      .flags = flags,
  };

  lock_rename(old_dir_pi->lower_path.dentry, new_dir_pi->lower_path.dentry);
  err = vfs_rename(&rd);
  unlock_rename(old_dir_pi->lower_path.dentry, new_dir_pi->lower_path.dentry);

  return err;
}

const struct inode_operations poaceae_dir_iops = {
    .lookup = poaceae_lookup,
    .getattr = poaceae_getattr,
    .setattr = poaceae_setattr,
    .listxattr = poaceae_listxattr,
    .create = poaceae_create,
    .unlink = poaceae_unlink,
    .mkdir = poaceae_mkdir,
    .rmdir = poaceae_rmdir,
    .rename = poaceae_rename,
};