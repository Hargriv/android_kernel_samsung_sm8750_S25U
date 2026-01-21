#include "poaceaefs.h"
#include <linux/fs_context.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/xattr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Poaceae Project");
MODULE_DESCRIPTION("Stealthy Stackable FS with Injection");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

static int poaceae_xattr_get(const struct xattr_handler *handler,
                             struct dentry *dentry, struct inode *inode,
                             const char *name, void *buffer, size_t size) {
  struct poaceae_inode_info *pi = POACEAE_I(inode);

  if (!pi->lower_path.dentry)
    return -EIO;

  return vfs_getxattr(mnt_idmap(pi->lower_path.mnt), pi->lower_path.dentry,
                      name, buffer, size);
}

static int poaceae_xattr_set(const struct xattr_handler *handler,
                             struct mnt_idmap *idmap, struct dentry *dentry,
                             struct inode *inode, const char *name,
                             const void *value, size_t size, int flags) {
  struct poaceae_inode_info *pi = POACEAE_I(inode);

  if (!pi->lower_path.dentry)
    return -EIO;

  return vfs_setxattr(mnt_idmap(pi->lower_path.mnt), pi->lower_path.dentry,
                      name, value, size, flags);
}

static const struct xattr_handler poaceae_xattr_handler = {
    .name = "",
    .prefix = "",
    .get = poaceae_xattr_get,
    .set = poaceae_xattr_set,
};

static const struct xattr_handler *poaceae_xattr_handlers[] = {
    &poaceae_xattr_handler,
    NULL,
};

static struct inode *poaceae_alloc_inode(struct super_block *sb) {
  struct poaceae_inode_info *pi;
  pi = kzalloc(sizeof(*pi), GFP_KERNEL);
  if (!pi)
    return NULL;
  inode_init_once(&pi->vfs_inode);
  pi->lower_path.dentry = NULL;
  pi->lower_path.mnt = NULL;
  return &pi->vfs_inode;
}

static void poaceae_destroy_inode(struct inode *inode) {
  struct poaceae_inode_info *pi = POACEAE_I(inode);
  if (pi->lower_path.dentry)
    path_put(&pi->lower_path);
  kfree(pi);
}

static int poaceae_statfs(struct dentry *dentry, struct kstatfs *buf) {
  struct poaceae_sb_info *sbi = POACEAE_SB(dentry->d_sb);
  return vfs_statfs(&sbi->lower_path, buf);
}

static const struct super_operations poaceae_sops = {
    .alloc_inode = poaceae_alloc_inode,
    .destroy_inode = poaceae_destroy_inode,
    .drop_inode = generic_delete_inode,
    .statfs = poaceae_statfs,
};

static int poaceae_fill_super(struct super_block *sb, struct fs_context *fc) {
  struct poaceae_sb_info *sbi = sb->s_fs_info;
  struct inode *root_inode;
  struct inode *lower_root_inode = d_inode(sbi->lower_path.dentry);

  fc->s_fs_info = NULL;

  sb->s_stack_depth = lower_root_inode->i_sb->s_stack_depth + 1;
  if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH)
    return -EINVAL;

  sb->s_op = &poaceae_sops;
  sb->s_magic = POACEAEFS_MAGIC;
  sb->s_time_gran = lower_root_inode->i_sb->s_time_gran;
  sb->s_xattr = poaceae_xattr_handlers;

  root_inode = new_inode(sb);
  if (!root_inode)
    return -ENOMEM;

  root_inode->i_ino = lower_root_inode->i_ino;
  root_inode->i_mode = lower_root_inode->i_mode;
  root_inode->i_op = &poaceae_dir_iops;
  root_inode->i_fop = &poaceae_dir_fops;

  path_get(&sbi->lower_path);
  POACEAE_I(root_inode)->lower_path = sbi->lower_path;

  sb->s_root = d_make_root(root_inode);
  if (!sb->s_root) {
    path_put(&sbi->lower_path);
    return -ENOMEM;
  }

  sb->s_root->d_fsdata = dget(sbi->lower_path.dentry);
  d_set_d_op(sb->s_root, &poaceae_dops);

  return 0;
}

static int poaceae_get_tree(struct fs_context *fc) {
  return get_tree_nodev(fc, poaceae_fill_super);
}

static void poaceae_free_sbi(struct poaceae_sb_info *sbi) {
  struct poaceae_hide_entry *h_entry, *h_tmp;
  struct poaceae_redirect_entry *r_entry, *r_tmp;
  struct poaceae_spoof_entry *s_entry, *s_tmp;
  struct poaceae_merge_entry *m_entry, *m_tmp;
  if (!sbi)
    return;

  mutex_lock(&sbi->hide_lock);
  list_for_each_entry_safe(h_entry, h_tmp, &sbi->hide_list, list) {
    list_del_rcu(&h_entry->list);
    kfree_rcu(h_entry, rcu);
  }
  mutex_unlock(&sbi->hide_lock);

  mutex_lock(&sbi->redirect_lock);
  list_for_each_entry_safe(r_entry, r_tmp, &sbi->redirect_list, list) {
    list_del_rcu(&r_entry->list);
    kfree_rcu(r_entry, rcu);
  }
  mutex_unlock(&sbi->redirect_lock);

  mutex_lock(&sbi->spoof_lock);
  list_for_each_entry_safe(s_entry, s_tmp, &sbi->spoof_list, list) {
    list_del_rcu(&s_entry->list);
    kfree_rcu(s_entry, rcu);
  }
  mutex_unlock(&sbi->spoof_lock);

  mutex_lock(&sbi->merge_lock);
  list_for_each_entry_safe(m_entry, m_tmp, &sbi->merge_list, list) {
    list_del_rcu(&m_entry->list);
    if (m_entry->target_path.dentry)
      path_put(&m_entry->target_path);
    kfree_rcu(m_entry, rcu);
  }
  mutex_unlock(&sbi->merge_lock);

  if (sbi->lower_path.dentry)
    path_put(&sbi->lower_path);
  kfree(sbi);
}

static void poaceae_free_fc(struct fs_context *fc) {
  poaceae_free_sbi(fc->s_fs_info);
}

static const struct fs_context_operations poaceae_context_ops = {
    .get_tree = poaceae_get_tree,
    .free = poaceae_free_fc,
};

static int poaceae_init_fs_context(struct fs_context *fc) {
  struct poaceae_sb_info *sbi;
  struct path path;
  int err;

  sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
  if (!sbi)
    return -ENOMEM;

  INIT_LIST_HEAD(&sbi->hide_list);
  mutex_init(&sbi->hide_lock);

  INIT_LIST_HEAD(&sbi->redirect_list);
  mutex_init(&sbi->redirect_lock);

  INIT_LIST_HEAD(&sbi->spoof_list);
  mutex_init(&sbi->spoof_lock);

  INIT_LIST_HEAD(&sbi->merge_list);
  mutex_init(&sbi->merge_lock);

  sbi->trusted_gid = INVALID_GID;
  bitmap_zero(sbi->bloom_filter, POACEAE_BLOOM_BITS);

  if (fc->source) {
    err = kern_path(fc->source, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
    if (err) {
      kfree(sbi);
      return err;
    }
    sbi->lower_path = path;
  } else {
    kfree(sbi);
    return -EINVAL;
  }

  fc->s_fs_info = sbi;
  fc->ops = &poaceae_context_ops;
  return 0;
}

static void poaceae_kill_sb(struct super_block *sb) {
  struct poaceae_sb_info *sbi = POACEAE_SB(sb);
  poaceae_free_sbi(sbi);
  kill_anon_super(sb);
}

static struct file_system_type poaceae_fs_type = {
    .owner = THIS_MODULE,
    .name = "poaceaefs",
    .init_fs_context = poaceae_init_fs_context,
    .kill_sb = poaceae_kill_sb,
};

static int __init poaceae_init(void) {
  return register_filesystem(&poaceae_fs_type);
}

static void __exit poaceae_exit(void) {
  unregister_filesystem(&poaceae_fs_type);
}

module_init(poaceae_init);
module_exit(poaceae_exit);