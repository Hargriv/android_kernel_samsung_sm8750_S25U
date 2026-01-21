#include "poaceaefs.h"
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static void poaceae_rebuild_bloom(struct poaceae_sb_info *sbi) {
  struct poaceae_hide_entry *h;
  struct poaceae_redirect_entry *r;
  struct poaceae_spoof_entry *s;

  bitmap_zero(sbi->bloom_filter, POACEAE_BLOOM_BITS);

  list_for_each_entry_rcu(h, &sbi->hide_list, list) {
    poaceae_bloom_add(sbi, h->name);
  }
  list_for_each_entry_rcu(r, &sbi->redirect_list, list) {
    poaceae_bloom_add(sbi, r->name);
  }
  list_for_each_entry_rcu(s, &sbi->spoof_list, list) {
    poaceae_bloom_add(sbi, s->name);
  }
}

static int poaceae_add_hide(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_hide_entry *entry;
  char *name;

  name = kmalloc(256, GFP_KERNEL);
  if (!name)
    return -ENOMEM;

  if (copy_from_user(name, (void __user *)arg, 256)) {
    kfree(name);
    return -EFAULT;
  }
  name[255] = '\0';

  entry = kzalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {
    kfree(name);
    return -ENOMEM;
  }

  strscpy(entry->name, name, sizeof(entry->name));
  entry->len = strlen(entry->name);
  kfree(name);

  mutex_lock(&sbi->hide_lock);
  list_add_rcu(&entry->list, &sbi->hide_list);
  poaceae_bloom_add(sbi, entry->name);
  mutex_unlock(&sbi->hide_lock);

  return 0;
}

static int poaceae_del_hide(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_hide_entry *entry, *tmp;
  char *name;

  name = kmalloc(256, GFP_KERNEL);
  if (!name)
    return -ENOMEM;

  if (copy_from_user(name, (void __user *)arg, 256)) {
    kfree(name);
    return -EFAULT;
  }
  name[255] = '\0';

  mutex_lock(&sbi->hide_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->hide_list, list) {
    if (strncmp(entry->name, name, sizeof(entry->name)) == 0) {
      list_del_rcu(&entry->list);
      kfree_rcu(entry, rcu);
    }
  }
  poaceae_rebuild_bloom(sbi);
  mutex_unlock(&sbi->hide_lock);

  kfree(name);
  return 0;
}

static int poaceae_clear_hide(struct poaceae_sb_info *sbi) {
  struct poaceae_hide_entry *entry, *tmp;

  mutex_lock(&sbi->hide_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->hide_list, list) {
    list_del_rcu(&entry->list);
    kfree_rcu(entry, rcu);
  }
  poaceae_rebuild_bloom(sbi);
  mutex_unlock(&sbi->hide_lock);

  return 0;
}

static int poaceae_add_redirect(struct poaceae_sb_info *sbi,
                                unsigned long arg) {
  struct poaceae_redirect_entry *entry;
  char *buf;
  char *target_path_str;
  char *src_name_str;
  struct path path_check;
  int err;

  buf = kmalloc(512, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  if (copy_from_user(buf, (void __user *)arg, 512)) {
    kfree(buf);
    return -EFAULT;
  }
  buf[511] = '\0';

  target_path_str = strchr(buf, '|');
  if (!target_path_str) {
    kfree(buf);
    return -EINVAL;
  }

  *target_path_str = '\0';
  src_name_str = buf;
  target_path_str++;

  err = kern_path(target_path_str, LOOKUP_FOLLOW, &path_check);
  if (!err) {
    if (path_check.dentry->d_sb->s_magic == POACEAEFS_MAGIC) {
      path_put(&path_check);
      kfree(buf);
      return -ELOOP;
    }
    path_put(&path_check);
  }

  entry = kzalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {
    kfree(buf);
    return -ENOMEM;
  }

  strscpy(entry->name, src_name_str, sizeof(entry->name));
  strscpy(entry->target, target_path_str, sizeof(entry->target));
  entry->name_len = strlen(entry->name);
  kfree(buf);

  mutex_lock(&sbi->redirect_lock);
  list_add_rcu(&entry->list, &sbi->redirect_list);
  poaceae_bloom_add(sbi, entry->name);
  mutex_unlock(&sbi->redirect_lock);

  return 0;
}

static int poaceae_clear_redirect(struct poaceae_sb_info *sbi) {
  struct poaceae_redirect_entry *entry, *tmp;

  mutex_lock(&sbi->redirect_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->redirect_list, list) {
    list_del_rcu(&entry->list);
    kfree_rcu(entry, rcu);
  }
  poaceae_rebuild_bloom(sbi);
  mutex_unlock(&sbi->redirect_lock);

  return 0;
}

static int poaceae_add_spoof(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_spoof_entry *entry;
  struct poaceae_ioctl_spoof args;

  if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
    return -EFAULT;

  args.name[255] = '\0';

  entry = kzalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry)
    return -ENOMEM;

  strscpy(entry->name, args.name, sizeof(entry->name));
  entry->uid = make_kuid(current_user_ns(), args.uid);
  entry->gid = make_kgid(current_user_ns(), args.gid);
  entry->mode = args.mode;
  entry->mtime = args.mtime;

  mutex_lock(&sbi->spoof_lock);
  list_add_rcu(&entry->list, &sbi->spoof_list);
  poaceae_bloom_add(sbi, entry->name);
  mutex_unlock(&sbi->spoof_lock);

  return 0;
}

static int poaceae_del_spoof(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_spoof_entry *entry, *tmp;
  char *name;

  name = kmalloc(256, GFP_KERNEL);
  if (!name)
    return -ENOMEM;

  if (copy_from_user(name, (void __user *)arg, 256)) {
    kfree(name);
    return -EFAULT;
  }

  name[255] = '\0';

  mutex_lock(&sbi->spoof_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->spoof_list, list) {
    if (strncmp(entry->name, name, sizeof(entry->name)) == 0) {
      list_del_rcu(&entry->list);
      kfree_rcu(entry, rcu);
    }
  }
  poaceae_rebuild_bloom(sbi);
  mutex_unlock(&sbi->spoof_lock);
  kfree(name);

  return 0;
}

static int poaceae_clear_spoof(struct poaceae_sb_info *sbi) {
  struct poaceae_spoof_entry *entry, *tmp;

  mutex_lock(&sbi->spoof_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->spoof_list, list) {
    list_del_rcu(&entry->list);
    kfree_rcu(entry, rcu);
  }
  poaceae_rebuild_bloom(sbi);
  mutex_unlock(&sbi->spoof_lock);

  return 0;
}

static int poaceae_add_merge(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_merge_entry *entry;
  char *buf;
  char *target_path_str;
  char *src_path_str;
  int err;

  buf = kmalloc(512, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  if (copy_from_user(buf, (void __user *)arg, 512)) {
    kfree(buf);
    return -EFAULT;
  }

  buf[511] = '\0';
  target_path_str = strchr(buf, '|');
  if (!target_path_str) {
    kfree(buf);
    return -EINVAL;
  }
  *target_path_str = '\0';
  src_path_str = buf;
  target_path_str++;

  entry = kzalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {
    kfree(buf);
    return -ENOMEM;
  }

  strscpy(entry->src, src_path_str, sizeof(entry->src));
  strscpy(entry->target, target_path_str, sizeof(entry->target));
  kfree(buf);

  err = kern_path(entry->target, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
                  &entry->target_path);
  if (err) {
    kfree(entry);
    return err;
  }

  if (entry->target_path.dentry->d_sb->s_magic == POACEAEFS_MAGIC) {
    path_put(&entry->target_path);
    kfree(entry);
    return -ELOOP;
  }

  mutex_lock(&sbi->merge_lock);
  list_add_rcu(&entry->list, &sbi->merge_list);
  mutex_unlock(&sbi->merge_lock);

  return 0;
}

static int poaceae_del_merge(struct poaceae_sb_info *sbi, unsigned long arg) {
  struct poaceae_merge_entry *entry, *tmp;
  char *src;

  src = kmalloc(256, GFP_KERNEL);
  if (!src)
    return -ENOMEM;

  if (copy_from_user(src, (void __user *)arg, 256)) {
    kfree(src);
    return -EFAULT;
  }
  src[255] = '\0';

  mutex_lock(&sbi->merge_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->merge_list, list) {
    if (strncmp(entry->src, src, sizeof(entry->src)) == 0) {
      list_del_rcu(&entry->list);
      path_put(&entry->target_path);
      kfree_rcu(entry, rcu);
    }
  }
  mutex_unlock(&sbi->merge_lock);
  kfree(src);

  return 0;
}

static int poaceae_clear_merge(struct poaceae_sb_info *sbi) {
  struct poaceae_merge_entry *entry, *tmp;

  mutex_lock(&sbi->merge_lock);
  list_for_each_entry_safe(entry, tmp, &sbi->merge_list, list) {
    list_del_rcu(&entry->list);
    path_put(&entry->target_path);
    kfree_rcu(entry, rcu);
  }
  mutex_unlock(&sbi->merge_lock);
  return 0;
}

long poaceae_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
  struct poaceae_sb_info *sbi = POACEAE_SB(file->f_inode->i_sb);

  if (!capable(CAP_SYS_ADMIN))
    return -EPERM;

  switch (cmd) {
  case POACEAE_IOC_ADD_HIDE:
    return poaceae_add_hide(sbi, arg);
  case POACEAE_IOC_DEL_HIDE:
    return poaceae_del_hide(sbi, arg);
  case POACEAE_IOC_CLEAR_HIDE:
    return poaceae_clear_hide(sbi);

  case POACEAE_IOC_ADD_REDIRECT:
    return poaceae_add_redirect(sbi, arg);
  case POACEAE_IOC_DEL_REDIRECT:
    return poaceae_clear_redirect(sbi);
  case POACEAE_IOC_CLEAR_REDIRECT:
    return poaceae_clear_redirect(sbi);

  case POACEAE_IOC_ADD_SPOOF:
    return poaceae_add_spoof(sbi, arg);
  case POACEAE_IOC_DEL_SPOOF:
    return poaceae_del_spoof(sbi, arg);
  case POACEAE_IOC_CLEAR_SPOOF:
    return poaceae_clear_spoof(sbi);

  case POACEAE_IOC_ADD_MERGE:
    return poaceae_add_merge(sbi, arg);
  case POACEAE_IOC_DEL_MERGE:
    return poaceae_del_merge(sbi, arg);
  case POACEAE_IOC_CLEAR_MERGE:
    return poaceae_clear_merge(sbi);

  case POACEAE_IOC_SET_TRUSTED_GID: {
    u32 gid;
    if (get_user(gid, (u32 __user *)arg))
      return -EFAULT;
    if (gid == (u32)-1)
      sbi->trusted_gid = INVALID_GID;
    else
      sbi->trusted_gid = make_kgid(current_user_ns(), gid);
    return 0;
  }

  default:
    return -ENOTTY;
  }
}