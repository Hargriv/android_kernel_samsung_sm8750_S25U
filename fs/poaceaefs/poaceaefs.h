#ifndef _POACEAEFS_H
#define _POACEAEFS_H

#include <linux/bitmap.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/xattr.h>

#define POACEAEFS_MAGIC 0x504F4143

#define POACEAE_IOC_ADD_HIDE _IOW(POACEAEFS_MAGIC, 1, char[256])
#define POACEAE_IOC_DEL_HIDE _IOW(POACEAEFS_MAGIC, 2, char[256])
#define POACEAE_IOC_CLEAR_HIDE _IO(POACEAEFS_MAGIC, 3)

#define POACEAE_IOC_ADD_REDIRECT _IOW(POACEAEFS_MAGIC, 4, char[512])
#define POACEAE_IOC_DEL_REDIRECT _IOW(POACEAEFS_MAGIC, 5, char[256])
#define POACEAE_IOC_CLEAR_REDIRECT _IO(POACEAEFS_MAGIC, 6)

struct poaceae_ioctl_spoof {
  char name[256];
  u32 uid;
  u32 gid;
  u16 mode;
  u64 mtime;
};

#define POACEAE_IOC_ADD_SPOOF                                                  \
  _IOW(POACEAEFS_MAGIC, 7, struct poaceae_ioctl_spoof)
#define POACEAE_IOC_DEL_SPOOF _IOW(POACEAEFS_MAGIC, 8, char[256])
#define POACEAE_IOC_CLEAR_SPOOF _IO(POACEAEFS_MAGIC, 9)

#define POACEAE_IOC_ADD_MERGE _IOW(POACEAEFS_MAGIC, 10, char[512])
#define POACEAE_IOC_DEL_MERGE _IOW(POACEAEFS_MAGIC, 11, char[256])
#define POACEAE_IOC_CLEAR_MERGE _IO(POACEAEFS_MAGIC, 12)

#define POACEAE_IOC_SET_TRUSTED_GID _IOW(POACEAEFS_MAGIC, 13, u32)

#define POACEAE_BLOOM_BITS 1024

struct poaceae_inode_info {
  struct inode vfs_inode;
  struct path lower_path;
};

static inline struct poaceae_inode_info *POACEAE_I(struct inode *inode) {
  return container_of(inode, struct poaceae_inode_info, vfs_inode);
}

struct poaceae_hide_entry {
  struct list_head list;
  struct rcu_head rcu;
  char name[256];
  size_t len;
};

struct poaceae_redirect_entry {
  struct list_head list;
  struct rcu_head rcu;
  char name[256];
  char target[256];
  size_t name_len;
};

struct poaceae_spoof_entry {
  struct list_head list;
  struct rcu_head rcu;
  char name[256];
  kuid_t uid;
  kgid_t gid;
  umode_t mode;
  time64_t mtime;
};

struct poaceae_merge_entry {
  struct list_head list;
  struct rcu_head rcu;
  char src[256];
  char target[256];
  struct path target_path;
};

struct poaceae_sb_info {
  struct path lower_path;

  struct list_head hide_list;
  struct mutex hide_lock;

  struct list_head redirect_list;
  struct mutex redirect_lock;

  struct list_head spoof_list;
  struct mutex spoof_lock;

  struct list_head merge_list;
  struct mutex merge_lock;

  kgid_t trusted_gid;
  DECLARE_BITMAP(bloom_filter, POACEAE_BLOOM_BITS);
};

static inline struct poaceae_sb_info *POACEAE_SB(struct super_block *sb) {
  return sb->s_fs_info;
}

static inline void poaceae_bloom_add(struct poaceae_sb_info *sbi,
                                     const char *name) {
  u32 hash = hash_32((unsigned long)name, 32);
  set_bit(hash % POACEAE_BLOOM_BITS, sbi->bloom_filter);
}

static inline bool poaceae_bloom_check(struct poaceae_sb_info *sbi,
                                       const char *name) {
  u32 hash = hash_32((unsigned long)name, 32);
  return test_bit(hash % POACEAE_BLOOM_BITS, sbi->bloom_filter);
}

extern const struct inode_operations poaceae_dir_iops;
extern const struct file_operations poaceae_dir_fops;
extern const struct dentry_operations poaceae_dops;

long poaceae_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif