#include "poaceaefs.h"

struct poaceae_dir_context {
  struct dir_context ctx;
  struct dir_context *real_ctx;
  struct poaceae_sb_info *sbi;
  bool is_trusted;
};

static bool poaceae_filldir(struct dir_context *ctx, const char *name,
                            int namlen, loff_t offset, u64 ino,
                            unsigned int d_type) {
  struct poaceae_dir_context *pctx =
      container_of(ctx, struct poaceae_dir_context, ctx);
  struct poaceae_hide_entry *entry;
  bool hidden = false;

  if (pctx->is_trusted)
    return pctx->real_ctx->actor(pctx->real_ctx, name, namlen, offset, ino,
                                 d_type);

  if (!poaceae_bloom_check(pctx->sbi, name))
    return pctx->real_ctx->actor(pctx->real_ctx, name, namlen, offset, ino,
                                 d_type);

  rcu_read_lock();
  list_for_each_entry_rcu(entry, &pctx->sbi->hide_list, list) {
    if (namlen == entry->len && strncmp(name, entry->name, namlen) == 0) {
      hidden = true;
      break;
    }
  }
  rcu_read_unlock();

  if (hidden)
    return true;

  return pctx->real_ctx->actor(pctx->real_ctx, name, namlen, offset, ino,
                               d_type);
}

static int poaceae_iterate(struct file *file, struct dir_context *ctx) {
  struct file *lower_file = file->private_data;
  struct poaceae_sb_info *sbi = POACEAE_SB(file->f_inode->i_sb);
  struct poaceae_dir_context pctx;
  struct poaceae_redirect_entry *r_entry;
  struct poaceae_merge_entry *m_entry;
  struct poaceae_inode_info *pi = POACEAE_I(file->f_inode);
  char *buf, *path_str;
  struct path *merge_paths = NULL;
  int merge_count = 0;
  int i;
  int ret;

  if (!lower_file)
    return -EINVAL;

  pctx.real_ctx = ctx;
  pctx.ctx.actor = poaceae_filldir;
  pctx.ctx.pos = ctx->pos;
  pctx.sbi = sbi;
  pctx.is_trusted =
      gid_valid(sbi->trusted_gid) && gid_eq(current_gid(), sbi->trusted_gid);

  ret = iterate_dir(lower_file, &pctx.ctx);
  ctx->pos = pctx.ctx.pos;

  if (pctx.is_trusted)
    return ret;

  rcu_read_lock();
  list_for_each_entry_rcu(r_entry, &sbi->redirect_list, list) {
    if (!dir_emit(ctx, r_entry->name, r_entry->name_len,
                  1000000 + hash_32((unsigned long)r_entry, 32), DT_REG)) {
      break;
    }
  }
  rcu_read_unlock();

  buf = (char *)__get_free_page(GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  path_str = d_path(&pi->lower_path, buf, PAGE_SIZE);
  if (IS_ERR(path_str)) {
    free_page((unsigned long)buf);
    return PTR_ERR(path_str);
  }

  rcu_read_lock();
  list_for_each_entry_rcu(m_entry, &sbi->merge_list, list) {
    if (strcmp(path_str, m_entry->src) == 0)
      merge_count++;
  }
  rcu_read_unlock();

  if (merge_count > 0) {
    merge_paths = kcalloc(merge_count, sizeof(struct path), GFP_KERNEL);
    if (merge_paths) {
      int count = 0;
      rcu_read_lock();
      list_for_each_entry_rcu(m_entry, &sbi->merge_list, list) {
        if (strcmp(path_str, m_entry->src) == 0) {
          if (count < merge_count) {
            merge_paths[count] = m_entry->target_path;
            path_get(&merge_paths[count]);
            count++;
          }
        }
      }
      rcu_read_unlock();

      for (i = 0; i < count; i++) {
        struct file *merge_file;
        merge_file = dentry_open(&merge_paths[i], O_RDONLY, current_cred());
        if (!IS_ERR(merge_file)) {
          iterate_dir(merge_file, ctx);
          fput(merge_file);
        }
        path_put(&merge_paths[i]);
      }
      kfree(merge_paths);
    }
  }

  free_page((unsigned long)buf);

  return ret;
}

static int poaceae_open(struct inode *inode, struct file *file) {
  struct poaceae_inode_info *pi = POACEAE_I(inode);
  struct file *lower_file;
  const struct cred *cred = current_cred();

  if (!pi->lower_path.dentry)
    return -ENOENT;

  lower_file = dentry_open(&pi->lower_path, file->f_flags, cred);

  if (IS_ERR(lower_file))
    return PTR_ERR(lower_file);

  file->private_data = lower_file;
  return 0;
}

static int poaceae_release(struct inode *inode, struct file *file) {
  struct file *lower_file = file->private_data;
  if (lower_file)
    fput(lower_file);
  return 0;
}

static ssize_t poaceae_read_iter(struct kiocb *iocb, struct iov_iter *iter) {
  struct file *file = iocb->ki_filp;
  struct file *lower_file = file->private_data;
  int ret;

  if (!lower_file)
    return -EINVAL;

  iocb->ki_filp = lower_file;
  ret = call_read_iter(lower_file, iocb, iter);
  iocb->ki_filp = file;

  return ret;
}

static ssize_t poaceae_write_iter(struct kiocb *iocb, struct iov_iter *iter) {
  struct file *file = iocb->ki_filp;
  struct file *lower_file = file->private_data;
  int ret;

  if (!lower_file)
    return -EINVAL;

  iocb->ki_filp = lower_file;
  ret = call_write_iter(lower_file, iocb, iter);
  iocb->ki_filp = file;

  return ret;
}

const struct file_operations poaceae_dir_fops = {
    .owner = THIS_MODULE,
    .iterate_shared = poaceae_iterate,
    .open = poaceae_open,
    .release = poaceae_release,
    .llseek = generic_file_llseek,
    .read_iter = poaceae_read_iter,
    .write_iter = poaceae_write_iter,
    .unlocked_ioctl = poaceae_ioctl,
    .compat_ioctl = poaceae_ioctl,
};