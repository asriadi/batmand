/*
 * Copyright (C) 2007-2008 B.A.T.M.A.N. contributors:
 * Marek Lindner, Simon Wunderlich
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */





#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define PROC_ROOT_DIR "batman-adv"
#define PROC_FILE_INTERFACES "interfaces"
#define PROC_FILE_ORIG_INTERVAL "orig_interval"
#define PROC_FILE_ORIGINATORS "originators"
#define PROC_FILE_GATEWAYS "gateways"
#define PROC_FILE_LOG "log"
#define PROC_FILE_LOG_LEVEL "log_level"
#define PROC_FILE_TRANSTABLE_LOCAL "transtable_local"
#define PROC_FILE_TRANSTABLE_GLOBAL "transtable_global"
#define PROC_FILE_VIS "vis"



void cleanup_procfs(void);
int setup_procfs(void);
int proc_interfaces_read(struct seq_file *seq, void *offset);
int proc_interfaces_open(struct inode *inode, struct file *file);
ssize_t proc_interfaces_write(struct file *instance, const char __user *userbuffer, size_t count, loff_t *data);
int proc_orig_interval_read(struct seq_file *seq, void *offset);
int proc_orig_interval_open(struct inode *inode, struct file *file);
ssize_t proc_orig_interval_write(struct file *file, const char __user * buffer, size_t count, loff_t * ppos);
int proc_originators_open(struct inode *inode, struct file *file);
int proc_originators_read(struct seq_file *seq, void *offset);
/*int proc_gateways_read(char *buf, char **start, off_t offset, int size, int *eof, void *data);*/
int proc_log_level_open(struct inode *inode, struct file *file);
int proc_log_level_read(struct seq_file *seq, void *offset);
ssize_t proc_log_level_write(struct file *instance, const char __user *userbuffer, size_t count, loff_t *data);
int proc_transtable_local_open(struct inode *inode, struct file *file);
int proc_transtable_local_read(struct seq_file *seq, void *offset);
int proc_transtable_global_open(struct inode *inode, struct file *file);
int proc_transtable_global_read(struct seq_file *seq, void *offset);
int proc_vis_open(struct inode *inode, struct file *file);
int proc_vis_read(struct seq_file *seq, void *offset);
ssize_t proc_dummy_write(struct file *file, const char __user * buffer, size_t count, loff_t * ppos);
