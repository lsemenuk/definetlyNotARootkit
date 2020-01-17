obj-m += rootkit-main.h rootkit-main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	sudo insmod rootkit-main.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	- sudo rmmod rootkit-main > /dev/null 2>&1
