MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS := -I. -I$(src)/../include

#obj-m += xt_seng.o
obj-m += seng.o
seng-objs := xt_seng.o xt_seng_genl.o xt_seng_metadb.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
