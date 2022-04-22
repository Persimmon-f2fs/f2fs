# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_F2FS_FS) += f2fs.o

f2fs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
f2fs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
f2fs-y		+= shrinker.o extent_cache.o sysfs.o zoned_checkpoint.o
f2fs-y 		+= zoned_meta_table.o tests/zoned_meta_tests.o
f2fs-$(CONFIG_F2FS_STAT_FS) += debug.o
f2fs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
f2fs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f2fs-$(CONFIG_FS_VERITY) += verity.o
f2fs-$(CONFIG_F2FS_FS_COMPRESSION) += compress.o
f2fs-$(CONFIG_F2FS_IOSTAT) += iostat.o
f2fs-$(CONFIG_F2FS_FS_UNIT_TEST) += tests/zoned_checkpoint_tests.o

# ensure that we're using our version of f2fs_fs.h
# we've also modified the name of the exported fs
#
ifdef PROJECT_ROOT
ccflags-y:=-I${PROJECT_ROOT}/include

KERNEL_DIR:=/lib/modules/`uname -r`/build
PWD:=${PROJECT_ROOT}/fs/f2fs

CCLS:=${PWD}/.ccls

default:
	make -C ${KERNEL_DIR} M=${PWD}

clean:
	make -C ${KERNEL_DIR} M=${PWD} clean

${CCLS}:
	@echo "-I" >> $@
	@echo "${PROJECT_ROOT}/include" >> $@
	@echo "-I" >> $@
	@echo "${KERNEL_DIR}/include" >> $@
	@echo "-std=c99" >> $@
endif
