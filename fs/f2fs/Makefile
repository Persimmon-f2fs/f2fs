# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_F2FS_FS) += f2fs_mod.o

f2fs_mod-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
f2fs_mod-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
f2fs_mod-y		+= shrinker.o extent_cache.o sysfs.o zoned_checkpoint.o
f2fs_mod-y 		+= zoned_meta_table.o chunk_pages.o
f2fs_mod-$(CONFIG_F2FS_STAT_FS) += debug.o
f2fs_mod-$(CONFIG_F2FS_FS_XATTR) += xattr.o
f2fs_mod-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f2fs_mod-$(CONFIG_FS_VERITY) += verity.o
f2fs_mod-$(CONFIG_F2FS_FS_COMPRESSION) += compress.o
f2fs_mod-$(CONFIG_F2FS_IOSTAT) += iostat.o

# ensure that we're using our version of f2fs_fs.h
# we've also modified the name of the exported fs
#
ifdef PROJECT_ROOT
ifdef KERNEL_DIR

PWD:=${PROJECT_ROOT}/fs/f2fs

default:
	make -C ${KERNEL_DIR} M=${PWD}

clean:
	make -C ${KERNEL_DIR} M=${PWD} clean

endif
endif

