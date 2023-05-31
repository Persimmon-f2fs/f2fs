#include "f2fs.h"
#include "zoned_meta_table.h"
#include "segment.h"
#include "iostat.h"
#include <linux/f2fs_fs.h>
#include <linux/err.h>
#include <linux/pagevec.h>

struct page *get_chunk_page(struct f2fs_sb_info *sbi, block_t lba)
{
	struct address_space *mapping = META_MAPPED_MAPPING(sbi);
	struct page *page;
	block_t index, meta_lba;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META_MAPPED,
		.op = REQ_OP_READ,
		.op_flags = REQ_META | REQ_PRIO,
		.encrypted_page = NULL,
		.is_por = false,
	};
	int err;

	index = GET_BAT_IDX(sbi, lba) +
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->last_ssa_blkaddr) +
			1; // avoid conflicting with other mapped pages
	meta_lba =  GET_BAT_ENTRY(sbi, lba);

repeat:
	page = f2fs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (PageUptodate(page))
		goto out;

	if (meta_lba == BLOCK_UNALLOCATED) {
		memset(page_address(page), 0, PAGE_SIZE);
		SetPageUptodate(page);
		goto out;
	}

	fio.page = page;
	fio.new_blkaddr = meta_lba;
	fio.old_blkaddr = meta_lba;

	err = f2fs_submit_page_bio(&fio);
	if (err) {
		f2fs_err(sbi, "could not read page!");
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	}

	f2fs_update_iostat(sbi, FS_META_READ_IO, F2FS_BLKSIZE);

	lock_page(page);
	if (unlikely(page->mapping != mapping)) {
		f2fs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		f2fs_put_page(page, 1);
		return ERR_PTR(-EIO);
	}
out:
	return page;
}

struct page *grab_bat_page(struct f2fs_sb_info *sbi, block_t lba)
{
	struct address_space *mapping = META_MAPPED_MAPPING(sbi);
	struct page *page;
	block_t index = GET_BAT_IDX(sbi, lba) +
			le32_to_cpu(F2FS_RAW_SUPER(sbi)->last_ssa_blkaddr) +
			1; // avoid conflicting with other mapped pages
repeat:
	page = f2fs_grab_cache_page(mapping, index, false);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (!PageUptodate(page))
		SetPageUptodate(page);
	return page;
}