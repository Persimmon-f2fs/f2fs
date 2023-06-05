#include "f2fs.h"
#include "zoned_meta_table.h"
#include "segment.h"
#include "iostat.h"
#include <linux/f2fs_fs.h>
#include <linux/err.h>
#include <linux/pagevec.h>

struct page *get_chunk_page(struct f2fs_sb_info *sbi, block_t lba)
{
	struct address_space *mapping = META_CHUNK_MAPPING(sbi);
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

	index = GET_BAT_IDX(sbi, lba);
	meta_lba = GET_BAT_ENTRY(sbi, lba);

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

struct page *grab_chunk_page(struct f2fs_sb_info *sbi, block_t lba)
{
	struct address_space *mapping = META_CHUNK_MAPPING(sbi);
	struct page *page;
	block_t index = GET_BAT_IDX(sbi, lba);

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

// must be called from the mmi write lock
static int __write_chunk_page(struct f2fs_sb_info *sbi, struct page *page,
			      enum iostat_type io_type)
{
	struct f2fs_mm_info *mmi = sbi->mm_info;
	block_t meta_lba = 0;
	int err = 0;

	if (mmi->current_wp + 2 >= LAST_BLOCK_IN_SEC(sbi, mmi->current_secno)) {
		// zone would be full! move to the next
		err = choose_next_secno(sbi, false);
		if (err)
			goto out;
	}

	meta_lba = mmi->current_wp;

	mmi->bat_addrs[page->index] = meta_lba;

	issue_page_write(sbi, page, meta_lba, io_type);

	clear_page_dirty_for_io(page);

	mmi->current_wp++;

out:
	return err;
}

int write_chunk_page(struct page *page, struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	int err = 0;

	if (unlikely(f2fs_cp_error(sbi))) {
		goto redirty_out;
	}
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING))) {
		goto redirty_out;
	}

	down_write(&sbi->mm_info->mmi_lock);
	err = __write_chunk_page(sbi, page, FS_META_IO);
	up_write(&sbi->mm_info->mmi_lock);

	dec_page_count(sbi, F2FS_CHUNK_META_DIRTY);

	if (wbc->for_reclaim)
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, META_CHUNK);

	unlock_page(page);

	if (unlikely(f2fs_cp_error(sbi)))
		f2fs_submit_merged_write(sbi, META_CHUNK);

	return err;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

static int write_chunk_pages(struct address_space *mapping,
			     struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_M_SB(mapping);
	long written;

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	if (wbc->sync_mode != WB_SYNC_ALL &&
	    get_pages(sbi, F2FS_CHUNK_META_DIRTY) <
		    nr_pages_to_skip(sbi, META_CHUNK))
		goto skip_write;

	/* if locked failed, cp will flush dirty pages instead */
	if (!f2fs_down_write_trylock(&sbi->cp_global_sem))
		goto skip_write;

	written = f2fs_sync_meta_chunk_pages(sbi, META_CHUNK, wbc->nr_to_write,
					     FS_META_IO);
	f2fs_up_write(&sbi->cp_global_sem);
	wbc->nr_to_write = max((long)0, wbc->nr_to_write - written);

	return 0;

skip_write:
	wbc->pages_skipped += get_pages(sbi, F2FS_CHUNK_META_DIRTY);
	return 0;
}

static bool dirty_chunk_folio(struct address_space *mapping,
			      struct folio *folio)
{
	if (!folio_test_uptodate(folio))
		folio_mark_uptodate(folio);
	if (!folio_test_dirty(folio)) {
		filemap_dirty_folio(mapping, folio);
		inc_page_count(F2FS_M_SB(mapping), F2FS_CHUNK_META_DIRTY);
		set_page_private_reference(&folio->page);
		return true;
	}
	return false;
}

const struct address_space_operations f2fs_chunk_aops = {
	.writepage = write_chunk_page,
	.writepages = write_chunk_pages, // unless needed
	.dirty_folio = dirty_chunk_folio,
	.invalidate_folio = f2fs_invalidate_folio,
	.releasepage = f2fs_release_page,
};
