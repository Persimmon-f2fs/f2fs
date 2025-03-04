#include "f2fs.h"
#include "zoned_meta_table.h"
#include "segment.h"
#include "iostat.h"
#include <linux/f2fs_fs.h>
#include <linux/err.h>
#include <linux/pagevec.h>

static int copy_data_from_ssd(struct f2fs_sb_info *sbi, u32 *dest,
			      u32 start_blk, u32 read_amt)
{
	struct page *blk_page;
	u32 copy_idx, copy_amt, blk_count, blk;
	int err = 0;

	// read the table from ssd
	blk_count = CEILING(read_amt, F2FS_BLKSIZE);
	copy_amt = read_amt;
	copy_idx = 0;
	blk = start_blk;
	for (blk = start_blk; blk < start_blk + blk_count; ++blk) {
		blk_page = f2fs_get_meta_page(sbi, blk);
		if (IS_ERR(blk_page)) {
			err = PTR_ERR(blk_page);
			goto out;
		}
		copy_amt = MIN(F2FS_BLKSIZE, copy_amt);
		memcpy(dest + copy_idx, page_address(blk_page), copy_amt);

		copy_idx += copy_amt;
		copy_amt -= copy_amt;
		f2fs_put_page(blk_page, 1);
	}

out:
	return err;
}

static int read_mm_info_state(struct f2fs_sb_info *sbi, block_t cp_addr)
{
	int err = 0;
	struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
	u32 bat_block, bit_block, bitmap_block;
	struct f2fs_mm_info *mm_info = sbi->mm_info;

	// f2fs_info(sbi, "reading meta state!!!");

	bat_block = cp_addr + le32_to_cpu(cp->cp_pack_start_meta_bat);
	bit_block = cp_addr + le32_to_cpu(cp->cp_pack_start_meta_bit);
	bitmap_block = cp_addr + le32_to_cpu(cp->cp_pack_start_meta_bitmap);

	err = copy_data_from_ssd(sbi, mm_info->bat_addrs, bat_block,
				 sizeof(block_t) * F2FS_BAT_SIZE(sbi));
	if (err) {
		f2fs_err(sbi, "Could not read bat table");
		goto out;
	}

	err = copy_data_from_ssd(sbi, mm_info->block_information_table,
				 bit_block, F2FS_BIT_SIZE(sbi));
	if (err) {
		f2fs_err(sbi, "Could not read bit table");
		goto out;
	}

	err = copy_data_from_ssd(sbi, mm_info->section_bitmap, bitmap_block,
				 sizeof(block_t) * F2FS_BITMAP_SIZE(sbi));
	if (err) {
		f2fs_err(sbi, "Could not read bitmap table");
		goto out;
	}

out:
	return err;
}

static int write_data_to_ssd(struct f2fs_sb_info *sbi, void *src, u32 start_blk,
			     u32 write_amt)
{
	struct page *blk_page = NULL;
	u32 copy_idx, copy_amt, blk_count, blk;
	int err = 0;

	copy_idx = 0;
	blk_count = CEILING(write_amt, F2FS_BLKSIZE);
	blk = start_blk;

	for (blk = start_blk; blk < start_blk + blk_count; ++blk) {
		blk_page = f2fs_grab_meta_page(sbi, blk);
		copy_amt = MIN(PAGE_SIZE, write_amt);

		memcpy(page_address(blk_page), src + copy_idx, copy_amt);
		set_page_dirty(blk_page);
		f2fs_put_page(blk_page, 1);

		copy_idx += copy_amt;
		write_amt -= copy_amt;
	}

	return err;
}

int mm_write_info(struct f2fs_sb_info *sbi, u32 start_blk)
{
	int err = 0;
	struct f2fs_mm_info *mmi = sbi->mm_info;

	// f2fs_info(sbi, "write current_wp: %u", mmi->current_wp);
	f2fs_info(sbi, "write_mm_info. start_blk: %u", start_blk);

	err = write_data_to_ssd(sbi, mmi->bat_addrs, start_blk,
				sizeof(u32) * F2FS_BAT_SIZE(sbi));
	if (err)
		goto out;
	start_blk += F2FS_BAT_BLOCKS(sbi);

	err = write_data_to_ssd(sbi, mmi->block_information_table, start_blk,
				F2FS_BIT_SIZE(sbi));
	if (err)
		goto out;
	start_blk += F2FS_BIT_BLOCKS(sbi);

	err = write_data_to_ssd(sbi, mmi->section_bitmap, start_blk,
				sizeof(u32) * F2FS_BITMAP_SIZE(sbi));
	if (err)
		goto out;
	start_blk += F2FS_BITMAP_BLOCKS(sbi);

	// f2fs_info(sbi, "done writing mm_info");

out:
	return err;
}

/*
 * From the most recent meta blkaddr (given by the checkpoint), read up to the write pointer
 * all entries that were appended to the current segment.
 *
 * Checkpointing needs to happen often enough that they are in the same zone (segment).
 */
static int recover_mm_info_state(struct f2fs_sb_info *sbi)
{
	int err = 0;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	block_t wp_block = 0, start_block = 0;
	unsigned int current_secno = 0;
	struct page *meta_page = NULL;
	struct f2fs_meta_block *meta_block = NULL;

	if (!ckpt) {
		f2fs_err(sbi, "ckpt is null!");
		return -1;
	}

	current_secno = le32_to_cpu(ckpt->cur_meta_secno);

	err = fetch_section_write_pointer(sbi, current_secno, &wp_block);
	if (err) {
		f2fs_err(sbi,
			 "Could not fetch write pointer for cur_meta_secno");
		return err;
	}

	start_block = le32_to_cpu(ckpt->cur_meta_wp);
	// TODO: read ahead meta pages

	f2fs_info(sbi, "start_block: %u, wp_block: %u", start_block, wp_block);

	// iterate through all blocks from current offset to write pointer
	// iterate two at a time since the actual meta block is the block
	// adjacent to the (meta) data
	start_block += 1;
	for (; start_block < wp_block; start_block += 2) {
		meta_page = f2fs_get_meta_page(sbi, start_block);
		if (IS_ERR(meta_page)) {
			f2fs_err(sbi, "Could not read meta_page");
			err = PTR_ERR(meta_page);
			return err;
		}

		meta_block = page_address(meta_page);

		if (!meta_block->is_gc_end) {
			// gc_ends mark the end of garbage collection and their data blocks are empty
			SET_BAT_ENTRY(sbi, meta_block->lba, start_block);
		}

		if (meta_block->prev_zone_id != BLOCK_UNALLOCATED) {
			// case where we've created data
			SET_BIT_ENTRY(sbi, meta_block->prev_zone_id,
				      meta_block->invalid_count);
			memcpy(sbi->mm_info->section_bitmap,
			       meta_block->section_bitmap, SECTION_BITMAP_SIZE);
		}
		put_page(meta_page);
	}

	// also set the wp
	sbi->mm_info->current_secno = current_secno;
	sbi->mm_info->current_wp = wp_block;

	// f2fs_info(sbi, "read current_secno: %u, current_wp: %u", current_secno,
		//   wp_block);

	return err;
}

void check_bat_addrs(struct f2fs_sb_info *sbi)
{
	block_t cur_blk = 0, first = 0, last = 0, bat_addr = 0;

	first = le32_to_cpu(F2FS_RAW_SUPER(sbi)->nat_blkaddr);
	last = le32_to_cpu(F2FS_RAW_SUPER(sbi)->last_ssa_blkaddr);

	for (cur_blk = first + BAT_CHUNK_SIZE; cur_blk <= last; ++cur_blk) {
		bat_addr = GET_BAT_ENTRY(sbi, cur_blk);
		if (bat_addr != BLOCK_UNALLOCATED) {
			//             f2fs_err(sbi, "addr: (%u) has bat_addr: (%u)",
			//                    cur_blk, bat_addr);
			break;
		}
	}
}

int create_f2fs_mm_info(struct f2fs_sb_info *sbi, block_t cp_addr)
{
	int err = 0, j = 0;
	struct f2fs_mm_info *mm_info = NULL;
	block_t *bat_addrs = NULL, *bit_addrs = NULL;

	// f2fs_info(sbi, "bat size: %u", F2FS_BAT_SIZE(sbi));

	mm_info = kmalloc(sizeof(struct f2fs_mm_info), GFP_KERNEL);
	if (!mm_info) {
		err = -ENOMEM;
		goto error;
	}

	bat_addrs = kmalloc(sizeof(block_t) * F2FS_BAT_SIZE(sbi), GFP_KERNEL);
	if (!bat_addrs) {
		err = -ENOMEM;
		goto error;
	}
	bit_addrs = kmalloc(F2FS_BIT_SIZE(sbi), GFP_KERNEL);
	if (!bit_addrs) {
		err = -ENOMEM;
		goto error;
	}

	// f2fs_info(sbi, "number of meta sections: %u", le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta));
	for (j = FIRST_META_SECNO(sbi);
	     j < le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta); ++j) {
		// f2fs_info(sbi, "section %d start %u", j, START_BLOCK_FROM_SEG0(sbi, GET_SEG_FROM_SEC(sbi, j)));
		// f2fs_info(sbi, "end: %u", LAST_BLOCK_IN_SEC(sbi, j));
	}

	mm_info->bat_addrs = bat_addrs;
	mm_info->block_information_table = bit_addrs;
	init_rwsem(&mm_info->mmi_lock);
	sbi->mm_info = mm_info;

	err = read_mm_info_state(sbi, cp_addr);
	if (err) {
		goto error;
	}

	err = recover_mm_info_state(sbi);
	if (err) {
		goto error;
	}

	check_bat_addrs(sbi);

	// DUMP_BAT(sbi);

	return err;
error:

	// clean up data
	if (mm_info) {
		kfree(mm_info);
	}
	if (bat_addrs) {
		kfree(bat_addrs);
	}
	if (bit_addrs) {
		kfree(bit_addrs);
	}

	return -1;
}

void destroy_f2fs_mm_info(struct f2fs_sb_info *sbi)
{
	// DUMP_BAT(sbi);
	kfree(sbi->mm_info->bat_addrs);
	kfree(sbi->mm_info->block_information_table);
	kfree(sbi->mm_info);
}

// assumed to be called under write lock
int choose_next_secno(struct f2fs_sb_info *sbi, bool in_gc_loop)
{
	struct f2fs_super_block *fsb = F2FS_RAW_SUPER(sbi);
	struct f2fs_mm_info *mmi = sbi->mm_info;
	unsigned int empty_secno = 0, selected_secno = 0, bound = 0,
		     number_empty = 0;
	int err = 0;

	empty_secno = FIRST_META_SECNO(sbi);
	bound = FIRST_META_SECNO(sbi) + (le32_to_cpu(fsb->section_count_meta));
	number_empty = 0;

	// f2fs_info(sbi, "choosing next secno");

	// f2fs_info(sbi, "empty_secno: %u, bound: %u", empty_secno, bound);
	// f2fs_info(sbi, "bound blkaddr: %u", START_BLOCK_FROM_SEG0(sbi, GET_SEG_FROM_SEC(sbi, bound)));

	for (; empty_secno < bound; ++empty_secno) {
		if (GET_SECTION_BITMAP(sbi, empty_secno) == SECTION_EMPTY) {
			selected_secno = empty_secno;
			number_empty++;
		}
	}

	// set the current bound
	mmi->current_secno = selected_secno;
	mmi->current_wp = START_BLOCK_FROM_SEG0(
		sbi, GET_SEG_FROM_SEC(sbi, selected_secno));
	SET_SECTION_BITMAP(sbi, selected_secno, SECTION_NON_EMPTY);
	// f2fs_info(sbi, "Chose next meta section. current_secno: %u, current_wp: %u, number_empty: %u",
	// mmi->current_secno, mmi->current_wp, number_empty);

	if (number_empty == 1 && !in_gc_loop) {
		err = mm_do_garbage_collection(sbi);
		if (err) {
			f2fs_err(sbi, "Could not perform garbage collection.");
		}
	}

	// TODO: initiate checkpoint procedure
	return err;
}

// assumed to be called under write lock
static int write_mapped_page(struct f2fs_sb_info *sbi, struct page *virt_page,
			     enum iostat_type io_type)
{
	struct f2fs_mm_info *mmi = sbi->mm_info;
	struct f2fs_meta_block *mb = NULL;
	struct page *meta_page = NULL;
	block_t lba = 0, data_lba = 0;
	int err = 0;

	// f2fs_info(sbi, "current_wp: %u", mmi->current_wp);

	if (mmi->current_wp + 2 >= LAST_BLOCK_IN_SEC(sbi, mmi->current_secno)) {
		// zone would be full! move to the next
		err = choose_next_secno(sbi, false);
		if (err)
			goto out;
	}

	data_lba = mmi->current_wp;

	// f2fs_info(sbi, "Writing mapped page with data_lba: %u and meta_lba: %u", data_lba, meta_lba);

	// grab the latest bat entry for the respective lba
	lba = virt_page->index;

	// make a dummy page for the metadata
	// f2fs_info(sbi, "grabbing new meta page");
	meta_page = get_chunk_page(sbi, lba);

	mb = page_address(meta_page);

	// gross, but important logic
	// this will update the chunk ptr to point to the block
	// perhaps there's a better way of doing this, but we need to set the page
	// dirty immediately after this operation (maybe encapsulate this in a function.)
	mb->bat_chunk[SLOT_IN_BAT(sbi, lba)] = cpu_to_le32(data_lba);

	SET_SECTION_BITMAP(sbi, GET_SEC_FROM_BLK(sbi, data_lba),
			   SECTION_NON_EMPTY);

	// f2fs_info(sbi, "writing the pages");
	issue_page_write(sbi, virt_page, data_lba, META_MAPPED, io_type);

	set_page_dirty(meta_page);

	clear_page_dirty_for_io(virt_page);

	mmi->current_wp++;

	f2fs_put_page(meta_page, 1);

	// f2fs_info(sbi, "wrote some pages");

out:
	return err;
}

static struct page *__grab_mapped_page(struct f2fs_sb_info *sbi, u32 lba,
				       bool for_write)
{
	struct address_space *mapped_meta_address = META_MAPPED_MAPPING(sbi);
	struct page *page = NULL;
repeat:
	page = f2fs_grab_cache_page(mapped_meta_address, lba, for_write);
	if (!page) {
		cond_resched();
		goto repeat;
	}
	if (!PageUptodate(page)) {
		SetPageUptodate(page);
	}

	// TODO: do we wait on page writeback here? really that should be done with the physical page
	f2fs_wait_on_page_writeback(page, META_MAPPED, true, true);
	return page;
}

struct page *grab_mapped_page(struct f2fs_sb_info *sbi, u32 lba, bool for_write)
{
	return __grab_mapped_page(sbi, lba, for_write);
}

static int read_phys_pages(struct f2fs_sb_info *sbi, struct page *virt_page)
{
	int err = 0;
	block_t lba, phys_lba;
	struct page *meta_page;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META_MAPPED,
		.op = REQ_OP_READ,
		.op_flags = REQ_META | REQ_PRIO,
		.encrypted_page = NULL,
		.is_por = false,
		.page = virt_page,
	};
	// struct f2fs_bio_info *io = sbi->write_io[META_MAPPED] + HOT;

	lba = virt_page->index;

	// f2fs_info(sbi, "Looking up meta_page at chunk_lba: %u", chunk_lba);
	meta_page = get_chunk_page(sbi, lba);
	if (IS_ERR(meta_page)) {
		f2fs_err(sbi, "Could not grab meta page");
		return PTR_ERR(meta_page);
	}

	phys_lba = MM_PHYS_ADDR(sbi, page_address(meta_page), lba);
	if (phys_lba == BLOCK_UNALLOCATED) {
		memset(page_address(virt_page), 0, PAGE_SIZE);
		f2fs_put_page(meta_page, true);
		return 0;
	}

	// prepare the fio
	fio.old_blkaddr = phys_lba;
	fio.new_blkaddr = phys_lba;

	// f2fs_info(sbi, "reading phys_lba: %u", phys_lba);

	err = f2fs_submit_page_bio(&fio);
	if (err) {
		f2fs_err(sbi, "could not read page!");
		goto out;
	}

	f2fs_update_iostat(sbi, FS_META_READ_IO, F2FS_BLKSIZE);

	lock_page(virt_page);

out:
	f2fs_put_page(meta_page, true);

	return err;
}

// assumed to be called under write or read lock
static struct page *__get_mapped_page(struct f2fs_sb_info *sbi, u32 lba,
				      bool for_write)
{
	struct page *virt_page = NULL;
	struct address_space *mma = META_MAPPED_MAPPING(sbi);
	int err = 0;

	// when we grab the page, if it was created, then we need to read from disk
	// always read the physical page for now

repeat:
	virt_page = f2fs_grab_cache_page(mma, lba, for_write);
	if (!virt_page) {
		cond_resched();
		goto repeat;
	}
	if (IS_ERR(virt_page)) {
		f2fs_err(sbi, "Could not grab meta page");
		goto out;
	}
	if (PageUptodate(virt_page)) {
		goto out;
	}

	// grab the physical page by looking up the chunk address
	// If the block is currently unallocated, fill with 0's

	err = read_phys_pages(sbi, virt_page);
	if (err) {
		// f2fs_info(sbi, "reading phys pages failed.");
		f2fs_put_page(virt_page, true);
		return ERR_PTR(err);
	}

	if (unlikely(virt_page->mapping != mma)) {
		// f2fs_info(sbi, "virt page mapping not the same as mma");
		f2fs_put_page(virt_page, 1);
		goto repeat;
	}

	// should be safe to do this here?
	SetPageUptodate(virt_page);

out:
	return virt_page;
}

struct page *get_mapped_page(struct f2fs_sb_info *sbi, u32 lba, bool for_write)
{
	struct page *page;
	down_read(&sbi->mm_info->mmi_lock);
	page = __get_mapped_page(sbi, lba, for_write);
	up_read(&sbi->mm_info->mmi_lock);
	return page;
}

struct page *get_mapped_page_retry(struct f2fs_sb_info *sbi, u32 lba,
				   bool for_write)
{
	struct page *page;
	int count = 0;

	down_read(&sbi->mm_info->mmi_lock);
retry:
	page = __get_mapped_page(sbi, lba, true);
	if (IS_ERR(page)) {
		if (PTR_ERR(page) == -EIO && ++count <= DEFAULT_RETRY_IO_COUNT)
			goto retry;
		f2fs_stop_checkpoint(sbi, false);
	}

	up_read(&sbi->mm_info->mmi_lock);

	return page;
}

void update_mapped_page(struct f2fs_sb_info *sbi, void *src, block_t blk_addr)
{
	struct page *page = grab_mapped_page(sbi, blk_addr, true);

	memcpy(page_address(page), src, F2FS_BLKSIZE);
	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

// assumed to be called under a write lock
static int mm_migrate_page(struct f2fs_sb_info *sbi, block_t phys_blk, u32 lba)
{
	int err = 0;
	struct f2fs_mm_info *mmi = sbi->mm_info;
	struct page *data_page = NULL, *virt_page = NULL;

	if (mmi->current_wp + 2 >= LAST_BLOCK_IN_SEC(sbi, mmi->current_secno)) {
		// zone would be full! move to the next
		err = choose_next_secno(sbi, false);
		if (err)
			goto out;
	}

	virt_page = __grab_mapped_page(sbi, lba, true);
	if (IS_ERR(virt_page)) {
		err = PTR_ERR(virt_page);
		f2fs_err(sbi, "Could not grab virt_page");
		goto out;
	}
	data_page = f2fs_get_meta_page(sbi, phys_blk);
	if (IS_ERR(data_page)) {
		err = PTR_ERR(data_page);
		f2fs_err(sbi, "Could not grab data_page");
		goto put_virt_page;
	}

	// copy the data from phys page to virt page
	memcpy(page_address(virt_page), page_address(data_page), PAGE_SIZE);

	f2fs_put_page(data_page, true);

	err = write_mapped_page(sbi, virt_page, FS_META_IO);
	if (err) {
		f2fs_err(sbi, "Failed to migrate page");
	}

put_virt_page:
	f2fs_put_page(virt_page, true);
out:
	return err;
}

int mm_write_meta_page(struct page *page, struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	int err = 0;

	if (unlikely(f2fs_cp_error(sbi))) {
		goto redirty_out;
	}
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING))) {
		goto redirty_out;
	}

// not really sure what this is doing
#if 0
	if (wbc->for_reclaim && page->index < GET_SUM_BLOCK(sbi, 0)) {
		goto redirty_out;
    }
#endif

	down_write(&sbi->mm_info->mmi_lock);

	err = write_mapped_page(sbi, page, FS_META_IO);
	up_write(&sbi->mm_info->mmi_lock);

	dec_page_count(sbi, F2FS_MM_META_DIRTY);

	if (wbc->for_reclaim)
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, META_MAPPED);

	unlock_page(page);

	if (unlikely(f2fs_cp_error(sbi)))
		f2fs_submit_merged_write(sbi, META_MAPPED);

	return err;

redirty_out:
	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

static int mm_write_meta_pages(struct address_space *mapping,
			       struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_M_SB(mapping);
	long written;

	// f2fs_info(sbi, "write_meta_pages");

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	if (wbc->sync_mode != WB_SYNC_ALL &&
	    get_pages(sbi, F2FS_MM_META_DIRTY) <
		    nr_pages_to_skip(sbi, META_MAPPED))
		goto skip_write;

	/* if locked failed, cp will flush dirty pages instead */
	if (!f2fs_down_write_trylock(&sbi->cp_global_sem))
		goto skip_write;

	written = f2fs_sync_meta_mapped_pages(sbi, META_MAPPED,
					      wbc->nr_to_write, FS_META_IO);
	f2fs_up_write(&sbi->cp_global_sem);
	wbc->nr_to_write = max((long)0, wbc->nr_to_write - written);

	return 0;

skip_write:
	wbc->pages_skipped += get_pages(sbi, F2FS_MM_META_DIRTY);
	return 0;
}

// this function does not require the mmi lock
static bool mm_dirty_mapped_folio(struct address_space *mapping,
				  struct folio *folio)
{
	if (!folio_test_uptodate(folio))
		folio_mark_uptodate(folio);
	if (!folio_test_dirty(folio)) {
		filemap_dirty_folio(mapping, folio);
		inc_page_count(F2FS_M_SB(mapping), F2FS_MM_META_DIRTY);
		set_page_private_reference(&folio->page);
		return true;
	}
	return false;
}

const struct address_space_operations f2fs_mm_aops = {
	.writepage = mm_write_meta_page,
	.writepages = mm_write_meta_pages, // unless needed
#if 0
    .set_page_dirty = mm_set_mapped_page_dirty,
    .invalidatepage = f2fs_invalidate_page,
#endif
	.dirty_folio = mm_dirty_mapped_folio,
	.invalidate_folio = f2fs_invalidate_folio,
	.releasepage = f2fs_release_page,
};

// assumed to be called under write lock
static int mm_write_gc_end(struct f2fs_sb_info *sbi, unsigned int secno)
{
	struct page *data_page = NULL, *meta_page = NULL;
	struct f2fs_mm_info *mmi = sbi->mm_info;
	struct f2fs_meta_block *mb = NULL;
	int err = 0;

	if (mmi->current_wp + 2 >= LAST_BLOCK_IN_SEC(sbi, mmi->current_secno)) {
		// zone would be full! move to the next
		err = choose_next_secno(sbi, false);
		if (err)
			goto out;
	}

	data_page = f2fs_grab_meta_page(sbi, mmi->current_wp);
	if (IS_ERR(data_page)) {
		f2fs_err(sbi, "Could not grab data page!");
		goto out;
	}

	meta_page = f2fs_grab_meta_page(sbi, mmi->current_wp + 1);
	if (IS_ERR(meta_page)) {
		f2fs_err(sbi, "Could not grab data page!");
		goto put_data_page;
	}

	// update necessary metadata fields
	mb = page_address(meta_page);
	memcpy(mb->section_bitmap, mmi->section_bitmap, SECTION_BITMAP_SIZE);
	mb->prev_zone_id = le32_to_cpu(secno);
	mb->invalid_count = le32_to_cpu(0);
	mb->is_gc_end = true;

	set_page_dirty(data_page);
	set_page_dirty(meta_page);

	f2fs_wait_on_page_writeback(data_page, META, true, true);
	f2fs_wait_on_page_writeback(meta_page, META, true, true);

	mmi->current_wp += 2;

	f2fs_put_page(meta_page, true);
put_data_page:
	f2fs_put_page(data_page, true);
out:
	return err;
}

// assumed to be called under a lock, either shared or writer
static struct page *fetch_chunk_page(struct f2fs_sb_info *sbi, block_t lba)
{
	if (!GET_BAT_ENTRY(sbi, lba)) {
		return NULL;
	}
	return f2fs_grab_meta_page(sbi, GET_BAT_ENTRY(sbi, lba));
}

// assumed to be called under write lock
static int mm_garbage_collect_segment(struct f2fs_sb_info *sbi, block_t secno,
				      u32 invalid_count)
{
	struct f2fs_super_block *fsb = F2FS_RAW_SUPER(sbi);
	struct page *meta_page = NULL, *chunk_page = NULL;
	struct f2fs_meta_block *mb_old = NULL, *mb_fresh = NULL;
	u32 blklen, cur_blk = 0, nr_migrated = 0;
	block_t blkstart = 0, chunk_blk, blk_end;
	int err = 0;

	f2fs_info(sbi, "starting garbage collect segment!");

	blkstart = START_BLOCK_FROM_SEG0(sbi, GET_SEG_FROM_SEC(sbi, secno));
	f2fs_info(sbi, "blkstart: %u", blkstart);

	blklen = f2fs_usable_segs_in_sec(sbi, secno)
		 << le32_to_cpu(fsb->log_blocks_per_seg);

	blk_end = LAST_BLOCK_IN_SEC(sbi, secno);

	for (cur_blk = blkstart; cur_blk + 1 < blk_end; cur_blk += 2) {
		meta_page = f2fs_get_meta_page(sbi, cur_blk + 1);
		if (IS_ERR(meta_page)) {
			f2fs_err(sbi, "Could not fetch meta page, %ld",
				 PTR_ERR(meta_page));
			err = PTR_ERR(meta_page);
			goto out;
		}
		mb_old = page_address(meta_page);

		// account for case when previously unallocated?
		chunk_page = fetch_chunk_page(sbi, mb_old->lba);
		if (!chunk_page) {
			f2fs_put_page(meta_page, true);
			continue;
		}
		if (IS_ERR(chunk_page)) {
			err = PTR_ERR(chunk_page);
			f2fs_err(sbi, "Could not read chunk_page");
			f2fs_put_page(meta_page, true);
			goto out;
		}
		mb_fresh = page_address(chunk_page);
		chunk_blk = MM_PHYS_ADDR(sbi, mb_fresh, mb_old->lba);
		f2fs_put_page(chunk_page, true);
		f2fs_put_page(meta_page, true);

		if (chunk_blk == cur_blk) {
			err = mm_migrate_page(sbi, cur_blk, mb_old->lba);
			if (err) {
				f2fs_err(sbi, "could not migrate page!");
				goto out;
			}
			nr_migrated++;
		}

		cond_resched();
	}

	if (unlikely(nr_migrated) > invalid_count) {
		f2fs_err(sbi, "more blocks were migrated than expected!");
	}

	// free the segment
	// since the metadata is also appended to the end of the log, we need not mark
	// this segment as prefree

	err = f2fs_issue_discard_zone(sbi, blkstart, blklen);
	if (err) {
		f2fs_err(sbi, "Could not free zone!");
		goto out;
	}

	// mark the zone as empty, and the number of invalid blocks 0
	SET_SECTION_BITMAP(sbi, GET_SEC_FROM_BLK(sbi, blkstart), SECTION_EMPTY);
	SET_BIT_ENTRY(sbi, GET_SEC_FROM_BLK(sbi, blkstart), 0);

	// write a message indicating gc completed on this
	err = mm_write_gc_end(sbi, GET_SEC_FROM_BLK(sbi, blkstart));
	if (err) {
		f2fs_err(sbi, "could not write gc end");
	}

out:
	return err;
}

// TODO: have a thread do this in the background
int mm_do_garbage_collection(struct f2fs_sb_info *sbi)
{
	unsigned int max_secno = 0, target_secno = 0, sec_count = 0;
	u32 max_invalid_blocks = 0;
	struct f2fs_mm_info *mmi = sbi->mm_info;
	size_t i = 0;
	int err = 0;
	unsigned int count = 0;

	// scan the bit for the entry with the largest number of invalid blocks

	f2fs_info(sbi, "Starting meta gc!");

again:
	max_secno = 0;
	max_invalid_blocks = mmi->block_information_table[0];
	sec_count = le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta);
	for (i = 1; i < sec_count; ++i) {
		if (max_invalid_blocks < mmi->block_information_table[i]) {
			max_secno = i;
			max_invalid_blocks = mmi->block_information_table[i];
		}
	}

	target_secno = max_secno + FIRST_META_SECNO(sbi);

	f2fs_info(sbi, "Garbage collecting secno: %u, invalid blocks: %u\n",
		  target_secno, max_invalid_blocks);
	err = mm_garbage_collect_segment(sbi, target_secno, max_invalid_blocks);

	f2fs_info(sbi, "finished meta gc!");

	if (count++ < 4)
		goto again;

	return err;
}

void test_mm_functionality(struct f2fs_sb_info *sbi)
{
	block_t blkaddr = FIRST_META_BLKADDR(sbi);
	struct page *write_page, *read_page;
	char *val;
	int i;

	for (i = 0; i < 100; i++) {
		write_page = grab_mapped_page(sbi, blkaddr + i, true);

		memset(page_address(write_page), 'a', PAGE_SIZE);

		val = page_address(write_page);

		f2fs_info(sbi, "val of read before write: %c", val[0]);

		set_page_dirty(write_page);

		f2fs_put_page(write_page, 1);
	}

	f2fs_wait_on_all_pages(sbi, F2FS_MM_META_DIRTY);

	for (i = 0; i < 100; i++) {
		read_page = get_mapped_page(sbi, blkaddr + i, false);

		read_phys_pages(sbi, read_page);

		val = page_address(read_page);

		f2fs_info(sbi, "val of read after write: %c", val[0]);

		f2fs_put_page(read_page, 1);
	}
}

void issue_page_write(struct f2fs_sb_info *sbi, struct page *page,
			     block_t lba, enum page_type p_type, enum iostat_type io_type)
{
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = p_type,
		.temp = HOT,
		.op = REQ_OP_WRITE,
		.op_flags = REQ_SYNC | REQ_META | REQ_PRIO,
		.old_blkaddr = lba,
		.new_blkaddr = lba,
		.page = page,
		.encrypted_page = NULL,
		.compressed_page = NULL,
		.in_list = false,
	};

	if (unlikely(lba >= MAIN_BLKADDR(sbi)))
		fio.op_flags &= ~REQ_META;

	set_page_writeback(page);
	ClearPageError(page);
	f2fs_submit_page_write(&fio);
	// f2fs_submit_page_bio(&fio);

	stat_inc_meta_count(sbi, lba);
	f2fs_update_iostat(sbi, io_type, F2FS_BLKSIZE);
}
