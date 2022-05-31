// File: zoned_checkpoint.c
// 
// This defines how checkpoints will work when given a zoned device

// Some concerns
// * Is there ever a state where there isn't a valid checkpoint defined?
//      -> see if f2fs_format writes one at format time.
// * How can I tell if a checkpoint pack is valid?
//      -> If the write pointer points to the result of the last valid checkpoint,
//          then it points to the block immediately following the last checkpoint footer.
//      -> I should be able to calculate the offset for the header based on the amount of data
//          contained within the footer
//      -> The checkpoint itself should only be valid if we verify the checksum.
//          * if we read the checksum offset, but it results in an invalid block address,
//              then the checkpoint is invalid
//          * if we read the checksum offset, but the checksum differs from the computed one,
//              then the checkpoint is invalid
//          * both of these cases can occur whenever the checkpoint footer is unable to be written


#include <linux/blkdev.h>
#include <linux/f2fs_fs.h>

#include "f2fs.h"
#include "segment.h"

#ifdef CONFIG_BLK_DEV_ZONED

#define CP_ZONE_ID(sbi, which) (\
        le32_to_cpu(F2FS_RAW_SUPER((sbi))->cp_blkaddr) + \
        (((which) == 1) ? 0 : (sbi)->blocks_per_blkz))


// helper function to issue blkdev_report_zone requests
static int __fetch_wp(struct f2fs_sb_info *sbi, block_t start_addr, block_t *next_start)
{
    int err = 0;
    unsigned int secno = 0;

    if (!sbi) {
        //printk(KERN_INFO "sbi is null\n");
        return -1;
    }

    secno = GET_SEC_FROM_BLK(sbi, start_addr);

    //printk(KERN_INFO "__fetch_wp\n");

    err = fetch_section_write_pointer(sbi, secno, next_start);

    return err;
}

static int __fetch_last_block(struct f2fs_sb_info *sbi, block_t start_addr, block_t *next_start)
{
    int err;
    err = __fetch_wp(sbi, start_addr, next_start);
    *next_start -= 1;
    return err;
}

// zoned_next_start
// This calls blkdev_report_zones and queries cp_blkaddr.
// Because this function will (probably) be called rarely, the zone handles aren't
// cached at all. This will probably need to change if checkpoints are more common tran
// anticipated.
int zoned_cp_next_start(struct f2fs_sb_info *sbi, block_t *next_start, u32 write_size_blocks)
{
    block_t start_addr = le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr);
    int err, devi;
    u32 end_segno, start_segno;
    block_t last_addr;

    if (sbi->cur_cp_pack == 1) { 
        start_addr += (sbi->segs_per_sec * sbi->blocks_per_seg);
    }

    err = __fetch_wp(sbi, start_addr, next_start);
    if (err)
        goto out;

    start_segno = GET_SEGNO_FROM_SEG0(sbi, start_addr);
    end_segno = start_segno + f2fs_usable_segs_in_sec(sbi, start_segno);
    last_addr = START_BLOCK_FROM_SEG0(sbi, end_segno);


    if (start_addr + write_size_blocks >= last_addr) {
        f2fs_info(sbi, "clearing zone for checkpoint!");
        devi = f2fs_target_device_index(sbi, start_addr);
        err = f2fs_issue_discard_zone(sbi, start_addr, sbi->segs_per_sec * sbi->blocks_per_seg);
        *next_start = start_addr;
    }

out:
    return err;
}

int zoned_cp_start(struct f2fs_sb_info *sbi, block_t *next_start) {
    block_t start_addr = le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr);

    if (sbi->cur_cp_pack == 2) { 
        start_addr += sbi->segs_per_sec * sbi->blocks_per_seg;
    }

    return __fetch_wp(sbi, start_addr, next_start);
}



// pretty similar to the orignal implementation of validate_checkpoint, but we read the 
// footer first before the header
struct page *
zoned_validate_checkpoint(struct f2fs_sb_info *sbi,
        block_t footer_ptr, unsigned long long *version)
{
	struct page *cp_page_2 = NULL, *cp_page_1 = NULL;
	struct f2fs_checkpoint *cp_block = NULL;
	unsigned long long cur_version = 0, pre_version = 0;
	int err = 0;
    block_t cp_addr;

    cp_addr = footer_ptr;

    err = get_checkpoint_version(sbi, cp_addr, &cp_block,
            &cp_page_2, version);
    if (err) {
        //printk(KERN_INFO "Failed to get_checkpoint_version!!\n");
        return NULL;
    }

	if (le32_to_cpu(cp_block->cp_pack_total_block_count) >
					sbi->blocks_per_seg) {
		f2fs_warn(sbi, "invalid cp_pack_total_block_count:%u",
			  le32_to_cpu(cp_block->cp_pack_total_block_count));
		goto invalid_cp;
	}
    pre_version = *version;

    // we're fetching the footer first, so decrement the cp_addr
    cp_addr -= le32_to_cpu(cp_block->cp_pack_total_block_count) - 1;

    //printk(KERN_INFO "2nd cp_addr: %zu\n", cp_addr);

    err = get_checkpoint_version(sbi, cp_addr, &cp_block,
            &cp_page_1, version);

    if (err) {
        //printk(KERN_INFO "failed to get second cp\n");
        goto invalid_cp;
    }
    cur_version = *version;
    
	if (cur_version == pre_version) {
        // success case
		*version = cur_version;
		f2fs_put_page(cp_page_1, 1);
		return cp_page_2;
	}
	f2fs_put_page(cp_page_1, 1);
invalid_cp:
    //printk(KERN_INFO "invalid cp!\n");
    f2fs_put_page(cp_page_2, 1);
    return NULL;
}

int zoned_get_valid_checkpoint(struct f2fs_sb_info *sbi, block_t *cp_addr)
{
	struct f2fs_checkpoint *cp_block;
	struct page *cp1, *cp2, *cur_page;
	unsigned long blk_size = sbi->blocksize;
	unsigned long long cp1_version = 0, cp2_version = 0;
	block_t cp_start_blk_no;
	unsigned int cp_blks = 1 + __cp_payload(sbi);
	block_t cp_blk_no;
	int i;
	int err;

    //printk(KERN_INFO "zoned_get_valid_checkpoint!\n");

	sbi->ckpt = f2fs_kvzalloc(sbi, array_size(blk_size, cp_blks),
				  GFP_KERNEL);
	if (!sbi->ckpt)
		return -ENOMEM;
	/*
	 * Finding out valid cp block involves read both
	 * sets( cp pack 1 and cp pack 2)
	 */
    // The change here is that the start_blk_no needs to be based off of a wp

    __fetch_last_block(sbi,
            START_BLOCK_FROM_SEG0(sbi, GET_SEG_FROM_SEC(sbi, 0)),
            &cp_start_blk_no);

    //printk(KERN_INFO "first zone_id: %u\n", CP_ZONE_ID(sbi, 1));
    printk(KERN_INFO "1st write_pointer: %u\n", cp_start_blk_no);

	cp1 = zoned_validate_checkpoint(sbi, cp_start_blk_no, &cp1_version);

	/* The second checkpoint pack should start at the next zone */
    __fetch_last_block(sbi,
            START_BLOCK_FROM_SEG0(sbi, GET_SEG_FROM_SEC(sbi, 1)),
            &cp_start_blk_no);


    //printk(KERN_INFO "second zone_id: %u\n", CP_ZONE_ID(sbi, 2));
    printk(KERN_INFO "2nd write_pointer: %u\n", cp_start_blk_no);

	cp2 = zoned_validate_checkpoint(sbi, cp_start_blk_no, &cp2_version);

	if (cp1 && cp2) {
		if (ver_after(cp2_version, cp1_version))
			cur_page = cp2;
		else
			cur_page = cp1;
	} else if (cp1) {
		cur_page = cp1;
	} else if (cp2) {
		cur_page = cp2;
	} else {
        f2fs_err(sbi, "None of the checkpoints are valid!\n");
		err = -EFSCORRUPTED;
		goto fail_no_cp;
	}

    //printk(KERN_INFO "one or more checkpoints are valid!\n");

    *cp_addr = cur_page->index;


	cp_block = (struct f2fs_checkpoint *)page_address(cur_page);
	memcpy(sbi->ckpt, cp_block, blk_size);

    // want the first pointer
    *cp_addr -= (le32_to_cpu(cp_block->cp_pack_total_block_count) - 1);

    sbi->cur_cp_addr = *cp_addr;

    //printk("total_block_count: %lu\n", le32_to_cpu(cp_block->cp_pack_total_block_count));

	if (cur_page == cp1)
		sbi->cur_cp_pack = 1;
	else
		sbi->cur_cp_pack = 2;

	/* Sanity checking of checkpoint */
	if (f2fs_sanity_check_ckpt(sbi)) {
        printk(KERN_INFO "the checkpoint failed the sanity test!\n");
		err = -EFSCORRUPTED;
		goto free_fail_no_cp;
	}

	if (cp_blks <= 1)
		goto done;

    __fetch_last_block(sbi,
            CP_ZONE_ID(sbi, (cur_page == cp1) ? 1 : 2),
            &cp_blk_no);

    // because cp_blk_no is the footer, we need to decrement it to
    // get to the beginning
    cp_blk_no -= cp_blks;

	for (i = 1; i < cp_blks; i++) {
		void *sit_bitmap_ptr;
		unsigned char *ckpt = (unsigned char *)sbi->ckpt;

		cur_page = f2fs_get_meta_page(sbi, cp_blk_no + i);
		if (IS_ERR(cur_page)) {
            f2fs_err(sbi, "could not get meta page");
			err = PTR_ERR(cur_page);
			goto free_fail_no_cp;
		}
		sit_bitmap_ptr = page_address(cur_page);
		memcpy(ckpt + i * blk_size, sit_bitmap_ptr, blk_size);
		f2fs_put_page(cur_page, 1);
	}


done:
	f2fs_put_page(cp1, 1);
	f2fs_put_page(cp2, 1);
	return 0;

free_fail_no_cp:
	f2fs_put_page(cp1, 1);
	f2fs_put_page(cp2, 1);
fail_no_cp:
	kvfree(sbi->ckpt);
	return err;
}

#endif


