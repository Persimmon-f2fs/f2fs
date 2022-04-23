#include "zoned_meta_tests.h"
#include "../zoned_meta_table.h"
#include <linux/f2fs_fs_modified.h>


// put tests here
static void
trivial_failure_case(struct mmi_test_t *test)
{
    ASSERT_NUM_EQUAL(test, 0, 1);
fail:
    return;
}

static void
trivial_success_case(struct mmi_test_t *test)
{
    ASSERT_NUM_EQUAL(test, 0, 0);
fail:
    return;
}

static void
can_get_mapped_page(struct mmi_test_t *test)
{
    struct page *page = NULL;
    char *data = NULL;
    struct f2fs_nat_block *nat_block;
    bool all_zero = true;
    block_t lba = le32_to_cpu(F2FS_RAW_SUPER(test->sbi)->nat_blkaddr);
    size_t i = 0;

    printk("nat lba: %lu\n", lba);

    page = get_mapped_page(test->sbi, lba, false);

    ASSERT_NUM_NOT_EQUAL(test, page, NULL);
    ASSERT_NUM_NOT_EQUAL(test, IS_ERR(page), true);

    nat_block = page_address(page);

    ASSERT_NUM_EQUAL(test,
            le32_to_cpu(nat_block->entries[F2FS_ROOT_INO(test->sbi)].block_addr),
            229376);

fail:
    if (page && !IS_ERR(page)) {
        f2fs_put_page(page, true);
    }
}

static void
can_write_mapped_page(struct mmi_test_t *test)
{
    struct page *meta_page = NULL;
    block_t lba = le32_to_cpu(F2FS_RAW_SUPER(test->sbi)->sit_blkaddr);
    char *expected_data = NULL;
    struct writeback_control wbc = {
        .for_reclaim = 0,
    };
    int err = 0;

    expected_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!expected_data) {
        goto fail;
    }


    memset(expected_data, 1, PAGE_SIZE);
    meta_page = get_mapped_page(test->sbi, lba, true);
    memcpy(page_address(meta_page), expected_data, PAGE_SIZE);

    err = META_MAPPED_MAPPING(test->sbi)->a_ops->writepage(meta_page, &wbc);
    ASSERT_NUM_EQUAL(test, err, 0);
    f2fs_put_page(meta_page, false);

    meta_page = NULL;
    meta_page = get_mapped_page(test->sbi, lba, true);

    ASSERT_MEM_EQUAL(test, page_address(meta_page), expected_data, PAGE_SIZE);

fail:
    if (expected_data) {
        kfree(expected_data);
    }

    if (meta_page && !IS_ERR(meta_page)) {
        f2fs_put_page(meta_page, true);
    }
    return;

}

static void
can_choose_next_secno(struct mmi_test_t *test)
{
    unsigned int initial_secno = test->sbi->mm_info->current_secno;
    size_t bound = test->sbi->blocks_per_seg * test->sbi->segs_per_sec;
    size_t i = 0;
    char *expected_data = NULL;
    struct page *meta_page = NULL;
    struct writeback_control wbc = {
        .for_reclaim = 0
    };
    int err = 0;
    block_t lba = le32_to_cpu(F2FS_RAW_SUPER(test->sbi)->nat_blkaddr);

    expected_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
    memset(expected_data, 1, PAGE_SIZE);

    printk("past allocation\n");

    for (i = 0; i < bound; ++i) {
        meta_page = get_mapped_page(test->sbi, lba + (i%10), true);
        memcpy(page_address(meta_page), expected_data, PAGE_SIZE);

        err = META_MAPPED_MAPPING(test->sbi)->a_ops->writepage(meta_page, &wbc);
        ASSERT_NUM_EQUAL(test, err, 0);
        f2fs_put_page(meta_page, false);
        meta_page = NULL;
    }

    ASSERT_NUM_NOT_EQUAL(test, initial_secno, test->sbi->mm_info->current_secno);

    for (i = 0; i < bound; ++i) {
        meta_page = get_mapped_page(test->sbi, lba + (i%10), true);
        
        ASSERT_MEM_EQUAL(test, page_address(meta_page), expected_data, PAGE_SIZE);
        f2fs_put_page(meta_page, PageLocked(meta_page));
        meta_page = NULL;
    }


fail:
    kfree(expected_data);
    if (meta_page && !IS_ERR(meta_page)) {
        f2fs_put_page(meta_page, PageLocked(meta_page));
    }
    return;
}

static void
can_collect_garbage(struct mmi_test_t *test)
{
    int err = 0;
    err = mm_do_garbage_collection(test->sbi);
    ASSERT_NUM_EQUAL(test, err, 0);
    DUMP_BITMAP(test->sbi);
fail:
    return;
}

static void
can_do_checkpoint(struct mmi_test_t *test)
{
    int err = 0;
	struct cp_control cpc = {
        .reason = CP_UMOUNT | CP_TRIMMED,
    };
    block_t cur_cp_addr = 0;
    int cur_cp_pack = test->sbi->cur_cp_pack;

    err = f2fs_write_checkpoint(test->sbi, &cpc);
    ASSERT_NUM_EQUAL(test, err, 0);
    ASSERT_NUM_NOT_EQUAL(test, cur_cp_pack, test->sbi->cur_cp_pack);

    err = zoned_get_valid_checkpoint(test->sbi, &cur_cp_addr);
    ASSERT_NUM_EQUAL(test, err, 0);
    ASSERT_NUM_EQUAL(test, cur_cp_addr, 65536);

    err = f2fs_build_segment_manager(test->sbi);
    ASSERT_NUM_EQUAL(test, err, 0);


fail:
    return;
}

static void
can_move_to_next_cp_zone(struct mmi_test_t *test)
{
    size_t bound = (test->sbi->blocks_per_blkz / 6) * 2, i = 0;
    int err = 0;
	struct cp_control cpc = {
        .reason = CP_UMOUNT | CP_TRIMMED,
    };

    block_t cur_cp_addr = 0;
    
    printk("writing cp %lu times!\n", bound);

    for (i = 0; i < bound; ++i) {
        err = f2fs_write_checkpoint(test->sbi, &cpc);
        ASSERT_NUM_EQUAL(test, err, 0);
    }

    err = zoned_get_valid_checkpoint(test->sbi, &cur_cp_addr);
    ASSERT_NUM_EQUAL(test, err, 0);

fail:
    return;
}

static void
can_write_nat_then_sit(struct mmi_test_t *test)
{
    struct page *sit_meta_page = NULL, *nat_meta_page = NULL;
    block_t sit_lba = le32_to_cpu(F2FS_RAW_SUPER(test->sbi)->sit_blkaddr);
    block_t nat_lba = le32_to_cpu(F2FS_RAW_SUPER(test->sbi)->nat_blkaddr);
    char *expected_data = NULL, *zeroed_data = NULL;
    struct writeback_control wbc = {
        .for_reclaim = 0,
    };
    int err = 0;
    size_t i = 0;
    
    // allocate expected data, getting a page of memory
    expected_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
    ASSERT_NUM_NOT_EQUAL(test, expected_data, NULL);
    zeroed_data = kmalloc(PAGE_SIZE, GFP_KERNEL);
    ASSERT_NUM_NOT_EQUAL(test, zeroed_data, NULL);

    // initailize expected data
    memset(expected_data, 1, PAGE_SIZE);  
    memset(zeroed_data, 0, PAGE_SIZE);

#if 0
    // First, write the nat page
    
    // fetch the page, then copy the data over

    nat_meta_page = get_mapped_page(test->sbi, nat_lba, true);
    memcpy(page_address(nat_meta_page), expected_data, PAGE_SIZE);
    
    // issue the write
    err = META_MAPPED_MAPPING(test->sbi)->a_ops->writepage(nat_meta_page, &wbc);

    // did everything go well?
    ASSERT_NUM_EQUAL(test, err, 0);
    f2fs_put_page(nat_meta_page, true);
#endif

    // Now, write the sit page
    
    // fetch the page, then copy the data over
    //for (i = 0; i < 1; ++i) {
    sit_meta_page = get_mapped_page(test->sbi, sit_lba + i, true);
    memcpy(page_address(sit_meta_page), expected_data, PAGE_SIZE);
    
    // issue the write
    set_page_dirty(sit_meta_page);
    f2fs_put_page(sit_meta_page, true);
    sit_meta_page = NULL;
    //}

    // OK, now that all the data has been written, fetch both pages again
    // and ensure that the correct data has been written.
    

    sit_meta_page = get_mapped_page(test->sbi, sit_lba, true);
    ASSERT_MEM_EQUAL(test, page_address(sit_meta_page), expected_data, PAGE_SIZE);
    f2fs_put_page(sit_meta_page, true);
    sit_meta_page = NULL;


    // confirm that the nat meta page is as we expect.
    nat_meta_page = get_mapped_page(test->sbi, nat_lba, true);
    ASSERT_MEM_NOT_EQUAL(test, page_address(nat_meta_page), zeroed_data, PAGE_SIZE);
    f2fs_put_page(nat_meta_page, true);
    nat_meta_page = NULL;

fail:
    if (expected_data) {
        kfree(expected_data);
    }
    if (zeroed_data) {
        kfree(zeroed_data);
    }
    if (sit_meta_page) {
        f2fs_put_page(sit_meta_page, true);
    }
    if (nat_meta_page) {
        f2fs_put_page(nat_meta_page, true);
    }



    return;
}

static const mmi_case_t tests[] = {
    trivial_failure_case,
    trivial_success_case,
#if 0
    can_get_mapped_page,
    can_write_mapped_page,
    can_choose_next_secno,
    can_collect_garbage,
    can_do_checkpoint,
//    can_move_to_next_cp_zone,
#endif
    can_write_nat_then_sit,
    NULL,
};


int
run_zoned_meta_tests(struct f2fs_sb_info *sbi)
{
    size_t i = 0;
    int ret = 0;
    struct mmi_test_t test_handle = {
        .sbi = sbi,
    };

    // clearing this flag for testing
	clear_sbi_flag(sbi, SBI_POR_DOING);

    i = 0;
    while (tests[i] != NULL) {
        test_handle.err = 0;   
        tests[i](&test_handle);

        if (test_handle.err) {
            f2fs_err(sbi, "failed test: %lu", i + 1);
            ret = -1;
        } else {
            printk(KERN_INFO"passed test: %lu\n", i + 1);
        }
        i++;
    }

    // reenable
	set_sbi_flag(sbi, SBI_POR_DOING);

    return ret;
}
