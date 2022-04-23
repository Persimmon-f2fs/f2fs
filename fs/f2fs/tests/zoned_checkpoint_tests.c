#include <kunit/test.h>
#include <linux/f2fs_fs_modified.h>
#include "test_util.h"
#include "../f2fs.h"
#include "../segment.h"

struct fetch_wp_ctx {
    u32 wp_count;
    struct {
        unsigned int segno;
        block_t wp;
    } wps[];
};

struct fetch_cp_ctx {
    u32 cp_count;
    struct {
        block_t block;
        struct f2fs_checkpoint *ckpt;
    } cps[];
};

struct checkpoint_test_ctx {
    struct f2fs_sb_info *sbi;
    struct fetch_wp_ctx *wp_ctx;    
    struct fetch_cp_ctx *cp_ctx;
};

const static struct f2fs_super_block raw_super = {
    .log_sectorsize = le32_to_cpu(9),
    .log_sectors_per_block = le32_to_cpu(3),
    .log_blocksize = le32_to_cpu(12),
    .log_blocks_per_seg = le32_to_cpu(9),
    .segs_per_sec = le32_to_cpu(1),
    .secs_per_zone = le32_to_cpu(1),
    .checksum_offset = le32_to_cpu(0),
    .block_count = le32_to_cpu(67108864),
    .section_count = le32_to_cpu(130693),
    .segment_count = le32_to_cpu(131071),
    .segment_count_ckpt = le32_to_cpu(2),
    .segment_count_sit = le32_to_cpu(10),
    .segment_count_nat = le32_to_cpu(110),
    .segment_count_ssa = le32_to_cpu(256),
    .segment_count_main = le32_to_cpu(130693),
    .segment0_blkaddr = le32_to_cpu(512),
    .cp_blkaddr = le32_to_cpu(512),
    .sit_blkaddr = le32_to_cpu(1536),
    .nat_blkaddr = le32_to_cpu(6656),
    .ssa_blkaddr = le32_to_cpu(62976),
    .main_blkaddr = le32_to_cpu(194048),
    .root_ino = le32_to_cpu(3),
    .node_ino = le32_to_cpu(1),
    .meta_ino = le32_to_cpu(2),
    .cp_payload = le32_to_cpu(0),
};


struct page * f2fs_get_meta_page(struct f2fs_sb_info *sbi, pgoff_t index)
{
    struct page *ret = NULL; 

    return ret;
}

static inline struct f2fs_super_block *
create_fake_super(struct kunit *test_handle)
{
    struct f2fs_super_block *sb_p; 
    sb_p = kunit_kzalloc(test_handle, sizeof(struct f2fs_super_block), GFP_KERNEL);
    memcpy(sb_p, &raw_super, sizeof(struct f2fs_super_block));
    return sb_p;
}

static inline struct f2fs_sb_info *
create_fake_sbi(struct kunit *test_handle)
{
    struct f2fs_sb_info *sbi = kunit_kzalloc(test_handle, sizeof(struct f2fs_sb_info), GFP_KERNEL);

    sbi->raw_super = create_fake_super(test_handle);
    init_sb_info(sbi);

    return sbi;
}

int fetch_segment_write_pointer(struct f2fs_sb_info *sbi, unsigned int segno, block_t *wp)
{
    int err = 0;
    struct kunit *test = current->kunit_test;
    struct checkpoint_test_ctx *ctx = test->priv;
    struct fetch_wp_ctx *wp_ctx = ctx->wp_ctx;
    block_t w_ptr = 0;
    size_t i = 0;

    if (wp_ctx == NULL) {
        return -1;
    }

    for (i = 0; i < wp_ctx->wp_count; ++i) {
        if (wp_ctx->wps[i].segno == segno) {
            w_ptr = wp_ctx->wps[i].wp;
            goto found;
        }
    }

    return ENOENT;
found:
    *wp = w_ptr;
    return err;
}

static int
zoned_test_init(struct kunit *test)
{
    int err = 0; 
    struct checkpoint_test_ctx *ctx;

    ctx  = kmalloc(sizeof(struct checkpoint_test_ctx), GFP_KERNEL);
    ctx->sbi = create_fake_sbi(test);
    ctx->cp_ctx = NULL;
    ctx->wp_ctx = NULL;

    return err;
}

static void
zoned_test_exit(struct kunit *test)
{
    kfree(test->priv);
}

/*
 * Named Resources:
 * - sbi
 * - write_pointer states
 * - mock checkpoint data
 */

/* Attempt to fetch a valid checkpoint
 */
static void can_fetch_first_valid(struct kunit *test_handle)
{
    int err = 0;
    struct f2fs_sb_info *sbi = NULL;
    struct f2fs_checkpoint *expected_ckpt = NULL;
    block_t cp_addr = 0, expected_cp_addr = 0; 

    expected_cp_addr = 5;

    sbi = create_fake_sbi(test_handle);
    err = zoned_get_valid_checkpoint(sbi, &cp_addr);
    
    KUNIT_EXPECT_EQ(test_handle, 0, err);
    KUNIT_EXPECT_EQ(test_handle, expected_cp_addr, cp_addr);
    // KUNIT_EXPECT_PTR_EQ(test_handle, sbi->ckpt, expected_ckpt)
}

static void can_fetch_second_valid(struct kunit *test_handle) {
    KUNIT_EXPECT_EQ(test_handle, 1, 1);
}

static void can_fetch_both_valid(struct kunit *test_handle) {
    KUNIT_EXPECT_EQ(test_handle, 1, 1);
}

static void can_fail_none_valid(struct kunit *test_handle) {
    KUNIT_EXPECT_EQ(test_handle, 1, 0);
}

static struct kunit_case zoned_checkpoint_test_cases[] = {
    KUNIT_CASE(can_fetch_first_valid),
    KUNIT_CASE(can_fetch_second_valid),
    KUNIT_CASE(can_fetch_both_valid),
    KUNIT_CASE(can_fail_none_valid),
    {}
};


static struct kunit_suite zoned_checkpoint_suite = {
    .name = "f2fs-zoned-checkpoint-suite",
    .init = zoned_test_init,
    .exit = zoned_test_exit,
    .test_cases = zoned_checkpoint_test_cases,
};
kunit_test_suite(zoned_checkpoint_suite);
