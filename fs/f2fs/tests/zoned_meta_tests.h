#include "../f2fs.h"
#include "../zoned_meta_table.h"

#ifndef __ZONE_META_TESTS_H__
#define __ZONE_META_TESTS_H__

struct mmi_test_t {
    struct f2fs_sb_info *sbi;
    int err;
};

#define ERR_PRINT(...) \
    do {\
        char *msg = kmalloc(100, GFP_KERNEL); \
        snprintf(msg, 100, __VA_ARGS__); \
        printk("[%s:%d] %s\n", __FUNCTION__, __LINE__, msg); \
        kfree(msg); \
    } while(0);

#define ASSERT_NUM_EQUAL(test, left, right) \
    if ((left) != (right)) { \
        ERR_PRINT("(%s) != (%s): %lu != %lu", #left, #right, left, right); \
        (test)->err = -1; \
        goto fail; \
    }

#define ASSERT_NUM_NOT_EQUAL(test, left, right) \
    if ((left) == (right)) { \
        ERR_PRINT("(%s) == (%s): %lu == %lu", #left, #right, left, right); \
        (test)->err = -1; \
        goto fail; \
    }

#define ASSERT_MEM_EQUAL(test, left, right, size) \
    if (memcmp((left), (right), (size)) != 0) {\
        ERR_PRINT("(%s) != (%s)", #left, #right); \
        (test)->err = -1;\
        goto fail;\
    }

#define ASSERT_MEM_NOT_EQUAL(test, left, right, size) \
    if (memcmp((left), (right), (size)) == 0) {\
        ERR_PRINT("(%s) == (%s)", #left, #right); \
        (test)->err = -1;\
        goto fail;\
    }

typedef void (*mmi_case_t)(struct mmi_test_t*);

int run_zoned_meta_tests(struct f2fs_sb_info *sbi);

#endif
