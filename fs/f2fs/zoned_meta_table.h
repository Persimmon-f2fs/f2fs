#ifndef __ZONED_META_TABLE_H__
#define __ZONED_META_TABLE_H__
#include <linux/f2fs_fs.h>
#include <linux/spinlock.h>
#include "f2fs.h"
#include "segment.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define CEILING(x,y) (((x) + (y) - 1) / (y))

static inline u32 F2FS_BAT_SIZE(struct f2fs_sb_info *sbi)
{
    struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
    return CEILING(le32_to_cpu(raw_super->last_ssa_blkaddr) -
        le32_to_cpu(raw_super->sit_blkaddr) + 1, BAT_CHUNK_SIZE);
}

static inline u32 F2FS_BIT_SIZE(struct f2fs_sb_info *sbi)
{
    return le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta) * sizeof(u32);
}


#define F2FS_BITMAP_SIZE(sbi) SECTION_BITMAP_SIZE

#define F2FS_BAT_BLOCKS(sbi) CEILING(F2FS_BAT_SIZE((sbi)), F2FS_BLKSIZE)
#define F2FS_BIT_BLOCKS(sbi) CEILING(F2FS_BAT_SIZE((sbi)), F2FS_BLKSIZE)
#define F2FS_BITMAP_BLOCKS(sbi) CEILING(F2FS_BITMAP_SIZE((sbi)), F2FS_BLKSIZE)

#define F2FS_TOTAL_META_MAPPED_BLKS(sbi) (F2FS_BAT_BLOCKS(sbi) + \
    F2FS_BIT_BLOCKS(sbi) + \
    F2FS_BITMAP_BLOCKS(sbi))

#define BLOCK_UNALLOCATED 0 // 0 is used for superblock so this can (probably) be used to indicate something is unused

enum {
    SECTION_EMPTY = 0,
    SECTION_NON_EMPTY,
};

struct f2fs_mm_info {
    u32 current_secno;
    block_t current_wp;
    block_t *bat_addrs;
    u32 *block_information_table;
    u32 section_bitmap[SECTION_BITMAP_SIZE];
    rwlock_t mmi_lock; // lock for manipulating mmi state w/in functions
};


static inline u32 FIRST_META_SECNO(struct f2fs_sb_info *sbi)
{
    struct f2fs_super_block *fsb = F2FS_RAW_SUPER(sbi);
    return GET_SEC_FROM_BLK(sbi, le32_to_cpu(fsb->sit_blkaddr));
}

static inline u32 FIRST_META_BLKADDR(struct f2fs_sb_info *sbi)
{
    return le32_to_cpu(F2FS_RAW_SUPER(sbi)->sit_blkaddr);
}


static inline u32 GET_BAT_IDX(struct f2fs_sb_info *sbi, u32 key)
{
    struct f2fs_super_block *fsb = F2FS_RAW_SUPER(sbi);
    key -= le32_to_cpu(fsb->sit_blkaddr);
    return key / BAT_CHUNK_SIZE;
}

static inline bool IS_VALID_META_BLKADDR(struct f2fs_sb_info *sbi, u32 meta_addr)
{
    return meta_addr >= le32_to_cpu(F2FS_RAW_SUPER(sbi)->sit_blkaddr) &&
           meta_addr <= le32_to_cpu(F2FS_RAW_SUPER(sbi)->last_ssa_blkaddr);
}

static inline bool IS_VALID_META_SECNO(struct f2fs_sb_info *sbi, u32 secno)
{
    return secno >= FIRST_META_SECNO(sbi) &&
        secno <= (FIRST_META_SECNO(sbi) + le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta)); 
}

static inline void SET_BAT_ENTRY(struct f2fs_sb_info *sbi, u32 key, u32 meta_addr)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (!IS_VALID_META_BLKADDR(sbi, key)) {
        return;
    }
    mmi->bat_addrs[GET_BAT_IDX(sbi, key)] = meta_addr;    
}

static inline block_t GET_BAT_ENTRY(struct f2fs_sb_info *sbi, u32 key)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (!IS_VALID_META_BLKADDR(sbi, key)) {
        //printk(KERN_INFO"block is invalid!\n");
        return 0;
    }

    //printk("idx: %lu\n", GET_BAT_IDX(sbi, key));
    return mmi->bat_addrs[GET_BAT_IDX(sbi, key)];    
}

static inline void SET_BIT_ENTRY(struct f2fs_sb_info *sbi, u32 segno, u32 count)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (segno == BLOCK_UNALLOCATED || !IS_VALID_META_SECNO(sbi, segno)) {
        f2fs_err(sbi, "could be invalid segno: %u\n", segno);
        return;
    }
    segno -= FIRST_META_SECNO(sbi);
    mmi->block_information_table[segno] = count;
}

static inline u32 GET_BIT_ENTRY(struct f2fs_sb_info *sbi, u32 segno)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (segno == BLOCK_UNALLOCATED || !IS_VALID_META_SECNO(sbi, segno)) {
        f2fs_err(sbi, "could be invalid segno: %u\n", segno);
        return 0;
    }
    segno -= FIRST_META_SECNO(sbi);
    return mmi->block_information_table[segno];
;
}


static inline void SET_SECTION_BITMAP(struct f2fs_sb_info *sbi, u32 segno, int state)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (!IS_VALID_META_SECNO(sbi, segno)) {
        f2fs_err(sbi, "could be invalid segno: (%u)", segno);
        return;
    }
    segno -= FIRST_META_SECNO(sbi);
    if (state == SECTION_NON_EMPTY) {
        mmi->section_bitmap[segno / 32] |= 1 << (segno % 32);
    } else {
        mmi->section_bitmap[segno / 32] &= ~(1 << (segno % 32));
    }
}

static inline bool GET_SECTION_BITMAP(struct f2fs_sb_info *sbi, u32 segno)
{
    struct f2fs_mm_info *mmi = sbi->mm_info;
    if (!IS_VALID_META_SECNO(sbi, segno)) {
        f2fs_err(sbi, "could be invalid segno: (%u)", segno);
        return 0;
    }
    segno -= FIRST_META_SECNO(sbi);
    return (mmi->section_bitmap[segno / 32] & (1 << (segno % 32))) != 0
        ? SECTION_NON_EMPTY
        : SECTION_EMPTY;
}

static inline u32 MM_PHYS_ADDR(struct f2fs_sb_info *sbi, struct f2fs_meta_block *mb, u32 lba) {
    return le32_to_cpu(mb->bat_chunk[(lba - FIRST_META_BLKADDR(sbi)) % BAT_CHUNK_SIZE]);
}


static inline void DUMP_BITMAP(struct f2fs_sb_info *sbi) 
{
    size_t i = 0;
    unsigned int cur_secno = 0;
    for (i = 0; i < le32_to_cpu(F2FS_RAW_SUPER(sbi)->section_count_meta); ++i) {
        cur_secno = FIRST_META_SECNO(sbi) + i;
        //printk("secno: (%lu), not empty: (%lu)\n",
        //       cur_secno, GET_SECTION_BITMAP(sbi, cur_secno));
    }
}
int mm_do_garbage_collection(struct f2fs_sb_info *sbi);

int
mm_write_info(struct f2fs_sb_info *sbi, u32 start_blk);

int
create_f2fs_mm_info(struct f2fs_sb_info *sbi, block_t cp_addr);

void
destroy_f2fs_mm_info(struct f2fs_sb_info *sbi);

struct page *
get_mapped_page(struct f2fs_sb_info *sbi, block_t lba, bool for_write);

struct page *
get_mapped_page_retry(struct f2fs_sb_info *sbi, block_t lba, bool for_write);

struct page *
grab_mapped_page(struct f2fs_sb_info *sbi, block_t lba, bool for_write);

void
update_mapped_page(struct f2fs_sb_info *sbi, void *src, block_t blk_addr);


extern const struct address_space_operations f2fs_mm_aops;

#endif // __ZONED_META_TABLE_H__
