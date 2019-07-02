#ifndef __JOURNAL_H
#define __JOURNAL_H

#include <linux/types.h>
#include <linux/fs.h>
#include "nova.h"
#include "super.h"


/* ======================= Lite journal ========================= */

#define NOVA_MAX_JOURNAL_LENGTH 	128
#define JOURNAL_BLOCK_LIST_LEN		256
#define JOURNAL_BLOCK_TAIL			4064

#define	JOURNAL_INODE	1
#define	JOURNAL_ENTRY	2

/* Lightweight journal entry */
/*
0 present neither haed nor tail
1 present head
2 present tail
*/
struct nova_lite_journal_entry {
	__le32 type;       // JOURNAL_INODE or JOURNAL_ENTRY
	__le32 head_or_tail;//0-init,1-head,2-finish
	__le64 data1;
	__le64 data2;
	__le32 padding;
	__le32 csum;
} __attribute((__packed__));//no align

/* Head and tail pointers into a circular queue of journal entries.  There's
 * one of these per CPU.
 */
//in DRAM
struct journal_ptr_pair {
	__le64 journal_head;
	__le64 journal_tail;
	__le32 cpu;
};

//in NVMM, the 4th bkock
struct keep_trace_journal_block {
	__le64 first;
	__le64 second;
};

struct nova_journal_page_tail {
	__le64 next_page;
	__le64 blocknr_curr;
	__le64 blocknr_total;
	__le64 first_blocknr;
} __attribute((__packed__));

/* Fit in PAGE_SIZE */
struct nova_journal_page {
	char padding[JOURNAL_BLOCK_TAIL];
	struct nova_journal_page_tail page_tail;
} __attribute((__packed__));


static inline
struct journal_ptr_pair *nova_get_journal_pointers(struct super_block *sb,
	int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (cpu >= sbi->cpus)
		BUG();

	return (struct journal_ptr_pair *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * JOURNAL_START) + cpu * CACHELINE_SIZE);
}

static inline
struct keep_trace_journal_block *nova_get_keep_trace_record_block(struct super_block *sb,
	int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (cpu >= sbi->cpus)
		BUG();

	return (struct keep_trace_journal_block *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * JOURNAL_START) + cpu * CACHELINE_SIZE);
}

int nova_allocate_journal_pages(struct super_block *sb, u64 *new_block, int cpuid);
int nova_free_journal_blocks(struct super_block *sb, unsigned long first_blocknr);
void nova_flush_journal_one_by_one(struct super_block *sb, u64 head, u64 tail, u64 *how_flush);

u64 nova_create_inode_transaction(struct super_block *sb,
	struct inode *inode, struct inode *dir, int cpu,
	int new_inode, int invalidate, struct journal_ptr_pair *pair);
u64 nova_create_rename_transaction(struct super_block *sb,
	struct inode *old_inode, struct inode *old_dir, struct inode *new_inode,
	struct inode *new_dir, struct nova_dentry *father_entry,
	int invalidate_new_inode, int cpu, struct journal_ptr_pair *pair);
u64 nova_create_logentry_transaction(struct super_block *sb,
	void *entry, enum nova_entry_type type, int cpu, struct journal_ptr_pair *pair);
void nova_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu, struct journal_ptr_pair *pair);
int nova_lite_journal_soft_init(struct super_block *sb);
int nova_lite_journal_hard_init(struct super_block *sb);

#endif
