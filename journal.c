/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "nova.h"
#include "journal.h"

/**************************** allocate journal block ******************************/

int nova_free_journal_blocks(struct super_block *sb, unsigned long first_blocknr)
{
	struct nova_inode_info_header sih;
	int num_res = JOURNAL_BLOCK_LIST_LEN;
	u64 head_block, tail_block;
	struct nova_journal_page *head_page;
	struct nova_journal_page *tail_page;
	u64 op_blocknr, free_blocknr;
	int num_del = 0;

	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;
	op_blocknr = (u64)first_blocknr;

	while( num_res ){
		head_block = op_blocknr << PAGE_SHIFT;
		head_page = (struct nova_journal_page *)nova_get_block(sb, head_block);
		num_del = head_page->page_tail.blocknr_curr;

		tail_block = (op_blocknr + num_del - 1) << PAGE_SHIFT;
		tail_page = (struct nova_journal_page *)nova_get_block(sb, tail_block);

		free_blocknr = op_blocknr;
		op_blocknr = tail_page->page_tail.next_page >> PAGE_SHIFT;

		nova_free_log_blocks(sb, &sih, free_blocknr, num_del);
		num_res -= num_del;
	}
	return 0;
}

static int nova_coalesce_journal_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long curr_blocknr,
	unsigned long total_pages, int curr_allocated, unsigned long first_blocknr)
{
	u64 prev_block, curr_block, last_block;
	struct nova_journal_page *prev_page;
	struct nova_journal_page *curr_page;
	struct nova_journal_page *last_page;
	unsigned long last_blocknr;

	curr_block = (u64)curr_blocknr << PAGE_SHIFT;
	curr_page = (struct nova_journal_page *)nova_get_block(sb, curr_block);
	nova_memunlock_block(sb, curr_page);
	curr_page->page_tail.blocknr_curr = curr_allocated;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_journal_page_tail), 0);
	nova_memlock_block(sb, curr_page);

	if ( prev_blocknr ) {
		/* Link prev block and newly allocated head block */
		prev_block = (u64)prev_blocknr << PAGE_SHIFT;//address in NVMM
		prev_page = (struct nova_journal_page *)nova_get_block(sb, prev_block);//global address
		nova_memunlock_block(sb, prev_page);
		nova_set_next_page_address_and_nr(sb, prev_page, curr_block, total_pages, 0, first_blocknr);
		nova_memlock_block(sb, prev_page);
	}

	if((total_pages + curr_allocated) == JOURNAL_BLOCK_LIST_LEN){
		last_blocknr = curr_blocknr + curr_allocated - 1;
		last_block = (u64)last_blocknr << PAGE_SHIFT;
		last_page = (struct nova_journal_page *)nova_get_block(sb, last_block);
		nova_memunlock_block(sb, last_page);
		/*the next block never be 1, so the 1 just a symbol to juge*/
		nova_set_next_page_address_and_nr(sb, last_page, 1, JOURNAL_BLOCK_LIST_LEN, 0, first_blocknr);
		nova_memlock_block(sb, last_page);
	}

	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_journal_pages(struct super_block *sb, u64 *new_block_nr, int cpuid)
{
	struct nova_inode_info_header sih;
	unsigned long num_pages = JOURNAL_BLOCK_LIST_LEN;//256
	unsigned long new_blocknr, first_blocknr;
	unsigned long prev_blocknr = 0;
	int allocated;
	int ret_pages = 0;

	sih.ino = NOVA_LITEJOURNAL_INO;//4, actually, it is useless here
	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;

	allocated = nova_new_log_blocks(sb, &sih, &new_blocknr,
		num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);
	if(allocated <= 0){
		nova_err(sb, "ERROR: no journal page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	nova_dbg_verbose("Pi %lu: Alloc %d log blocks @ 0x%lx\n",
		sih.ino, allocated, new_blocknr);

	first_blocknr = new_blocknr;
	/* Coalesce the pages */
	nova_coalesce_journal_pages(sb, 0, new_blocknr, 0, allocated, first_blocknr);
	ret_pages += allocated;
	prev_blocknr = new_blocknr + allocated - 1;
	num_pages -= allocated;

	while( num_pages ){
		allocated = nova_new_log_blocks(sb, &sih, &new_blocknr,
			num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);

		if(allocated <= 0){
			nova_err(sb, "ERROR: no journal page available: %d %d\n",
				num_pages, allocated);
			return allocated;
		}
		nova_dbg_verbose("Pi %lu: Alloc %d log blocks @ 0x%lx\n",
			sih.ino, allocated, new_blocknr);

		/* Coalesce the pages */
		nova_coalesce_journal_pages(sb, prev_blocknr, new_blocknr, ret_pages, allocated, first_blocknr);
		ret_pages += allocated;
		prev_blocknr = new_blocknr + allocated - 1;
		num_pages -= allocated;
	}

	*new_block_nr = first_blocknr;

	return ret_pages;//should be 256
}


/**************************** Lite journal ******************************/

static inline void
nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	nova_dbg("Entry %p: Type %u, data1 0x%llx, data2 0x%llx\n, checksum %u\n",
			entry, entry->type,
			entry->data1, entry->data2, entry->csum);
}

static inline int nova_update_journal_entry_csum(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	entry->csum = cpu_to_le32(crc);
	return 0;
}

static inline int nova_check_entry_integrity(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	if (entry->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}


// Get the next journal entry.
static inline u64 next_lite_journal(struct super_block *sb, u64 curr_p,
	struct journal_ptr_pair *pair, u64 *how_flush)
{
	struct nova_inode_info_header sih;
	size_t size = sizeof(struct nova_lite_journal_entry);//32B
	u64 curr_block;
	struct nova_journal_page *curr_page;

	u64 blocknr = 0;
	int allocated;
	u64 block_new;
	struct keep_trace_journal_block *keep_trace;

	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;

	//it is time to change the journal block, in one transaction, it is excuatable only once
	if ((curr_p & (PAGE_SIZE - 1)) + size >= JOURNAL_BLOCK_TAIL){

		how_flush[0] = 1; // it is used to flush journal entry

		curr_block = (curr_p >> PAGE_SHIFT) << PAGE_SHIFT;
		curr_page = (struct nova_journal_page *)nova_get_block(sb, curr_block);

		//in the consistent area
		if( curr_page->page_tail.next_page == 0 ){
			how_flush[1] = curr_p + 2 * size;
			return curr_p + 2 * size;
		}

		//in next area
		else if( curr_page->page_tail.next_page && curr_page->page_tail.blocknr_total != JOURNAL_BLOCK_LIST_LEN ){
			how_flush[1] = curr_page->page_tail.next_page;
			return curr_page->page_tail.next_page;
		}

		//need extra 256 journal block
		else if( curr_page->page_tail.next_page == 1 && curr_page->page_tail.blocknr_total == JOURNAL_BLOCK_LIST_LEN ){

			allocated = nova_allocate_journal_pages(sb, &blocknr, smp_processor_id());
			if(allocated != JOURNAL_BLOCK_LIST_LEN || blocknr == 0){
				printk("in function, the allocation is failure");
				return 0;//represent failure
			}

			keep_trace = nova_get_keep_trace_record_block(sb, pair->cpu);
			keep_trace->second = cpu_to_le64(blocknr);//new local block num
			nova_flush_buffer((void *)keep_trace, CACHELINE_SIZE, 0);
			block_new = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);//local address

			how_flush[1] = block_new;
			return block_new;
		}
		else{
			printk("It is impossible in function next_lite_journal_randomly_new");
			return 0;//represent failure
		}
	}

	return curr_p + size;
}


// Walk the journal for one CPU, and verify the checksum on each entry.
/*
static int nova_check_journal_entries(struct super_block *sb,
	struct journal_ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;
	int ret;
	u64 how_flush[2] = {0};

	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
									temp);
		ret = nova_check_entry_integrity(sb, entry);
		if (ret) {
			nova_dbg("Entry %p checksum failure\n", entry);
			nova_print_lite_transaction(entry);
			return ret;
		}
		temp = next_lite_journal(sb, temp, pair, how_flush);
	}

	return 0;
}
*/

/**************************** Journal Recovery ******************************/

#if 0
static void nova_undo_journal_inode(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	struct nova_inode *pi, *alter_pi;
	u64 pi_addr, alter_pi_addr;

	if (metadata_csum == 0)
		return;

	pi_addr = le64_to_cpu(entry->data1);
	alter_pi_addr = le64_to_cpu(entry->data2);

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);

	memcpy_to_pmem_nocache(pi, alter_pi, sizeof(struct nova_inode));
}

static void nova_undo_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 addr, value;

	addr = le64_to_cpu(entry->data1);
	value = le64_to_cpu(entry->data2);

	*(u64 *)nova_get_block(sb, addr) = (u64)value;
	nova_flush_buffer((void *)nova_get_block(sb, addr), CACHELINE_SIZE, 0);
}

static void nova_undo_lite_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 type;

	type = le64_to_cpu(entry->type);

	switch (type) {
	case JOURNAL_INODE:
		nova_undo_journal_inode(sb, entry);
		break;
	case JOURNAL_ENTRY:
		nova_undo_journal_entry(sb, entry);
		break;
	default:
		nova_dbg("%s: unknown data type %llu\n", __func__, type);
		break;
	}
}

/* Roll back all journal enries */
static int nova_recover_lite_journal(struct super_block *sb,
	struct journal_ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;
	u64 how_flush[2] = {0};

	nova_memunlock_journal(sb);
	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
									temp);
		nova_undo_lite_journal_entry(sb, entry);
		temp = next_lite_journal(sb, temp, pair, how_flush);
	}

	pair->journal_tail = pair->journal_head;
	nova_memlock_journal(sb);
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return 0;
}
#endif

/**************************** Create/commit ******************************/
#if 0
static u64 nova_append_replica_inode_journal(struct super_block *sb,
	u64 curr_p, struct inode *inode, struct journal_ptr_pair *pair, u64 *how_flush)
{
	struct nova_lite_journal_entry *entry;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							curr_p);
	//entry->type = cpu_to_le64(JOURNAL_INODE);
	entry->head_or_tail = 0;
	entry->type = cpu_to_le32(JOURNAL_INODE);
	entry->padding = 0;
	entry->data1 = cpu_to_le64(sih->pi_addr);
	entry->data2 = cpu_to_le64(sih->alter_pi_addr);

	if( curr_p == pair->journal_head )
		entry->head_or_tail = cpu_to_le32(1);//present the entry is a head
	else
		entry->head_or_tail = cpu_to_le32(2);//present the entry has been finished

	nova_update_journal_entry_csum(sb, entry);

	curr_p = next_lite_journal(sb, curr_p, pair, how_flush);
	return curr_p;
}
#endif

/* Create and append an undo entry for a small update to PMEM. */
static u64 nova_append_entry_journal(struct super_block *sb,
	u64 curr_p, void *field, struct journal_ptr_pair *pair, u64 *how_flush)
{
	struct nova_lite_journal_entry *entry;
	//struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 *aligned_field;
	u64 addr = 0;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							curr_p);
	entry->type = cpu_to_le32(JOURNAL_ENTRY);
	entry->head_or_tail = 0;
	entry->padding = 0;
	/* Align to 8 bytes */
	aligned_field = (u64 *)((unsigned long)field & ~7UL);
	/* Store the offset from the start of Nova instead of the pointer */


	//addr = (u64)nova_get_addr_off(sbi, aligned_field);
	entry->data1 = cpu_to_le64(addr);
	entry->data2 = cpu_to_le64(*aligned_field);

	if( curr_p == pair->journal_head )
		entry->head_or_tail = cpu_to_le32(1);//present the entry is a head
	else
		entry->head_or_tail = cpu_to_le32(2);//present the entry has been finished

	nova_update_journal_entry_csum(sb, entry);

	curr_p = next_lite_journal(sb, curr_p, pair, how_flush);
	return curr_p;
}


static u64 nova_journal_inode_tail(struct super_block *sb,
	u64 curr_p, struct journal_ptr_pair *pair, u64 *how_flush)
{
	int test = 1;
	curr_p = nova_append_entry_journal(sb, curr_p, &test, pair, how_flush);
	/*
	if (metadata_csum)
		curr_p = nova_append_entry_journal(sb, curr_p,
						&pi->alter_log_tail, pair, how_flush);
						*/
	return curr_p;
}


/* Create and append undo log entries for creating a new file or directory. */
static u64 nova_append_inode_journal(struct super_block *sb,
	u64 curr_p, struct inode *inode, int new_inode,
	int invalidate, int is_dir, struct journal_ptr_pair *pair, u64 *how_flush)
{
	int test = 1;
	/*
	if (metadata_csum)
		return nova_append_replica_inode_journal(sb, curr_p, inode, pair, how_flush);

	if (!pi) {
		nova_err(sb, "%s: get inode failed\n", __func__);
		return curr_p;
	}
	*/
	if (is_dir)
		return nova_journal_inode_tail(sb, curr_p, pair, how_flush);

	if (new_inode) {
		curr_p = nova_append_entry_journal(sb, curr_p,
						&test, pair, how_flush);
	} else {
		curr_p = nova_journal_inode_tail(sb, curr_p, pair, how_flush);
		if (invalidate) {
			curr_p = nova_append_entry_journal(sb, curr_p,
						&test, pair, how_flush);
			curr_p = nova_append_entry_journal(sb, curr_p,
						&test, pair, how_flush);
		}
	}

	return curr_p;
}


static u64 nova_append_dentry_journal(struct super_block *sb,
	u64 curr_p, struct nova_dentry *dentry, struct journal_ptr_pair *pair,u64 *how_flush)
{
	curr_p = nova_append_entry_journal(sb, curr_p, &dentry->ino, pair, how_flush);
	curr_p = nova_append_entry_journal(sb, curr_p, &dentry->csum, pair, how_flush);
	return curr_p;
}


void nova_flush_journal_in_batch(struct super_block *sb, u64 head,
	u64 tail, u64 *how_flush)
{
	void *journal_entry;

	// flush journal log entries in batch, head and tail are all local address in NVMM
	/*
		plan 1:
			1. in one page
			2. in two different page
	*/
	if(how_flush[0] == 1){
		/* in two different page */
		// head to page end
		journal_entry = nova_get_block(sb, head);
		// it is ok here, the least size of flush is CACHELINE
		nova_flush_buffer(journal_entry, sizeof(struct nova_lite_journal_entry), 0);

		// page start to tail
		journal_entry = nova_get_block(sb, how_flush[1]);
		nova_flush_buffer(journal_entry, tail - how_flush[1], 0);
	}
	else{
		// in one page
		journal_entry = nova_get_block(sb, head);
		nova_flush_buffer(journal_entry, tail - head, 0);
	}
	PERSISTENT_BARRIER();

	/*
		plan 2, overhead is large
			1. flush one journal entry evert time
 	*/
	/*
	if (head < tail) {
		journal_entry = nova_get_block(sb, head);
		nova_flush_buffer(journal_entry, tail - head, 0);
	} else {    // circular
		// head to end
		journal_entry = nova_get_block(sb, head);
		nova_flush_buffer(journal_entry,
			PAGE_SIZE - (head & ~PAGE_MASK), 0);

		// start to tail
		journal_entry = nova_get_block(sb, tail);
		nova_flush_buffer((void*)((u64)journal_entry & PAGE_MASK),
			tail & ~PAGE_MASK, 0);
	}
	PERSISTENT_BARRIER();
	*/
}


/* Journaled transactions for inode creation */
u64 nova_create_inode_transaction(struct super_block *sb,
	struct inode *inode, struct inode *dir, int cpu,
	int new_inode, int invalidate, struct journal_ptr_pair *pair)
{
	u64 temp;
	/*
		how_flush[0] represents that if this append operation make the curr_p to another page
		if how_flush[0], how_flush[1] represents the addr of next page
	 */
	u64 how_flush[2] = {0};

	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	//update itself
	temp = nova_append_inode_journal(sb, temp, inode,
					new_inode, invalidate, 0, pair, how_flush);

	//update directory file
	temp = nova_append_inode_journal(sb, temp, dir,
					new_inode, invalidate, 1, pair, how_flush);

	nova_flush_journal_in_batch(sb, pair->journal_head, temp, how_flush);
	pair->journal_tail = temp;
	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}


/* Journaled transactions for rename operations */
u64 nova_create_rename_transaction(struct super_block *sb,
	struct inode *old_inode, struct inode *old_dir, struct inode *new_inode,
	struct inode *new_dir, struct nova_dentry *father_entry,
	int invalidate_new_inode, int cpu, struct journal_ptr_pair *pair)
{
	u64 temp;
	u64 how_flush[2] = {0};

	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	/* Journal tails for old inode */
	temp = nova_append_inode_journal(sb, temp, old_inode, 0, 0, 0, pair, how_flush);

	/* Journal tails for old dir */
	temp = nova_append_inode_journal(sb, temp, old_dir, 0, 0, 1, pair, how_flush);

	if (new_inode) {
		/* New inode may be unlinked */
		temp = nova_append_inode_journal(sb, temp, new_inode, 0,
					invalidate_new_inode, 0, pair, how_flush);
	}

	if (new_dir)
		temp = nova_append_inode_journal(sb, temp, new_dir, 0, 0, 1, pair, how_flush);

	if (father_entry)
		temp = nova_append_dentry_journal(sb, temp, father_entry, pair, how_flush);

	nova_flush_journal_in_batch(sb, pair->journal_head, temp, how_flush);
	pair->journal_tail = temp;
	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}


/* For log entry inplace update */
u64 nova_create_logentry_transaction(struct super_block *sb,
	void *entry, enum nova_entry_type type, int cpu, struct journal_ptr_pair *pair)
{
	size_t size = 0;
	int i, count;
	u64 temp;
	u64 how_flush[2] = {0};

	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	size = nova_get_log_entry_size(sb, type);

	temp = pair->journal_head;

	count = size / 8;
	// it is impossible to overpass two journal page
	for (i = 0; i < count; i++) {
		temp = nova_append_entry_journal(sb, temp,
						(char *)entry + i * 8, pair, how_flush);
	}

	nova_flush_journal_in_batch(sb, pair->journal_head, temp, how_flush);
	pair->journal_tail = temp;

	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}


/* Commit the transactions by dropping the journal entries */
//tail is current tail pointer
void nova_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu, struct journal_ptr_pair *pair)
{
	u64 head_bk, tail_bk;
	struct keep_trace_journal_block *keep_trace;
	struct nova_journal_page *head_page;
	int ret = 0;

	if (pair->journal_tail != tail)
		BUG();

	head_bk = pair->journal_head >> PAGE_SHIFT;
	tail_bk = pair->journal_tail >> PAGE_SHIFT;

	if( head_bk != tail_bk ){

		head_page = (struct nova_journal_page *)nova_get_block(sb, head_bk << PAGE_SHIFT);

		if( head_page->page_tail.next_page == 1 && head_page->page_tail.blocknr_total == JOURNAL_BLOCK_LIST_LEN ){
			keep_trace = nova_get_keep_trace_record_block(sb, pair->cpu);

			if ( keep_trace->first != head_page->page_tail.first_blocknr || keep_trace->second != tail_bk ){
				printk("There is a non_consistency, the first_blocknr is %llu, the tail bk is %llu, but the keep_trace.first is %llu, the second is %llu\n",
					head_page->page_tail.first_blocknr,
					tail_bk,
					keep_trace->first,
					keep_trace->second);
				return;
			}

			//commit in DRAM
			pair->journal_head = tail;

			keep_trace->first = keep_trace->second;
			keep_trace->second = 0;
			nova_flush_buffer((void *)keep_trace, CACHELINE_SIZE, 0);
			//free 256 journal blcoks
			ret = nova_free_journal_blocks(sb, head_page->page_tail.first_blocknr);
			if( ret ){
				printk("Free Error in commit function!");
				return;
			}
		}
		else
			pair->journal_head = tail;
	}
	else
		pair->journal_head = tail;
}

/**************************** Initialization ******************************/

// Initialized DRAM journal state, validate, and recover
int nova_lite_journal_soft_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct journal_ptr_pair *pair;
	int i;
	int ret = 0;

	sbi->journal_locks = kcalloc(sbi->cpus, sizeof(spinlock_t),
				     GFP_KERNEL);
	if (!sbi->journal_locks)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++)
		spin_lock_init(&sbi->journal_locks[i]);

	for (i = 0; i < sbi->cpus; i++) {
		pair = &(sbi->journal_ptr_pairs[i]);

		if (pair->journal_head == pair->journal_tail)
			continue;

		/* Ensure all entries are genuine */
		/*
		ret = nova_check_journal_entries(sb, pair);
		if (ret) {
			nova_err(sb, "Journal %d checksum failure\n", i);
			ret = -EINVAL;
			break;
		}
		ret = nova_recover_lite_journal(sb, pair);
		*/
	}
	return ret;
}


/* Initialized persistent journal state */
int nova_lite_journal_hard_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct journal_ptr_pair *pair;
	u64 blocknr = 0;
	struct keep_trace_journal_block *keep_trace;//keep trace the journal block anytime
	int allocated;
	int i;
	u64 block;

	for (i = 0; i < sbi->cpus; i++) {
		pair = &(sbi->journal_ptr_pairs[i]);

		if( &(sbi->journal_ptr_pairs[i]) >= sbi->journal_ptr_pairs + (sbi->cpus) * sizeof(struct journal_ptr_pair) ){
			nova_err(sb, "The pair is overflow!\n");
			return -ENOMEM;
		}

		keep_trace = nova_get_keep_trace_record_block(sb, i);
		allocated = nova_allocate_journal_pages(sb, &blocknr, i);
		nova_dbg_verbose("%s: allocate log @ 0x%llu\n", __func__,
							blocknr);
		if (allocated != JOURNAL_BLOCK_LIST_LEN || blocknr == 0)
			return -ENOSPC;

		nova_memunlock_range(sb, (void *)keep_trace, CACHELINE_SIZE);//open the write window
		keep_trace->first = cpu_to_le64(blocknr);//record the begining of the address of the journal block list
		keep_trace->second = 0;
		nova_flush_buffer((void*)(keep_trace), CACHELINE_SIZE, 0);
		nova_memlock_range(sb, (void *)keep_trace, CACHELINE_SIZE);//close the write window

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);//local address
		pair->journal_head = pair->journal_tail = block;
		pair->cpu = i;
	}

	PERSISTENT_BARRIER();
	return nova_lite_journal_soft_init(sb);
}