/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "nova.h"
#include "inode.h"

unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[NOVA_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};
unsigned int num_of_oneM_blk[MAX_CPUS];//added by double_D

int nova_init_inode_inuse_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	sbi->s_inodes_used_count = NOVA_NORMAL_INODE_START;

	range_high = NOVA_NORMAL_INODE_START / sbi->cpus;
	if (NOVA_NORMAL_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			/* FIXME: free allocated memories */
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		nova_update_range_node_checksum(range_node);
		ret = nova_insert_inodetree(sbi, range_node, i);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_inode_node(range_node);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;
	}

	return 0;
}



/******************** Function *********************************/



/* coalesce inode describe region */
static int nova_coalesce_inode_des_region_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long curr_blocknr, unsigned long total_pages,
	int curr_allocated, unsigned long first_blocknr, unsigned long target_total_page)
{
	u64 prev_block, curr_block, last_block, first_block;
	struct nova_inode_des_page *prev_page;
	struct nova_inode_des_page *first_page;
	struct nova_inode_des_page *last_page;
	unsigned long last_blocknr;

	curr_block = (u64)curr_blocknr << PAGE_SHIFT;
	/* there is a group of sequent block in previous */
	if ( prev_blocknr ) {
		/* Link prev block and newly allocated head block */
		prev_block = (u64)prev_blocknr << PAGE_SHIFT;
		prev_page = (struct nova_inode_des_page *)nova_get_block(sb, prev_block);
		nova_memunlock_block(sb, prev_page);
		prev_page->tail.next_page = curr_block;
		nova_memlock_block(sb, prev_page);
		nova_flush_buffer(&prev_page->tail,
			sizeof(struct nova_inode_des_page), 0);
		PERSISTENT_BARRIER();
	}

	/* this is the last group of sequent block */
	if((total_pages + curr_allocated) == target_total_page){
		last_blocknr = curr_blocknr + curr_allocated - 1;
		last_block = (u64)last_blocknr << PAGE_SHIFT;
		last_page = (struct nova_inode_des_page *)nova_get_block(sb, last_block);
		nova_memunlock_block(sb, last_page);
		last_page->tail.next_page = 1;
		nova_memlock_block(sb, last_page);
		nova_flush_buffer(&last_page->tail,
			sizeof(struct nova_inode_des_page), 0);
		PERSISTENT_BARRIER();

		/* recording the end location in first block in one region */
		first_block = (u64)first_blocknr << PAGE_SHIFT;
		first_page = (struct nova_inode_des_page *)nova_get_block(sb, first_block);
		nova_memunlock_block(sb, first_page);
		first_page->tail.last_page_in_region = last_block;
		nova_memlock_block(sb, first_page);
		nova_flush_buffer(&last_page->tail,
			sizeof(struct nova_inode_des_page), 0);
		PERSISTENT_BARRIER();
	}
	return 0;
}

/*
int nova_alloc_inode_des_region_in_gc(struct super_block *sb, struct nova_inode_info_header *sih,
	int cpuid, int num_pages, u64 *block_addr_for_gc)
{
	unsigned long first_blocknr, new_blocknr;
	int allocated;
	int ret_pages = 0;
	unsigned long prev_blocknr = 0;
	u64 block;
	unsigned long target_total_page;

	target_total_page = num_pages;

	allocated = nova_new_log_blocks(sb, sih, &new_blocknr,
		num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);
	if(allocated <= 0){
		nova_err(sb, "ERROR: no journal page available: %d %d\n",
			num_pages, allocated);
		return -ENOSPC;
	}
	nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
		allocated, new_blocknr);
	first_blocknr = new_blocknr;
	block = (u64)first_blocknr << PAGE_SHIFT;//local address in NVM

	// Coalesce the pages
	nova_coalesce_inode_des_region_pages(sb, 0, new_blocknr, 0,
		allocated, first_blocknr, target_total_page);
	ret_pages += allocated;
	prev_blocknr = new_blocknr + allocated - 1;
	num_pages -= allocated;

	while(num_pages){
		allocated = nova_new_log_blocks(sb, sih, &new_blocknr,
			num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);
		if(allocated <= 0){
			nova_err(sb, "ERROR: no journal page available: %d %d\n",
				num_pages, allocated);
			return -ENOSPC;
		}
		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
			allocated, new_blocknr);
		// Coalesce the pages
		nova_coalesce_inode_des_region_pages(sb, prev_blocknr, new_blocknr,
			ret_pages, allocated, first_blocknr, target_total_page);
		ret_pages += allocated;
		prev_blocknr = new_blocknr + allocated - 1;
		num_pages -= allocated;
	}

	// the allocation is over
	*block_addr_for_gc = block;
	return 0;
}
*/

/* the new alloc machansim for inode describe region */
// the parameters target_end is a global pointer
static int nova_alloc_inode_des_region(struct super_block *sb,
	struct nova_inode_info_header *sih, int version, int if_init,
	struct nova_inode_des_page_tail *target_end, int cpuid)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_table *inode_des_region;
	struct curr_ain_loc_percpu *curr_location;
	int num_pages = INODE_DES_BLOCK_BLOCK_LIST_LEN;
	struct group_ratio *group_des;
	unsigned long first_blocknr, new_blocknr;
	unsigned long prev_blocknr = 0;
	int allocated;
	int ret_pages = 0;
	u64 first_block;

	curr_location = &(sbi->curr_ain_loc[cpuid]);
	allocated = nova_new_log_blocks(sb, sih, &new_blocknr,
		num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);

	if(allocated <= 0){
		nova_err(sb, "ERROR: no journal page available: %d %d\n",
			num_pages, allocated);
		return -ENOSPC;
	}
	nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
		allocated, new_blocknr);

	first_blocknr = new_blocknr;
	first_block = (u64)first_blocknr << PAGE_SHIFT;
	curr_location->curr_alloc_location = (u64)nova_get_block(sb, first_block);

	/* Coalesce the pages */
	nova_coalesce_inode_des_region_pages(sb, 0, new_blocknr, 0,
		allocated, first_blocknr, INODE_DES_BLOCK_BLOCK_LIST_LEN);

	ret_pages += allocated;
	prev_blocknr = new_blocknr + allocated - 1;
	num_pages -= allocated;

	while(num_pages){
		allocated = nova_new_log_blocks(sb, sih, &new_blocknr,
			num_pages, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);
		if(allocated <= 0){
			nova_err(sb, "ERROR: no journal page available: %d %d\n",
				num_pages, allocated);
			return -ENOSPC;
		}
		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
			allocated, new_blocknr);
		/* Coalesce the pages */
		nova_coalesce_inode_des_region_pages(sb, prev_blocknr, new_blocknr,
			ret_pages, allocated, first_blocknr, INODE_DES_BLOCK_BLOCK_LIST_LEN);
		ret_pages += allocated;
		prev_blocknr = new_blocknr + allocated - 1;
		num_pages -= allocated;
	}

	/* the allocation is over */
	if( if_init == 1 ){
		inode_des_region = nova_get_inode_table(sb, version, cpuid);
		if (!inode_des_region)
			return -EINVAL;

		nova_memunlock_range(sb, inode_des_region, CACHELINE_SIZE);
		inode_des_region->log_head = first_block;
		nova_memlock_range(sb, inode_des_region, CACHELINE_SIZE);
		nova_flush_buffer(inode_des_region, CACHELINE_SIZE, 0);

		(sbi->ain_group_des + cpuid)->group_num_percpu = 1;
		group_des = (sbi->ain_group_des + cpuid)->begin_group_per_cpu;
		group_des->invalid_ain_num = 0;
		group_des->page_num = INODE_DES_BLOCK_BLOCK_LIST_LEN;
		group_des->group_addr_begin = first_block;
	}
	else{
		nova_memunlock_range(sb, target_end, CACHELINE_SIZE);
		target_end->next_region = first_block;
		nova_memlock_range(sb, target_end, CACHELINE_SIZE);
		nova_flush_buffer(target_end, CACHELINE_SIZE, 0);
	}
	return 0;
}


/* initialize the inode describe region */
int nova_init_inode_des_region(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_reserved *pi = nova_get_inode_by_ino(sb, NOVA_INODETABLE_INO);
	struct nova_inode_info_header sih;
	int num_regions;
	int ret = 0;
	int i, j;

	nova_memunlock_inode_reserved(sb, pi);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->nova_ino = NOVA_INODETABLE_INO;
	pi->i_blk_type = NOVA_BLOCK_TYPE_4K;
	nova_memlock_inode_reserved(sb, pi);

	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;

	num_regions = 1;
	if (metadata_csum)
		num_regions = 2;

	for (i = 0; i < num_regions; i++) {
		for(j = 0; j < sbi->cpus; j++){
			ret = nova_alloc_inode_des_region(sb, &sih, i, 1, NULL, j);
			if (ret)
				return ret;
		}
	}
	PERSISTENT_BARRIER();

	return ret;
}



/*********************** Function **********************************/



inline int nova_insert_inodetree(struct nova_sb_info *sbi,
	struct nova_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = nova_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		nova_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

inline int nova_search_inodetree(struct nova_sb_info *sbi,
	unsigned long ino, struct nova_range_node **ret_node)
{
	struct rb_root *tree;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	internal_ino = ino / sbi->cpus;
	return nova_find_range_node(tree, internal_ino,
			NODE_INODE, ret_node);
}



/*********************** Function **********************************/
int nova_delete_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, bool delete_nvmm, bool delete_dead,
	u64 epoch_id)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	struct nova_file_write_entry *old_entry = NULL;
	unsigned long pgoff = start_blocknr;
	unsigned long old_pgoff = 0;
	unsigned int num_free = 0;
	int freed = 0;
	void *ret;
	INIT_TIMING(delete_time);

	NOVA_START_TIMING(delete_file_tree_t, delete_time);

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	/* Handle EOF blocks */
	do {
		entry = radix_tree_lookup(&sih->tree, pgoff);
		if (entry) {
			ret = radix_tree_delete(&sih->tree, pgoff);
			BUG_ON(!ret || ret != entry);
			if (entry != old_entry) {
				if (old_entry && delete_nvmm) {
					nova_free_old_entry(sb, sih,
							old_entry, old_pgoff,
							num_free, delete_dead,
							epoch_id);
					freed += num_free;
				}

				old_entry = entry;
				old_pgoff = pgoff;
				num_free = 1;
			} else {
				num_free++;
			}
			pgoff++;
		} else {
			/* We are finding a hole. Jump to the next entry. */
			entry = nova_find_next_entry(sb, sih, pgoff);
			if (!entry)
				break;

			if (metadata_csum == 0)
				entryc = entry;
			else if (!nova_verify_entry_csum(sb, entry, entryc))
				break;

			pgoff++;
			pgoff = pgoff > entryc->pgoff ? pgoff : entryc->pgoff;
		}
	} while (1);

	if (old_entry && delete_nvmm) {
		nova_free_old_entry(sb, sih, old_entry, old_pgoff,
					num_free, delete_dead, epoch_id);
		freed += num_free;
	}

	nova_dbgv("Inode %lu: delete file tree from pgoff %lu to %lu, %d blocks freed\n",
			sih->ino, start_blocknr, last_blocknr, freed);

	NOVA_END_TIMING(delete_file_tree_t, delete_time);
	return freed;
}


static int nova_free_dram_resource(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	unsigned long last_blocknr;
	int freed = 0;

	if (sih->ino == 0)
		return 0;

	if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode)))
		return 0;

	if (S_ISREG(sih->i_mode)) {
		last_blocknr = nova_get_last_blocknr(sb, sih);
		freed = nova_delete_file_tree(sb, sih, 0,
					last_blocknr, false, false, 0);
	} else {
		nova_delete_dir_tree(sb, sih);
		freed = 1;
	}

	return freed;
}


#if 0
static inline void check_eof_blocks(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_info_header *sih)
{
	if ((pi->i_flags & cpu_to_le32(NOVA_EOFBLOCKS_FL)) &&
		(inode->i_size + sb->s_blocksize) > (sih->i_blocks
			<< sb->s_blocksize_bits)) {
		nova_memunlock_inode(sb, pi);
		pi->i_flags &= cpu_to_le32(~NOVA_EOFBLOCKS_FL);
		nova_update_inode_checksum(pi);
		nova_update_alter_inode(sb, inode, pi);
		nova_memlock_inode(sb, pi);
	}
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void nova_truncate_file_blocks(struct inode *inode, loff_t start,
				    loff_t end, u64 epoch_id)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	int freed = 0;

	inode->i_mtime = inode->i_ctime = current_time(inode);

	nova_dbg_verbose("truncate: pi %p iblocks %lx %llx %llx %llx\n", pi,
			 sih->i_blocks, start, end, pi->i_size);

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (end == 0)
		return;
	last_blocknr = (end - 1) >> data_bits;

	if (first_blocknr > last_blocknr)
		return;

	freed = nova_delete_file_tree(sb, sih, first_blocknr,
				last_blocknr, true, false, epoch_id);

	inode->i_blocks -= (freed * (1 << (data_bits -
				sb->s_blocksize_bits)));

	sih->i_blocks = inode->i_blocks;
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(sb, pi, inode, sih);

}
#endif


/* search the radix tree to find hole or data
 * in the specified range
 * Input:
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */

static int nova_lookup_hole_in_range(struct super_block *sb,
	struct nova_inode_info_header *sih,
	unsigned long first_blocknr, unsigned long last_blocknr,
	int *data_found, int *hole_found, int hole)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	unsigned long blocks = 0;
	unsigned long pgoff, old_pgoff;

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	pgoff = first_blocknr;
	while (pgoff <= last_blocknr) {
		old_pgoff = pgoff;
		entry = radix_tree_lookup(&sih->tree, pgoff);
		if (entry) {
			*data_found = 1;
			if (!hole)
				goto done;
			pgoff++;
		} else {
			*hole_found = 1;
			entry = nova_find_next_entry(sb, sih, pgoff);
			pgoff++;
			if (entry) {
				if (metadata_csum == 0)
					entryc = entry;
				else if (!nova_verify_entry_csum(sb, entry,
								entryc))
					goto done;

				pgoff = pgoff > entryc->pgoff ?
					pgoff : entryc->pgoff;
				if (pgoff > last_blocknr)
					pgoff = last_blocknr + 1;
			}
		}

		if (!*hole_found || !hole)
			blocks += pgoff - old_pgoff;
	}
done:
	return blocks;
}


static int nova_read_root_inode(struct super_block *sb, struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_reserved *pi;//, fake_pi;
	struct nova_inode_info_header *sih = &si->header;
	int ret = -EIO;
	unsigned long ino;
	unsigned int flags;

	pi = nova_get_reserved_inode(sb, 1);
	/*
	ret = nova_get_reference(sb, pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%llx failed\n",
				__func__, pi_addr);
		goto bad_inode;
	}
	*/
	inode->i_mode = sih->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	flags = le32_to_cpu(pi->i_flags);

	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;

	ino = inode->i_ino;
	/* check if the inode is active. */
	if (inode->i_mode == 0 || pi->deleted == 1) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = sih->i_blocks;
	inode->i_mapping->a_ops = &nova_aops_dax;

	inode->i_op = &nova_dir_inode_operations;
	inode->i_fop = &nova_dir_operations;

	/* Update size and time after rebuild the tree */
	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}


static int nova_read_inode(struct super_block *sb, struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_ain_loc *pi_ain_loc = &si->ain_loc_and_lock;
	struct nova_inode_ssim *pi_ssim;
	struct nova_inode_complete_entry *complete_inode;
	int ret = -EIO;
	unsigned long ino;
	u32 i_flags_temp;
	u8 deleted_temp;

	read_lock(&pi_ain_loc->rblock_instance);
	pi_ssim = pi_ain_loc->ain_location;
	i_flags_temp = pi_ssim->i_flags;
	deleted_temp = pi_ssim->deleted;
	complete_inode = pi_ssim->complete_inode;
	read_unlock(&pi_ain_loc->rblock_instance);

	/*
	ret = nova_get_reference(sb, pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%llx failed\n",
				__func__, pi_addr);
		goto bad_inode;
	}
	*/

	inode->i_mode = sih->i_mode;
	i_uid_write(inode, le32_to_cpu(complete_inode->i_uid));
	i_gid_write(inode, le32_to_cpu(complete_inode->i_gid));
//	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_generation = le32_to_cpu(complete_inode->i_generation);
	nova_set_inode_flags(inode, complete_inode, le32_to_cpu(i_flags_temp));
	ino = inode->i_ino;

	/* check if the inode is active. */
	if (inode->i_mode == 0 || deleted_temp == 1) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = sih->i_blocks;
	inode->i_mapping->a_ops = &nova_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &nova_file_inode_operations;
		if (!test_opt(inode->i_sb, DATA_COW) && wprotect == 0)
			inode->i_fop = &nova_dax_file_operations;
		else
			inode->i_fop = &nova_wrap_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &nova_dir_inode_operations;
		inode->i_fop = &nova_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &nova_symlink_inode_operations;
		break;
	default:
		inode->i_op = &nova_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(complete_inode->dev.rdev));
		break;
	}

	/* Update size and time after rebuild the tree */
	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(complete_inode->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(complete_inode->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(complete_inode->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(complete_inode->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}


static int nova_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i = NULL;
	struct nova_range_node *curr_node;
	int found = 0;
	int cpuid = ino % sbi->cpus;
	unsigned long internal_ino = ino / sbi->cpus;
	int ret = 0;

	nova_dbg_verbose("Free inuse ino: %lu\n", ino);
	inode_map = &sbi->inode_maps[cpuid];

	mutex_lock(&inode_map->inode_table_mutex);
	found = nova_search_inodetree(sbi, ino, &i);
	if (!found) {
		nova_dbg("%s ERROR: ino %lu not found\n", __func__, ino);
		mutex_unlock(&inode_map->inode_table_mutex);
		return -EINVAL;
	}

	if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
		/* fits entire node */
		rb_erase(&i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(i);
		inode_map->num_range_node_inode--;
		goto block_found;
	}
	if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns left */
		i->range_low = internal_ino + 1;
		nova_update_range_node_checksum(i);
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
		/* Aligns right */
		i->range_high = internal_ino - 1;
		nova_update_range_node_checksum(i);
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns somewhere in the middle */
		curr_node = nova_alloc_inode_node(sb);
		NOVA_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block */
			goto block_found;
		}
		curr_node->range_low = internal_ino + 1;
		curr_node->range_high = i->range_high;
		nova_update_range_node_checksum(curr_node);

		i->range_high = internal_ino - 1;
		nova_update_range_node_checksum(i);

		ret = nova_insert_inodetree(sbi, curr_node, cpuid);
		if (ret) {
			nova_free_inode_node(curr_node);
			goto err;
		}
		inode_map->num_range_node_inode++;
		goto block_found;
	}

err:
	nova_error_mng(sb, "Unable to free inode %lu\n", ino);
	nova_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->range_low, i->range_high);
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;

block_found:
	sbi->s_inodes_used_count--;
	inode_map->freed++;
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}


static int nova_free_inode(struct super_block *sb, struct nova_inode_info_header *sih)
{
	int err = 0;
	INIT_TIMING(free_time);
	NOVA_START_TIMING(free_inode_t, free_time);

	nova_free_inode_log(sb, sih);

	sih->log_pages = 0;
	sih->i_mode = 0;
	sih->i_size = 0;
	sih->i_blocks = 0;
	err = nova_free_inuse_inode(sb, sih->ino);

	NOVA_END_TIMING(free_inode_t, free_time);
	return err;
}

/*
	Sometimes, this function just rebuild an inode partly,
	when this kind inode finishes it's function, we need to delete if from icache
	*/
struct inode *nova_iget_only_init_lock(struct super_block *sb, unsigned long ino)
{
	struct nova_inode_info *si;
	struct nova_ain_loc *pi_ain_loc;
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
/*
	{
		si = NOVA_I(inode);
		nova_dbgv("%s: inode %lu\n", __func__, ino);
		return &si->ain_loc_and_lock;
	}
*/

	/* new a vfs_inode */
	si = NOVA_I(inode);
	nova_dbgv("%s: inode %lu\n", __func__, ino);

	pi_ain_loc = &si->ain_loc_and_lock;
	rwlock_init(&pi_ain_loc->rblock_instance);
	return inode;
}


/* the ino must >= 32 or equal to 1 */
struct inode *nova_iget(struct super_block *sb, unsigned long ino)
{
	struct nova_inode_info *si;
	struct nova_ain_loc *pi_ain_loc;
	struct inode *inode;
	int err;

	/*
		for function iget_locked, if the inode is exist, return inode directly
		for root_inode, the function need to new an inode
	 */
	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	// if vfs inode exists, return it directly, the lock is ok
	if (!(inode->i_state & I_NEW))
		return inode;

	/* new a vfs_inode */
	si = NOVA_I(inode);
	nova_dbgv("%s: inode %lu\n", __func__, ino);

	if (ino == 1) {
		err = nova_rebuild_root_inode(sb, si);
		if (err) {
			nova_dbg("%s: failed to rebuild inode %d\n", __func__, 1);
			goto fail;
		}

		err = nova_read_root_inode(sb, inode);
		if (unlikely(err)) {
			nova_dbg("%s: failed to read inode %d\n", __func__, 1);
			goto fail;
		}
		goto root;
	}

	pi_ain_loc = &si->ain_loc_and_lock;
	rwlock_init(&pi_ain_loc->rblock_instance);

	err = nova_rebuild_inode(sb, si, ino, 1);
	if (err) {
		nova_dbg("%s: failed to rebuild inode %lu\n", __func__, ino);
		goto fail;
	}

	err = nova_read_inode(sb, inode);
	if (unlikely(err)) {
		nova_dbg("%s: failed to read inode %lu\n", __func__, ino);
		goto fail;
	}

root:
	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}


unsigned long nova_get_last_blocknr(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	//struct nova_inode *pi, fake_pi;
	unsigned long last_blocknr;
	unsigned int btype;
	unsigned int data_bits;
	//int ret;

	/*
	ret = nova_get_reference(sb, sih->pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%lx failed\n",
				__func__, sih->pi_addr);
		btype = 0;
	} else {
		btype = sih->i_blk_type;
	}
	*/
	btype = sih->i_blk_type;
	data_bits = blk_type_to_shift[btype];

	if (sih->i_size == 0)
		last_blocknr = 0;
	else
		last_blocknr = (sih->i_size - 1) >> data_bits;

	return last_blocknr;
}


static int nova_free_inode_resource(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	unsigned long last_blocknr;
	//struct nova_inode *alter_pi;
	struct nova_ain_loc *pi_ain_loc = NOVA_HLOC(sih);
	struct nova_inode_ssim *pi_ssim;
	int ret = 0;
	int freed = 0;
	u16 i_mode_temp;

	write_lock(&pi_ain_loc->rblock_instance);
	pi_ssim = pi_ain_loc->ain_location;
	nova_memunlock_inode_ssim(sb, pi_ssim);

	pi_ssim->deleted = 1;
	i_mode_temp = pi_ssim->i_mode;
	if (pi_ssim->valid_ino) {
		nova_dbg("%s: inode %lu still valid\n",
				__func__, sih->ino);
		pi_ssim->valid_ino = 0;
	}
	//nova_update_inode_checksum(pi);
	/*
	if (metadata_csum && sih->alter_pi_addr) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	*/

	nova_memlock_inode_ssim(sb, pi_ssim);
	write_unlock(&pi_ain_loc->rblock_instance);

	/* key step */
	pi_ain_loc->ain_location = NULL;

	/* We need the log to free the blocks from the b-tree */
	switch (__le16_to_cpu(i_mode_temp) & S_IFMT) {
	case S_IFREG:
		last_blocknr = nova_get_last_blocknr(sb, sih);
		nova_dbgv("%s: file ino %lu\n", __func__, sih->ino);
		freed = nova_delete_file_tree(sb, sih, 0,
					last_blocknr, true, true, 0);
		break;
	case S_IFDIR:
		nova_dbgv("%s: dir ino %lu\n", __func__, sih->ino);
		nova_delete_dir_tree(sb, sih);
		break;
	case S_IFLNK:
		/* Log will be freed later */
		nova_dbgv("%s: symlink ino %lu\n",
				__func__, sih->ino);
		freed = nova_delete_file_tree(sb, sih, 0, 0,
						true, true, 0);
		break;
	default:
		nova_dbgv("%s: special ino %lu\n",
				__func__, sih->ino);
		break;
	}

	nova_dbg_verbose("%s: Freed %d\n", __func__, freed);

	/* Then we can free the inode */
	ret = nova_free_inode(sb, sih);
	if (ret)
		nova_err(sb, "%s: free inode %lu failed\n",
				__func__, sih->ino);

	return ret;
}


void nova_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_ain_loc *pi_ain_loc = &si->ain_loc_and_lock;
	INIT_TIMING(evict_time);
	int destroy = 0;
	int ret;

	NOVA_START_TIMING(evict_inode_t, evict_time);
	if (!sih) {
		nova_err(sb, "%s: ino %lu sih is NULL!\n",
				__func__, inode->i_ino);
		NOVA_ASSERT(0);
		goto out;
	}

	// pi can be NULL if the file has already been deleted, but a handle
	// remains.
	#if 0
	if (pi && pi->nova_ino != inode->i_ino) {
		nova_err(sb, "%s: inode %lu ino does not match: %llu\n",
				__func__, inode->i_ino, pi->nova_ino);
		nova_dbg("inode size %llu, pi addr 0x%lx, pi head 0x%llx, tail 0x%llx, mode %u\n",
				inode->i_size, sih->pi_addr, sih->log_head,
				sih->log_tail, pi->i_mode);
		nova_dbg("sih: ino %lu, inode size %lu, mode %u, inode mode %u\n",
				sih->ino, sih->i_size,
				sih->i_mode, inode->i_mode);
		nova_print_inode_log(sb, inode);
	}
	#endif

	/* Check if this inode exists in at least one snapshot. */
	/*
	if (pi && pi->valid == 0) {
		ret = nova_append_inode_to_snapshot(sb, pi);
		if (ret == 0)
			goto out;
	}
	*/

	nova_dbg_verbose("%s: %lu\n", __func__, inode->i_ino);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		if (pi_ain_loc->ain_location) {
			ret = nova_free_inode_resource(sb, sih);
			if (ret)
				goto out;
		}

		destroy = 1;
		//pi = NULL; /* we no longer own the nova_inode */

		inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_size = 0;
	}
out:
	if (destroy == 0) {
		nova_dbgv("%s: destroying %lu\n", __func__, inode->i_ino);
		nova_free_dram_resource(sb, sih);
	}
	/* TODO: Since we don't use page-cache, do we really need the following
	 * call?
	 */
	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
	NOVA_END_TIMING(evict_inode_t, evict_time);
}


/* First rebuild the inode tree, then free the blocks */
#if 0
int nova_delete_dead_inode(struct super_block *sb, u64 ino)
{
	struct nova_inode_info si;
	struct nova_inode_info_header *sih;
	struct nova_inode *pi;
	u64 pi_addr = 0;
	int err;

	if (ino < NOVA_NORMAL_INODE_START) {
		nova_dbg("%s: invalid inode %llu\n", __func__, ino);
		return -EINVAL;
	}

	err = nova_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
	if (err) {
		nova_dbg("%s: get inode %llu address failed %d\n",
					__func__, ino, err);
		return -EINVAL;
	}

	if (pi_addr == 0)
		return -EACCES;

	memset(&si, 0, sizeof(struct nova_inode_info));
	err = nova_rebuild_inode(sb, &si, ino, pi_addr, 0);
	if (err)
		return err;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	sih = &si.header;

	nova_dbgv("Delete dead inode %lu, log head 0x%llx, tail 0x%llx\n",
			sih->ino, sih->log_head, sih->log_tail);

	return nova_free_inode_resource(sb, pi, sih);
}
#endif



/******** Function insulation ***********/



static int nova_alloc_unused_inode(struct super_block *sb, int cpuid,
	unsigned long *ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
	i = inode_map->first_inode_range;
	NOVA_ASSERT(i);
	if (!nova_range_node_checksum_ok(i)) {
		nova_dbg("%s: first node failed\n", __func__);
		return -EIO;
	}

	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct nova_range_node, node);
		if (!nova_range_node_checksum_ok(next_i)) {
			nova_dbg("%s: second node failed\n", __func__);
			return -EIO;
		}
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		nova_update_range_node_checksum(i);
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
		nova_update_range_node_checksum(i);
	} else {
		nova_dbg("%s: ERROR: new ino %lu, next low %lu\n", __func__,
			new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino = new_ino * sbi->cpus + cpuid;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	nova_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

/*
	Returns 0 on failure
	in this function, we just get an available inode number
	*/
u64 nova_new_nova_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	unsigned long free_ino = 0;
	int map_id;
	int ret;
	u64 ino;

	INIT_TIMING(new_inode_time);

	NOVA_START_TIMING(new_nova_inode_t, new_inode_time);
	map_id = sbi->map_id;
	sbi->map_id = (sbi->map_id + 1) % sbi->cpus;
	inode_map = &sbi->inode_maps[map_id];

	mutex_lock(&inode_map->inode_table_mutex);
	ret = nova_alloc_unused_inode(sb, map_id, &free_ino);
	if (ret) {
		nova_dbg("%s: alloc inode number failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}
	mutex_unlock(&inode_map->inode_table_mutex);
	ino = free_ino;

	NOVA_END_TIMING(new_nova_inode_t, new_inode_time);
	return ino;
}


/**********************************************/


static void nova_init_new_ain(struct super_block *sb,
	struct nova_inode_ssim *ain_entry, struct inode *vfs_inode)
{
	nova_memunlock_inode_ssim(sb, ain_entry);
	ain_entry->valid_ino = 0;
	ain_entry->valid_over_threshold = 1;
	ain_entry->update_times = 1;
	ain_entry->log_head = 0;
	ain_entry->log_tail = 0;
	ain_entry->vfs_inode = vfs_inode;
	ain_entry->complete_inode = 0;
	ain_entry->deleted = 0;
	ain_entry->i_mode = cpu_to_le16(vfs_inode->i_mode);
	ain_entry->csum = 0;
	nova_memlock_inode_ssim(sb, ain_entry);
	nova_flush_buffer(ain_entry, NOVA_INODE_SSIM_SIZE, 0);
}


static void nova_init_mova_ain(struct super_block *sb, struct nova_inode_ssim *to,
	struct nova_inode_ssim *from)
{
	nova_memunlock_inode_ssim(sb, to);
	to->valid_ino = 1;
	to->valid_over_threshold = 1;
	to->update_times = 1;
	to->log_head = from->log_head;
	to->log_tail = from->log_tail;
	to->vfs_inode = from->vfs_inode;
	to->complete_inode = from->complete_inode;
	to->deleted = from->deleted;
	to->i_mode = from->i_mode;
	to->i_flags = from->i_flags;
	to->csum = from->csum;
	nova_memlock_inode_ssim(sb, to);
	nova_flush_buffer(to, NOVA_INODE_SSIM_SIZE, 0);

	/* commit the ain move atomically */
	from->valid_ino = 0;
	nova_flush_buffer(from, CACHELINE_SIZE, 1);
}


static void nova_init_inode_complete(struct inode *inode, struct nova_inode_complete_entry *pi)
{
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_le32(inode->i_generation);
	pi->alter_log_head = 0;
	pi->alter_log_tail = 0;
	pi->delete_epoch_id = 0;

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);
}


int nova_append_ain(struct super_block *sb, struct inode *inode,
	struct nova_ain_loc *pi_ain_loc, int move_ain, int *if_gc)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct curr_ain_loc_percpu *curr_location;
	struct nova_inode_des_page_tail* inode_des_tail;
	struct nova_inode_ssim *ain_entry;
	struct group_ratio *group_des;
	unsigned long ino = inode->i_ino;
	unsigned int curr_loc_in_block;
	u64 curr_loc;
	int cpuid = ino % sbi->cpus;
	int group_index;
	int ret = 0;


	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;

	if (ino < NOVA_NORMAL_INODE_START) {
		nova_err(sb, "ERROR: it is impossible, we have no need to append dec entry for reserved inode!");
		return -ENOSPC;
	}

	curr_location = &(sbi->curr_ain_loc[cpuid]);
	/*
	  * judge if we need to extend metadate region, loc_in_block is between 0-4095
	  * two sub-regions: 0-4031 and 4032-4095
	  * INODE_DES_BLOCK_TAIL is 4032
	*/
	curr_loc = curr_location->curr_alloc_location;//global address
	curr_loc_in_block = curr_loc % NOVA_DEF_BLOCK_SIZE_4K;

	if(curr_loc_in_block == INODE_DES_BLOCK_TAIL){

		inode_des_tail = (struct nova_inode_des_page_tail *)curr_loc;
		if ( inode_des_tail->next_page == 1 ) {
			nova_info("There is no more space in inode describe region, the cpuid is %d\n", cpuid);
			/*
			  * if there is no more space in inode describe region
			  * In this function, we change sbi->curr_loc_in_des_region directly
			*/

			/* link new group with pervious groups */
			ret = nova_alloc_inode_des_region(sb, &sih, 0, 1, inode_des_tail, cpuid);
			if ( ret ) {
				nova_err(sb, "nova_alloc_inode_des_region in %s failure!\n", __func__);
				return ret;
			}

			ain_entry = (struct nova_inode_ssim*)(curr_location->curr_alloc_location);

			if (move_ain)
				nova_init_mova_ain(sb, ain_entry, pi_ain_loc->ain_location);
			else
				nova_init_new_ain(sb, ain_entry, inode);

			pi_ain_loc->ain_location = ain_entry;
			ret = nova_update_ino_loc_hash(sb, ino, ain_entry);
			if(ret)
				return ret;

			*if_gc = 1;









			/* start a new thread to excute GC for AIN */
			/*
			static int nova_snapshot_cleaner_init(struct nova_sb_info *sbi)
			{
				int ret = 0;
				init_waitqueue_head(&sbi->snapshot_cleaner_wait);
				sbi->snapshot_cleaner_thread = kthread_run(nova_snapshot_cleaner,
					sbi, "nova_snapshot_cleaner");
				if (IS_ERR(sbi->snapshot_cleaner_thread)) {
					nova_info("Failed to start NOVA snapshot cleaner thread\n");
					ret = -1;
				}
				nova_info("Start NOVA snapshot cleaner thread.\n");
				return ret;
			}
			*/
			write_unlock(&pi_ain_loc->rblock_instance);








			/*
				update the group_ratio and group_per_cpu
				*/
			(sbi->ain_group_des + cpuid)->group_num_percpu++;
			group_index = (sbi->ain_group_des + cpuid)->group_num_percpu - 1;
			group_des = (sbi->ain_group_des + cpuid)->begin_group_per_cpu;

			(group_des + group_index)->invalid_ain_num = 0;
			(group_des + group_index)->page_num = INODE_DES_BLOCK_BLOCK_LIST_LEN;
			(group_des + group_index)->group_addr_begin = nova_get_addr_off(sbi, (void *)ain_entry);
		}
		else{
			if(inode_des_tail->next_page == 0)
				/* they are in one sequent group */
				curr_location->curr_alloc_location = curr_loc + NOVA_INODE_SSIM_SIZE;
			else
				/* they are in list, rather than in a group */
				curr_location->curr_alloc_location = (u64)nova_get_block(sb, inode_des_tail->next_page);
		}
	}
	else
		curr_location->curr_alloc_location = curr_loc;

	ain_entry = (struct nova_inode_ssim*)(curr_location->curr_alloc_location);
	if (move_ain)
		nova_init_mova_ain(sb, ain_entry, pi_ain_loc->ain_location);
	else
		nova_init_new_ain(sb, ain_entry, inode);
	pi_ain_loc->ain_location = ain_entry;
	ret = nova_update_ino_loc_hash(sb, ino, ain_entry);
	if(ret)
		return ret;

	curr_location->curr_alloc_location += NOVA_INODE_SSIM_SIZE;
	return 0;
}


static void nova_get_inode_flags(struct inode *inode, struct nova_inode_ssim *pi_ssim)
{
	unsigned int flags = inode->i_flags;
	unsigned int nova_flags = le32_to_cpu(pi_ssim->i_flags);

	nova_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		nova_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		nova_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		nova_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		nova_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		nova_flags |= FS_DIRSYNC_FL;

	pi_ssim->i_flags = cpu_to_le32(nova_flags);
}

/*
	In this function, we allocate nova_inode_info, including vfs_inode, and make initialization partly
	And we append an new AIN for the new inode, we need to get the curr append location lock to guarantee
	that in every moment, only one thread can append AIN
	*/
struct inode *nova_new_vfs_inode(enum nova_new_inode_type type,
	struct inode *dir, u64 ino, umode_t mode, size_t size,
	dev_t rdev, const struct qstr *qstr, u64 epoch_id)
{
	struct super_block *sb;
	struct nova_sb_info *sbi;
	struct inode *inode;
	struct nova_inode_info *si, *si_dir;
	struct nova_inode_info_header *sih = NULL;
	struct nova_ain_loc *pi_ain_loc = NULL, *pi_ain_loc_dir = NULL;
	struct nova_inode_ssim *pi_ssim;//, *diri;
	struct nova_inode_complete_entry inode_complete_data;
	struct nova_inode_update update;
	unsigned int dir_flags;
	int errval;
	int ret;
	int cpuid;
	int if_gc = 0;


	INIT_TIMING(new_inode_time);

	NOVA_START_TIMING(new_vfs_inode_t, new_inode_time);
	sb = dir->i_sb;
	sbi = (struct nova_sb_info *)sb->s_fs_info;
	cpuid = ino % sbi->cpus;

	/* init vfs_inode */
	inode = new_inode(sb);
	if (!inode) {
		errval = -ENOMEM;
		goto fail2;
	}
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;
	inode->i_ino = ino;
	/*
	if (metadata_csum) {
		// Get alternate inode address
		errval = nova_get_alter_inode_address(sb, ino, &alter_pi_addr);
		if (errval)
			goto fail1;
	}
	*/
	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &nova_file_inode_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		if (!test_opt(inode->i_sb, DATA_COW) && wprotect == 0)
			inode->i_fop = &nova_dax_file_operations;
		else
			inode->i_fop = &nova_wrap_file_operations;
		break;
	case TYPE_MKNOD:
		init_special_inode(inode, mode, rdev);
		inode->i_op = &nova_special_inode_operations;
		break;
	case TYPE_SYMLINK:
		inode->i_op = &nova_symlink_inode_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		break;
	case TYPE_MKDIR:
		inode->i_op = &nova_dir_inode_operations;
		inode->i_fop = &nova_dir_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		set_nlink(inode, 2);
		break;
	default:
		nova_dbg("Unknown new inode type %d\n", type);
		break;
	}
	/*
		init the other part of nova_inode_info
			1. header
			2. ain_loc_and_lock
	*/
	si = NOVA_I(inode);
	pi_ain_loc = &si->ain_loc_and_lock;
	sih = &si->header;

	si_dir = NOVA_I(dir);
	pi_ain_loc_dir = &si_dir->ain_loc_and_lock;

	/* 1. init header */
	nova_init_header(sb, sih, inode->i_mode);
	sih->ino = ino;
	sih->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	/* 2. append AIN and init ain_loc_and_lock */
	rwlock_init(&pi_ain_loc->rblock_instance);

	/* get lock, so curr thread can append AIN entry */
	spin_lock(&((sbi->curr_ain_loc[cpuid]).curr_loc_spinlock));
	ret = nova_append_ain(sb, inode, pi_ain_loc, 0, &if_gc);
	if (ret) {
		nova_dbg("%s: Append a new AIN in nova_new_nova_inode failure %d!\n", __func__, ret);
		spin_unlock(&((sbi->curr_ain_loc[cpuid]).curr_loc_spinlock));
		errval = -EINVAL;
		goto fail1;
	}

	/*
		init AIN
		Because current thread hold the lock of the whole AIN region, so the pi_ssim is ok within the lock
		But as for the dir...
	*/
	pi_ssim = pi_ain_loc->ain_location;
	nova_memunlock_inode_ssim(sb, pi_ssim);
	/*
	if (metadata_csum) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
								alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	*/

	if (dir->i_ino == 1)
		pi_ssim->i_flags = nova_mask_flags(mode, nova_get_inode_by_ino(sb, 1)->i_flags);
	else{
		/*
			If one thread in another core excute the GC, current thread excute the code ---- pi_ain_loc_dir->ain_location to get the handle of dir_AIN,
			and then the GC change the loc of dir_AIN, and delete the content in origin location, so the pi_ssim_sir is inavailable
			So, here, if the inode of dir is in the same AIN with the new inode, it is impossible for GC to change the handle of pi_ssim_dir,
			but, if the inode of dir is in the different AIN, the GC thread maybe get the append lock and change the location of pi_ssim_dir
		*/
		if (cpuid == dir->i_ino % sbi->cpus) {
			// there is no need to lock dir
			dir_flags = (pi_ain_loc_dir->ain_location)->i_flags;
		}
		else{
			read_lock(&pi_ain_loc_dir->rblock_instance);
			dir_flags = (pi_ain_loc_dir->ain_location)->i_flags;
			read_unlock(&pi_ain_loc_dir->rblock_instance);
		}

		pi_ssim->i_flags = nova_mask_flags(mode, dir_flags);
	}

	nova_get_inode_flags(inode, pi_ssim);

	/* inode_complete_data is a temporary struct in DRAM */
	inode_complete_data.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	inode_complete_data.nova_ino = ino;
	inode_complete_data.i_create_time = current_time(inode).tv_sec;
	inode_complete_data.create_epoch_id = epoch_id;
	nova_init_inode_complete(inode, &inode_complete_data);

	/*
	allocate log for the new AIN
		1. append nova_inode_complete_entry entry in inode log
		2. init the head and tail of nova_inode_ssim
		3. init nova_inode_complete_entry
		*/
	update.tail = 0;
	update.alter_tail = 0;

	ret = nova_append_inode_complete_entry(sb, inode, &update, &inode_complete_data);
	if ( ret ){
		nova_err(sb, "%s failed\n", __func__);
		errval = -EINVAL;
		goto fail1;
	}
	pi_ssim->complete_inode = (struct nova_inode_complete_entry *)nova_get_block(sb, pi_ssim->log_head);
	pi_ssim->log_tail = update.tail;

	/* the init of nova_inode_ssim has been done */
	nova_memlock_inode_ssim(sb, pi_ssim);
	nova_flush_buffer(pi_ssim, NOVA_INODE_SSIM_SIZE, 0);
	nova_set_inode_flags(inode, pi_ssim->complete_inode, le32_to_cpu(pi_ssim->i_flags));

	spin_unlock(&((sbi->curr_ain_loc[cpuid]).curr_loc_spinlock));

	if (insert_inode_locked(inode) < 0) {
		nova_err(sb, "nova_new_inode failed ino %lx\n", inode->i_ino);
		errval = -EINVAL;
		goto fail1;
	}

	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
fail2:
	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return ERR_PTR(errval);
}



/******** Function insulation ***********/



int nova_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called.
	 */
//	BUG();
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because NOVA always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void nova_dirty_inode(struct inode *inode, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	//struct nova_inode_info_header *sih = &si->header;
	struct nova_ain_loc *pi_ain_loc;
	struct nova_inode_ssim *pi_ssim;
	struct nova_inode_reserved *pi_root;
	struct nova_inode_complete_entry *pi_complete;

	if (sbi->mount_snapshot)
		return;

	if(inode->i_ino == 1){
		pi_root = nova_get_inode_by_ino(sb, 1);
		nova_memunlock_inode_reserved(sb, pi_root);
		pi_root->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
		nova_memlock_inode_reserved(sb, pi_root);
		nova_flush_buffer(&pi_root->i_atime, sizeof(pi_root->i_atime), 0);
	}
	else{
		pi_ain_loc = &si->ain_loc_and_lock;
		read_lock(&pi_ain_loc->rblock_instance);
		pi_ssim = pi_ain_loc->ain_location;
		pi_complete = pi_ssim->complete_inode;
		read_unlock(&pi_ain_loc->rblock_instance);

		/* check the inode before updating to make sure all fields are good */
		/*
		if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
						sih->alter_pi_addr, &inode_copy, 0) < 0)
			return;
			*/

		/* only i_atime should have changed if at all.
		 * we can do in-place atomic update
		 */
		nova_memunlock_inode_entry_complete(sb, pi_complete);
		pi_complete->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
		//nova_update_inode_checksum(pi);
		//nova_update_alter_inode(sb, inode, pi);
		nova_memlock_inode_entry_complete(sb, pi_complete);
		/* Relax atime persistency */
		nova_flush_buffer(&pi_complete->i_atime, sizeof(pi_complete->i_atime), 0);
	}
}

#if 0
static void nova_setsize(struct inode *inode, loff_t oldsize, loff_t newsize,
	u64 epoch_id)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	INIT_TIMING(setsize_time);

	/* We only support truncate regular file */
	if (!(S_ISREG(inode->i_mode))) {
		nova_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
		return;
	}

	NOVA_START_TIMING(setsize_t, setsize_time);

	inode_dio_wait(inode);

	nova_dbgv("%s: inode %lu, old size %llu, new size %llu\n",
		__func__, inode->i_ino, oldsize, newsize);

	if (newsize != oldsize) {
		nova_clear_last_page_tail(sb, inode, newsize);
		i_size_write(inode, newsize);
		sih->i_size = newsize;
	}

	/* FIXME: we should make sure that there is nobody reading the inode
	 * before truncating it. Also we need to munmap the truncated range
	 * from application address space, if mmapped.
	 */
	/* synchronize_rcu(); */

	/* FIXME: Do we need to clear truncated DAX pages? */
//	dax_truncate_page(inode, newsize, nova_dax_get_block);

	truncate_pagecache(inode, newsize);
	nova_truncate_file_blocks(inode, newsize, oldsize, epoch_id);
	NOVA_END_TIMING(setsize_t, setsize_time);
}
#endif


int nova_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int flags = sih->i_flags;

	if (flags & FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & FS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}


int nova_notify_change(struct dentry *dentry, struct iattr *attr)
{
	#if 0
	struct inode *inode = dentry->d_inode;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_ain_loc *pi_ain_loc = &si->ain_loc_and_lock;
	struct super_block *sb = inode->i_sb;

	int ret;
	unsigned int ia_valid = attr->ia_valid, attr_mask;
	loff_t oldsize = inode->i_size;
	u64 epoch_id;
	INIT_TIMING(setattr_time);

	NOVA_START_TIMING(setattr_t, setattr_time);

	ret = setattr_prepare(dentry, attr);
	if (ret)
		goto out;

	/* Update inode with attr except for size */
	setattr_copy(inode, attr);

	epoch_id = nova_get_epoch_id(sb);

	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME
			| ATTR_MTIME | ATTR_CTIME;

	ia_valid = ia_valid & attr_mask;

	if (ia_valid == 0)
		goto out;

	ret = nova_handle_setattr_operation(sb, inode, ia_valid,
					attr, epoch_id);
	if (ret)
		goto out;

	/* Only after log entry is committed, we can truncate size */
	if ((ia_valid & ATTR_SIZE) && (attr->ia_size != oldsize ||
			(pi_ain_loc->ain_location)->i_flags & cpu_to_le32(NOVA_EOFBLOCKS_FL))) {
//		nova_set_blocksize_hint(sb, inode, pi, attr->ia_size);

		/* now we can freely truncate the inode */
		nova_setsize(inode, oldsize, attr->ia_size, epoch_id);
	}

	sih->trans_id++;
out:
	NOVA_END_TIMING(setattr_t, setattr_time);
	return ret;
	#endif
	return 0;
}


void nova_set_inode_flags(struct inode *inode, struct nova_inode_complete_entry *pi_complete,
	unsigned int flags)
{
	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi_complete->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}


/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long nova_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	unsigned long blocks = 0, offset_in_block;
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !sih->i_size) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & ((1UL << data_bits) - 1);

	first_blocknr = *offset >> data_bits;
	last_blocknr = inode->i_size >> data_bits;

	nova_dbg_verbose("find_region offset %llx, first_blocknr %lx, last_blocknr %lx hole %d\n",
		  *offset, first_blocknr, last_blocknr, hole);

	blocks = nova_lookup_hole_in_range(inode->i_sb, sih,
		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

	/* Searching data but only hole found till the end */
	if (!hole && !data_found && hole_found)
		return -ENXIO;

	if (data_found && !hole_found) {
		/* Searching data but we are already into them */
		if (hole)
			/* Searching hole but only data found, go to the end */
			*offset = inode->i_size;
		return 0;
	}

	/* Searching for hole, hole found and starting inside an hole */
	if (hole && hole_found && !blocks) {
		/* we found data after it */
		if (!data_found)
			/* last hole */
			*offset = inode->i_size;
		return 0;
	}

	if (offset_in_block) {
		blocks--;
		*offset += (blocks << data_bits) +
			   ((1 << data_bits) - offset_in_block);
	} else {
		*offset += blocks << data_bits;
	}

	return 0;
}


/******** Function insulation ***********/


static ssize_t nova_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	/* DAX does not support direct IO */
	return -EIO;
}

static int nova_writepages(struct address_space *mapping,
	struct writeback_control *wbc)
{
	int ret;
	INIT_TIMING(wp_time);

	NOVA_START_TIMING(write_pages_t, wp_time);
	ret = dax_writeback_mapping_range(mapping,
			mapping->host->i_sb->s_bdev, wbc);
	NOVA_END_TIMING(write_pages_t, wp_time);
	return ret;
}

const struct address_space_operations nova_aops_dax = {
	.writepages		= nova_writepages,
	.direct_IO		= nova_direct_IO,
	/*.dax_mem_protect	= nova_dax_mem_protect,*/
};