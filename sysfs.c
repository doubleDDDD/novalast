/*
 * BRIEF DESCRIPTION
 *
 * Proc fs operations
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"
#include "inode.h"

const char *proc_dirname = "fs/NOVA";
struct proc_dir_entry *nova_proc_root;

static unsigned long journal_start;
void rbtree_inorder_for_each_entry(struct seq_file *, struct rb_node *);//declaration,added by double_D

/* ====================== Statistics ======================== */
static int nova_seq_timing_show(struct seq_file *seq, void *v)
{
	int i;

	nova_get_timing_stats();

	seq_puts(seq, "=========== NOVA kernel timing stats ===========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			seq_printf(seq, "\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			seq_printf(seq, "%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			seq_printf(seq, "%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	seq_puts(seq, "\n");
	return 0;
}

static int nova_seq_timing_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_timing_show, PDE_DATA(inode));
}

ssize_t nova_seq_clear_stats(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);

	nova_clear_stats(sb);
	return len;
}

static const struct file_operations nova_seq_timing_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_timing_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_IO_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long alloc_log_count = 0;
	unsigned long alloc_log_pages = 0;
	unsigned long alloc_data_count = 0;
	unsigned long alloc_data_pages = 0;
	unsigned long free_log_count = 0;
	unsigned long freed_log_pages = 0;
	unsigned long free_data_count = 0;
	unsigned long freed_data_pages = 0;
	int i;

	nova_get_timing_stats();
	nova_get_IO_stats();

	seq_puts(seq, "============ NOVA allocation stats ============\n\n");

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		alloc_log_count += free_list->alloc_log_count;
		alloc_log_pages += free_list->alloc_log_pages;
		alloc_data_count += free_list->alloc_data_count;
		alloc_data_pages += free_list->alloc_data_pages;
		free_log_count += free_list->free_log_count;
		freed_log_pages += free_list->freed_log_pages;
		free_data_count += free_list->free_data_count;
		freed_data_pages += free_list->freed_data_pages;
	}

	seq_printf(seq, "alloc log count %lu, allocated log pages %lu\n"
		"alloc data count %lu, allocated data pages %lu\n"
		"free log count %lu, freed log pages %lu\n"
		"free data count %lu, freed data pages %lu\n",
		alloc_log_count, alloc_log_pages,
		alloc_data_count, alloc_data_pages,
		free_log_count, freed_log_pages,
		free_data_count, freed_data_pages);

	seq_printf(seq, "Fast GC %llu, check pages %llu, free pages %llu, average %llu\n",
		Countstats[fast_gc_t], IOstats[fast_checked_pages],
		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
	seq_printf(seq, "Thorough GC %llu, checked pages %llu, free pages %llu, average %llu\n",
		Countstats[thorough_gc_t],
		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
		Countstats[thorough_gc_t] ?
			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t]
			: 0);

	seq_puts(seq, "\n");

	seq_puts(seq, "================ NOVA I/O stats ================\n\n");
	seq_printf(seq, "Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], IOstats[read_bytes],
		Countstats[dax_read_t] ?
			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
	seq_printf(seq, "COW write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[do_cow_write_t], IOstats[cow_write_bytes],
		Countstats[do_cow_write_t] ?
			IOstats[cow_write_bytes] / Countstats[do_cow_write_t] : 0,
		IOstats[cow_write_breaks], Countstats[do_cow_write_t] ?
			IOstats[cow_write_breaks] / Countstats[do_cow_write_t]
			: 0);
	seq_printf(seq, "Inplace write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[inplace_write_t], IOstats[inplace_write_bytes],
		Countstats[inplace_write_t] ?
			IOstats[inplace_write_bytes] /
			Countstats[inplace_write_t] : 0,
		IOstats[inplace_write_breaks], Countstats[inplace_write_t] ?
			IOstats[inplace_write_breaks] /
			Countstats[inplace_write_t] : 0);
	seq_printf(seq, "Inplace write %llu, allocate new blocks %llu\n",
			Countstats[inplace_write_t],
			IOstats[inplace_new_blocks]);
	seq_printf(seq, "DAX get blocks %llu, allocate new blocks %llu\n",
			Countstats[dax_get_block_t], IOstats[dax_new_blocks]);
	seq_printf(seq, "Dirty pages %llu\n", IOstats[dirty_pages]);
	seq_printf(seq, "Protect head %llu, tail %llu\n",
			IOstats[protect_head], IOstats[protect_tail]);
	seq_printf(seq, "Block csum parity %llu\n", IOstats[block_csum_parity]);
	seq_printf(seq, "Page fault %llu, dax cow fault %llu, dax cow fault during snapshot creation %llu\n"
			"CoW write overlap mmap range %llu, mapping/pfn updated pages %llu\n",
			Countstats[mmap_fault_t], Countstats[mmap_cow_t],
			IOstats[dax_cow_during_snapshot],
			IOstats[cow_overlap_mmap],
			IOstats[mapping_updated_pages]);
	seq_printf(seq, "fsync %llu, fdatasync %llu\n",
			Countstats[fsync_t], IOstats[fdatasync]);

	seq_puts(seq, "\n");

	//nova_print_snapshot_lists(sb, seq);
	seq_puts(seq, "\n");

	return 0;
}

static int nova_seq_IO_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_IO_show, PDE_DATA(inode));
}

static const struct file_operations nova_seq_IO_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_IO_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_show_allocator(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long log_pages = 0;
	unsigned long data_pages = 0;

	seq_puts(seq, "======== NOVA per-CPU allocator stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		seq_printf(seq, "Free list %d: block start %lu, block end %lu, num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		if (free_list->first_node) {
			seq_printf(seq, "First node %lu - %lu\n",
					free_list->first_node->range_low,
					free_list->first_node->range_high);
		}

		if (free_list->last_node) {
			seq_printf(seq, "Last node %lu - %lu\n",
					free_list->last_node->range_low,
					free_list->last_node->range_high);
		}

		seq_printf(seq, "Free list %d: csum start %lu, replica csum start %lu, csum blocks %lu, parity start %lu, parity blocks %lu\n",
			i, free_list->csum_start, free_list->replica_csum_start,
			free_list->num_csum_blocks,
			free_list->parity_start, free_list->num_parity_blocks);

		seq_printf(seq, "Free list %d: alloc log count %lu, allocated log pages %lu, alloc data count %lu, allocated data pages %lu, free log count %lu, freed log pages %lu, free data count %lu, freed data pages %lu\n",
			   i,
			   free_list->alloc_log_count,
			   free_list->alloc_log_pages,
			   free_list->alloc_data_count,
			   free_list->alloc_data_pages,
			   free_list->free_log_count,
			   free_list->freed_log_pages,
			   free_list->free_data_count,
			   free_list->freed_data_pages);

		log_pages += free_list->alloc_log_pages;
		log_pages -= free_list->freed_log_pages;

		data_pages += free_list->alloc_data_pages;
		data_pages -= free_list->freed_data_pages;
	}

	seq_printf(seq, "\nCurrently used pmem pages: log %lu, data %lu\n",
			log_pages, data_pages);

	return 0;
}

static int nova_seq_allocator_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_allocator,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_allocator_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_allocator_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Snapshot ======================== */
static int nova_seq_create_snapshot_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "Write to create a snapshot\n");
	return 0;
}

static int nova_seq_create_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_create_snapshot_show,
				PDE_DATA(inode));
}

ssize_t nova_seq_create_snapshot(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	//struct address_space *mapping = filp->f_mapping;
	//struct inode *inode = mapping->host;
	//struct super_block *sb = PDE_DATA(inode);

	//nova_create_snapshot(sb);
	return len;
}

static const struct file_operations nova_seq_create_snapshot_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_create_snapshot_open,
	.read		= seq_read,
	.write		= nova_seq_create_snapshot,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_delete_snapshot_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "Echo index to delete a snapshot\n");
	return 0;
}

static int nova_seq_delete_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_delete_snapshot_show,
				PDE_DATA(inode));
}

ssize_t nova_seq_delete_snapshot(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	//struct address_space *mapping = filp->f_mapping;
	//struct inode *inode = mapping->host;
	//struct super_block *sb = PDE_DATA(inode);
	u64 epoch_id;

	sscanf(buf, "%llu", &epoch_id);
	//nova_delete_snapshot(sb, epoch_id);

	return len;
}

static const struct file_operations nova_seq_delete_snapshot_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_delete_snapshot_open,
	.read		= seq_read,
	.write		= nova_seq_delete_snapshot,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_show_snapshots(struct seq_file *seq, void *v)
{
	//struct super_block *sb = seq->private;

	//nova_print_snapshots(sb, seq);
	return 0;
}

static int nova_seq_show_snapshots_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_snapshots,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_show_snapshots_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_show_snapshots_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Performance ======================== */
static int nova_seq_test_perf_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Echo function:poolmb:size:disks to test function performance working on size of data.\n"
			"    example: echo 1:128:4096:8 > /proc/fs/NOVA/pmem0/test_perf\n"
			"The disks value only matters for raid functions.\n"
			"Set function to 0 to test all functions.\n");
	return 0;
}

static int nova_seq_test_perf_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_test_perf_show, PDE_DATA(inode));
}

ssize_t nova_seq_test_perf(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	size_t size;
	unsigned int func_id, poolmb, disks;

	if (sscanf(buf, "%u:%u:%zu:%u", &func_id, &poolmb, &size, &disks) == 4)
		nova_test_perf(sb, func_id, poolmb, size, disks);
	else
		nova_warn("Couldn't parse test_perf request: %s", buf);

	return len;
}

static const struct file_operations nova_seq_test_perf_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_test_perf_open,
	.read		= seq_read,
	.write		= nova_seq_test_perf,
	.llseek		= seq_lseek,
	.release	= single_release,
};


/* ====================== GC ======================== */


static int nova_seq_gc_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Echo inode number to trigger garbage collection\n"
		   "    example: echo 34 > /proc/fs/NOVA/pmem0/gc\n");
	return 0;
}

static int nova_seq_gc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_gc_show, PDE_DATA(inode));
}

ssize_t nova_seq_gc(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	#if 0
	u64 target_inode_number;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	struct inode *target_inode;
	struct nova_inode *target_pi;
	struct nova_inode_info *target_sih;

	char *_buf;
	int retval = len;

	_buf = kmalloc(len, GFP_KERNEL);
	if (_buf == NULL)  {
		retval = -ENOMEM;
		nova_dbg("%s: kmalloc failed\n", __func__);
		goto out;
	}

	if (copy_from_user(_buf, buf, len)) {
		retval = -EFAULT;
		goto out;
	}

	_buf[len] = 0;
	sscanf(_buf, "%llu", &target_inode_number);
	nova_info("%s: target_inode_number=%llu.", __func__,
		  target_inode_number);

	/* FIXME: inode_number must exist */
	if (target_inode_number < NOVA_NORMAL_INODE_START &&
			target_inode_number != NOVA_ROOT_INO) {
		nova_info("%s: invalid inode %llu.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_inode = nova_iget(sb, target_inode_number);
	if (target_inode == NULL) {
		nova_info("%s: inode %llu does not exist.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_pi = nova_get_inode(sb, target_inode);
	if (target_pi == NULL) {
		nova_info("%s: couldn't get nova inode %llu.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_sih = NOVA_I(target_inode);

	nova_info("%s: got inode %llu @ 0x%p; pi=0x%p\n", __func__,
		  target_inode_number, target_inode, target_pi);

	nova_inode_log_fast_gc(sb, target_pi, &target_sih->header,
			       0, 0, 0, 0, 1);
	iput(target_inode);

out:
	kfree(_buf);
	return retval;
	#endif
	return 0;
}

static const struct file_operations nova_seq_gc_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_gc_open,
	.read		= seq_read,
	.write		= nova_seq_gc,
	.llseek		= seq_lseek,
	.release	= single_release,
};




/* ====================== write operation count ======================== */

/* ====================== write operation metadata count ======================== */
static unsigned long identify_journal_location(struct super_block * sb, unsigned long journal_start )
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	for(i = 0; i < sbi->cpus; i++){
		free_list = nova_get_free_list(sb, i);
		if( free_list->num_blocknode == 1 && ((free_list->block_end - free_list->block_start + 1) - (free_list->num_free_blocks)) > 512 ){
			journal_start = free_list->block_start + 512;
			return journal_start;
			break;
		}
	}
	return journal_start;
}


static int nova_seq_writeop_metadata_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long j;

	journal_start = identify_journal_location(sb, journal_start);

	seq_puts(seq, "======== NOVA primary super_block writeop stats ========\n");
	seq_printf(seq, "The writeop count of primary super_block is %lu\n", *p_global);

	seq_puts(seq, "======== NOVA replica super_block writeop stats ========\n");
	seq_printf(seq, "The writeop count of replica super_block is %lu\n", *(p_global + ((sbi -> initsize >> PAGE_SHIFT) - 1)));

	seq_puts(seq, "======== NOVA reserved inodes writeop stats ========\n");
	seq_printf(seq, "The writeop count of reserved inodes is %lu\n", *(p_global + 1));

	seq_puts(seq, "======== NOVA replica reserved inodes writeop stats ========\n");
	seq_printf(seq, "The writeop count of replica reserved inodes is %lu\n", *(p_global + ((sbi -> initsize >> PAGE_SHIFT) - 2)));

	seq_puts(seq, "======== NOVA reserved 2 writeop stats ========\n");
	seq_printf(seq, "The writeop count of reserved 2 is %lu\n", *(p_global + 2));

	seq_puts(seq, "======== NOVA journal pointers writeop stats ========\n");
	seq_printf(seq, "The writeop count of journal pointers is %lu\n", *(p_global + 3));

	seq_puts(seq, "======== NOVA inode pointer tables writeop stats ========\n");
	seq_printf(seq, "The writeop count of inode pointer tables is %lu\n", *(p_global + 4));


	seq_puts(seq, "======== NOVA reserved 6 writeop stats ========\n");
	seq_printf(seq, "The writeop count of reserved 6 is %lu\n", *(p_global + 6));

	seq_puts(seq, "======== NOVA reserved 7 writeop stats ========\n");
	seq_printf(seq, "The writeop count of reserved 7 is %lu\n", *(p_global + 7));


	seq_puts(seq, "======== NOVA per-CPU writeop stats, include csum, parity and their replication; inode tables, journals and data(log) pages========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		/*identify the location of journals*/
		seq_printf(seq, "The cpu is %d\n", i);
		seq_puts(seq, "======== NOVA csum stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		for(j = free_list->csum_start; j != free_list->csum_start + free_list->num_csum_blocks; j++){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));;
		}

		seq_puts(seq, "======== NOVA replica csum stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		for(j = free_list->replica_csum_start; j != free_list->replica_csum_start + free_list->num_csum_blocks; j++){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));;
		}

		seq_puts(seq, "======== NOVA parity stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		for(j = free_list->parity_start; j != free_list->parity_start + free_list->num_parity_blocks; j++){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));;
		}

		seq_puts(seq, "======== NOVA replica parity stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		for(j = free_list->replica_parity_start; j != free_list->replica_parity_start + free_list->num_parity_blocks; j++){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));;
		}


		seq_puts(seq, "======== NOVA inode table stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		/*inode tables*/

		for(j = free_list->block_start; j != free_list->block_start + 512; j++){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));;
		}

	}

	seq_puts(seq, "======== NOVA journal stats ========\n");
	seq_puts(seq, "======== block numbers  and  write operations count ========\n");
	for( j = journal_start; j != journal_start + sbi->cpus; j++){
		seq_printf(seq, "%lu %lu\n", j, *(p_global + j));
	}

	seq_puts(seq, "======== All the metadate write operation count stats of NOVA ========\n");

	return 0;
}



static int nova_seq_writeop_metadata_open(struct inode *inode, struct file *file)
{
	if( metadata_writeop_statistics == 1 ){
		return single_open(file, nova_seq_writeop_metadata_show, PDE_DATA(inode));
	}
	return -1;
}

static const struct file_operations nova_seq_writeop_metadata_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_writeop_metadata_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};



/* ====================== write operation of data and log count ======================== */
static int nova_seq_writeop_data_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long j;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		seq_puts(seq, "======== NOVA data page write operation count stats ========\n");
		seq_puts(seq, "======== block numbers  and  write operations count ========\n");
		seq_printf(seq, "Free_list %d\n",i);

		for( j = free_list->block_start; j != free_list->block_end + 1; j++ ){
			seq_printf(seq, "%lu %lu\n", j, *(p_global + j));
		}
	}
	return 0;
}


static int nova_seq_writeop_data_open(struct inode *inode, struct file *file)
{
	if( data_writeop_statistics == 1 ){
		return single_open(file, nova_seq_writeop_data_show, PDE_DATA(inode));
	}
	return -1;
}

static const struct file_operations nova_seq_writeop_data_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_writeop_data_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


//add the rb_tree state of the free list

/* ====================== free_list rbtree the fragment ======================== */
/*
void rbtree_inorder_for_each_entry(struct seq_file *seq, struct rb_node *block_free_test){
	struct nova_range_node *node_test;
	if(block_free_test == NULL){
		return;
	}
	rbtree_inorder_for_each_entry(seq, block_free_test->rb_left);
	node_test = container_of(block_free_test, struct nova_range_node, node);
	seq_printf(seq, "range_low is %lu range_high is %lu\n",
		node_test->range_low,
		node_test->range_high);
	rbtree_inorder_for_each_entry(seq, block_free_test->rb_right);
}

static int nova_seq_show_freelist_node(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	struct rb_node *block_free_test;

	seq_puts(seq, "======== NOVA per-CPU free_list stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		block_free_test = (free_list->block_free_tree).rb_node;
		if( fragment_statistics == 1 ){
			seq_printf(seq,"My test: Free list %d, and all the free blocknode:\n",i);
			rbtree_inorder_for_each_entry(seq, block_free_test);
		}
	}
	return 0;
}

static int nova_seq_freelist_node_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_freelist_node,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_freelist_node_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_freelist_node_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
*/

/*
// data or log
static int nova_seq_data_or_log(struct seq_file *seq, void *v){
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long j;

	seq_puts(seq, "====== The rate of data and log ======\n");
	for( i=0; i < sbi->cpus; i++ ){
		free_list = nova_get_free_list(sb, i);
		for( j = free_list->block_start; j != free_list->block_end; j++){
			seq_printf(seq, "%lu %lld\n", j, *(data_or_log_global+j));
		}
	}
	return 0;
}

static int nova_seq_data_or_log_open(struct inode* inode, struct file *file){
	if( log_or_data == 1 )
		return single_open(file, nova_seq_data_or_log, PDE_DATA(inode));
	return -1;
}

static const struct file_operations nova_seq_data_or_log_fops = {
	.owner		= THIS_MODULE,
	.open       = nova_seq_data_or_log_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = single_release,
};
*/

/* ====================== Setup/teardown======================== */
void nova_sysfs_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (nova_proc_root)
		sbi->s_proc = proc_mkdir(sbi->s_bdev->bd_disk->disk_name,
					 nova_proc_root);

	if (sbi->s_proc) {
		proc_create_data("timing_stats", 0444, sbi->s_proc,
				 &nova_seq_timing_fops, sb);
		proc_create_data("IO_stats", 0444, sbi->s_proc,
				 &nova_seq_IO_fops, sb);
		proc_create_data("allocator", 0444, sbi->s_proc,
				 &nova_seq_allocator_fops, sb);
		proc_create_data("create_snapshot", 0444, sbi->s_proc,
				 &nova_seq_create_snapshot_fops, sb);
		proc_create_data("delete_snapshot", 0444, sbi->s_proc,
				 &nova_seq_delete_snapshot_fops, sb);
		proc_create_data("snapshots", 0444, sbi->s_proc,
				 &nova_seq_show_snapshots_fops, sb);
		proc_create_data("test_perf", 0444, sbi->s_proc,
				 &nova_seq_test_perf_fops, sb);
		proc_create_data("gc", 0444, sbi->s_proc,
				 &nova_seq_gc_fops, sb);
		proc_create_data("write_operation_metadata_count", 0444, sbi->s_proc,
				 &nova_seq_writeop_metadata_fops, sb);//added by double_D
		proc_create_data("write_operation_data_count", 0444, sbi->s_proc,
				 &nova_seq_writeop_data_fops, sb);//added by double_D
	}
}

void nova_sysfs_exit(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->s_proc) {
		remove_proc_entry("timing_stats", sbi->s_proc);
		remove_proc_entry("IO_stats", sbi->s_proc);
		remove_proc_entry("allocator", sbi->s_proc);
		remove_proc_entry("create_snapshot", sbi->s_proc);
		remove_proc_entry("delete_snapshot", sbi->s_proc);
		remove_proc_entry("snapshots", sbi->s_proc);
		remove_proc_entry("test_perf", sbi->s_proc);
		remove_proc_entry("gc", sbi->s_proc);
		remove_proc_entry("write_operation_metadata_count", sbi->s_proc);//added by double_D
		remove_proc_entry("write_operation_data_count", sbi->s_proc);//added by double_D
		remove_proc_entry(sbi->s_bdev->bd_disk->disk_name,
					nova_proc_root);
	}
}
