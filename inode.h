#ifndef __INODE_H
#define __INODE_H

struct nova_inode_info_header;
struct nova_inode;

#include "super.h"
#include "log.h"

/* 64*63 = 4032 */
#define INODE_DES_BLOCK_TAIL 			4032
#define INODE_DES_BLOCK_BLOCK_LIST_LEN 	256

/* data structure in the end of nova_inode_des page */
struct nova_inode_des_page_tail {
	__le64 next_page;	//only valid in the end of a group in list
	__le64 next_region;	//only valid in the end of a region
	__le64 last_page_in_region;	//only hold on in the first page
} __attribute((__packed__));

/* describe the inode describe page */
struct nova_inode_des_page {
	char padding[INODE_DES_BLOCK_TAIL];
	struct nova_inode_des_page_tail tail;
} __attribute((__packed__));

/* curr AIN allocate location */
struct curr_ain_loc_percpu {
	__le64 curr_alloc_location; // global address
	spinlock_t curr_loc_spinlock;
} __attribute((__packed__));

/* the ain group des */
struct group_ratio{
	u64 invalid_ain_num;
	u64 page_num;
	u64 group_addr_begin;// address in NVMM, local address
} __attribute((__packed__));

struct ain_group_des_percpu{
	int group_num_percpu;
	struct group_ratio* begin_group_per_cpu;
} __attribute((__packed__));

/*
 * Structure of an inode descriptor in NVM
 * At most 64 bytes, 44 bytes now
 */
struct nova_inode_ssim {
	u8 valid_ino;				// if this inode is valid?
	u8 valid_over_threshold;	// if this AIN is valid, if the update_times is over the threshold
	u8 update_times;			// if this value over threshold, we need to transfer AIN
	u8 deleted;					// Is this inode deleted?
	__le16 i_mode;		 		// File mode, data or dir; access authority
	__le64 log_head;
	__le64 log_tail;
	struct inode *vfs_inode;
	struct nova_inode_complete_entry *complete_inode;
	__le32	i_flags;
	__le32 csum;
} __attribute((__packed__));

/* the entry in inode-loc hash */
struct nova_ino_loc_hash {
	__le64 nova_ino;	/* inode number */
	struct nova_inode_ssim *pi_ssim_in_hash;	/* real location in NVMM + DRAM */
} __attribute((__packed__));

/*
 * Structure of an inode in PMEM
 * Keep the inode size to within 120 bytes: We use the last eight bytes
 * as inode table tail pointer.
 */
struct nova_inode_reserved {

	/* first 40 bytes */
	u8	i_rsvd;		 /* reserved. used to be checksum */
	u8	valid;		 /* Is this inode valid? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_blk_type;	 /* data block size this inode uses */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode b-tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le16	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le64	nova_ino;	 /* nova inode number */

	__le64	log_head;	 /* Log head pointer */
	__le64	log_tail;	 /* Log tail pointer */

	/* last 40 bytes */
	__le64	alter_log_head;	 /* Alternate log head pointer */
	__le64	alter_log_tail;	 /* Alternate log tail pointer */

	__le64	create_epoch_id; /* Transaction ID when create */
	__le64	delete_epoch_id; /* Transaction ID when deleted */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	__le32	csum;            /* CRC32 checksum */

	/* Leave 8 bytes for inode table tail pointer */
} __attribute((__packed__));

/* help to ain gc */
/*
struct ain_gc_des{
	int if_less_than_64;
	int begin_index;//0-9
	int group_amount_less_than_64;//0-9
	u64 page_num;
} __attribute((__packed__));
*/

enum nova_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};

/*
 * Inode table.  It's a linked list of pages.
 */
struct inode_table {
	__le64 log_head;
};

/*
 * NOVA-specific inode state kept in DRAM
 */
struct nova_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct radix_tree_root tree;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	struct list_head list;		/* SB list of mmap sih */
	int num_vmas;
	unsigned short i_mode;		/* Dir or file? */
	unsigned int i_flags;
	unsigned long log_pages;	/* Num of log pages */
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long valid_entries;	/* For thorough GC */
	unsigned long num_entries;	/* For thorough GC */
	u64 last_setattr;		/* Last setattr entry */
	u64 last_link_change;		/* Last link change entry */
	u64 last_dentry;		/* Last updated dentry */
	u64 trans_id;			/* Transaction ID */
	u64 log_head;			/* Log head pointer */
	u64 log_tail;			/* Log tail pointer */
	u64 alter_log_head;		/* Alternate log head pointer */
	u64 alter_log_tail;		/* Alternate log tail pointer */
	u8  i_blk_type;
};

/* For rebuild purpose, temporarily store pi infomation */
struct nova_inode_rebuild {
	u64	i_size;
	u32	i_flags;	/* Inode flags */
	u32	i_ctime;	/* Inode modification time */
	u32	i_mtime;	/* Inode b-tree Modification time */
	u32	i_atime;	/* Access time */
	u32	i_uid;		/* Owner Uid */
	u32	i_gid;		/* Group Id */
	u32	i_generation;	/* File version (for NFS) */
	u16	i_links_count;	/* Links count */
	u16	i_mode;		/* File mode */
	u64	trans_id;
};

struct nova_ain_loc {
	struct nova_inode_ssim *ain_location; 	/* the leatest location of AIN */
	rwlock_t rblock_instance; 				/* per AIN lock */
};

/*
 * DRAM state for inodes
 */
struct nova_inode_info {
	struct nova_inode_info_header header;
	struct nova_ain_loc ain_loc_and_lock;
	struct inode vfs_inode;
};

static inline struct nova_inode_info *NOVA_I(struct inode *inode)
{
	return container_of(inode, struct nova_inode_info, vfs_inode);
}

static inline struct nova_inode_info_header *NOVA_IH(struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	return &si->header;
}

static inline struct nova_ain_loc *NOVA_HLOC(struct nova_inode_info_header *sih)
{
	struct nova_inode_info *si = container_of(sih, struct nova_inode_info, header);
	return &si->ain_loc_and_lock;
}


#if 0
static inline struct nova_inode *nova_get_alter_inode(struct super_block *sb,
	struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode fake_pi;
	void *addr;
	int rc;

	if (metadata_csum == 0)
		return NULL;

	addr = nova_get_block(sb, sih->alter_pi_addr);
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct nova_inode));
	if (rc)
		return NULL;

	return (struct nova_inode *)addr;
}


static inline int nova_update_alter_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi)
{
	struct nova_inode *alter_pi;

	if (metadata_csum == 0)
		return 0;

	alter_pi = nova_get_alter_inode(sb, inode);
	if (!alter_pi)
		return -EINVAL;

	memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	return 0;
}

static inline int nova_update_inode_checksum(struct nova_inode_ssim *pi)
{
	u32 crc = 0;

	if (metadata_csum == 0)
		return 0;

	crc = nova_crc32c(~0, (__u8 *)pi,
			(sizeof(struct nova_inode_ssim) - sizeof(__le32)));

	pi->csum = crc;
	nova_flush_buffer(pi, sizeof(struct nova_inode_ssim), 1);
	return 0;
}

static inline int nova_check_inode_checksum(struct nova_inode_ssim *pi)
{
	u32 crc = 0;

	if (metadata_csum == 0)
		return 0;

	crc = nova_crc32c(~0, (__u8 *)pi,
			(sizeof(struct nova_inode_ssim) - sizeof(__le32)));

	if (pi->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

static inline void nova_update_tail(struct nova_inode_ssim *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->log_tail = new_tail;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}
#endif


static inline struct nova_inode_ssim *nova_get_ssim_by_ino(struct super_block *sb, unsigned long ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_ino_loc_hash *target;
	unsigned int hash_table_num, hash_table_off;
	u64 hash_table_begin;

	hash_table_num = ino / INODE_LOC_HASH_INIT_SIZE;
	hash_table_off = ino % INODE_LOC_HASH_INIT_SIZE;
	hash_table_begin = *(sbi->to_slot_node + hash_table_num);

	if(!hash_table_begin){
		nova_info("Get hash_table_begin err in nova_get_ssim_by_ino!\n");
		return NULL;
	}

	target = (struct nova_ino_loc_hash *)hash_table_begin + hash_table_off;
	return target->pi_ssim_in_hash;
}


static inline int nova_update_ino_loc_hash(struct super_block *sb, unsigned long ino, struct nova_inode_ssim* value)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_ino_loc_hash *target;
	unsigned int hash_table_num, hash_table_off;
	u64 hash_table_begin;

	hash_table_num = ino / INODE_LOC_HASH_INIT_SIZE;
	hash_table_off = ino % INODE_LOC_HASH_INIT_SIZE;
	hash_table_begin = *(sbi->to_slot_node + hash_table_num);

	if(!hash_table_begin){
		*(sbi->to_slot_node + hash_table_num) = (u64)kcalloc(1,
			INODE_LOC_HASH_INIT_SIZE * sizeof(struct nova_ino_loc_hash), GFP_KERNEL);

		if(!(*(sbi->to_slot_node + hash_table_num))){
			nova_info("Extend hash table failure in update_inode_loc_hash_table!\n");
			return -ENOMEM;
		}

		hash_table_begin = *(sbi->to_slot_node + hash_table_num);
	}

	target = (struct nova_ino_loc_hash *)hash_table_begin + hash_table_off;
	target->pi_ssim_in_hash = value;
	return 0;
}


static inline u64 nova_get_reserved_inode_addr(struct super_block *sb,
	u64 inode_number)
{
	return (NOVA_DEF_BLOCK_SIZE_4K * RESERVE_INODE_START) +
			inode_number * NOVA_INODE_RESERVED_SIZE;
}

#if 0
static inline u64 nova_get_alter_reserved_inode_addr(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return nova_get_addr_off(sbi, sbi->replica_reserved_inodes_addr) +
			inode_number * NOVA_INODE_SIZE;
}
#endif


static inline struct nova_inode_reserved *nova_get_reserved_inode(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 addr;

	addr = nova_get_reserved_inode_addr(sb, inode_number);

	return (struct nova_inode_reserved *)(sbi->virt_addr + addr);
}

#if 0
static inline struct nova_inode *
nova_get_alter_reserved_inode(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 addr;

	addr = nova_get_alter_reserved_inode_addr(sb, inode_number);

	return (struct nova_inode *)(sbi->virt_addr + addr);
}
#endif

/* If this is part of a read-modify-write of the inode metadata,
 * nova_memunlock_inode() before calling!
 */
static inline struct nova_inode_reserved *nova_get_inode_by_ino(struct super_block *sb,
						  u64 ino)
{
	if (ino == 0 || ino >= NOVA_NORMAL_INODE_START)
		return NULL;

	return nova_get_reserved_inode(sb, ino);
}


static inline void nova_update_tail_reserved_inode(struct nova_inode_reserved *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->log_tail = new_tail;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}


#if 0
static inline void nova_update_alter_tail(struct nova_inode *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	if (metadata_csum == 0)
		return;

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->alter_log_tail = new_tail;
	nova_flush_buffer(&pi->alter_log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}


static inline void nova_update_alter_tail_reserved_inode(struct nova_inode_reserved *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	if (metadata_csum == 0)
		return;

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->alter_log_tail = new_tail;
	nova_flush_buffer(&pi->alter_log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}
#endif


static inline void nova_update_reserved_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode_reserved *pi,
	struct nova_inode_update *update, int update_alter)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	sih->log_tail = update->tail;
	//sih->alter_log_tail = update->alter_tail;
	nova_update_tail_reserved_inode(pi, update->tail);
	/*
	if (metadata_csum)
		nova_update_alter_tail(pi, update->alter_tail);

	nova_update_inode_checksum(pi);
	if (inode && update_alter)
		nova_update_alter_inode(sb, inode, pi);
		*/
}


int nova_append_ain(struct super_block *sb, struct inode *inode,
	struct nova_ain_loc *si_ain, int move_ain, int *if_gc);

static inline void nova_update_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode_update *update,
	int update_alter)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_ain_loc *pi_ain_loc = &si->ain_loc_and_lock;
	struct nova_inode_ssim *pi_ssim;
	struct nova_inode_reserved *pi_reserved;
	//int ret;
	int if_gc = 0;

	sih->log_tail = update->tail;
	//sih->alter_log_tail = update->alter_tail;

	if(inode->i_ino == 1){
		pi_reserved = nova_get_inode_by_ino(sb, 1);
		nova_update_reserved_inode(sb, inode, pi_reserved, update, update_alter);
	}
	else{
		write_lock(&pi_ain_loc->rblock_instance);
		pi_ssim = pi_ain_loc->ain_location;
		PERSISTENT_BARRIER();

		pi_ssim->log_tail = update->tail;
		pi_ssim->update_times += 1;
		nova_flush_buffer(pi_ssim, CACHELINE_SIZE, 1);
		/*
		if(pi_ssim->update_times > AIN_VALID_THRESHOLD){
			ret = nova_append_ain(sb, inode, pi_ain_loc, 1, &if_gc);
		}
		*/
		if(if_gc == 0)
			write_unlock(&pi_ain_loc->rblock_instance);
	}
	/*
	if (metadata_csum)
		nova_update_alter_tail(pi, update->alter_tail);
		*/
	/*
	nova_update_inode_checksum(pi);
	if (inode && update_alter)
		nova_update_alter_inode(sb, inode, pi);
		*/
}


static inline
struct inode_table *nova_get_inode_table(struct super_block *sb,
	int version, int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int table_start;

	if (cpu >= sbi->cpus)
		return NULL;

	if ((version & 0x1) == 0)
		table_start = INODE_TABLE0_START;
	else
		table_start = INODE_TABLE1_START;

	return (struct inode_table *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * table_start) +
		cpu * CACHELINE_SIZE);
}

static inline unsigned int
nova_inode_blk_shift(struct nova_inode_info_header *sih)
{
	return blk_type_to_shift[sih->i_blk_type];
}

static inline uint32_t nova_inode_blk_size(struct nova_inode_info_header *sih)
{
	return blk_type_to_size[sih->i_blk_type];
}

extern const struct address_space_operations nova_aops_dax;
int nova_init_inode_inuse_list(struct super_block *sb);
extern int nova_init_inode_des_region(struct super_block *sb);// init inode_table
//int nova_get_alter_inode_address(struct super_block *sb, u64 ino,
//	u64 *alter_pi_addr);
unsigned long nova_get_last_blocknr(struct super_block *sb,
	struct nova_inode_info_header *sih);
//int nova_set_blocksize_hint(struct super_block *sb, struct inode *inode,
//	struct nova_inode *pi, loff_t new_size);
extern struct inode *nova_iget(struct super_block *sb, unsigned long ino);
extern struct inode *nova_iget_only_init_lock(struct super_block *sb, unsigned long ino);
extern void nova_evict_inode(struct inode *inode);
extern int nova_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void nova_dirty_inode(struct inode *inode, int flags);
extern int nova_notify_change(struct dentry *dentry, struct iattr *attr);
extern int nova_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags);
extern void nova_set_inode_flags(struct inode *inode, struct nova_inode_complete_entry *pi,
	unsigned int flags);
extern unsigned long nova_find_region(struct inode *inode, loff_t *offset,
		int hole);
int nova_delete_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, bool delete_nvmm,
	bool delete_dead, u64 trasn_id);
u64 nova_new_nova_inode(struct super_block *sb);
extern struct inode *nova_new_vfs_inode(enum nova_new_inode_type,
	struct inode *dir, u64 ino, umode_t mode, size_t size,
	dev_t rdev, const struct qstr *qstr, u64 epoch_id);
#endif