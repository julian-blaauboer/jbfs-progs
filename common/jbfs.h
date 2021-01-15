// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Julian Blaauboer

#ifndef JBFS_PROGS_JBFS_H
#define JBFS_PROGS_JBFS_H

#define JBFS_INODE_SIZE 256
#define JBFS_SB_MAGIC 0x12050109
#define JBFS_GD_MAGIC 0x030f1106

struct jbfs_super_block {
	uint32_t s_magic;
	uint32_t s_log_block_size;
	uint64_t s_flags;
	uint64_t s_num_blocks;
	uint64_t s_num_groups;
	uint32_t s_local_inode_bits;
	uint32_t s_group_size;
	uint32_t s_group_data_blocks;
	uint32_t s_group_inodes;
	uint32_t s_offset_group;
	uint32_t s_offset_inodes;
	uint32_t s_offset_refmap;
	uint32_t s_offset_data;
	uint32_t s_checksum;
} __attribute__((packed));

struct jbfs_group_descriptor {
	uint32_t g_magic;
	uint32_t g_free_inodes;
	uint32_t g_free_blocks;
	uint32_t g_checksum;
} __attribute__((packed));

struct jbfs_inode {
	uint16_t i_mode;
	uint16_t i_nlinks;
	uint32_t i_uid;
	uint32_t i_gid;
	uint32_t i_flags;
	uint64_t i_size;
	uint64_t i_mtime;
	uint64_t i_atime;
	uint64_t i_ctime;
	uint64_t i_extents[12][2];
	uint64_t i_cont;
} __attribute__((packed));

struct jbfs_dirent {
	uint64_t d_ino;
	uint16_t d_size;
	uint8_t d_len;
	char d_name[];
} __attribute__((packed));

#endif
