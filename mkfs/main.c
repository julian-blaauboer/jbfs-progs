// SPDX-License-Identifier: MIT
// Copyright (C) 2021 Julian Blaauboer

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <uuid/uuid.h>

#include "common/jbfs.h"
#include "version.h"

struct parameters {
	unsigned long flags;
	unsigned int block_size;
	unsigned int group_size;
	unsigned int group_inodes;
	unsigned int groups;
	unsigned int root_mode;
	unsigned int root_uid;
	unsigned int root_gid;
	uint8_t label[48];
	uuid_t uuid;
};

struct sizes {
	unsigned long bitmap;
	unsigned long inodes;
	unsigned long refmap;
	unsigned long data;
};

inline unsigned ilog2(unsigned long x)
{
	unsigned i = 0;
	while (!((x>>i)&1)) i++;
	return i;
}

const char *sanity_check(const struct parameters *params)
{
	errno = EINVAL;

	if (params->block_size < 1024)
		return "Block size too small";
	if (params->block_size > 65536)
		return "Block size too large";
	if (params->block_size & (params->block_size-1))
		return "Block size not power of 2";
	if (params->group_size & (params->group_size-1))
		return "Group size not power of 2";
	if (params->group_inodes < 1)
		return "Too few inodes";
	if (params->root_mode > 0777)
		return "Invalid mode for root directory";

	errno = 0;
	return NULL;
}

unsigned long blocks_needed(unsigned long block_size, unsigned long bytes)
{
	return (bytes + block_size - 1) / block_size;
}

unsigned long calculate_group_size(const struct parameters *params,
				   struct sizes *sizes)
{
	sizes->bitmap =
	    blocks_needed(params->block_size, (params->group_inodes + 7) / 8);
	sizes->inodes =
	    blocks_needed(params->block_size,
			  JBFS_INODE_SIZE * params->group_inodes);
	sizes->refmap = blocks_needed(params->block_size, sizes->data);

	return 1 + sizes->bitmap + sizes->inodes + sizes->refmap + sizes->data;
}

void write_sb(uint8_t *block, const struct parameters *params,
	     const struct sizes *sizes, unsigned groups, unsigned data_blocks)
{
	int offset = params->block_size == 1024;
	struct jbfs_super_block *sb = (struct jbfs_super_block *) (block + !offset*1024);

	sb->s_magic = JBFS_SB_MAGIC;
	sb->s_log_block_size = ilog2(params->block_size);
	sb->s_flags = params->flags;
	sb->s_num_blocks = data_blocks;
	sb->s_num_groups = groups;
	sb->s_local_inode_bits = ilog2(params->group_inodes);
	sb->s_group_size = params->group_size;
	sb->s_group_data_blocks = sizes->data;
	sb->s_group_inodes = params->group_inodes;
	sb->s_offset_group = 1 + offset;
	sb->s_offset_inodes = 1 + sizes->bitmap;
	sb->s_offset_refmap = sb->s_offset_inodes + sizes->inodes;
	sb->s_offset_data = sb->s_offset_refmap + sizes->refmap;
	memcpy(sb->s_label, params->label, sizeof(sb->s_label));
	memcpy(sb->s_uuid, params->uuid, sizeof(sb->s_uuid));
	sb->s_default_root = 1;
	sb->s_checksum = 0;
}

void write_gd(uint8_t *block, const struct parameters *params,
	     const struct sizes *sizes)
{
	struct jbfs_group_descriptor *gd = (struct jbfs_group_descriptor *) block;
	gd->g_magic = JBFS_GD_MAGIC;
	gd->g_free_inodes = params->group_inodes;
	gd->g_free_blocks = sizes->data;
	gd->g_checksum = 0;
}

int write_full(int fd, uint8_t *block, int size)
{
	int offset = 0;
	int written = 0;

	while (size > 0) {
		written = write(fd, block, size);
		if (written == -1)
			return -1;
		offset += written;
		size -= written;
	}

	return 0;
}

int read_full(int fd, uint8_t *block, int size)
{
	int offset = 0;
	int nread = 0;

	while (size > 0) {
		nread = read(fd, block, size);
		if (nread == -1)
			return -1;
		offset += nread;
		size -= nread;
	}

	return 0;
}

int create_root_dir(int fd, uint8_t *block, const struct parameters *params,
		    const struct sizes *sizes)
{
	struct jbfs_group_descriptor *gd;
	struct jbfs_inode *inode;
	struct jbfs_dirent *dot, *dotdot;
	int i;

	/* Re-read first group, decrement inodes and blocks */
	if (read_full(fd, block, params->block_size) == -1)
		return -1;
	if (lseek(fd, -(int)params->block_size, SEEK_CUR) == -1)
		return -1;

	gd = (struct jbfs_group_descriptor *)block;
	gd->g_free_inodes -= 1;
	gd->g_free_blocks -= 1;

	if (write_full(fd, block, params->block_size) == -1)
		return -1;

	/* Mark first inode in use */
	memset(block, 0, params->block_size);
	block[0] = 1;
	if (write_full(fd, block, params->block_size) == -1)
		return -1;

	/* Go to start of inode table */
	if (lseek(fd, params->block_size * (sizes->bitmap - 1), SEEK_CUR) == -1)
		return -1;

	/* Fill root inode */
	inode = (struct jbfs_inode *)block;
	inode->i_mode = S_IFDIR | params->root_mode;
	inode->i_nlinks = 2;
	inode->i_uid = params->root_uid;
	inode->i_gid = params->root_gid;
	inode->i_flags = 0;
	inode->i_size = params->block_size;
	inode->i_mtime = time(NULL) << 10;
	inode->i_atime = inode->i_mtime;
	inode->i_ctime = inode->i_mtime;
	for (i = 0; i < 12; ++i) {
		inode->i_extents[i][0] = 0;
		inode->i_extents[i][1] = 0;
	}
	inode->i_extents[0][0] = (params->block_size == 1024) + 2 +
	                         sizes->bitmap + sizes->inodes + sizes->refmap;
	inode->i_extents[0][1] = inode->i_extents[0][0] + 1;
	inode->i_cont = 0;

	if (write_full(fd, block, params->block_size) == -1)
		return -1;

	/* Go to first refmap block */
	if (lseek(fd, params->block_size * (sizes->inodes - 1), SEEK_CUR) == -1)
		return -1;

	/* Mark first block in use */
	memset(block, 0, params->block_size);
	block[0] = 1;
	if (write_full(fd, block, params->block_size) == -1)
		return -1;

	/* Go to first data block */
	if (lseek(fd, params->block_size * (sizes->refmap - 1), SEEK_CUR) == -1)
		return -1;

	/* Create empty directory, no need to clear block */
	dot = (struct jbfs_dirent *)block;
	dotdot = (struct jbfs_dirent *)(block + 16);

	dot->d_ino = 1;
	dot->d_size = 16;
	dot->d_len = 1;
	dot->d_name[0] = '.';

	dotdot->d_ino = 1;
	dotdot->d_size = params->block_size - 16;
	dotdot->d_len = 2;
	dotdot->d_name[0] = '.';
	dotdot->d_name[1] = '.';

	if (write_full(fd, block, params->block_size) == -1)
		return -1;

	return 0;
}

int format(const char *dev, const struct parameters *params)
{
	uint8_t *block;
	int fd;
	off_t size;
	uint64_t group, groups;
	uint64_t blocks, sb_blocks;
	uint64_t data_blocks = 0;
	uint64_t min_group_size;
	struct sizes sizes;
	const char *reason;

	/* Check whether all values are within bounds */
	reason = sanity_check(params);
	if (reason)
		goto out_no_file;

	/* Check whether everything fits in one group */
	sizes.data = 1;
	min_group_size = calculate_group_size(params, &sizes);
	if (min_group_size > params->group_size) {
		reason = "Group too small";
		errno = EINVAL;
		goto out_no_file;
	}

	/* Calculate number of data blocks that fit in one group */
	sizes.data = params->group_size;
	while (calculate_group_size(params, &sizes) > params->group_size)
		--sizes.data;

	/* Open the device */
	fd = open(dev, O_RDWR);
	if (fd == -1) {
		reason = "Unable to open file";
		goto out_no_file;
	}

	/* Check the size of the device */
	size = lseek(fd, 0, SEEK_END);
	if (size == -1) {
		reason = "Unable to seek to end of dev";
		goto out_no_mem;
	}

	/* Calculate blocks and check whether we have enough */
	sb_blocks = 1024 / params->block_size + 1;
	blocks = size / params->block_size;

	if (blocks < sb_blocks + min_group_size + 1) {
		reason = "Not enough blocks";
		errno = ENOSPC;
		goto out_no_mem;
	}

	/* If we have defined our own number of groups */
	if (params->groups) {
		if (params->group_size * (params->groups - 1) + min_group_size >
		    blocks - sb_blocks) {
			reason = "Too many groups";
			errno = ENOSPC;
			goto out_no_mem;
		} else {
			groups = params->groups;
		}
	} else {
		groups = (blocks - sb_blocks) / params->group_size;
		groups +=
		    (blocks - sb_blocks) % params->group_size >= min_group_size;
	}

	printf("Formatting '%s'\n", dev);
	printf("  %lu blocks, %lu group(s)\n", blocks, groups);

	/* Allocate a buffer that will be reused for every block write */
	block = malloc(params->block_size);
	if (!block) {
		reason = "Memory allocation failed";
		goto out_no_mem;
	}

	/* Go to first group */
	if (lseek(fd, params->block_size * sb_blocks, SEEK_SET) == -1) {
		reason = "Seeking to first group failed";
		goto out;
	}

	/* Fill group descriptors and zero bitmaps and refmaps */
	blocks -= sb_blocks;
	for (group = 0; group < groups; ++group) {
		unsigned i, zblocks;

		if (blocks < params->group_size) {
			sizes.data = blocks;
			while (calculate_group_size(params, &sizes) > blocks)
				--sizes.data;
		}

		write_gd(block, params, &sizes);
		if (write_full(fd, block, params->block_size) == -1) {
			reason = "Writing group descriptor failed";
			goto out;
		}

		memset(block, 0, params->block_size);
		zblocks = sizes.bitmap + sizes.inodes + sizes.refmap;
		for (i = 0; i < zblocks; ++i) {
			if (write_full(fd, block, params->block_size) == -1) {
				reason = "Zeroing out group failed";
				goto out;
			}
		}

		if (lseek(fd, params->block_size * sizes.data, SEEK_CUR) == -1) {
			reason = "Seeking to next group failed";
			goto out;
		}

		blocks -= params->group_size;
		data_blocks += sizes.data;
	}

	/* Write out super */
	write_sb(block, params, &sizes, groups, data_blocks);
	if (lseek(fd, params->block_size * (sb_blocks - 1), SEEK_SET) == -1) {
		reason = "Seeking to superblock failed";
		goto out;
	}
	if (write_full(fd, block, params->block_size) == -1) {
		reason = "Writing superblock failed";
		goto out;
	}

	/* Create root directory as an empty directory */
	if (create_root_dir(fd, block, params, &sizes) == -1) {
		reason = "Creating root directory failed";
		goto out;
	}

 out:
	free(block);
 out_no_mem:
	close(fd);
 out_no_file:
	if (reason) {
		printf("%s: %s\n", dev, reason);
		return -1;
	}
	return 0;
}

void version(void)
{
	printf("mkfs.jbfs (jbfs-tools v" VERSION ")\n");
}

void usage(const char *name)
{
	printf("Usage: %s [options] dev\n", name);
	printf("Options:\n");
	printf("  -b|--block-size SIZE       set block size in bytes (default=4096)\n");
	printf("  -g|--group-size SIZE       set group size in blocks (default=65536)\n");
	printf("  -G|--groups NUM            set number of groups, or 0 for automatic (default=0)\n");
	printf("  -I|--inodes-per-group NUM  set number of inodes per group (default=4096)\n");
	printf("  -L|--label LABEL           set label of filesystem\n");
	printf("  -U|--uuid UUID             set UUID of filesystem\n");
	printf("  -m|--mode OOO              set mode for root directory (default=755)\n");
	printf("  --uid ID                   set UID for root directory (default=0)\n");
	printf("  --gid ID                   set GID for root directory (default=0)\n");
	printf("  -F|--flag FLAG             set flag FLAG\n");
	printf("  -h|--help                  print help and exit\n");
	printf("  -V|--version               print version and exit\n");
}

void int_from_opt(const char *name, unsigned int *num, const char *desc, int b)
{
	char *end;
	*num = strtoul(optarg, &end, b);
	if (!optarg[0] || isspace(optarg[0]) || optarg[0] == '-' ||
	    *end || errno) {
		printf("%s: invalid %s '%s'\n\n", name, desc, optarg);
		usage(name);
		exit(1);
	}
}

int parse_flag(unsigned long *flags, const char *flag)
{
	return -1;
}

int main(int argc, char **argv)
{
	const char *name = argc ? argv[0] : "mkfs.jbfs";
	struct parameters params;

	char *end;
	int c;

	uuid_generate(params.uuid);
	params.block_size = 4096;
	params.group_size = 65536;
	params.group_inodes = 4096;
	params.groups = 0;
	params.root_mode = 0755;
	params.root_uid = 0;
	params.root_gid = 0;
	params.flags = 0;

	memset(params.label, 0, 16);

	struct option long_options[] = {
		{"block-size", required_argument, NULL, 'b'},
		{"inodes-per-group", required_argument, NULL, 'I'},
		{"group-size", required_argument, NULL, 'g'},
		{"groups", required_argument, NULL, 'G'},
		{"label", required_argument, NULL, 'L'},
		{"uuid", required_argument, NULL, 'U'},
		{"mode", required_argument, NULL, 'm'},
		{"uid", required_argument, NULL, 1000},
		{"gid", required_argument, NULL, 1001},
		{"flag", required_argument, NULL, 'F'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0}
	};

	/* Parse options */
	while ((c = getopt_long(argc, argv, "b:I:g:G:L:U:m:F:hV", long_options, NULL)) != -1) {
		switch (c) {
		case 'b':
			int_from_opt(name, &params.block_size, "block size", 0);
			break;
		case 'I':
			int_from_opt(name, &params.group_inodes, "number of inodes per group", 0);
			break;
		case 'g':
			int_from_opt(name, &params.group_size, "group size", 0);
			break;
		case 'G':
			int_from_opt(name, &params.groups, "number of groups", 0);
			break;
		case 'L':
			if (strnlen(optarg, 48 + 2) > 48) {
				printf("%s: label too long '%s'\n\n", name, optarg);
				usage(name);
				return 1;
			}
			strncpy(params.label, optarg, 48);
			break;
		case 'U':
			if (uuid_parse(optarg, params.uuid) == -1) {
				printf("%s: invalid UUID '%s'\n\n", name, optarg);
				usage(name);
				return 1;
			}
			break;
		case 'm':
			int_from_opt(name, &params.root_mode, "root mode", 8);
			break;
		case 1000:
			int_from_opt(name, &params.root_uid, "root UID", 0);
			break;
		case 1001:
			int_from_opt(name, &params.root_gid, "root GID", 0);
			break;
		case 'F':
			if (parse_flag(&params.flags, optarg) == -1) {
				printf("%s: unknown flag '%s'\n\n", name, optarg);
				usage(name);
				return 1;
			}
			break;
		case 'h':
			usage(name);
			return 0;
		case 'V':
			version();
			return 0;
		case '?':
			printf("\n");
			usage(name);
			return 1;
		}
	}

	/* If there are no positional arguments, print version and help */
	if (optind >= argc) {
		version();
		printf("\n");
		usage(name);
		return 0;
	}

	/*
	 * I haven't decided how to handle labels/UUIDs with multiple
	 * devices yet. For now, I've simply limited mkfs.jbfs to format
	 * only one device at a time.
	 */
	if (format(argv[optind], &params) == -1)
		perror(argv[optind]);

	return 0;
}
