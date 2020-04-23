#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * build with: gcc -Wall -o dumpify dumpify.c
 */

#define	DKIOC		(0x04 << 8)
#define	DKIOCDUMPINIT	(DKIOC | 28)	/* Dumpify a zvol */
#define	DKIOCDUMPFINI	(DKIOC | 29)	/* Un-Dumpify a zvol */

void usage() {
	printf("Usage: ./dumpify dumpify|undumpify ZVOL_PATH\n");
	exit(1);
}

int main(int argc, char **argv) {
	int fd;
	int ret;
	int num;
	char *file;

	if (argc < 3)
		usage();

	if (strcmp(argv[1], "dumpify") == 0) {
		num = DKIOCDUMPINIT;
	} else if (strcmp(argv[1], "undumpify") == 0) {
		num = DKIOCDUMPFINI;
	} else {
		usage();
	}

	file = argv[2];
	fd = open(file, O_RDWR);
	if (fd < 0 && errno == EPERM)
		fd = open(file, O_RDONLY);
	if (fd < 0) {
		error(1, errno, "Cannot open %s: ", file);
		exit(1);
	}

	ret = ioctl(fd, num);

	if (ret) {
		fprintf(stderr, "Returned %d (errno: %d, \"%m\")\n", ret, errno);
	} else {
		fprintf(stderr, "Returned 0\n");
	}

	close(fd);

	return ret;
}
