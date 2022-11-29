#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lib/packet_fields.h"
#include <unistd.h>

enum return_codes {
	SUCCESS = 0,
	INVOCATION_ERROR = 1,
	FILE_ERROR = 2,
	MEMORY_ERROR = 3
};

static struct {
	bool little_endian;
} options = { false };

int main(int argc, char *argv[])
{
	int opt;
	// Option-handling syntax borrowed from Liam Echlin in
	// getopt-demo.c
	while ((opt = getopt(argc, argv, "b")) != -1) {

		switch (opt) {
			// a[scii sort]
		case 'b':
			options.little_endian = true;
			break;
		case '?':
			return (INVOCATION_ERROR);
		}
	}
	char *invocation_name = argv[0];
	argc -= optind;
	argv += optind;

	if (argc == 0 || argc > 1) {
		printf("Usage: %s [OPTION]... [FILE]\n", invocation_name);
		return (INVOCATION_ERROR);
	}

	FILE *fo = fopen(argv[0], "r");
	if (!fo) {
		fprintf(stderr, "%s could not be opened", argv[0]);
		perror(" \b");
		return (FILE_ERROR);
	}
	// TODO: While loop that re-defines the packet fields each loop and
	// only writes to file if reaches the end without continue
	// TODO: parse_packet_contents(fo);

	fclose(fo);
	return (0);
}
