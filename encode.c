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

int parse_packet_contents(FILE * fo);
int skip_to_next_packet(FILE * fo);

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

int parse_packet_contents(FILE * fo)
{
	char *line_buf = NULL;
	size_t buf_size = 0;

	getline(&line_buf, &buf_size, fo);
	char *word = strtok(line_buf, ":");
	//printf("%s <--- string\n", word);
	if (strcmp(word, "Version") != 0) {
		skip_to_next_packet(fo);
	}
	word = strtok(NULL, " \n");
	// Set Version field in packet  

	getline(&line_buf, &buf_size, fo);
	strtok(line_buf, ":");
	if (strcmp(word, "Sequence") != 0) {
		skip_to_next_packet(fo);
	}
	// Set sequence num in packet

	getline(&line_buf, &buf_size, fo);
	strtok(line_buf, ":");
	if (strcmp(word, "From") != 0) {
		skip_to_next_packet(fo);
	}
	// Set From num in packet

	getline(&line_buf, &buf_size, fo);
	strtok(line_buf, ":");
	if (strcmp(word, "To") != 0) {
		skip_to_next_packet(fo);
	}
	// Set To num in packet

	getline(&line_buf, &buf_size, fo);
	strtok(line_buf, ":");
	if (strcmp(word, "Message") == 0) {
		// Parse Message packet
	} else if (strcmp(word, "Command") == 0) {
		// Parse Command packet
	} else if (strcmp(word, "Max Hit Points") == 0) {
		// Parse Status packet
	} else if (strcmp(word, "Latitude") == 0) {
		// Parse GPS packet
	} else {
		skip_to_next_packet(fo);
	}

	if (line_buf) {
		free(line_buf);
	}
	return (1);
}

int skip_to_next_packet(FILE * fo)
{
	char *line_buf = NULL;
	size_t buf_size = 0;

	for (;;) {
		unsigned int offset = ftell(fo);
		if ((getline(&line_buf, &buf_size, fo) != -1)) {
			if (!strcmp(strtok(line_buf, " :\n"), "Version")) {
				fseek(fo, offset, SEEK_SET);
				return (1);
			}
			continue;
		}
		break;
	}

	return (0);
}
