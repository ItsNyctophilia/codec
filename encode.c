#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lib/packet_fields.h"
#include <arpa/inet.h>
#include <unistd.h>

enum return_codes {
	SUCCESS = 0,
	INVOCATION_ERROR = 1,
	FILE_ERROR = 2,
	MEMORY_ERROR = 3
};

static struct {
	bool little_endian;
} options = { true };

void generate_file_header(bool little_endian, struct pcap_header *ph);
int parse_packet_contents(bool little_endian, FILE * fo);
int skip_to_next_packet(FILE * fo);

bool file_header_present = false;

int main(int argc, char *argv[])
{
	int opt;
	// Option-handling syntax borrowed from Liam Echlin in
	// getopt-demo.c
	while ((opt = getopt(argc, argv, "b")) != -1) {

		switch (opt) {
			// a[scii sort]
		case 'b':
			options.little_endian = false;
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

	//do {
	//      int exit_flag = false;
	int exit_flag = parse_packet_contents(options.little_endian, fo);

	//} while (exit_flag = false);

	fclose(fo);
	return (0);
}

int parse_packet_contents(bool little_endian, FILE * fo)
{
	char *line_buf = NULL;
	size_t buf_size = 0;
	int eof_flag = 0;

	for (;;) {

		eof_flag = getline(&line_buf, &buf_size, fo);
		if (eof_flag == -1) {
			break;
		}
		char *word = strtok(line_buf, ":");
		//printf("%s <--- string\n", word);
		if (strcmp(word, "Version") != 0) {
			printf("word: %s", word);
			skip_to_next_packet(fo);
		}
		word = strtok(NULL, " \n");
		// Set Version field in packet  

		eof_flag = getline(&line_buf, &buf_size, fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Sequence") != 0) {
			printf("word: %s", word);
			skip_to_next_packet(fo);
		}
		// Set sequence num in packet

		eof_flag = getline(&line_buf, &buf_size, fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "From") != 0) {
			printf("word: %s", word);
			skip_to_next_packet(fo);
		}
		// Set From num in packet

		eof_flag = getline(&line_buf, &buf_size, fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "To") != 0) {
			printf("word: %s", word);
			skip_to_next_packet(fo);
		}
		// Set To num in packet

		eof_flag = getline(&line_buf, &buf_size, fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Message") == 0) {
			puts("Message payload found.");
		} else if (strcmp(word, "Command") == 0) {
			puts("Command payload found.");
		} else if (strcmp(word, "Max Hit Points") == 0) {
			puts("Status payload found.");
		} else if (strcmp(word, "Latitude") == 0) {
			puts("GPS payload found.");
		} else {
			skip_to_next_packet(fo);
			if (line_buf) {
				free(line_buf);
			}
			continue;
		}
		if (!file_header_present) {
			struct pcap_header ph;
			generate_file_header(little_endian, &ph);
			file_header_present = true;
			printf("%X\n", ph.magic_number);
		}
		skip_to_next_packet(fo);
	}

	if (line_buf) {
		free(line_buf);
	}
	return (1);
}

int skip_to_next_packet(FILE * fo)
// Sets the file pointer to the next instance of the word "Version", 
// which is the first word in any given packet's output from decode
{
	char *line_buf = NULL;
	size_t buf_size = 0;

	for (;;) {
		unsigned int offset = ftell(fo);
		if ((getline(&line_buf, &buf_size, fo) != -1)) {
			if (!strcmp(strtok(line_buf, ":"), "Version")) {
				fseek(fo, offset, SEEK_SET);
				if (line_buf) {
					free(line_buf);
				}
				return (1);
			}
			continue;
		}
		if (line_buf) {
			free(line_buf);
			break;
		}
	}
	return (0);
}

void generate_file_header(bool little_endian, struct pcap_header *ph)
{
	uint32_t magic_number = 0xA1B2C3D4;
	uint16_t major_version = 2;
	uint16_t minor_version = 4;
	uint32_t link_type = 1;

	if (little_endian) {
		ph->magic_number = magic_number;
		ph->major_version = major_version;
		ph->minor_version = minor_version;
		ph->link_layer_type = link_type;
	} else {
		ph->magic_number = htonl(magic_number);
		ph->major_version = htons(major_version);
		ph->minor_version = htons(minor_version);
		ph->link_layer_type = htonl(link_type);
	}
	ph->gmt_offset = 0;
	ph->accuracy_delta = 0;
	ph->max_capture_len = 0;

	return;
}
