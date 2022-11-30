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
void parse_packet_contents(bool little_endian, FILE * input_fo,
			   FILE * output_fo);
int parse_message(struct zerg_header *zh, FILE * input_fo);
int parse_status(struct zerg_header *zh, FILE * input_fo);
void set_static_headers(struct ethernet_header *eh, struct ip_header *ih,
			struct udp_header *uh);
void set_length_fields(bool little_endian, const uint16_t len,
		       struct packet_header *ph, struct ip_header *ih,
		       struct udp_header *uh, struct zerg_header *zh);
void write_headers(bool *file_header_present, bool little_endian,
		   struct packet_header *ph, struct ethernet_header *eh,
		   struct ip_header *ih, struct udp_header *uh,
		   struct zerg_header *zh, FILE * output_fo);
int skip_to_next_packet(FILE * input_fo);
// TODO: Add to lib later

float reverse_float(const float num);

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

	if (argc != 2) {
		printf("Usage: %s [OPTION]... [INFILE] [OUTFILE]\n",
		       invocation_name);
		return (INVOCATION_ERROR);
	}

	FILE *input_fo = fopen(argv[0], "r");
	if (!input_fo) {
		fprintf(stderr, "%s could not be opened", argv[0]);
		perror(" \b");
		return (FILE_ERROR);
	}
	FILE *output_fo = fopen(argv[1], "w");
	if (!output_fo) {
		fprintf(stderr, "%s could not be opened", argv[1]);
		perror(" \b");
		return (FILE_ERROR);
	}
	parse_packet_contents(options.little_endian, input_fo, output_fo);

	fclose(input_fo);
	fclose(output_fo);
	return (0);
}

void parse_packet_contents(bool little_endian, FILE * input_fo,
			   FILE * output_fo)
{
	bool file_header_present = false;
	char *line_buf = NULL;
	size_t buf_size = 0;
	int eof_flag = 0;

	for (;;) {
		// TODO: Check all return codes from skip_to_next_packet
		struct packet_header ph = { 0, 0, 0, 0 };
		struct ethernet_header eh = { 0, 0, 0 };
		struct ip_header ih = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		struct udp_header uh = { 0, 0, 0, 0 };
		struct zerg_header zh = { 0, 0, 0, 0, 0, 0, 0 };
		set_static_headers(&eh, &ih, &uh);

		char *err = '\0';

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			break;
		}
		char *word = strtok(line_buf, ":");
		if (strcmp(word, "Version") != 0) {
			fprintf(stderr,
				"Expected \"Version:\"; received \"%s\"\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing version number\n");
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		zh.zerg_version = strtol(word, &err, 10);
		if (*err) {
			fprintf(stderr,
				"Expected version number; received \"%s\"\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Sequence") != 0) {
			fprintf(stderr,
				"Expected \"Sequence:\"; received \"%s\"\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing sequence number\n");
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		zh.zerg_sequence = htonl(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr,
				"Expected sequence number; received %s\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "From") != 0) {
			printf("Expected \"From:\"; received \"%s\"", word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing Source ID\n");
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		zh.zerg_src = htons(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr, "Expected source ID; received \"%s\"\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			break;
		}
		word = strtok(line_buf, ":");
		if (!word) {
			printf("Expected \"To:\"; received \"%s\"", word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing destination ID\n");
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}
		zh.zerg_dst = htons(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr,
				"Expected destination ID; received \"%s\"\n",
				word);
			if ((skip_to_next_packet(input_fo))) {
				continue;
			} else {
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
		}

		unsigned int offset = ftell(input_fo);
		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			break;
		}
		fseek(input_fo, offset, SEEK_SET);
		word = strtok(line_buf, ":");
		if (strcmp(word, "Message") == 0) {
			// Case: Message payload
			zh.zerg_packet_type = 0;
			if ((!parse_message(&zh, input_fo))) {
				if ((skip_to_next_packet(input_fo))) {
					continue;
				} else {
					if (line_buf) {
						free(line_buf);
					}
					return;
				}
			}
			char *message =
			    ((struct zerg_message *)zh.zerg_payload)->message;
			if (message[0] == ' ') {
				// Remove leading space if present
				message = message + 1;
			}
			uint16_t len = strlen(message);
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite(message, len, 1, output_fo);
			free(((struct zerg_message *)zh.zerg_payload)->message);
			free(zh.zerg_payload);
		} else if (strcmp(word, "Max Hit Points") == 0) {
			// Case: Status payload
			zh.zerg_packet_type = 1;
			if ((!parse_status(&zh, input_fo))) {
				if ((skip_to_next_packet(input_fo))) {
					continue;
				} else {
					if (line_buf) {
						free(line_buf);
					}
					return;
				}
			}
			char *name =
			    ((struct zerg_status *)zh.zerg_payload)->name;
			if (name[0] == ' ') {
				name = name + 1;
			}
			uint16_t len =
			    strlen(name) + sizeof(struct zerg_status) -
			    sizeof((struct zerg_status *) zh.zerg_payload)->
			    name;
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite((struct zerg_status *)zh.zerg_payload,
			       len - strlen(name), 1, output_fo);
			fwrite(name, strlen(name), 1, output_fo);
			free(((struct zerg_status *)zh.zerg_payload)->name);
			free(zh.zerg_payload);
		} else if (strcmp(word, "Command") == 0) {
			puts("Command payload input_found.");
		} else if (strcmp(word, "Latitude") == 0) {
			puts("GPS payload input_found.");
		} else {
			skip_to_next_packet(input_fo);
			if (line_buf) {
				free(line_buf);
			}
			continue;
		}
		skip_to_next_packet(input_fo);
	}

	if (line_buf) {
		free(line_buf);
	}
	return;
}

void write_headers(bool *file_header_present, bool little_endian,
		   struct packet_header *ph, struct ethernet_header *eh,
		   struct ip_header *ih, struct udp_header *uh,
		   struct zerg_header *zh, FILE * output_fo)
{
	if (!*file_header_present) {
		struct pcap_header fh;
		generate_file_header(little_endian, &fh);
		*file_header_present = true;
		fwrite(&fh, sizeof(fh), 1, output_fo);
	}
	fwrite(ph, sizeof(*ph), 1, output_fo);
	fwrite(eh, sizeof(*eh), 1, output_fo);
	fwrite(ih, sizeof(*ih), 1, output_fo);
	fwrite(uh, sizeof(*uh), 1, output_fo);
	fwrite(zh, sizeof(*zh) - sizeof(zh->zerg_payload), 1, output_fo);
}

void set_static_headers(struct ethernet_header *eh, struct ip_header *ih,
			struct udp_header *uh)
{
	uint16_t ethertype = 0x0800;	// IPv4 ethertype
	eh->eth_ethernet_type = htons(ethertype);
	uint16_t dst_port = 3751;	// Default zerg port
	uh->udp_dst_port = htons(dst_port);
	ih->ip_version = 4;	// IPv4
	ih->ip_header_length = 5;	// Min IPv4 header length

	return;
}

void set_length_fields(bool little_endian, const uint16_t len,
		       struct packet_header *ph, struct ip_header *ih,
		       struct udp_header *uh, struct zerg_header *zh)
{
	zh->zerg_len = htons(len) << 8;	// Bit shifting 16 bit int to fit
	// leftmost part of the 24 bit field.
	uh->udp_len = htons(len + sizeof(struct udp_header));
	ih->ip_packet_length =
	    htons(len + sizeof(struct udp_header) + sizeof(struct ip_header));
	ih->ip_protocol = 17;	// UDP
	if (!little_endian) {
		ph->untruncated_len =
		    htons(len + sizeof(struct udp_header) +
			  sizeof(struct ip_header) +
			  sizeof(struct ethernet_header));
	} else {
		ph->untruncated_len =
		    len + sizeof(struct udp_header) + sizeof(struct ip_header) +
		    sizeof(struct ethernet_header);

	}
	ph->data_capture_len = ph->untruncated_len;

	return;
}

int parse_message(struct zerg_header *zh, FILE * input_fo)
{
	char *line_buf = NULL;
	size_t buf_size = 0;
	char *word;

	getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
	word = strtok(NULL, "\n");
	if (!word) {
		fprintf(stderr, "Missing Message\n");
		free(line_buf);
		return (0);
	}
	// TODO: Error handle malloc calls
	char *message = malloc(strlen(word) + 1);
	strncpy(message, word, strlen(word));
	message[strlen(word)] = '\0';
	struct zerg_message *zm = malloc(sizeof(*zm));

	zm->message = message;
	zh->zerg_payload = zm;
	if (line_buf) {
		free(line_buf);
	}

	return (1);
}

int parse_status(struct zerg_header *zh, FILE * input_fo)
{
	int eof_flag = 0;
	char *line_buf = NULL;
	size_t buf_size = 0;
	char *word = '\0';
	char *err = '\0';

	struct zerg_status *zs = malloc(sizeof(*zs));

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zs);
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Max Hit Points") != 0) {
		fprintf(stderr, "Expected \"Max Hit Points:\"; received %s\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Max Hit Points Value\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	zs->max_hp = htonl(strtol(word, &err, 10) << 8);
	if (*err) {
		fprintf(stderr,
			"Expected Max Hit Points value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zs);
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Current Hit Points") != 0) {
		fprintf(stderr,
			"Expected \"Current Hit Points:\"; received %s\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Current Hit Points Value\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	zs->current_hp = htonl(strtol(word, &err, 10) << 8);
	if (*err) {
		fprintf(stderr,
			"Expected Current Hit Points value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zs);
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Armor") != 0) {
		fprintf(stderr, "Expected \"Armor:\"; received %s\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Armor Value\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	zs->armor = htonl(strtol(word, &err, 10) << 24);
	if (*err) {
		fprintf(stderr, "Expected Armor value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zs);
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Type") != 0) {
		fprintf(stderr, "Expected \"Type:\"; received %s\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Zerg Type\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	if (strcmp(word, "Overmind") == 0) {
		zs->type = 0;
	} else if (strcmp(word, "Larva") == 0) {
		zs->type = 1;
	} else if (strcmp(word, "Cerebrate") == 0) {
		zs->type = 2;
	} else if (strcmp(word, "Overlord") == 0) {
		zs->type = 3;
	} else if (strcmp(word, "Queen") == 0) {
		zs->type = 4;
	} else if (strcmp(word, "Drone") == 0) {
		zs->type = 5;
	} else if (strcmp(word, "Zergling") == 0) {
		zs->type = 6;
	} else if (strcmp(word, "Lurker") == 0) {
		zs->type = 7;
	} else if (strcmp(word, "Broodling") == 0) {
		zs->type = 8;
	} else if (strcmp(word, "Hydralisk") == 0) {
		zs->type = 9;
	} else if (strcmp(word, "Guardian") == 0) {
		zs->type = 10;
	} else if (strcmp(word, "Scourge") == 0) {
		zs->type = 11;
	} else if (strcmp(word, "Ultralisk") == 0) {
		zs->type = 12;
	} else if (strcmp(word, "Mutalisk") == 0) {
		zs->type = 13;
	} else if (strcmp(word, "Defiler") == 0) {
		zs->type = 14;
	} else if (strcmp(word, "Devourer") == 0) {
		zs->type = 15;
	} else {
		fprintf(stderr, "Expected Zerg Type; received %s\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zs);
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Max Speed") != 0) {
		fprintf(stderr, "Expected \"Max Speed:\"; received %s\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Max Speed Value\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	zs->max_speed = reverse_float(strtof(word, &err));
	if (*err) {
		fprintf(stderr, "Expected Max Speed value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zs);
		return (0);
	}

	getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
	if (strcmp(word, "Name") != 0) {
		fprintf(stderr, "Expected \"Name:\"; received %s\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, "\n");
	if (!word) {
		fprintf(stderr, "Missing Zerg Name\n");
		free(line_buf);
		free(zs);
		return (0);
	}
	// TODO: Error handle malloc calls
	char *name = malloc(strlen(word) + 1);
	strncpy(name, word, strlen(word));
	name[strlen(word)] = '\0';
	zs->name = name;
	zh->zerg_payload = zs;
	if (line_buf) {
		free(line_buf);
	}
	return (1);
}

int skip_to_next_packet(FILE * input_fo)
// Sets the file pointer to the next instance of the word "Version", 
// which is the first word in any given packet's output from decode
{
	char *line_buf = NULL;
	size_t buf_size = 0;

	for (;;) {
		unsigned int offset = ftell(input_fo);
		if ((getline(&line_buf, &buf_size, input_fo) != -1)) {
			if (!strcmp(strtok(line_buf, ":"), "Version")) {
				fseek(input_fo, offset, SEEK_SET);
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

void generate_file_header(bool little_endian, struct pcap_header *fh)
{
	uint32_t magic_number = 0xA1B2C3D4;	// .pcap magic number
	uint16_t major_version = 2;
	uint16_t minor_version = 4;
	uint32_t link_type = 1;	// Ethernet

	if (little_endian) {
		fh->magic_number = magic_number;
		fh->major_version = major_version;
		fh->minor_version = minor_version;
		fh->link_layer_type = link_type;
	} else {
		fh->magic_number = htonl(magic_number);
		fh->major_version = htons(major_version);
		fh->minor_version = htons(minor_version);
		fh->link_layer_type = htonl(link_type);
	}
	fh->gmt_offset = 0;
	fh->accuracy_delta = 0;
	fh->max_capture_len = 0;

	return;
}

float reverse_float(const float num)
// Reverses the byte order of the passed float. Returns the 
// reversed float.
// Syntax taken from Gregor Brandt: https://stackoverflow.com/a/2782742.
{
	float ret_val;
	char *float_to_convert = (char *)&num;
	char *return_float = (char *)&ret_val;

	return_float[0] = float_to_convert[3];
	return_float[1] = float_to_convert[2];
	return_float[2] = float_to_convert[1];
	return_float[3] = float_to_convert[0];

	return (ret_val);
}
