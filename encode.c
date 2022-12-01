#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lib/shared_fields.h"
#include <arpa/inet.h>
#include <unistd.h>

static struct {
	bool little_endian;
} options = { true };

void generate_file_header(bool little_endian, struct pcap_header *ph);
void parse_packet_contents(bool little_endian, FILE * input_fo,
			   FILE * output_fo);
int parse_message(struct zerg_header *zh, FILE * input_fo);
int parse_status(struct zerg_header *zh, FILE * input_fo);
int parse_command(struct zerg_header *zh, FILE * input_fo);
int parse_gps(struct zerg_header *zh, FILE * input_fo);
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
	FILE *output_fo = fopen(argv[1], "wb");
	if (!output_fo) {
		fprintf(stderr, "%s could not be opened", argv[1]);
		perror(" \b");
		return (FILE_ERROR);
	}

	parse_packet_contents(options.little_endian, input_fo, output_fo);

	fclose(input_fo);
	fclose(output_fo);
	return (SUCCESS);
}

void parse_packet_contents(bool little_endian, FILE * input_fo,
			   FILE * output_fo)
// Iterates through each line of the given input file, compares lines
// of human-readable text to expected inputs and, upon validation,
// writes the encodable packets to the given output file.
{
	bool file_header_present = false;
	char *line_buf = NULL;
	size_t buf_size = 0;
	int eof_flag = 0;

	for (;;) {
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
			uint16_t len;
			char *message;
			if ((parse_message(&zh, input_fo)) == -2) {
				// Case: Empty message
				len = 0;
			} else {
				message =
				    ((struct zerg_message *)zh.
				     zerg_payload)->message;
				if (message[0] == ' ') {
					// Remove leading space if present
					message = message + 1;
				}
				len = strlen(message);
			}
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite(message, len, 1, output_fo);
			if (ntohs(ih.ip_packet_length) + 14 < 60) {
				// Add buffer required by ethernet header
				// if packet length too short
				int padding_difference =
				    60 - (ntohs(ih.ip_packet_length) + 14);
				for (int i = 0; i < padding_difference; ++i) {
					char null_buffer[] = "\0";
					fwrite(null_buffer, 1, 1, output_fo);
				}
			}
			free(((struct zerg_message *)zh.zerg_payload)->message);
			free(zh.zerg_payload);
		} else if (strcmp(word, "Max Hit Points") == 0) {
			// Case: Status payload
			zh.zerg_packet_type = 1;
			uint16_t len;
			uint16_t name_len;
			char *name;
			int return_value;
			return_value = parse_status(&zh, input_fo);
			if (return_value == 0) {
				// Case: Invalid packet
				if ((skip_to_next_packet(input_fo))) {
					continue;
				} else {
					if (line_buf) {
						free(line_buf);
					}
					return;
				}
			} else if (return_value == -1) {
				// Case: Unexpected EOF
				if (line_buf) {
					free(line_buf);
				}
				return;
			} else if (return_value == -2) {
				// Case: Empty message
				len =
				    sizeof(struct zerg_status) -
				    sizeof((struct zerg_status *)
					   zh.zerg_payload)->name;;
				name_len = 0;
			} else {
				name =
				    ((struct zerg_status *)zh.
				     zerg_payload)->name;
				if (name[0] == ' ') {
					name = name + 1;
				}
				len =
				    strlen(name) + sizeof(struct zerg_status) -
				    sizeof((struct zerg_status *)
					   zh.zerg_payload)->name;
				name_len = strlen(name);
			}
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite((struct zerg_status *)zh.zerg_payload,
			       len - name_len, 1, output_fo);
			fwrite(name, name_len, 1, output_fo);
			if (ntohs(ih.ip_packet_length) + 14 < 60) {
				// Add buffer required by ethernet header
				// if packet length too short
				int padding_difference =
				    60 - (ntohs(ih.ip_packet_length) + 14);
				for (int i = 0; i < padding_difference; ++i) {
					char null_buffer[] = "\0";
					fwrite(null_buffer, 1, 1, output_fo);
				}
			}
			free(((struct zerg_status *)zh.zerg_payload)->name);
			free(zh.zerg_payload);
		} else if (strcmp(word, "Command") == 0) {
			// Case: Command payload
			zh.zerg_packet_type = 2;
			int return_value = parse_command(&zh, input_fo);
			if (return_value == 0) {
				if ((skip_to_next_packet(input_fo))) {
					// Case: Invalid packet
					continue;
				} else {
					if (line_buf) {
						free(line_buf);
					}
					return;
				}
			} else if (return_value == -1) {
				// Case: Unexpected EOF
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
			uint16_t len;
			if (ntohs
			    (((struct zerg_command *)zh.zerg_payload)->
			     command) % 2 == 0) {
				len = 2;	// Size of command payload for even commands
			} else {
				len = 8;	// Size of command payload for odd commands
			}
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite((struct zerg_command *)zh.zerg_payload, len, 1,
			       output_fo);
			if (ntohs(ih.ip_packet_length) + 14 < 60) {
				int padding_difference =
				    60 - (ntohs(ih.ip_packet_length) + 14);
				for (int i = 0; i < padding_difference; ++i) {
					char null_buffer[] = "\0";
					fwrite(null_buffer, 1, 1, output_fo);
				}
			}
			free(zh.zerg_payload);
		} else if (strcmp(word, "Latitude") == 0) {
			zh.zerg_packet_type = 3;
			uint16_t len = 32;
			int return_value;
			return_value = parse_gps(&zh, input_fo);
			if (return_value == 0) {
				if ((skip_to_next_packet(input_fo))) {
					// Case: Invalid packet
					continue;
				} else {
					if (line_buf) {
						free(line_buf);
					}
					return;
				}
			} else if (return_value == -1) {
				// Case: Unexpected EOF
				if (line_buf) {
					free(line_buf);
				}
				return;
			}
			set_length_fields(little_endian,
					  sizeof(zh) - sizeof(zh.zerg_payload) +
					  len, &ph, &ih, &uh, &zh);
			write_headers(&file_header_present, little_endian, &ph,
				      &eh, &ih, &uh, &zh, output_fo);
			fwrite((struct zerg_gps *)zh.zerg_payload, len, 1,
			       output_fo);
			if (ntohs(ih.ip_packet_length) + 14 < 60) {
				int padding_difference =
				    60 - (ntohs(ih.ip_packet_length) + 14);
				for (int i = 0; i < padding_difference; ++i) {
					char null_buffer[] = "\0";
					fwrite(null_buffer, 1, 1, output_fo);
				}
			}
			free(zh.zerg_payload);
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

	struct zerg_message *zm = malloc(sizeof(*zm));
	if (!zm) {
		fprintf(stderr, "Memory allocation error.\n");
		exit(MEMORY_ERROR);
	}

	getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
	word = strtok(NULL, "\n");
	if (!word) {
		// Case: empty message
		zh->zerg_payload = zm;
		zm->message = NULL;
		free(line_buf);
		return (-2);
	}
	char *message = malloc(strlen(word) + 1);
	if (!message) {
		fprintf(stderr, "Memory allocation error.\n");
		free(line_buf);
		free(zm);
		exit(MEMORY_ERROR);
	}
	strncpy(message, word, strlen(word));
	message[strlen(word)] = '\0';

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
	char *word;
	char *err = '\0';

	struct zerg_status *zs = malloc(sizeof(*zs));
	if (!zs) {
		fprintf(stderr, "Memory allocation error.\n");
		exit(MEMORY_ERROR);
	}

	eof_flag = getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
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
		fprintf(stderr,
			"Unexpected EOF; expected \"Current Hit Points:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Current Hit Points") != 0) {
		fprintf(stderr,
			"Expected \"Current Hit Points:\"; received \"%s\"\n",
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
		fprintf(stderr, "Unexpected EOF; expected \"Armor:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Armor") != 0) {
		fprintf(stderr, "Expected \"Armor:\"; received \"%s\"\n", word);
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
		fprintf(stderr, "Unexpected EOF; expected \"Type:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Type") != 0) {
		fprintf(stderr, "Expected \"Type:\"; received \"%s\"\n", word);
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
		fprintf(stderr, "Expected Zerg Type; received \"%s\"\n", word);
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
		fprintf(stderr, "Unexpected EOF; expected \"Max Speed:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Max Speed") != 0) {
		fprintf(stderr, "Expected \"Max Speed:\"; received \"%s\"\n",
			word);
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
		fprintf(stderr, "Expected \"Name:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zs);
		return (0);
	}
	word = strtok(NULL, "\n");
	if (!word) {
		// Case: empty message
		zh->zerg_payload = zs;
		zs->name = NULL;
		free(line_buf);
		return (-2);
	}
	char *name = malloc(strlen(word) + 1);
	if (!name) {
		fprintf(stderr, "Memory allocation error.\n");
		free(line_buf);
		free(zs);
		exit(MEMORY_ERROR);
	}
	strncpy(name, word, strlen(word));
	name[strlen(word)] = '\0';
	zs->name = name;
	zh->zerg_payload = zs;
	if (line_buf) {
		free(line_buf);
	}
	return (1);
}

int parse_command(struct zerg_header *zh, FILE * input_fo)
{
	int eof_flag = 0;
	char *line_buf = NULL;
	size_t buf_size = 0;
	char *word;
	char *err = '\0';

	struct zerg_command *zc = malloc(sizeof(*zc));
	if (!zc) {
		fprintf(stderr, "Memory allocation error.\n");
		exit(MEMORY_ERROR);
	}

	getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Command\n");
		free(line_buf);
		free(zc);
		return (0);
	}
	uint16_t command;
	if (strcmp(word, "GET_STATUS") == 0) {
		command = 0;
		zc->command = htons(command);
	} else if (strcmp(word, "GOTO") == 0) {
		command = 1;
		zc->command = htons(command);
	} else if (strcmp(word, "GET_GPS") == 0) {
		command = 2;
		zc->command = htons(command);
	} else if (strcmp(word, "RETURN") == 0) {
		command = 4;
		zc->command = htons(command);
	} else if (strcmp(word, "SET_GROUP") == 0) {
		command = 5;
		zc->command = htons(command);
	} else if (strcmp(word, "STOP") == 0) {
		command = 6;
		zc->command = htons(command);
	} else if (strcmp(word, "REPEAT") == 0) {
		command = 7;
		zc->command = htons(command);
	} else {
		fprintf(stderr, "Expected Command; received \"%s\"\n", word);
		free(line_buf);
		free(zc);
		return (0);
	}
	if (command % 2 == 0) {
		zh->zerg_payload = zc;
		if (line_buf) {
			free(line_buf);
		}
		return (1);
	} else if (command == 1) {
		// Case: GOTO Payload
		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			if (line_buf) {
				free(line_buf);
			}
			free(zc);
			fprintf(stderr,
				"Unexpected EOF; expected \"Bearing:\"\n");
			return (-1);
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Bearing") != 0) {
			fprintf(stderr,
				"Expected \"Bearing:\"; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing Bearing Value\n");
			free(line_buf);
			free(zc);
			return (0);
		}
		float bearing = reverse_float(strtof(word, &err));
		zc->parameter_2f = bearing;
		if (*err) {
			fprintf(stderr,
				"Expected Bearing value; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			if (line_buf) {
				free(line_buf);
			}
			free(zc);
			fprintf(stderr,
				"Unexpected EOF; expected \"Distance:\"\n");
			return (-1);
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Distance") != 0) {
			fprintf(stderr,
				"Expected \"Distance:\"; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing Distance Value\n");
			free(line_buf);
			free(zc);
			return (0);
		}
		zc->parameter_1 = htons(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr,
				"Expected Distance value; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		zh->zerg_payload = zc;
		if (line_buf) {
			free(line_buf);
		}
		return (1);

	} else if (command == 5) {
		// Case: SET_GROUP Payload
		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			if (line_buf) {
				free(line_buf);
			}
			free(zc);
			fprintf(stderr,
				"Unexpected EOF; expected \"Action:\"\n");
			return (-1);
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Action") != 0) {
			fprintf(stderr,
				"Expected \"Action:\"; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		word = strtok(NULL, "\n");
		if (word[0] == ' ') {
			// Remove leading space if present
			word = word + 1;
		}
		if (!word) {
			fprintf(stderr, "Missing Action\n");
			free(line_buf);
			free(zc);
			return (0);
		}
		if (strcmp(word, "Add to") == 0) {
			zc->parameter_1 = 1;
		} else if (strcmp(word, "Remove from") == 0) {
			zc->parameter_1 = 0;
		} else {
			fprintf(stderr,
				"Expected Action to take; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			if (line_buf) {
				free(line_buf);
			}
			free(zc);
			fprintf(stderr,
				"Unexpected EOF; expected \"Group:\"\n");
			return (-1);
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Group") != 0) {
			fprintf(stderr,
				"Expected \"Group:\"; received \"%s\"\n", word);
			free(line_buf);
			free(zc);
			return (0);
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing Group ID\n");
			free(line_buf);
			free(zc);
			return (0);
		}
		zc->parameter_2i = htonl(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr, "Expected Group ID; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		if (line_buf) {
			free(line_buf);
		}
		zh->zerg_payload = zc;
		return (1);
	} else if (command == 7) {
		zc->parameter_1 = 0;

		eof_flag = getline(&line_buf, &buf_size, input_fo);
		if (eof_flag == -1) {
			if (line_buf) {
				free(line_buf);
			}
			free(zc);
			fprintf(stderr,
				"Unexpected EOF; expected \"Sequence:\"\n");
			return (-1);
		}
		word = strtok(line_buf, ":");
		if (strcmp(word, "Sequence") != 0) {
			fprintf(stderr,
				"Expected \"Sequence:\"; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		word = strtok(NULL, " \n");
		if (!word) {
			fprintf(stderr, "Missing Sequence ID\n");
			free(line_buf);
			free(zc);
			return (0);
		}
		zc->parameter_2u = htonl(strtol(word, &err, 10));
		if (*err) {
			fprintf(stderr,
				"Expected Sequence ID; received \"%s\"\n",
				word);
			free(line_buf);
			free(zc);
			return (0);
		}
		if (line_buf) {
			free(line_buf);
		}
		zh->zerg_payload = zc;
		return (1);
	}
	if (line_buf) {
		free(line_buf);
	}
	return (1);
}

int parse_gps(struct zerg_header *zh, FILE * input_fo)
{
	int eof_flag = 0;
	char *line_buf = NULL;
	size_t buf_size = 0;
	char *word;
	char *err = '\0';
	struct zerg_gps *zg = malloc(sizeof(*zg));
	if (!zg) {
		fprintf(stderr, "Memory allocation error.\n");
		exit(MEMORY_ERROR);
	}

	getline(&line_buf, &buf_size, input_fo);
	word = strtok(line_buf, ":");
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Latitude degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	double degrees = 0;
	degrees = strtod(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Latitude minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	double minutes = strtod(word, &err);
	if (*err) {
		fprintf(stderr,
			"Expected Latitude minutes value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n\"");
	if (!word) {
		fprintf(stderr, "Missing Latitude seconds value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	double seconds = strtod(word, &err);
	if (*err) {
		fprintf(stderr,
			"Expected Latitude seconds value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = (degrees + (minutes / 60) + (seconds / 3600));
	zg->latitude = reverse_double(degrees);
	getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zg);
		fprintf(stderr, "Unexpected EOF; expected \"Longitude:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Longitude") != 0) {
		fprintf(stderr,
			"Expected \"Longitude:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Longitude degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = 0;
	degrees = strtod(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Longitude minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	minutes = strtod(word, &err);
	if (*err) {
		fprintf(stderr,
			"Expected Longitude minutes value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n\"");
	if (!word) {
		fprintf(stderr, "Missing Longitude seconds value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	seconds = strtod(word, &err);
	if (*err) {
		fprintf(stderr,
			"Expected Longitude seconds value; received \"%s\"\n",
			word);
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = (degrees + (minutes / 60) + (seconds / 3600));
	zg->longitude = reverse_double(degrees);

	getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zg);
		fprintf(stderr, "Unexpected EOF; expected \"Altitude:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Altitude") != 0) {
		fprintf(stderr,
			"Expected \"Altitude:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Altitude degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = 0;
	degrees = strtof(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Altitude minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	zg->altitude = reverse_float(degrees);

	getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zg);
		fprintf(stderr, "Unexpected EOF; expected \"Bearing:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Bearing") != 0) {
		fprintf(stderr,
			"Expected \"Bearing:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Bearing degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = 0;
	degrees = strtof(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Bearing minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	zg->bearing = reverse_float(degrees);

	getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zg);
		fprintf(stderr, "Unexpected EOF; expected \"Speed:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Speed") != 0) {
		fprintf(stderr, "Expected \"Speed:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Speed degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = 0;
	degrees = strtof(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Speed minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	zg->speed = reverse_float(degrees);

	getline(&line_buf, &buf_size, input_fo);
	if (eof_flag == -1) {
		if (line_buf) {
			free(line_buf);
		}
		free(zg);
		fprintf(stderr, "Unexpected EOF; expected \"Accuracy:\"\n");
		return (-1);
	}
	word = strtok(line_buf, ":");
	if (strcmp(word, "Accuracy") != 0) {
		fprintf(stderr,
			"Expected \"Accuracy:\"; received \"%s\"\n", word);
		free(line_buf);
		free(zg);
		return (0);
	}
	word = strtok(NULL, " \n");
	if (!word) {
		fprintf(stderr, "Missing Accuracy degrees value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	degrees = 0;
	degrees = strtof(word, NULL);
	word = strtok(NULL, " \n'");
	if (!word) {
		fprintf(stderr, "Missing Accuracy minutes value\n");
		free(line_buf);
		free(zg);
		return (0);
	}
	zg->accuracy = reverse_float(degrees);
	zh->zerg_payload = zg;
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
