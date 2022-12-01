#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib/shared_fields.h"
#include <netinet/in.h>

enum program_defaults {
	DEFAULT_PACKET_NUM = 5
};

int load_packets(struct zerg_header **payloads, size_t num_packets,
		 size_t max_packets, bool little_endian, FILE * fo);
int load_message(struct zerg_header *payloads, size_t length, FILE * fo);
int load_status(struct zerg_header *payloads, size_t length, FILE * fo);
int load_command(struct zerg_header *payloads, size_t length, FILE * fo);
int load_gps(struct zerg_header *payloads, size_t length, FILE * fo);
void destroy_payloads(struct zerg_header *payloads, int num_payloads);
int resize_array(struct zerg_header **payloads, int max_payloads);
void print_headers(struct zerg_header *payloads, int num_payloads);
void print_message(struct zerg_header payload);
void print_status(struct zerg_header payload);
void print_command(struct zerg_header payload);
void print_gps(struct zerg_header payload);
void format_gps_output(const double num, double *degrees, double *minutes,
		       double *seconds);

int total_packets = 0;

int main(int argc, char *argv[])
{
	if (argc == 1 || argc > 2) {
		fprintf(stderr, "Usage: %s [FILE]\n", argv[0]);
		return (INVOCATION_ERROR);
	}
	FILE *fo = fopen(argv[1], "rb");
	if (!fo) {
		fprintf(stderr, "%s could not be opened", argv[1]);
		perror(" \b");
		return (FILE_ERROR);
	}

	struct zerg_header *payloads =
	    calloc(DEFAULT_PACKET_NUM, sizeof(*payloads));
	if (!payloads) {
		fprintf(stderr, "Memory allocation error\n");
		fclose(fo);
		return (MEMORY_ERROR);
	}

	struct pcap_header fh;	// [f]ile [h]eader
	bool little_endian = true;	// Denotes the endianness of the pcap headers
	fread(&fh, 1, sizeof(fh), fo);
	if (fh.magic_number == 0xA1B2C3D4) {
		// Case: Packet has same byte order as host (Little Endian)
		if (fh.major_version != 2 || fh.minor_version != 4) {
			fprintf(stderr,
				"%s is not of a type that is currently supported\n",
				argv[1]);
			destroy_payloads(payloads, 0);
			fclose(fo);
			return (SUCCESS);
		}
		little_endian = true;
	} else if (fh.magic_number == 0xD4C3B2A1) {
		// Case: Packet has reverse byte order from host (Big Endian)
		if (ntohs(fh.major_version) != 2
		    || ntohs(fh.minor_version) != 4) {
			fprintf(stderr,
				"%s is not of a type that is currently supported\n",
				argv[1]);
			destroy_payloads(payloads, 0);
			fclose(fo);
			return (SUCCESS);
		}
		little_endian = false;
	} else {
		// Case: Malformed magic number
		fprintf(stderr,
			"%s is not of a type that is currently supported\n",
			argv[1]);
		destroy_payloads(payloads, 0);
		fclose(fo);
		return (SUCCESS);
	}

	int num_payloads =
	    load_packets(&payloads, 0, DEFAULT_PACKET_NUM, little_endian, fo);
	print_headers(payloads, num_payloads);

	fclose(fo);
	destroy_payloads(payloads, num_payloads);

	return (SUCCESS);
}

int load_packets(struct zerg_header **payloads, size_t num_payloads,
		 size_t max_payloads, bool little_endian, FILE * fo)
// Loads zerg packet headers into payloads and returns the number of
// successfully added packets.
{
	for (;;) {
		int return_code = 0;
		if (num_payloads == max_payloads) {
			return_code = resize_array(payloads, max_payloads);
			max_payloads *= 2;
			if (return_code == MEMORY_ERROR) {
				destroy_payloads(*payloads, num_payloads);
				fclose(fo);
				fprintf(stderr, "Memory allocation Error\n");
				exit(MEMORY_ERROR);
			}
		}
		struct packet_header ph;
		struct ethernet_header eh;
		struct ip_header ih;
		struct udp_header uh;
		size_t test_len = 0;
		++total_packets;
		long packet_start = ftell(fo);

		test_len = fread(&ph, 1, sizeof(ph), fo);
		if (test_len != sizeof(ph)) {
			// Case: EOF reached
			break;
		}
		// TODO: Check packet header length for validity?
		// Potential use of fseek and ftell to skip files
		test_len = fread(&eh, 1, sizeof(eh), fo);
		if (test_len != sizeof(eh)) {
			// Case: EOF reached
			break;
		}
		if (eh.eth_ethernet_type != 8) {
			// Case: Ethertype was not IPv4 (8)
			fprintf(stderr,
				"Only IPv4 packets are currently supported; packet #%d discarded\n",
				total_packets);
			if (little_endian) {
				fseek(fo,
				      packet_start + ph.untruncated_len +
				      sizeof(ph), SEEK_SET);
			} else {
				fseek(fo,
				      packet_start + ntohl(ph.untruncated_len) +
				      sizeof(ph), SEEK_SET);
			}
			continue;
		}

		test_len = fread(&ih, 1, sizeof(ih), fo);
		if (test_len != sizeof(ih)) {
			// Case: EOF reached
			break;
		}
		if (ih.ip_version != 4) {
			// Case: IP Version was not 4
			fprintf(stderr,
				"Only IPv4 packets are currently supported; packet #%d discarded\n",
				total_packets);
			if (little_endian) {
				fseek(fo,
				      packet_start + ph.untruncated_len +
				      sizeof(ph), SEEK_SET);
			} else {
				fseek(fo,
				      packet_start + ntohl(ph.untruncated_len) +
				      sizeof(ph), SEEK_SET);
			}
			continue;
		}
		if (ih.ip_protocol != 0x11) {
			// Case: IPv4 header next protocol was not UDP
			fprintf(stderr,
				"Only UDP packets are currently supported; packet #%d discarded\n",
				total_packets);
			if (little_endian) {
				// TODO: Figure out why this number has to be 16 to work
				fseek(fo,
				      packet_start + ph.untruncated_len +
				      sizeof(ph), SEEK_SET);
			} else {
				fseek(fo,
				      packet_start + ntohl(ph.untruncated_len) +
				      sizeof(ph), SEEK_SET);
			}
			continue;
		}

		test_len = fread(&uh, 1, sizeof(uh), fo);
		if (test_len != sizeof(uh)) {
			// Case: EOF reached
			break;
		}
		if (ntohs(uh.udp_dst_port) != 3751) {
			// Case: UDP destination port did not match
			// Zerg protocol port (3751)
			fprintf(stderr,
				"Only packets bound for port 3751 are currently supported; packet #%d discarded\n",
				total_packets);
			if (little_endian) {
				fseek(fo,
				      packet_start + ph.untruncated_len +
				      sizeof(ph), SEEK_SET);
			} else {
				fseek(fo,
				      packet_start + ntohl(ph.untruncated_len) +
				      sizeof(ph), SEEK_SET);
			}
			continue;
		}
		test_len =
		    fread((&(*payloads)[num_payloads]), 1,
			  sizeof((*payloads)[0]) -
			  sizeof((*payloads)[0].zerg_payload), fo);
		if (test_len !=
		    sizeof((*payloads)[0]) -
		    sizeof((*payloads)[0].zerg_payload)) {
			// Case: EOF reached
			break;
		}
		if ((*payloads)[num_payloads].zerg_version != 1) {
			// Case: Ethertype was not IPv4 (8)
			fprintf(stderr,
				"Only version 1 Zerg packets are currently supported; packet #%d discarded\n",
				total_packets);
			if (little_endian) {
				fseek(fo,
				      packet_start + ph.untruncated_len +
				      sizeof(ph), SEEK_SET);
			} else {
				fseek(fo,
				      packet_start + ntohl(ph.untruncated_len) +
				      sizeof(ph), SEEK_SET);
			}
			continue;
		}
		return_code = 0;
		unsigned int corrected_len =
		    shift_24_bit_int((*payloads)[num_payloads].zerg_len);
		corrected_len -= 12;
		switch ((*payloads)[num_payloads].zerg_packet_type) {
		case 0:
			return_code =
			    load_message(&((*payloads)[num_payloads]),
					 corrected_len, fo);
			break;
		case 1:
			return_code =
			    load_status(&((*payloads)[num_payloads]),
					corrected_len, fo);
			break;
		case 2:
			return_code =
			    load_command(&((*payloads)[num_payloads]),
					 corrected_len, fo);
			break;
		case 3:
			return_code =
			    load_gps(&((*payloads)[num_payloads]),
				     corrected_len, fo);
			break;
		default:
			--num_payloads;
			return_code = 0;
			break;
		}
		if (return_code == 0) {
			break;
		} else if (return_code == -1) {
			// Currently unused; use later for validation
			// of packets mid-read
			continue;
		} else {
			++num_payloads;
		}
		unsigned short len = ntohs(ih.ip_packet_length);

		if (len + 14 < 60) {
			size_t eth_padding_len = 60 - len - 14;
			for (size_t i = 0; i < eth_padding_len; ++i) {
				// Until padding has been removed, read one byte
				// at a time into ph, which will be overwritten
				// when the next packet is read anyway.
				fread(&ph, 1, 1, fo);
			}
		}
	}
	return (num_payloads);
}

int load_message(struct zerg_header *payloads, size_t length, FILE * fo)
// Loads the message payload from a given zerg packet.
{
	// TODO: Discard packets with letter V
	char *message = malloc(length + 1);	// Message + '\0'
	if (!message) {
		fprintf(stderr, "Memory allocation error.\n");
		return (0);
	}
	size_t read_length = fread(message, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(message);
		return (0);
	}
	message[length] = '\0';
	struct zerg_message *message_struct = malloc(sizeof(*message_struct));
	if (!message_struct) {
		fprintf(stderr, "Memory allocation error.\n");
		free(message);
		return (0);
	}
	message_struct->message = message;
	payloads->zerg_payload = message_struct;
	return (1);
}

int load_status(struct zerg_header *payloads, size_t length, FILE * fo)
// Loads the status payload from a given zerg packet.
{
	size_t string_len = length - 12;
	char *name = malloc(string_len + 1);	// String + '\0'
	if (!name) {
		fprintf(stderr, "Memory allocation error.\n");
		return (0);
	}
	struct zerg_status *status_struct = malloc(sizeof(*status_struct));
	if (!status_struct) {
		fprintf(stderr, "Memory allocation error.\n");
		free(name);
		return (0);
	}

	size_t read_length = fread(status_struct, 1, length - string_len, fo);
	if (read_length != length - string_len) {
		// Case: EOF
		free(name);
		free(status_struct);
		return (0);
	}

	read_length = fread(name, 1, string_len, fo);
	if (read_length != string_len) {
		// Case: EOF
		free(name);
		free(status_struct);
		return (0);
	}
	name[string_len] = '\0';
	status_struct->name = name;
	payloads->zerg_payload = status_struct;
	return (1);
}

int load_command(struct zerg_header *payloads, size_t length, FILE * fo)
// Loads the command payload from a given zerg packet.
{
	struct zerg_command *command_struct =
	    calloc(1, sizeof(*command_struct));
	if (!command_struct) {
		return (0);
	}
	size_t read_length = fread(command_struct, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(command_struct);
		return (0);
	}
	payloads->zerg_payload = command_struct;
	return (1);
}

int load_gps(struct zerg_header *payloads, size_t length, FILE * fo)
// Loads the gps payload from a given zerg packet.
{
	struct zerg_gps *gps_struct = malloc(sizeof(*gps_struct));
	if (!gps_struct) {
		fprintf(stderr, "Memory allocation error.\n");
		return (0);
	}
	size_t read_length = fread(gps_struct, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(gps_struct);
		return (0);
	}
	payloads->zerg_payload = gps_struct;
	return (1);
}

void destroy_payloads(struct zerg_header *payloads, int num_payloads)
// Destroys the payloads structarray at various stages of it being
// built and filled out. Syntax taken from Liam Echlin in array.c.
{
	for (int i = 0; i < num_payloads; ++i) {
		switch (payloads[i].zerg_packet_type) {
		case 0:
			free(((struct zerg_message *)payloads[i].zerg_payload)->
			     message);
			free((struct zerg_message *)payloads[i].zerg_payload);
			break;
		case 1:
			free(((struct zerg_status *)payloads[i].
			      zerg_payload)->name);
			free((struct zerg_status *)payloads[i].zerg_payload);
			break;
		case 2:
			free((struct zerg_command *)payloads[i].zerg_payload);
			break;
		case 3:
			free((struct zerg_gps *)payloads[i].zerg_payload);
			break;
		}

	}
	free(payloads);
}

int resize_array(struct zerg_header **payloads, int max_payloads)
{
	max_payloads *= 2;
	struct zerg_header *tmp_payloads =
	    realloc(*payloads, (sizeof(*tmp_payloads) * max_payloads));
	if (!tmp_payloads) {
		return (MEMORY_ERROR);
	}
	*payloads = tmp_payloads;
	printf("Resized to: %zu\n", (sizeof(*tmp_payloads) * max_payloads));
	return (1);
}

void print_headers(struct zerg_header *payloads, int num_payloads)
{
	if (!payloads) {
		return;
	}
	for (int i = 0; i < num_payloads; ++i) {
		printf("Version: %u\n"
		       "Sequence: %u\n"
		       "From: %u\n"
		       "To: %u\n",
		       payloads[i].zerg_version,
		       ntohl(payloads[i].zerg_sequence),
		       ntohs(payloads[i].zerg_src),
		       ntohs(payloads[i].zerg_dst));
		switch (payloads[i].zerg_packet_type) {
		case 0:
			print_message(payloads[i]);
			break;
		case 1:
			print_status(payloads[i]);
			break;
		case 2:
			print_command(payloads[i]);
			break;
		case 3:
			print_gps(payloads[i]);
			break;
		}
		if (i + 1 != num_payloads) {
			putchar('\n');
		}
	}
	return;
}

void print_message(struct zerg_header payload)
{
	printf("Message: %s\n",
	       ((struct zerg_message *)payload.zerg_payload)->message);
	return;
}

void print_status(struct zerg_header payload)
{
	unsigned int max_hp =
	    shift_24_bit_int(((struct zerg_status *)payload.
			      zerg_payload)->max_hp);
	int hp = 0;
	hp = shift_24_bit_int(((struct zerg_status *)payload.zerg_payload)->
			      current_hp);
	unsigned int armor =
	    ((struct zerg_status *)payload.zerg_payload)->armor;
	unsigned int type = ((struct zerg_status *)payload.zerg_payload)->type;
	float speed =
	    reverse_float(((struct zerg_status *)payload.
			   zerg_payload)->max_speed);
	printf("Max Hit Points: %u\n" "Current Hit Points: %d\n" "Armor: %u\n"
	       "Type: ", max_hp, hp, armor);
	switch (type) {
	case 0:
		puts("Overmind");
		break;
	case 1:
		puts("Larva");
		break;
	case 2:
		puts("Cerebrate");
		break;
	case 3:
		puts("Overlord");
		break;
	case 4:
		puts("Queen");
		break;
	case 5:
		puts("Drone");
		break;
	case 6:
		puts("Zergling");
		break;
	case 7:
		puts("Lurker");
		break;
	case 8:
		puts("Broodling");
		break;
	case 9:
		puts("Hydralisk");
		break;
	case 10:
		puts("Guardian");
		break;
	case 11:
		puts("Scourge");
		break;
	case 12:
		puts("Ultralisk");
		break;
	case 13:
		puts("Mutalisk");
		break;
	case 14:
		puts("Defiler");
		break;
	case 15:
		puts("Devourer");
	}
	printf("Max Speed: %g\n", speed);
	printf("Name: %s\n",
	       ((struct zerg_status *)payload.zerg_payload)->name);
	return;
}

void print_command(struct zerg_header payload)
{

	unsigned int command =
	    ntohs(((struct zerg_command *)payload.zerg_payload)->command);
	printf("Command: ");
	switch (command) {
	case 0:
		puts("GET_STATUS");
		break;
	case 1:
		{
			float bearing = reverse_float((((struct zerg_command *)
							payload.zerg_payload)->
						       parameter_2));
			unsigned int distance = ntohs((((struct zerg_command *)
							payload.
							zerg_payload)->parameter_1));
			puts("GOTO");
			printf("Bearing: %g degrees\n" "Distance: %u m\n",
			       bearing, distance);
			break;
		}
	case 2:
		puts("GET_GPS");
		break;
	case 4:
		puts("RETURN");
		break;
	case 5:
		{
			unsigned int action =
			    ((struct zerg_command *)payload.
			     zerg_payload)->parameter_1;
			int group = ntohl(((struct zerg_command *)
					   payload.zerg_payload)->parameter_2);
			puts("SET_GROUP");
			switch (action) {
			case 0:
				puts("Action: Remove from");
				break;
			default:
				puts("Action: Add to");
				break;
			}
			printf("Group: %d\n", group);
			break;
		}
	case 6:
		puts("STOP");
		break;
	case 7:
		{
			unsigned int sequence = ntohl(((struct zerg_command *)
						       payload.
						       zerg_payload)->parameter_2);
			puts("REPEAT");
			printf("Sequence: %u\n", sequence);
			break;
		}
	}
	return;
}

void print_gps(struct zerg_header payload)
{
	double degrees = 0;
	double minutes = 0;
	double seconds = 0;
	double longitude =
	    reverse_double(((struct zerg_gps *)payload.
			    zerg_payload)->longitude);
	double latitude =
	    reverse_double(((struct zerg_gps *)payload.zerg_payload)->latitude);
	float altitude =
	    reverse_float(((struct zerg_gps *)payload.zerg_payload)->altitude);
	float bearing =
	    reverse_float(((struct zerg_gps *)payload.zerg_payload)->bearing);
	float speed =
	    reverse_float(((struct zerg_gps *)payload.zerg_payload)->speed);
	float accuracy =
	    reverse_float(((struct zerg_gps *)payload.zerg_payload)->accuracy);

	format_gps_output(latitude, &degrees, &minutes, &seconds);
	printf("Latitude: %g° %g' %2.2f\" ", degrees, minutes, seconds);
	if (degrees >= 0) {
		puts("N");
	} else {
		puts("S");
	}
	format_gps_output(longitude, &degrees, &minutes, &seconds);
	printf("Longitude: %g° %g' %2.2f\" ", degrees, minutes, seconds);
	if (degrees >= 0) {
		puts("E");
	} else {
		puts("W");
	}

	printf("Altitude: %f fathoms\n" "Bearing: %f deg.\n"
	       "Speed: %f m/s\n" "Accuracy: %g m\n",
	       altitude, bearing, speed, accuracy);
	return;
}

void format_gps_output(const double num, double *degrees, double *minutes,
		       double *seconds)
// Accepts a double and three placeholder values that will hold the 
// converted values after turning the decimal representation of the
// longitude/latitude field into degrees/minutes/seconds format.
{
	double absolute = fabs(num);
	*degrees = floor(absolute);
	double minutes_not_truncated = (absolute - *degrees) * 60;
	*minutes = floor(minutes_not_truncated);
	*seconds = (minutes_not_truncated - *minutes) * 60;
	return;
}
