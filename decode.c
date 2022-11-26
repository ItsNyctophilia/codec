#include <stdio.h>
#include <stdlib.h>
#include "lib/packet_fields.h"
#include <netinet/in.h>

enum return_codes {
	SUCCESS = 0,
	INVOCATION_ERROR = 1,
	FILE_ERROR = 2,
	MEMORY_ERROR = 3
};

enum program_defaults {
	DEFAULT_PACKET_NUM = 5
};

int load_packets(struct zerg_header **payloads, size_t num_packets,
		 size_t max_packets, FILE * fo);
int shift_24_bit_int(unsigned int num);
float reverse_float(const float num);
double reverse_double(const double num);
int load_message(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo);
int load_status(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo);
int load_command(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo);
int load_gps(struct zerg_header *payloads, size_t index, size_t length,
	     FILE * fo);
void destroy_payloads(struct zerg_header *payloads, int num_payloads);
int resize_array(struct zerg_header **payloads, int max_payloads);
void print_headers(struct zerg_header *payloads, int num_payloads);
void print_message(struct zerg_header payload);
void print_status(struct zerg_header payload);
void print_command(struct zerg_header payload);
void print_gps(struct zerg_header payload);

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
		fprintf(stderr, "Memory allocation error.\n");
		fclose(fo);
		return (MEMORY_ERROR);
	}

	struct pcap_header fh;	// [f]ile [h]eader
	fread(&fh, 1, sizeof(fh), fo);
	// TODO: Check major/minor version and magic num for pcap validity
	// as well as endianness

	int num_payloads = load_packets(&payloads, 0, DEFAULT_PACKET_NUM, fo);
	print_headers(payloads, num_payloads);

	fclose(fo);
	destroy_payloads(payloads, num_payloads);

	return (SUCCESS);
}

int load_packets(struct zerg_header **payloads, size_t num_payloads,
		 size_t max_payloads, FILE * fo)
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
				fprintf(stderr, "Memory allocation Error.\n");
				exit(MEMORY_ERROR);
			}
		}
		struct packet_header ph;
		struct ethernet_header eh;
		struct ip_header ih;
		struct udp_header uh;
		//struct zerg_header zh;
		size_t test_len = 0;

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

		test_len = fread(&ih, 1, sizeof(ih), fo);
		if (test_len != sizeof(ih)) {
			// Case: EOF reached
			break;
		}
		test_len = fread(&uh, 1, sizeof(uh), fo);
		if (test_len != sizeof(uh)) {
			// Case: EOF reached
			break;
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
		// TODO: reallocate payloads before loading new packet
		return_code = 0;
		unsigned int corrected_len =
		    shift_24_bit_int((*payloads)[num_payloads].zerg_len);
		corrected_len -= 12;
		switch ((*payloads)[num_payloads].zerg_packet_type) {

		case 0:
			return_code =
			    load_message(&((*payloads)[num_payloads]),
					 num_payloads, corrected_len, fo);
			break;
		case 1:
			return_code =
			    load_status(&((*payloads)[num_payloads]),
					num_payloads, corrected_len, fo);
			break;
		case 2:
			return_code =
			    load_command(&((*payloads)[num_payloads]),
					 num_payloads, corrected_len, fo);
			break;
		case 3:
			return_code =
			    load_gps(&((*payloads)[num_payloads]), num_payloads,
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

	//printf("Message: %s\n",((struct zerg_message *)payloads[0].zerg_payload)->message);

	return (num_payloads);
}

int load_message(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo)
// Loads the message payload from a given zerg packet.
{
	// TODO: Discard packets with letter V
	char *message = malloc(length + 1);	// Message + '\0'
	size_t read_length = fread(message, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(message);
		return (0);
	}
	message[length] = '\0';
	// TODO: Error handle malloc
	struct zerg_message *message_struct = malloc(sizeof(*message_struct));
	message_struct->message = message;
	payloads->zerg_payload = message_struct;
	return (1);
}

int load_status(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo)
// Loads the status payload from a given zerg packet.
{
	size_t string_len = length - 12;
	// TODO: handle malloc calls
	char *name = malloc(string_len + 1);	// String + '\0'
	struct zerg_status *status_struct = malloc(sizeof(*status_struct));

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

int load_command(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo)
// Loads the command payload from a given zerg packet.
{
	struct zerg_command *command_struct =
	    calloc(1, sizeof(*command_struct));
	// TODO: Error handle calloc call
	size_t read_length = fread(command_struct, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(command_struct);
		return (0);
	}
	payloads->zerg_payload = command_struct;
	return (1);
}

int load_gps(struct zerg_header *payloads, size_t index, size_t length,
	     FILE * fo)
// Loads the gps payload from a given zerg packet.
{
	struct zerg_gps *gps_struct = malloc(sizeof(*gps_struct));
	size_t read_length = fread(gps_struct, 1, length, fo);
	if (read_length != length) {
		// Case: EOF
		free(gps_struct);
		return (0);
	}
	payloads->zerg_payload = gps_struct;
	return (1);
}

int shift_24_bit_int(const unsigned int num)
// Reverses the byte order of a 24 bit integer. Returns the reversed
// integer.
// TODO: Validate this is supposed to be int instead of unsigned int
{
	unsigned int tmp_len = 0;
	tmp_len = num & 0xFF;
	tmp_len = (num >> 8) & 0xFF;
	tmp_len = (num >> 16) & 0xFF;
	return (tmp_len);
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

double reverse_double(const double num)
// Reverses the byte order of the passed double. Can probably
// be merged with reverse_float later.
{
	double ret_val;
	char *double_to_convert = (char *)&num;
	char *return_double = (char *)&ret_val;

	return_double[0] = double_to_convert[7];
	return_double[1] = double_to_convert[6];
	return_double[2] = double_to_convert[5];
	return_double[3] = double_to_convert[4];
	return_double[4] = double_to_convert[3];
	return_double[5] = double_to_convert[2];
	return_double[6] = double_to_convert[1];
	return_double[7] = double_to_convert[0];

	return (ret_val);
}

void destroy_payloads(struct zerg_header *payloads, int num_payloads)
// Destroys the payloads structarray at various stages of it being
// built and filled out. Syntax taken from Liam Echlin in array.c.
{
	if (!payloads) {
		return;
	}
	for (int i = 0; i < num_payloads; ++i) {
		//printf("Payload type: %u\n", payloads[i].zerg_packet_type);   // DEVPRINT
		switch (payloads[i].zerg_packet_type) {
		case 0:
			free(((struct zerg_message *)payloads[i].
			      zerg_payload)->message);
			free((struct zerg_message *)payloads[i].zerg_payload);
			break;
		case 1:
			free(((struct zerg_status *)payloads[i].zerg_payload)->
			     name);
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
	    shift_24_bit_int(((struct zerg_status *)payload.zerg_payload)->
			     max_hp);
	int hp =
	    shift_24_bit_int(((struct zerg_status *)payload.zerg_payload)->
			     current_hp);
	unsigned int armor =
	    ((struct zerg_status *)payload.zerg_payload)->armor;
	unsigned int type = ((struct zerg_status *)payload.zerg_payload)->type;
	float speed =
	    reverse_float(((struct zerg_status *)payload.zerg_payload)->
			  max_speed);
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
	printf("Max Speed: %f\n", speed);
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
			float bearing =
			    reverse_float((((struct zerg_command *)payload.
					    zerg_payload)->parameter_2));
			unsigned int distance =
			    ntohs((((struct zerg_command *)payload.
				    zerg_payload)->parameter_1));
			puts("GOTO");
			printf("Bearing: %f" "Distance: %u", bearing, distance);
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
			    ((struct zerg_command *)payload.zerg_payload)->
			    parameter_1;
			int group =
			    ntohl(((struct zerg_command *)payload.
				   zerg_payload)->parameter_2);
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
			unsigned int sequence =
			    ntohl(((struct zerg_command *)payload.
				   zerg_payload)->parameter_2);
			puts("REPEAT");
			printf("Sequence: %u", sequence);
			break;
		}
	}
	return;
}

void print_gps(struct zerg_header payload)
{
	double longitude =
	    reverse_double(((struct zerg_gps *)payload.zerg_payload)->
			   longitude);
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
	printf("Longitude: %f degrees\n" "Latitude: %f degrees\n"
	       "Altitude: %f fathoms\n" "Bearing: %f degrees\n"
	       "Speed: %f m/s\n" "Accuracy: %f\n", longitude, latitude,
	       altitude, bearing, speed, accuracy);
	return;
}
