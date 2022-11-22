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

int load_packets(struct zerg_header *payloads, size_t num_packets,
		 size_t max_packets, FILE * fo);
int shift_24_bit_int(unsigned int num);
float reverse_float(const float num);
int load_message(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo);
int load_status(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo);
int load_command(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo);
void destroy_payloads(struct zerg_header *payloads, int num_payloads);
int resize_array(struct zerg_header *payloads, int num_payloads,
		 int max_payloads);

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

	struct pcap_header fh;
	fread(&fh, 1, sizeof(fh), fo);
	// TODO: Check major/minor version and magic num for pcap validity
	// as well as endianness

	int num_payloads = load_packets(payloads, 0, DEFAULT_PACKET_NUM, fo);

	fclose(fo);
	destroy_payloads(payloads, num_payloads);

	return (SUCCESS);
}

int load_packets(struct zerg_header *payloads, size_t num_payloads,
		 size_t max_payloads, FILE * fo)
// Loads zerg packet headers into payloads and returns the number of
// successfully added packets.
{
	for (;;) {
		int return_code = 0;
		/*if (num_payloads == max_payloads) {
		   return_code = resize_array(payloads, num_payloads, max_payloads);
		   max_payloads *= 2;
		   }
		   if (return_code == MEMORY_ERROR) {
		   destroy_payloads(payloads, num_payloads);
		   fclose(fo);
		   fprintf(stderr, "Memory allocation Error.\n");
		   exit(MEMORY_ERROR);
		   } */
		struct packet_header ph;
		struct ethernet_header eh;
		struct ip_header ih;
		struct udp_header uh;
		struct zerg_header zh;
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
		    fread(&payloads[num_payloads], 1,
			  sizeof(zh) - sizeof(zh.zerg_payload), fo);
		if (test_len !=
		    sizeof(payloads[num_payloads]) -
		    sizeof(payloads->zerg_payload)) {
			// Case: EOF reached
			break;
		}
		// TODO: reallocate payloads before loading new packet
		return_code = 0;
		unsigned int corrected_len =
		    shift_24_bit_int(payloads[num_payloads].zerg_len);
		corrected_len -= 12;
		switch (payloads->zerg_packet_type) {

		case 0:
			return_code =
			    load_message(&payloads[num_payloads], num_payloads,
					 corrected_len, fo);
			break;
		case 1:
			return_code =
			    load_status(&payloads[num_payloads], num_payloads,
					corrected_len, fo);
			break;
		case 2:
			return_code =
			    load_command(&payloads[num_payloads], num_payloads,
					corrected_len, fo);
			break;
		case 3:
			--num_payloads;
			return_code = 1;
			break;
		default:
			--num_payloads;
			return_code = 1;
			break;
		}
		if (return_code == 0) {
			break;
		} else if (return_code == -1) {
			continue;
		} else {
			++num_payloads;
		}
	}

	//printf("Message: %s\n",((struct zerg_message *)payloads[0].zerg_payload)->message);

	return (num_payloads);
}

int load_message(struct zerg_header *payloads, size_t index, size_t length,
		 FILE * fo)
{
	// TODO: Discard packets with letter V
	char *message = malloc(length + 1);
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
	payloads[index].zerg_payload = message_struct;
	return (1);
}

int load_status(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo)
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
	payloads[index].zerg_payload = status_struct;
	return (1);
}

int load_command(struct zerg_header *payloads, size_t index, size_t length,
		FILE * fo)
{
    struct zerg_command *command_struct = calloc(1, sizeof(*command_struct));
    // TODO: Error handle calloc call
    size_t read_length = fread(command_struct, 1, length, fo);
    if (read_length != length) {
		// Case: EOF
		free(command_struct);
		return (0);
	}
    payloads[index].zerg_payload = command_struct;
    return(1);
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

void destroy_payloads(struct zerg_header *payloads, int num_payloads)
// Destroys the payloads structarray at various stages of it being
// built and filled out. Syntax borrowed from Liam Echlin in array.c.
{
	if (!payloads) {
		return;
	}
	for (int i = 0; i < num_payloads; ++i) {
		printf("Payload type: %u\n", payloads[i].zerg_packet_type);	// DEVPRINT
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
			// free GPS packet
			break;
		}

	}
	free(payloads);
}

/*int resize_array(struct zerg_header *payloads, int num_payloads, int max_payloads)
{
    max_payloads *= 2;
    struct zerg_header *tmp_payloads = realloc(payloads, (sizeof(*tmp_payloads) * max_payloads));
    if (!tmp_payloads) {
        return(MEMORY_ERROR);
    }
    payloads = tmp_payloads;
    return(1);
}*/
