#include <stdio.h>
#include <stdlib.h>
#include "lib/packet_fields.h"

enum return_codes {
	SUCCESS = 0,
	INVOCATION_ERROR = 1,
	FILE_ERROR = 2,
	MEMORY_ERROR = 3
};

enum program_defaults {
	DEFAULT_PACKET_NUM = 1
};

int load_packets(struct zerg_header *payloads, size_t num_packets,
		 size_t max_packets, FILE * fo);

int main(int argc, char *argv[])
{
	if (argc == 1 || argc > 2) {
		fprintf(stderr, "Usage: %s [FILE]\n", argv[0]);
		return (INVOCATION_ERROR);
	}
	FILE *fo = fopen(argv[1], "r");
	if (!fo) {
		fprintf(stderr, "%s could not be opened", argv[1]);
		perror(" \b");
		return (FILE_ERROR);
	}

	struct zerg_header *payloads =
	    malloc(DEFAULT_PACKET_NUM * sizeof *payloads);
	// TODO: check malloc return code
	struct pcap_header fh;
	fread(&fh, 1, sizeof(fh), fo);
	// TODO: Check major/minor version and magic num for pcap validity
	// as well as endianness
	printf("Version: %x.%x\n", fh.major_version, fh.minor_version);

	load_packets(payloads, DEFAULT_PACKET_NUM, DEFAULT_PACKET_NUM, fo);

	fclose(fo);
	free(payloads);

	return (SUCCESS);
}

int load_packets(struct zerg_header *payloads, size_t num_packets,
		 size_t max_packets, FILE * fo)
{
	struct packet_header ph;
	struct ethernet_header eh;
	struct ip_header ih;
	struct udp_header uh;
	struct zerg_header zh;
	fread(&ph, 1, sizeof(ph), fo);
	// TODO: Check packet header length for validity?
	// Potential use of fseek and ftell to skip files

	printf("packet len: %u\n", ph.data_capture_len);

	fread(&eh, 1, sizeof(eh), fo);
	printf("eth type: %x\n", eh.eth_ethernet_type);

	fread(&ih, 1, sizeof(ih), fo);
	fread(&uh, 1, sizeof(uh), fo);
	fread(&zh, 1, sizeof(zh) - sizeof(zh.zerg_payload), fo);

	printf("zerg type: %u\n", zh.zerg_packet_type);
	printf("zerg sequence: %x\n", zh.zerg_len);

	switch (zh.zerg_packet_type) {

	case 0:
		// Parse message packet
		break;
	case 1:
		// Parse status packet
		break;
	case 2:
		// Parse command packet
		break;
	case 3:
		// Parse GPS packet
		break;
	default:
        // Discard packet 
        break;
	}
	return (1);
}
