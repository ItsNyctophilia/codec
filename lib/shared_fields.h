enum return_codes {
	SUCCESS = 0,
	INVOCATION_ERROR = 1,
	FILE_ERROR = 2,
	MEMORY_ERROR = 3
};

struct __attribute__((__packed__)) pcap_header {
	unsigned int magic_number:32;
	unsigned int major_version:16;
	unsigned int minor_version:16;
	unsigned int gmt_offset:32;
	unsigned int accuracy_delta:32;
	unsigned int max_capture_len:32;
	unsigned int link_layer_type:32;
};

struct __attribute__((__packed__)) packet_header {
	unsigned int unix_epoch:32;
	unsigned int us_from_epoch:32;
	unsigned int data_capture_len:32;
	unsigned int untruncated_len:32;
};

struct __attribute__((__packed__)) ethernet_header {
	unsigned long eth_dst_mac:48;
	unsigned long eth_src_mac:48;
	unsigned int eth_ethernet_type:16;
};

struct __attribute__((__packed__)) ip_header {
	unsigned int ip_header_length:4;
	unsigned int ip_version:4;
	unsigned int ip_dscp_ecn:8;
	unsigned int ip_packet_length:16;
	unsigned int ip_id:16;
	unsigned int ip_flags_and_frags:16;
	unsigned int ip_ttl:8;
	unsigned int ip_protocol:8;
	unsigned int ip_checksum:16;
	unsigned int ip_src_ip:32;
	unsigned int ip_dst_ip:32;
};

struct __attribute__((__packed__)) udp_header {
	unsigned int udp_src_port:16;
	unsigned int udp_dst_port:16;
	unsigned int udp_len:16;
	unsigned int udp_checksum:16;
};

struct __attribute__((__packed__)) zerg_header {
	unsigned int zerg_packet_type:4;
	unsigned int zerg_version:4;
	unsigned int zerg_len:24;
	unsigned int zerg_src:16;
	unsigned int zerg_dst:16;
	unsigned int zerg_sequence:32;
	void *zerg_payload;
};

struct __attribute__((__packed__)) zerg_message {
	char *message;
};

struct __attribute__((__packed__)) zerg_status {
	int current_hp:24;
	unsigned int armor:8;
	unsigned int max_hp:24;
	unsigned int type:8;
	float max_speed;
	char *name;
};

struct __attribute__((__packed__)) zerg_command {
	unsigned int command:16;
	unsigned int parameter_1:16;
	union __attribute__((__packed__)) {
		int parameter_2i;
		unsigned int parameter_2u;
		float parameter_2f;
	};
};

struct __attribute__((__packed__)) zerg_gps {
	double longitude;
	double latitude;
	float altitude;
	float bearing;
	float speed;
	float accuracy;
};

double reverse_double(const double num);

float reverse_float(const float num);

int shift_24_bit_int(int num);
