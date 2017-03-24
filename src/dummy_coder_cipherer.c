#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/conv.h>

#include <coder.h>
#include <cipherer.h>

#define SUFFIX_PLAIN ".plain"
#define SUFFIX_CRC ".crc"
#define SUFFIX_CC ".cc"
#define SUFFIX_INTERLEAVED ".il"
#define SUFFIX_BURSTMAP ".burstmap"
#define SUFFIX_XCCH ".xcch"
#define SUFFIX_FACCH ".facch"
#define HEX_FILE_LINE_LEN 32

static int ciphering = 1;
static int encode = 1;
static char* data_path = "hex_data";
static char* data_type = SUFFIX_PLAIN;
static int input_len = -1;
static char path_buf[100];

static enum mode {
	PLAIN_ENCODE,
	BURSTMAP_DECODE_XCCH,
	BURSTMAP_DECODE_FACCH,
	CRC_ENCODE,
	CRC_DECODE,
	IL_ENCODE_XCCH,
	IL_DECODE_XCCH,
	CC_ENCODE,
	CC_DECODE,
	IL_ENCODE_FACCH,
	IL_DECODE_FACCH,
	MODE_UNDEFINED
} mode = MODE_UNDEFINED;

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] =
		                {
		                        {
		                                "no-ciphering", no_argument,
		                                &ciphering, 0}, {
		                                "data-path", required_argument,
		                                0, 'p'}, {
		                                "encode", no_argument, &encode,
		                                1}, {
		                                "decode", no_argument, &encode,
		                                0}, {
		                                "input-type", required_argument,
		                                0, 't'}, {0, 0, 0, 0}, };

		c = getopt_long(argc, argv, "p:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			data_path = optarg;
			break;
		case 't':
			data_type = optarg;
			break;
		default:
			break;
		}
	}
}

int is_hex_char(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
	       || (c >= 'A' && c <= 'F');
}

void set_mode()
{
	switch (input_len) {
	case LEN_PLAIN:
		mode = PLAIN_ENCODE;
		break;
	case LEN_CRC:
		mode = encode ? CRC_ENCODE : CRC_DECODE;
		break;
	case LEN_CC:
		if (strcmp(data_type, "il") == 0) {
			mode = encode ? IL_ENCODE_XCCH : IL_DECODE_XCCH;
		} else {
			mode = encode ? CC_ENCODE : CC_DECODE;
		}
		break;
	case LEN_INTERLEAVED_FACCH:
		mode = encode ? IL_ENCODE_FACCH : IL_DECODE_FACCH;
		break;
	case LEN_BURSTMAP_XCCH:
		mode = BURSTMAP_DECODE_XCCH;
		break;
	case LEN_BURSTMAP_FACCH:
		mode = BURSTMAP_DECODE_FACCH;
		break;
	default:
		mode = MODE_UNDEFINED;
		break;
	}
}

void parse_file(uint8_t *data_buf)
{
	int max_hex_len = MAX_DATA_LEN / 4;
	char hexstring[max_hex_len + 1];
	char cbuf;
	int i = 0;
	FILE *fp = fopen(data_path, "r");
	if (fp == NULL) {
		fprintf(stderr, "File %s could not be opened: ", data_path);
		perror("");
		exit(EXIT_FAILURE);
	}
	for (cbuf = fgetc(fp); i < max_hex_len && cbuf != EOF;
	                cbuf = fgetc(fp)) {
		if (is_hex_char(cbuf)) {
			hexstring[i++] = cbuf;
		}
	}
	fclose(fp);
	input_len = i * 4; // one hex is 4 bit
	// add null termination to string
	hexstring[i] = '\0';

	// len for this function is in bytes
	osmo_hexparse(hexstring, data_buf, MAX_DATA_LEN / 8);
}

void write_file(char * path, uint8_t * data_buf, int len_bytes)
{
	char *hexstring;
	int i = 0;

	hexstring = osmo_hexdump(data_buf, len_bytes / 8);

	FILE *fp = fopen(path, "w");
	if (fp == NULL) {
		fprintf(stderr, "File %s could not be created", path);
		perror("");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < strlen(hexstring); ++i) {
		fputc(hexstring[i], fp);
		if (!(i + 1 % HEX_FILE_LINE_LEN)) {
			fputc('\r', fp);
			fputc('\n', fp);
		}
	}
	fclose(fp);
}

char* get_path(char* base_path, char* suffix1, char* suffix2)
{
	strncpy(path_buf, base_path, strlen(base_path) + 1);
	strcat(strcat(path_buf, suffix1), suffix2);
	return path_buf;
}

void write_files(uint8_t *plain, uint8_t *crc, uint8_t *cc, uint8_t *il_facch,
                 uint8_t *il_xcch, uint8_t *burstmap_facch,
                 uint8_t *burstmap_xcch)
{

	if (plain) {
		write_file(get_path(data_path, SUFFIX_FACCH,
		SUFFIX_PLAIN),
		           plain, LEN_PLAIN);
	}
	if (crc) {
		write_file(get_path(data_path, "", SUFFIX_CRC), crc,
		LEN_CRC + 4);
	}
	if (cc) {
		write_file(get_path(data_path, "", SUFFIX_CC), cc,
		LEN_CC);
	}
	if (il_xcch) {
		write_file(get_path(data_path, SUFFIX_XCCH,
		SUFFIX_INTERLEAVED),
		           il_xcch, LEN_INTERLEAVED_XCCH);
	}
	if (il_xcch) {
		write_file(get_path(data_path, SUFFIX_FACCH,
		SUFFIX_INTERLEAVED),
		           il_facch, LEN_INTERLEAVED_FACCH);
	}
	if (burstmap_xcch) {
		write_file(get_path(data_path, SUFFIX_XCCH,
		SUFFIX_BURSTMAP),
		           burstmap_xcch, LEN_BURSTMAP_XCCH);
	}
	if (burstmap_facch) {
		write_file(get_path(data_path, SUFFIX_FACCH,
		SUFFIX_BURSTMAP),
		           burstmap_facch, LEN_BURSTMAP_FACCH);
	}
}

int main(int argc, char **argv)
{

	uint8_t input_buf[input_len];
	uint8_t burstmap_xcch[LEN_BURSTMAP_XCCH / 8];
	uint8_t il_xcch[LEN_INTERLEAVED_XCCH / 8];
	uint8_t burstmap_facch[LEN_BURSTMAP_FACCH / 8];
	uint8_t il_facch[LEN_INTERLEAVED_FACCH / 8];
	uint8_t cc[LEN_CC / 8];
	// need an extra byte buffer as crc_len is not of factor 8 (tailing bits)
	uint8_t crc[(LEN_CRC + 8) / 8];
	uint8_t plain[LEN_PLAIN / 8];

	handle_options(argc, argv);

	parse_file(input_buf);

	set_mode();

	switch (mode) {
	case PLAIN_ENCODE:
		xcch_encode(PLAIN, input_buf, burstmap_xcch, il_xcch, cc, crc);
		facch_encode(PLAIN, input_buf, burstmap_facch, il_facch, NULL,
		NULL);
		write_files(NULL, crc, cc, il_facch, il_xcch, burstmap_facch,
		            burstmap_xcch);
		break;
	case CRC_ENCODE:
		xcch_encode(CRC, input_buf, burstmap_xcch, il_xcch, cc, NULL);
		facch_encode(CRC, input_buf, burstmap_facch, il_facch, NULL,
		             NULL);
		write_files(NULL, NULL, cc, il_facch, il_xcch, burstmap_facch,
		            burstmap_xcch);
		break;
	case CC_ENCODE:
		xcch_encode(CC, input_buf, burstmap_xcch, il_xcch, NULL, NULL);
		facch_encode(CC, input_buf, burstmap_facch, il_facch, NULL,
		             NULL);
		write_files(NULL, NULL, NULL, il_facch, il_xcch, burstmap_facch,
		            burstmap_xcch);
		break;
	case IL_ENCODE_XCCH:
		xcch_encode(IL_XCCH, input_buf, burstmap_xcch, NULL, NULL,
		            NULL);
		write_files(NULL, NULL, NULL, NULL, NULL, NULL, burstmap_xcch);
		break;
	case IL_ENCODE_FACCH:
		xcch_encode(IL_FACCH, input_buf, burstmap_facch, NULL, NULL,
		            NULL);
		write_files(NULL, NULL, NULL, NULL, NULL, burstmap_facch,
		NULL);
		break;
	case CRC_DECODE:
		xcch_decode(CC, input_buf, NULL, NULL, NULL, plain);
		write_files(plain, NULL, NULL, NULL, NULL, NULL, NULL);
		break;
	case CC_DECODE:
		xcch_decode(CC, input_buf, NULL, NULL, crc, plain);
		write_files(plain, crc, NULL, NULL, NULL, NULL, NULL);
		break;
	case IL_DECODE_XCCH:
		xcch_decode(IL_FACCH, input_buf, NULL, cc, crc, plain);
		write_files(plain, crc, cc, NULL, NULL, NULL, NULL);
		break;
	case IL_DECODE_FACCH:
		facch_decode(IL_FACCH, input_buf, NULL, cc, crc, plain);
		write_files(plain, crc, cc, NULL, NULL, NULL, NULL);
		break;
	case BURSTMAP_DECODE_XCCH:
		xcch_decode(BURSTMAP_XCCH, input_buf, il_xcch, cc, crc, plain);
		write_files(plain, crc, cc, NULL, il_xcch, NULL,
		NULL);
		break;
	case BURSTMAP_DECODE_FACCH:
		facch_decode(BURSTMAP_FACCH, input_buf, il_facch, cc, crc,
		             plain);
		write_files(plain, crc, cc, il_facch, NULL, NULL,
		NULL);
		break;
	case MODE_UNDEFINED:
		fprintf(stderr, "Invalid data length of %d - exit. ",
		        input_len);
		exit(EXIT_FAILURE);
		break;
	}
	return EXIT_SUCCESS;
}
