#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <osmocom/core/utils.h>

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
static char* data_path = "hex_data";
static int input_len = -1;
static int substep_output = 0;
static char path_buf[100];

static enum mode {
	ENCODE_XCCH_FACCH, DECODE_XCCH, DECODE_FACCH, UNDEFINED
} mode = UNDEFINED;

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {{
		        "no-ciphering", no_argument, &ciphering, 0}, {
		        "data-path", required_argument, 0, 'p'}, {
		        "substep-output", no_argument, &substep_output, 1}, {
		        0, 0, 0, 0}, };

		c = getopt_long(argc, argv, "p:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			data_path = optarg;
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
	case 184:
		mode = ENCODE_XCCH_FACCH;
		break;
	case 4 * 116:
		mode = DECODE_XCCH;
		break;
	case 8 * 116:
		mode = DECODE_FACCH;
		break;
	default:
		mode = UNDEFINED;
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

char* getPath(char* base_path, char* suffix1, char* suffix2)
{
	strncpy(path_buf, base_path, strlen(base_path) + 1);
	strcat(strcat(path_buf, suffix1), suffix2);
	return path_buf;
}

int main(int argc, char **argv)
{

	uint8_t input_data_buf[input_len];
	uint8_t burstmap_xcch[LEN_BURSTMAP_XCCH / 8];
	uint8_t il_xcch[LEN_INTERLEAVED_XCCH / 8];
	uint8_t burstmap_facch[LEN_BURSTMAP_FACCH / 8];
	uint8_t il_facch[LEN_INTERLEAVED_FACCH / 8];
	uint8_t cc[LEN_CC / 8];
	// need an extra byte buffer as crc_len is not of factor 8 (tailing bits)
	uint8_t crc[(LEN_CRC + 8) / 8];
	uint8_t plain[LEN_PLAIN / 8];

	handle_options(argc, argv);

	parse_file(input_data_buf);

	set_mode();

	switch (mode) {
	case ENCODE_XCCH_FACCH:
		xcch_encode(input_data_buf, burstmap_xcch, il_xcch, cc, crc);
		facch_encode(input_data_buf, burstmap_facch, il_facch, NULL,
		             NULL);
		if (ciphering) {
			// TODO encrypt the coded data buffers
		}
		write_file(getPath(data_path, SUFFIX_XCCH, SUFFIX_BURSTMAP),
		           burstmap_xcch, LEN_BURSTMAP_XCCH);
		write_file(getPath(data_path, SUFFIX_FACCH, SUFFIX_BURSTMAP),
		           burstmap_facch, LEN_BURSTMAP_FACCH);
		if (substep_output) {
			write_file(getPath(data_path, SUFFIX_XCCH,
			                   SUFFIX_INTERLEAVED),
			           il_xcch, LEN_INTERLEAVED_XCCH);
			write_file(getPath(data_path, SUFFIX_FACCH,
			                   SUFFIX_INTERLEAVED),
			           il_facch, LEN_INTERLEAVED_FACCH);
			write_file(getPath(data_path, "", SUFFIX_CC), cc,
			           LEN_CC);
			write_file(getPath(data_path, "", SUFFIX_CRC), crc,
			           LEN_CRC + 4);
		}
		break;
	case DECODE_XCCH:
		if (ciphering) {
			// TODO decipher the input data buffer
		}
		xcch_decode(plain, input_data_buf, il_xcch, cc, crc);
		write_file(getPath(data_path, SUFFIX_XCCH, SUFFIX_PLAIN), plain,
		           LEN_PLAIN);
		if (substep_output) {
			write_file(getPath(data_path, SUFFIX_XCCH,
			                   SUFFIX_INTERLEAVED),
			           il_xcch, LEN_INTERLEAVED_XCCH);
			write_file(getPath(data_path, "", SUFFIX_CC), cc,
			           LEN_CC);
			write_file(getPath(data_path, "", SUFFIX_CRC), crc,
			           LEN_CRC + 4);
		}
		break;
	case DECODE_FACCH:
		if (ciphering) {
			// TODO decipher the input data buffer
		}
		facch_decode(plain, input_data_buf, il_facch, cc, crc);
		write_file(getPath(data_path, SUFFIX_FACCH, SUFFIX_PLAIN),
		           plain, LEN_PLAIN);
		if (substep_output) {
			write_file(getPath(data_path, SUFFIX_FACCH,
			                   SUFFIX_INTERLEAVED),
			           il_facch, LEN_INTERLEAVED_FACCH);
			write_file(getPath(data_path, "", SUFFIX_CC), cc,
			           LEN_CC);
			write_file(getPath(data_path, "", SUFFIX_CRC), crc,
			           LEN_CRC + 4);
		}
		break;
	case UNDEFINED:
		fprintf(stderr, "Invalid data length of %d - exit. ",
		        input_len);
		exit(EXIT_FAILURE);
		break;
	}
	// not reached
	return EXIT_SUCCESS;
}
