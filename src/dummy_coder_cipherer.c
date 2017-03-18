#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <osmocom/core/utils.h>

#include <coder.h>
#include <cipherer.h>

#define SUFFIX_ENCODED ".enc"
#define SUFFIX_DECODED ".dec"
#define SUFFIX_XCCH ".xcch"
#define SUFFIX_FACCH ".facch"
#define HEX_FILE_LINE_LEN 32
#define MAX_DATA_LEN (8 * 116) // length of facch interleaved encoded bursts

static int ciphering = 1;
static char* data_path = "hex_data";
static int data_len = -1;


static enum mode {
	ENCODE_XCCH_FACCH,
	DECODE_XCCH,
	DECODE_FACCH,
	UNDEFINED
} mode = UNDEFINED;

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {{
		        "no-ciphering", no_argument, &ciphering, 0}, {
		        "data-path", required_argument, 0, 'p'},
		{0, 0, 0, 0}, };

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

void set_mode() {
	switch (data_len) {
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
	for (cbuf = fgetc(fp); i < max_hex_len && cbuf != EOF; cbuf = fgetc(fp)) {
		if (is_hex_char(cbuf)) {
			hexstring[i++] = cbuf;
		}
	}
	fclose(fp);
	data_len = i * 4; // one hex is 4 bit
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
		if(!(i+1 % HEX_FILE_LINE_LEN)) {
			fputc('\r', fp);
			fputc('\n', fp);
		}
	}
	fclose(fp);
}

int main(int argc, char **argv)
{

	uint8_t input_data_buf[data_len];
	uint8_t enc_bursts_xcch[4 * 116 / 8];
	uint8_t enc_bursts_facch[8 * 116 / 8];
	uint8_t dec_data[184 / 8];
	char path_buf[100];

	handle_options(argc, argv);

	parse_file(input_data_buf);

	set_mode();

	switch (mode) {
	case ENCODE_XCCH_FACCH:
		xcch_encode(input_data_buf, enc_bursts_xcch);
		facch_encode(input_data_buf, enc_bursts_facch);
		if (ciphering) {
			// TODO encrypt the coded data buffers
		}
		strncpy(path_buf, data_path, strlen(data_path) + 1);
		write_file(strcat(strcat(path_buf, SUFFIX_XCCH), SUFFIX_ENCODED),
		           enc_bursts_xcch, 4 * 116);
		strncpy(path_buf, data_path, strlen(data_path) + 1);
		write_file(strcat(strcat(path_buf, SUFFIX_FACCH), SUFFIX_ENCODED),
		           enc_bursts_facch, 8 * 116);
		break;
	case DECODE_XCCH:
		if (ciphering) {
			// TODO decipher the input data buffer
		}
		xcch_decode(dec_data, input_data_buf);
		write_file(strcat(strcat(data_path, SUFFIX_XCCH), SUFFIX_DECODED),
				           dec_data, 184);
		break;
	case DECODE_FACCH:
		if (ciphering) {
			// TODO decipher the input data buffer
		}
		// encoding as facch
		facch_decode(dec_data, input_data_buf);
		write_file(strcat(strcat(data_path, SUFFIX_FACCH), SUFFIX_DECODED),
				           dec_data, 184);
		break;
	case UNDEFINED:
		fprintf(stderr, "Invalid data length of %d - exit. ", data_len);
	        exit(EXIT_FAILURE);
		break;
	}
	// not reached
	return EXIT_SUCCESS;
}
