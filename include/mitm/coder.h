#pragma once

#include <osmocom/core/bits.h>
#include <osmocom/core/crcgen.h>

#define LEN_PLAIN (184)
#define LEN_CRC (LEN_PLAIN + 40 + 4)
#define LEN_CC (4 * 114)
#define LEN_INTERLEAVED_XCCH (4 * 114)
#define LEN_INTERLEAVED_FACCH (8 * 114)
#define LEN_BURSTMAP_XCCH (4 * 116)
#define LEN_BURSTMAP_FACCH (8 * 116)
#define MAX_DATA_LEN LEN_BURSTMAP_FACCH

/**
 * GSM SACCH, FACCH, BCCH, CBCH, PCH, AGCH, SDCCH parity (FIRE code)
 *
 * g(x) = (x^23 + 1)(x^17 + x^3 + 1)
 *      = x^40 + x^26 + x^23 + x^17 + x^3 + a1
 */
static const struct osmo_crc64gen_code gsm0503_fire_crc40 = {
	.bits = 40,
	.poly =	0x0004820009ULL,
	.init = 0x0000000000ULL,
	.remainder = 0xffffffffffULL
};

// DO NOT CHANGE ORDER!
enum data_type {
	PLAIN = 0,
	CRC,
	CC,
	IL_XCCH,
	IL_FACCH,
	BURSTMAP_XCCH,
	BURSTMAP_FACCH,
	DATA_TYPE_UNDEFINED
};

// GSM SACCH, FACCH, BCCH, CBCH, PCH, AGCH, SDCCH convolutional code defined in libosmocore/gsm/gsm0503_conv.c
extern const struct osmo_conv_code gsm0503_xcch;

/**
 * Encoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * type [in] data_type of input
 * input [in] pointer to the start of the message data.
 * burst_buf [out] buffer for generated burst data
 * il_buf [out] buffer for generated interleaved
 * cc_buf [out] buffer for generated convolutional coded data
 * crc_buf [out] buffer for data with generated crc parity bits and buf
 *
 */
int xcch_encode(const enum data_type type, const uint8_t *input,
                uint8_t *burst_buf, uint8_t *il_buf, uint8_t *cc_buf,
                uint8_t *crc_buf);

/**
 * Decoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * type [in] data_type of input
 * input [in] pointer to the start of the message data.
 * il_buf [out] buffer for generated interleaved
 * cc_buf [out] buffer for generated convolutional coded data
 * crc_buf [out] buffer for data with generated crc parity bits and buf
 * plain_buf [out] buffer for decoded plain data
 */
int xcch_decode(const enum data_type input_type, const uint8_t *input,
                uint8_t *il_buf, uint8_t *cc_buf, uint8_t *crc_buf,
                uint8_t *data_buf);

/**
 * Encoding for channel FACCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.2 in TS05.03
 *
 * type [in] data_type of input
 * input [in] pointer to the start of the message data.
 * burst_buf [out] buffer for generated burst data
 * il_buf [out] buffer for generated interleaved
 * cc_buf [out] buffer for generated convolutional coded data
 * crc_buf [out] buffer for data with generated crc parity bits and buf
 */
int facch_encode(const enum data_type type, const uint8_t *input,
                 uint8_t *burst_buf, uint8_t *il_buf, uint8_t *cc_buf,
                 uint8_t *crc_buf);

/**
 * Decoding for channel FACCH.
 *
 * Note: not the complete output bursts are filled with data,
 * only first 56 data bits of the first four bursts and second
 * 56 data bits of the last 4 bursts.
 *
 * @see 4.2 in TS05.03
 *
 * type [in] data_type of input
 * input [in] pointer to the start of the message data.
 * il_buf [out] buffer for generated interleaved
 * cc_buf [out] buffer for generated convolutional coded data
 * crc_buf [out] buffer for data with generated crc parity bits and buf
 * plain_buf [out] buffer for decoded plain data
 */
int facch_decode(const enum data_type input_type, const uint8_t *input,
                 uint8_t *il_buf, uint8_t *cc_buf, uint8_t *crc_buf,
                 uint8_t *data_buf);
