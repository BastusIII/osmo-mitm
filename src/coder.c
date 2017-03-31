/*
 * coder.c
 *
 *  Created on: Mar 16, 2017
 *      Author: basti
 */

#include <stddef.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
#include <osmocom/core/crcgen.h>

#include <coder.h>

/**
 * @see osmo-bts-trx/gsm0503_interleaving.c
 */
void gsm0503_xcch_deinterleave(sbit_t *cB, const sbit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 3;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		cB[k] = iB[B * 114 + j];
	}
}

/**
 * @see osmo-bts-trx/gsm0503_interleaving.c
 */
void gsm0503_xcch_interleave(ubit_t *cB, ubit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 3;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		iB[B * 114 + j] = cB[k];
	}
}

/**
 * @see osmo-bts-trx/gsm0503_interleaving.c
 */
void gsm0503_tch_fr_deinterleave(sbit_t *cB, sbit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 7;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		cB[k] = iB[B * 114 + j];
	}
}

/**
 * @see osmo-bts-trx/gsm0503_interleaving.c
 */
void gsm0503_tch_fr_interleave(ubit_t *cB, ubit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 7;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		iB[B * 114 + j] = cB[k];
	}
}

/**
 * @see osmo-bts-trx/gsm0503_mapping.c
 */
void gsm0503_xcch_burst_unmap(sbit_t *iB, const sbit_t *eB, sbit_t *hu,
                              sbit_t *hl)
{
	memcpy(iB, eB, 57);
	memcpy(iB + 57, eB + 59, 57);

	if (hu)
		*hu = eB[57];

	if (hl)
		*hl = eB[58];
}

/**
 * @see osmo-bts-trx/gsm0503_mapping.c
 */
void gsm0503_xcch_burst_map(ubit_t *iB, ubit_t *eB, const ubit_t *hu,
                            const ubit_t *hl)
{
	memcpy(eB, iB, 57);
	memcpy(eB + 59, iB + 57, 57);

	if (hu)
		eB[57] = *hu;
	if (hl)
		eB[58] = *hl;
}

/**
 * @see osmo-bts-trx/gsm0503_mapping.c
 */
void gsm0503_tch_burst_unmap(sbit_t *iB, sbit_t *eB, sbit_t *h, int odd)
{
	int i;

	/* brainfuck: only copy even or odd bits */
	if (iB) {
		for (i = odd; i < 57; i += 2)
			iB[i] = eB[i];
		for (i = 58 - odd; i < 114; i += 2)
			iB[i] = eB[i + 2];
	}

	if (h) {
		if (!odd)
			*h = eB[58];
		else
			*h = eB[57];
	}
}

/**
 * @see osmo-bts-trx/gsm0503_mapping.c
 */
void gsm0503_tch_burst_map(ubit_t *iB, ubit_t *eB, const ubit_t *h, int odd)
{
	int i;

	/* brainfuck: only copy even or odd bits */
	if (eB) {
		for (i = odd; i < 57; i += 2)
			eB[i] = iB[i];
		for (i = 58 - odd; i < 114; i += 2)
			eB[i + 2] = iB[i];
	}

	if (h) {
		if (!odd)
			eB[58] = *h;
		else
			eB[57] = *h;
	}
}

int xcch_encode(const enum data_type type, const uint8_t *input,
                uint8_t *burst_buf, uint8_t *il_buf, uint8_t *cc_buf,
                uint8_t *crc_buf)
{
	int tail_index, i;
	ubit_t hu = 1, hl = 1;
	ubit_t uD[LEN_CRC] = {0}; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	ubit_t cD[LEN_CC] = {0}; // buffer for convolutional coded data
	ubit_t iD[LEN_INTERLEAVED_XCCH] = {0}; // buffer for interleaved data
	ubit_t eD[LEN_BURSTMAP_XCCH] = {0}; // buffer for the 4 * 116 bit mapped bursts

	// get unpacked bit buffer from message data
	switch (type) {
	case PLAIN:
		osmo_pbit2ubit(uD, input, LEN_PLAIN);
		break;
	case CRC:
		osmo_pbit2ubit(uD, input, LEN_CRC);
		break;
	case CC:
		osmo_pbit2ubit(cD, input, LEN_CC);
		break;
	case IL_XCCH:
		osmo_pbit2ubit(iD, input, LEN_INTERLEAVED_XCCH);
		break;
	default:
		fprintf(stderr, "Wrong input type");
		return -1;
	}
	if (type < CRC) {
		// calculate and set firecode parity bits
		osmo_crc64gen_set_bits(&gsm0503_fire_crc40, uD, LEN_PLAIN,
		                       &uD[LEN_PLAIN]);
		// set tailbits to 0
		for (tail_index = LEN_CRC - 4; tail_index <= LEN_CRC - 1;
		                ++tail_index) {
			uD[tail_index] = 0;
		}
	}
	if (type < CC) {
		// convolutional encode message data + parity bits + tail
		osmo_conv_encode(&gsm0503_xcch, uD, cD);
	}
	if (type < IL_XCCH) {
		// interleave convolutional coder output
		gsm0503_xcch_interleave(cD, iD);
	}
	if (type < BURSTMAP_XCCH) {
		// map each data block on a burst. hl and hn are 1 for XCCH.
		for (i = 0; i < 4; i++) {
			gsm0503_xcch_burst_map(&iD[i * 114], &eD[i * 116], &hu,
			                       &hl);
		}
	}

	osmo_ubit2pbit(burst_buf, eD, LEN_BURSTMAP_XCCH);

	if (il_buf) {
		osmo_ubit2pbit(il_buf, iD, LEN_INTERLEAVED_XCCH);
	}
	if (cc_buf) {
		osmo_ubit2pbit(cc_buf, cD, LEN_CC);
	}
	if (crc_buf) {
		osmo_ubit2pbit(crc_buf, uD, LEN_CRC);
	}

	return 0;
}

int xcch_decode(const enum data_type input_type, const uint8_t *input,
                uint8_t *il_buf, uint8_t *cc_buf, uint8_t *crc_buf,
                uint8_t *plain_buf)
{
	int i, crc_error;
	sbit_t hu, hl; // buffer for hl and hn values returned by unmapping
	ubit_t uD[LEN_CRC] = {0}; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	sbit_t cD[LEN_CC] = {0}; // buffer for convolutional coded data
	sbit_t iD[LEN_INTERLEAVED_FACCH] = {0}; // buffer for interleaved data
	sbit_t eD[LEN_BURSTMAP_XCCH] = {0}; // buffer for the 4 * 116 bit mapped bursts
	ubit_t buf[LEN_BURSTMAP_XCCH] = {0}; // buffer for the 4 * 116 bit mapped bursts

	// get unpacked bit buffer from message data
	switch (input_type) {
	case CRC:
		osmo_pbit2ubit(buf, input, LEN_CRC);
		break;
	case CC:
		osmo_pbit2ubit(buf, input, LEN_CC);
		// convert ubits to sbits for further processing
		osmo_ubit2sbit(cD, buf, LEN_CC);
		break;
	case IL_XCCH:
		osmo_pbit2ubit(buf, input, LEN_INTERLEAVED_XCCH);
		osmo_ubit2sbit(iD, buf, LEN_INTERLEAVED_XCCH);
		break;
	case BURSTMAP_XCCH:
		osmo_pbit2ubit(buf, input, LEN_BURSTMAP_XCCH);
		osmo_ubit2sbit(eD, buf, LEN_BURSTMAP_XCCH);
		break;
	default:
		fprintf(stderr, "Wrong input type");
		return -1;
	}

	if (input_type > IL_XCCH) {
		for (i = 0; i < 4; i++) {
			// hu and hl can be savely ignored, they are always 1
			gsm0503_xcch_burst_unmap(&iD[i * 114], &eD[i * 116],
			                         &hu, &hl);
		}
	}
	if (input_type > CC) {
		gsm0503_xcch_deinterleave(cD, iD);
	}
	if (input_type > CRC) {
		osmo_conv_decode(&gsm0503_xcch, cD, uD);
	}
	if (input_type > PLAIN) {
		crc_error = osmo_crc64gen_check_bits(&gsm0503_fire_crc40, uD,
		LEN_PLAIN,
		                                     &uD[LEN_PLAIN]);
	}
	// unpack bits to output buffer
	osmo_ubit2pbit(plain_buf, uD, LEN_PLAIN);

	if (il_buf) {
		osmo_sbit2ubit(buf, iD, LEN_INTERLEAVED_XCCH);
		osmo_ubit2pbit(il_buf, buf, LEN_INTERLEAVED_XCCH);
	}
	if (cc_buf) {
		osmo_sbit2ubit(buf, cD, LEN_CC);
		osmo_ubit2pbit(cc_buf, buf, LEN_CC);
	}
	if (crc_buf) {
		osmo_ubit2pbit(crc_buf, uD, LEN_CRC);
	}

	return crc_error;
}

int facch_encode(const enum data_type type, const uint8_t *input,
                 uint8_t *burst_buf, uint8_t *il_buf, uint8_t *cc_buf,
                 uint8_t *crc_buf)
{
	int tail_index, i;
	ubit_t h = 1;
	ubit_t uD[LEN_CRC] = {0}; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	ubit_t cD[LEN_CC] = {0}; // buffer for convolutional coded data
	ubit_t iD[LEN_INTERLEAVED_FACCH] = {0}; // buffer for interleaved data
	ubit_t eD[LEN_BURSTMAP_FACCH] = {0}; // buffer for the 8 * 116 bit mapped bursts

	// get unpacked bit buffer from message data
	switch (type) {
	case PLAIN:
		osmo_pbit2ubit(uD, input, LEN_PLAIN);
		break;
	case CRC:
		osmo_pbit2ubit(uD, input, LEN_CRC);
		break;
	case CC:
		osmo_pbit2ubit(cD, input, LEN_CC);
		break;
	case IL_FACCH:
		osmo_pbit2ubit(iD, input, LEN_INTERLEAVED_FACCH);
		break;
	default:
		fprintf(stderr, "Wrong input type");
		return -1;
	}
	if (type < CRC) {
		// calculate and set firecode parity bits
		osmo_crc64gen_set_bits(&gsm0503_fire_crc40, uD, LEN_PLAIN,
		                       &uD[LEN_PLAIN]);
		// set tailbits to 0
		for (tail_index = LEN_CRC - 4; tail_index <= LEN_CRC - 1;
		                ++tail_index) {
			uD[tail_index] = 0;
		}
	}
	if (type < CC) {
		// convolutional encode message data + parity bits + tail
		osmo_conv_encode(&gsm0503_xcch, uD, cD);
	}
	if (type < IL_FACCH) {
		// interleave convolutional coder output
		gsm0503_tch_fr_interleave(cD, iD);
	}
	if (type < BURSTMAP_FACCH) {
		// map each data block on a burst. h is 1 for facch.
		for (i = 0; i < 8; i++) {
			gsm0503_tch_burst_map(&iD[i * 114], &eD[i * 116], &h,
			                      i >= 4);
		}
	}

	osmo_ubit2pbit(burst_buf, eD, LEN_BURSTMAP_FACCH);

	if (il_buf) {
		osmo_ubit2pbit(il_buf, iD, LEN_INTERLEAVED_FACCH);
	}
	if (cc_buf) {
		osmo_ubit2pbit(cc_buf, cD, LEN_CC);
	}
	if (crc_buf) {
		osmo_ubit2pbit(crc_buf, uD, LEN_CRC);
	}

	return 0;
}

int facch_decode(const enum data_type input_type, const uint8_t *input,
                 uint8_t *il_buf, uint8_t *cc_buf, uint8_t *crc_buf,
                 uint8_t *data_buf)
{
	int i, crc_error, steal = 0;
	sbit_t h; // buffer for h, the stealing flag
	ubit_t uD[LEN_CRC] = {0}; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	sbit_t cD[LEN_CC] = {0}; // buffer for convolutional coded data
	sbit_t iD[LEN_INTERLEAVED_FACCH] = {0}; // buffer for interleaved data
	sbit_t eD[LEN_BURSTMAP_FACCH] = {0}; // buffer for the 8 * 116 bit mapped bursts
	ubit_t buf[LEN_BURSTMAP_FACCH] = {0}; // buffer for the 4 * 116 bit mapped bursts

	// get unpacked bit buffer from message data
	switch (input_type) {
	case CRC:
		osmo_pbit2ubit(buf, input, LEN_CRC);
		break;
	case CC:
		osmo_pbit2ubit(buf, input, LEN_CC);
		// convert ubits to sbits for further processing
		osmo_ubit2sbit(cD, buf, LEN_CC);
		break;
	case IL_FACCH:
		osmo_pbit2ubit(buf, input, LEN_INTERLEAVED_FACCH);
		osmo_ubit2sbit(iD, buf, LEN_INTERLEAVED_FACCH);
		break;
	case BURSTMAP_FACCH:
		osmo_pbit2ubit(buf, input, LEN_BURSTMAP_FACCH);
		osmo_ubit2sbit(eD, buf, LEN_BURSTMAP_FACCH);
		break;
	default:
		fprintf(stderr, "Wrong input type");
		return -1;
	}

	if (input_type > IL_FACCH) {
		for (i = 0; i < 8; i++) {
			// stealing flag should be set to 1 for facch
			gsm0503_tch_burst_unmap(&iD[i * 114], &eD[i * 116], &h,
			                        i >= 4);
			steal -= h;

		}
		if (steal <= 0) {
			fprintf(stderr, "error with stealing flags in FACCH");
			return 1;
		}
	}
	if (input_type > CC) {
		gsm0503_tch_fr_deinterleave(cD, iD);
	}
	if (input_type > CRC) {
		// FACCH is encoded the same as the other signaling channels
		osmo_conv_decode(&gsm0503_xcch, cD, uD);
	}
	if (input_type > PLAIN) {
		crc_error = osmo_crc64gen_check_bits(&gsm0503_fire_crc40, uD,
		LEN_PLAIN,
		                                     &uD[LEN_PLAIN]);
	}
	// unpack bits to output buffer
	osmo_ubit2pbit(data_buf, uD, LEN_PLAIN);

	if (il_buf) {
		osmo_sbit2ubit(buf, iD, LEN_INTERLEAVED_FACCH);
		osmo_ubit2pbit(il_buf, buf, LEN_INTERLEAVED_FACCH);
	}
	if (cc_buf) {
		osmo_sbit2ubit(buf, cD, LEN_CC);
		osmo_ubit2pbit(cc_buf, buf, LEN_CC);
	}
	if (crc_buf) {
		osmo_ubit2pbit(crc_buf, uD, LEN_CRC);
	}

	return crc_error;
}
