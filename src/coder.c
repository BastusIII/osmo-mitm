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

/**
 * GSM SACCH, FACCH, BCCH, CBCH, PCH, AGCH, SDCCH parity (FIRE code)
 *
 * g(x) = (x^23 + 1)(x^17 + x^3 + 1)
 *      = x^40 + x^26 + x^23 + x^17 + x^3 + a1
 */
static const struct osmo_crc64gen_code gsm0503_fire_crc40 = {
	.bits = 40,
	.poly = 0x0004820009ULL,
	.init = 0x0000000000ULL,
	.remainder = 0xffffffffffULL,
};

// GSM SACCH, FACCH, BCCH, CBCH, PCH, AGCH, SDCCH convolutional code defined in libosmocore/gsm/gsm0503_conv.c
extern const struct osmo_conv_code gsm0503_xcch;

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

	for (k=0; k<456; k++) {
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

	for (k=0; k<456; k++) {
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
		for (i=odd; i<57; i+=2)
			iB[i] = eB[i];
		for (i=58-odd; i<114; i+=2)
			iB[i] = eB[i+2];
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
		for (i=odd; i<57; i+=2)
			eB[i] = iB[i];
		for (i=58-odd; i<114; i+=2)
			eB[i+2] = iB[i];
	}

	if (h) {
		if (!odd)
			eB[58] = *h;
		else
			eB[57] = *h;
	}
}

/**
 * Encoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * burst_buf [out] has to be able to hold 4*116/8 bit generated bursts.
 * data [in] pointer to the start of the 184 bit message data.
 */
int xcch_encode(const uint8_t *data, uint8_t *burst_buf)
{
	int tail_index, i;
	ubit_t hu = 1, hl = 1;
	ubit_t uD[184+40+4]; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	ubit_t cD[4*114]; // buffer for convolutional coded data
	ubit_t iD[4*114]; // buffer for interleaved data
	ubit_t eD[4*116]; // buffer for the 4 * 116 bit mapped bursts

	// get unpacked bit buffer from message data
	osmo_pbit2ubit(uD, data, 184);

	// calculate and set firecode parity bits
	osmo_crc64gen_set_bits(&gsm0503_fire_crc40, uD, 184, &uD[184]);

	// set tailbits to 0
	for (tail_index = 224; tail_index <= 227; ++tail_index) {
		uD[tail_index] = 0;
	}

	// convolutional encode message data + parity bits + tail
	osmo_conv_encode(&gsm0503_xcch, uD, cD);

	// interleave convolutional coder output
	gsm0503_xcch_interleave(cD, iD);

	// map each data block on a burst. hl and hn are 1 for XCCH.
	for (i = 0; i < 4; i++) {
		gsm0503_xcch_burst_map(&iD[i * 114], &eD[i * 116], &hu,
		                       &hl);
	}

	osmo_ubit2pbit(burst_buf, eD, 4*116);
	return 0;
}

/**
 * Decoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * bursts [in] pointer to an array of the 4*116 ubit burst data.
 * data_buf [out] has to be able to hold 184 bit message data
 */
int xcch_decode(uint8_t *data_buf, const uint8_t *bursts)
{
	int i, crc_error;
	sbit_t hu, hl; // buffer for hl and hn values returned by unmapping
	ubit_t uD[184+40+4]; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	sbit_t cD[4*114]; // buffer for convolutional coded data
	sbit_t iD[4*114]; // buffer for interleaved data
	sbit_t eD[4*116]; // buffer for the 4 * 116 bit mapped bursts
	ubit_t eD_u[4*116]; // buffer for the 4 * 116 bit mapped bursts

	// convert ubits to sbits for further processing
	osmo_pbit2ubit(eD_u, bursts, 4*116);
	osmo_ubit2sbit(eD, eD_u, 4*116);

	for (i = 0; i < 4; i++) {
		// hu and hl can be savely ignored, they are always 1
		gsm0503_xcch_burst_unmap(&iD[i * 114], &eD[i * 116], &hu,
		                         &hl);
	}

	gsm0503_xcch_deinterleave(cD, iD);

	osmo_conv_decode(&gsm0503_xcch, cD, uD);

	crc_error = osmo_crc64gen_check_bits(&gsm0503_fire_crc40, uD, 184,
	                                     &uD[184]);

	// unpack bits to output buffer
	osmo_ubit2pbit(data_buf, uD, 184);

	return crc_error;
}

/**
 * Encoding for channel FACCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.2 in TS05.03
 *
 * burst_buf [out] has to be able to hold 8*116 ubits generated bursts.
 * data [in] pointer to the start of the 184 bit message data.
 */
int facch_encode(const uint8_t *data, uint8_t *burst_buf)
{
	int tail_index, i;
	ubit_t h = 1;
	ubit_t uD[184+40+4]; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	ubit_t cD[4*114]; // buffer for convolutional coded data
	ubit_t iD[8*116]; // buffer for interleaved data
	ubit_t eD[8*116] = {0}; // buffer for the 8 * 116 bit mapped bursts
	// TODO: it should not matter id eD is initialized with zeros, but it does change the outcome randomly! It probably has sth. to do with the interleavin and mapping to 8 blocks instead of 4.

	// get unpacked bit buffer from message data
	osmo_pbit2ubit(uD, data, 184);

	// calculate and set firecode parity bits
	osmo_crc64gen_set_bits(&gsm0503_fire_crc40, uD, 184, &uD[184]);

	// set tailbits to 0
	for (tail_index = 224; tail_index <= 227; ++tail_index) {
		uD[tail_index] = 0;
	}

	// convolutional encode message data + parity bits + tail
	osmo_conv_encode(&gsm0503_xcch, uD, cD);

	// interleave convolutional coder output
	gsm0503_tch_fr_interleave(cD, iD);

	// map each data block on a burst. h is 1 for facch.
	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_map(&iD[i * 114], &eD[i * 116], &h,
		                       i >= 4);
	}

	osmo_ubit2pbit(burst_buf, eD, 8 * 116);

	return 0;
}

/**
 * Decoding for channel FACCH.
 *
 * Note: not the complete output bursts are filled with data,
 * only first 56 data bits of the first four bursts and second
 * 56 data bits of the last 4 bursts.
 *
 * @see 4.2 in TS05.03
 *
 * bursts [in] pointer to an array of the 8*116 ubit burst data.
 * data_buf [out] has to be able to hold 184 bit message data
 */
int facch_decode(uint8_t *data_buf, const uint8_t *bursts)
{
	int i, crc_error, steal = 0;
	sbit_t h; // buffer for h, the stealing flag
	ubit_t uD[184+40+4]; // buffer for 184 bit data + 40 bits crc + 4 zero bits tail
	sbit_t cD[4*114]; // buffer for convolutional coded data
	sbit_t iD[8*114]; // buffer for interleaved data
	sbit_t eD[8*116]; // buffer for the 8 * 116 bit mapped bursts
	ubit_t eD_u[8*116]; // buffer for the 4 * 116 bit mapped bursts

	// convert ubits to sbits for further processing
	osmo_pbit2ubit(eD_u, bursts, 8*116);
	osmo_ubit2sbit(eD, eD_u, 8*116);

	for (i = 0; i < 8; i++) {
		// stealing flag should be set to 1 for facch
		gsm0503_tch_burst_unmap(&iD[i * 114], &eD[i * 116], &h,
		                         i >= 4);
		steal -= h;
	}

	gsm0503_tch_fr_deinterleave(cD, iD);

	if(steal <= 0) {
		fprintf(stderr, "error with stealing flags in FACCH");
		return 1;
	}
	// FACCH is encoded the same as the other signaling channels
	osmo_conv_decode(&gsm0503_xcch, cD, uD);

	crc_error = osmo_crc64gen_check_bits(&gsm0503_fire_crc40, uD, 184,
	                                     &uD[184]);

	// unpack bits to output buffer
	osmo_ubit2pbit(data_buf, uD, 184);

	return crc_error;
}
