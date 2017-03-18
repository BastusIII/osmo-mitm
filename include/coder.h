#pragma once

#include <osmocom/core/bits.h>

/**
 * Encoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * burst_buf [out] has to be able to hold 4*116 bit burst data
 * data [in] pointer to the start of the 184 bit message data.
 */
int xcch_encode(uint8_t *data, uint8_t *burst_buf);

/**
 * Decoding for channels SACCH, SDCCH, BCCH, PCH, AGCH.
 *
 * @see 4.1, 4.4, 4.5 in TS05.03
 *
 * bursts [in] pointer to an array of the 4*116 bit burst data.
 * data_buf [out] has to be able to hold 184 bit message data
 */
int xcch_decode(uint8_t *data_buf, uint8_t *bursts);

/**
 * Encoding for channel FACCH.
 * Will generate 4 bursts a 116 bit in the output buffer.
 *
 * @see 4.2 in TS05.03
 *
 * burst_buf [out] has to be able to hold 8*116 bit generated burst data.
 * data [in] pointer to the start of the 184 bit message data.
 */
int facch_encode(uint8_t *data, uint8_t *burst_buf);

/**
 * Decoding for channel FACCH.
 *
 * Note: not the complete output bursts are filled with data,
 * only first 56 data bits of the first four bursts and second
 * 56 data bits of the last 4 bursts.
 *
 * @see 4.2 in TS05.03
 *
 * bursts [in] pointer to an array of the 8*116 bit burst data.
 * data_buf [out] has to be able to hold 184 bit message data
 */
int facch_decode(uint8_t *data_buf, uint8_t *bursts);
