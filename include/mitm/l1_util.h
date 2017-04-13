#pragma once

#include <stdint.h>

struct chan_desc {
	uint8_t chan_type;
	uint8_t subchan;
	uint8_t timeslot;
};

int is_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type);

void set_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type);
