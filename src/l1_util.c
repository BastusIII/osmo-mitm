#include <stdint.h>

#include <mitm/l1_util.h>

int is_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type) {
	return chan->chan_type == chan_type && chan->subchan == subslot && chan->timeslot == timeslot;
}

void set_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type) {
	chan->chan_type = chan_type;
	chan->timeslot = timeslot;
	chan->subchan = subslot;
}
