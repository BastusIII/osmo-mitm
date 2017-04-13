#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

#define IMSI_MAX_DIGITS 15

struct map_imsi_tmsi {
	char imsi[IMSI_MAX_DIGITS + 1];
	uint32_t tmsi;
	struct llist_head entry;
};

struct map_imsi_tmsi* get_subscriber(uint8_t *mi, int mi_len);
struct map_imsi_tmsi* add_subscriber(uint8_t *mi, int mi_len);
int is_subscriber(struct map_imsi_tmsi *subscriber, uint8_t *mi, int mi_len);
int update_subscriber(struct map_imsi_tmsi *subscriber, uint8_t *mi, int mi_len);
int get_mi_type(uint8_t *mi);
