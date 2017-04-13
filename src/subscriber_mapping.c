#include <string.h>
#include <talloc.h>
#include <stddef.h>
#include <stdint.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/linuxlist.h>

#include <mitm/subscriber_mapping.h>

#define tmsi_from_string(str) strtoul(str, NULL, 10)

static LLIST_HEAD(subscribers);

static struct map_imsi_tmsi* get_subscriber_ext(uint8_t *mi, int mi_len, int add) {

	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct map_imsi_tmsi* subscriber = NULL;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		llist_for_each_entry(subscriber, &subscribers, entry) {
			if (strcmp(mi_string, subscriber->imsi) == 0) {
				return subscriber;
			}
		}
		if(add) {
			// tmsi not yet mapped -> create mapping to NULL
			subscriber = talloc_zero(NULL, struct map_imsi_tmsi);
			strcpy(subscriber->imsi, mi_string);
			llist_add(&subscriber->entry, &subscribers);
		}
		break;
	case GSM_MI_TYPE_TMSI:
		llist_for_each_entry(subscriber, &subscribers, entry)
		{
			if (tmsi_from_string(mi_string) == subscriber->tmsi) {
				return subscriber;
			}
		}
		if(add) {
			// imsi not yet mapped -> create mapping to NULL
			subscriber = talloc_zero(NULL, struct map_imsi_tmsi);
			subscriber->tmsi = tmsi_from_string(mi_string);
			llist_add(&subscriber->entry, &subscribers);
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
	default:
		// not interested in imei or any other identity type
		break;
	}
	return subscriber;
}

struct map_imsi_tmsi* add_subscriber(uint8_t *mi, int mi_len) {
	return get_subscriber_ext(mi,mi_len, 1);
}

struct map_imsi_tmsi* get_subscriber(uint8_t *mi, int mi_len) {
	return get_subscriber_ext(mi,mi_len, 0);
}

int is_subscriber(struct map_imsi_tmsi *subscriber, uint8_t *mi, int mi_len)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		return strcmp(mi_string, subscriber->imsi) == 0;
	case GSM_MI_TYPE_TMSI:
		return tmsi_from_string(mi_string) == subscriber->tmsi;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
	default:
		// not supported
		break;
	}
	return 0;
}

int update_subscriber(struct map_imsi_tmsi *subscriber, uint8_t *mi, int mi_len)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		strcpy(subscriber->imsi, mi_string);
		return 1;
	case GSM_MI_TYPE_TMSI:
		subscriber->tmsi = tmsi_from_string(mi_string);
		return 1;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
	default:
		// not supported
		break;
	}
	return 0;
}

int get_mi_type(uint8_t *mi) {
	return mi[0] & GSM_MI_TYPE_MASK;;
}
