#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <virtphy/common_util.h>
#include <osmocom/core/gsmtap.h>
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

static char* dl_rx_grp = DEFAULT_DL_RX_GRP;
static char* dl_tx_grp = DEFAULT_DL_TX_GRP;
static char* ul_rx_grp = DEFAULT_UL_RX_GRP;
static char* ul_tx_grp = DEFAULT_UL_TX_GRP;
static int port = DEFAULT_MCAST_PORT;

static struct virt_um_inst *downlink = NULL;
static struct virt_um_inst *uplink = NULL;

static enum mitm_states {
	STATE_INTERCEPT_SABM, // Wait for SABM - CM Service Request
	STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD, // Wait for either SERVICE ACCEPT or CIPHERING MODE COMMAND
	STATE_INTERCEPT_SETUP, // Wait for SETUP message
	STATE_IMSI_CATCHER // we need to get the target imsi - tmsi mapping before we can go on with the attack. Basically we are an imsi catcher in this state.
} mitm_state = STATE_IMSI_CATCHER;

static enum mi_check_retval {
	MI_CHECK_VICTIM_SUBSCR,
	MI_CHECK_UNMAPPED_TMSI,
	MI_CHECK_OTHER_SUBSCR
};

static struct chan_desc {
	uint8_t type;
	uint8_t subchan;
	uint8_t timeslot;

} ded_chan;

static struct map_imsi_tmsi {
	char imsi[IMSI_MAX_DIGITS + 1];
	uint32_t tmsi;
	struct llist_head entry;
};

static struct pending_imsi_request {
	struct map_imsi_tmsi * map;
	struct chan_desc chan;
	uint8_t pending = 0;
} pending_imsi_req;

static int setup_burst_counter = 0;

static uint32_t intercept_arfcn = 666;

static char imsi_victim[GSM_EXTENSION_LENGTH + 1] = "2926709347452663";
static char msisdn_victim[GSM_EXTENSION_LENGTH + 1] = "017519191919";
static char msisdn_called[GSM_EXTENSION_LENGTH + 1] = "017518181818";
static char msisdn_attacker[GSM_EXTENSION_LENGTH + 1] = "017517171717";


LLIST_HEAD(other_subscribers);

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

void manipulate_setup_message(uint8_t *msg) {
 // TODO: manipulate message
}

int mi_check(uint8_t *mi, uint8_t mi_len, struct map_imsi_tmsi *map) {
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		return strcmp(mi_string, imsi_victim) == 0 ? MI_CHECK_VICTIM_SUBSCR : MI_CHECK_OTHER_SUBSCR;
	case GSM_MI_TYPE_TMSI:
		llist_for_each_entry(map, other_subscribers, entry)
		{
			if (tmsi_from_string(mi_string) == map->tmsi) {
				// tmsi mapped to NULL
				if (map->imsi == NULL) {
					return MI_CHECK_UNMAPPED_TMSI;
				}
				// tmsi mapped to victims imsi
				else if (strcmp(map->imsi,
				                  imsi_victim)) {
					return MI_CHECK_VICTIM_SUBSCR;
				}
				// tmsi mapped to other imsi
				else {
					return MI_CHECK_OTHER_SUBSCR;
				}
			}
		}
		// tmsi not yet mapped -> create mapping to NULL
		map = talloc_zero(NULL, struct map_imsi_tmsi);
		map->tmsi = tmsi_from_string(mi_string);
		llist_add(map, other_subscribers);
		return MI_CHECK_UNMAPPED_TMSI;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
	default:
		// not interested in imei or any other identity type
		return MI_CHECK_OTHER_SUBSCR;
	}
}

static void downlink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)

	// ignore all downlink messages we do not want to intercept
	if (intercept_arfcn != arfcn) {
		// TODO implement handling. For now we say all traffic we intercept is from either attacked bts or ms
	}

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch (mitm_state) {
	case STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD:
		// check if the msg is received in a dedicated channel.
		// Can also be TCH/FACCH because of very early assignment
		if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_TCH_F) {

			uint8_t rsl_chantype, link_id, chan_nr;
			struct lapdm_msg_ctx mctx;
			struct lapd_msg_ctx lctx;

			memset(&mctx, 0, sizeof(mctx));
			memset(&lctx, 0, sizeof(lctx));

			chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
			chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);

			if(!pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx, &lctx)) {
				// lapdm context could not be properly parsed
				break;
			}

			// check if we have an information frame
			if(LAPDm_CTRL_is_I(lctx.format)) {
				struct gsm48_hdr *l3_hdr = msgb_l3(msg);

				// check if we have a MM msg
				if(l3_hdr->proto_discr == GSM48_PDISC_MM) {
					// of type service accept
					if(l3_hdr->msg_type == GSM48_MT_MM_CM_SERV_ACC) {
						mitm_state = STATE_INTERCEPT_SETUP;
						setup_burst_counter = 1;
					}
					// or ciphering request
					else if(l3_hdr->msg_type == GSM48_MT_RR_CIPH_M_CMD) {
						mitm_state = STATE_INTERCEPT_SETUP;
						setup_burst_counter = 2;
					}
				}
			}

		}
		break;
	default:
		break;
	}

	// push all the bits that have been pulled before so that we have l1 header at data pointer again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);

	// Forward msg to downlink
	virt_um_write_msg(downlink, msg);
}

static void uplink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	uint8_t encoded_msg[LEN_PLAIN / 8] = {0};
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)

	// ignore all downlink messages we do not want to intercept
	if (intercept_arfcn != arfcn) {
		// TODO implement handling. For now we say all traffic we intercept is from either attacked bts or ms
	}

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch(mitm_state) {
	case STATE_IMSI_CATCHER:
		if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8) {
			uint8_t rsl_chantype, link_id, chan_nr;
			struct lapdm_msg_ctx mctx;
			struct lapd_msg_ctx lctx;

			memset(&mctx, 0, sizeof(mctx));
			memset(&lctx, 0, sizeof(lctx));

			chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
			chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);

			if(pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx, &lctx)) {
				printf("Frame number %d: lapd context could not be retrieved...", gh->frame_number);
				break;
			}

			if(pending_imsi_req.pending) {
				//TODO: check for responses of the pending request and switch to intercept_sabm state if the victim was found and is mapped
				break;
			}

			// check if we have a unnumbered frame of type SABM
			if(LAPDm_CTRL_is_U(lctx.format) && (lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME)) {
				struct gsm48_hdr *l3_hdr = msgb_l3(msg);
				struct map_imsi_tmsi *mapped;

				// check if we have a MM CM service request
				if(l3_hdr->proto_discr == GSM48_PDISC_MM &&
				   l3_hdr->msg_type == GSM48_MT_MM_CM_SERV_REQ) {
					struct gsm48_service_request *sreq = (struct gsm48_service_request *) l3_hdr->data;

					switch(mi_check(sreq->mi, sreq->mi_len, &mapped)) {
					case MI_CHECK_VICTIM_SUBSCR:

						break;
					case MI_CHECK_UNMAPPED_TMSI:
						pending_imsi_req.map = mapped;
						pending_imsi_req.chan = ded_chan;
						// send imsi identity request to subscriber to get the imsi-tmsi mapping for him
						tx_identity_req();
						break;
					case MI_CHECK_OTHER_SUBSCR:
						// we are not interested in cm requests of subscribers other than victim
						break;
					}
				}
			}
		}
		break;
	case STATE_INTERCEPT_SABM:
		// check if the msg is received in a dedicated channel.
		// Can also be TCH/FACCH because of very early assignment
		if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_TCH_F) {

			uint8_t rsl_chantype, link_id, chan_nr;
			struct lapdm_msg_ctx mctx;
			struct lapd_msg_ctx lctx;

			memset(&mctx, 0, sizeof(mctx));
			memset(&lctx, 0, sizeof(lctx));

			chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
			chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);

			if(pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx, &lctx)) {
				printf("Frame number %d: lapd context could not be retrieved...", gh->frame_number);
				break;
			}

			// check if we have a unnumbered frame of type SABM
			if(LAPDm_CTRL_is_U(lctx.format) && (lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME)) {
				struct gsm48_hdr *l3_hdr = msgb_l3(msg);
				struct map_imsi_tmsi *mapped;

				// check if we have a MM CM service request
				if(l3_hdr->proto_discr == GSM48_PDISC_MM &&
				   l3_hdr->msg_type == GSM48_MT_MM_CM_SERV_REQ) {
					struct gsm48_service_request *sreq = (struct gsm48_service_request *) l3_hdr->data;

					// check if we have a mobile originated call setup from our victim
					if(sreq->cm_service_type == GSM48_CMSERV_MO_CALL_PACKET
					   && mi_check(sreq->mi, sreq->mi_len) == MI_CHECK_VICTIM_SUBSCR) {
						// if we are here, we know that our victim requested a call establisment from the network
						ded_chan.type = gsmtap_chantype;
						ded_chan.timeslot = timeslot;
						ded_chan.subchan = subslot;
						mitm_state = STATE_INTERCEPT_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
					}
				}
			}
		}
	break;
	case STATE_INTERCEPT_SETUP:
		if(ded_chan.type == gsmtap_chantype && ded_chan.subchan == subslot && ded_chan.timeslot == timeslot) {
			// the third message on uplink after ciphering mode command should be the setup message
			// 1: LAPDM-Receive-Ready, 2: CIPHERING-MODE-COMPLETE, 3: SETUP
			if(++setup_burst_counter == 3) {
				// encode message as virtual layer does not support encoding right now
				xcch_encode(PLAIN, msgb_data(msg), encoded_msg, NULL, NULL, NULL);
				manipulate_setup_message(encoded_msg);
				xcch_decode(BURSTMAP_XCCH, encoded_msg, NULL, NULL, NULL, msgb_data(msg));
				mitm_state = STATE_INTERCEPT_SABM;
			}
		}
		// do nothing if the incoming msg is not on the synced channel
		break;
	default:
		break;
	}

	// push all the bits that have been pulled before so that we have l1 header at data pointer again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);
	// Forward msg to uplink
	virt_um_write_msg(uplink, msg);
}

/*
 * Just forward to test connection e.g.
 */
static void uplink_rcv_cb_simple_forward(struct virt_um_inst *vui, struct msgb *msg) {
	virt_um_write_msg(uplink, msg);
}

/*
 * Just forward to test connection e.g.
 */
static void downlink_rcv_cb_simple_forward(struct virt_um_inst *vui, struct msgb *msg) {
	virt_um_write_msg(downlink, msg);
}

int main(int argc, char **argv)
{
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
