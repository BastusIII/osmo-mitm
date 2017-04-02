#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap_util.h>
#include <coder.h>

#define DEFAULT_DL_RX_GRP DEFAULT_MS_MCAST_GROUP
#define DEFAULT_DL_TX_GRP "226.0.0.1"
#define DEFAULT_UL_RX_GRP "226.0.0.2"
#define DEFAULT_UL_TX_GRP DEFAULT_BTS_MCAST_GROUP
#define DEFAULT_MCAST_PORT 4729 /* IANA-registered port for GSMTAP */

static char* dl_rx_grp = DEFAULT_DL_RX_GRP;
static char* dl_tx_grp = DEFAULT_DL_TX_GRP;
static char* ul_rx_grp = DEFAULT_UL_RX_GRP;
static char* ul_tx_grp = DEFAULT_UL_TX_GRP;
static int port = DEFAULT_MCAST_PORT;

static struct virt_um_inst *downlink = NULL;
static struct virt_um_inst *uplink = NULL;

static enum mitm_states {
	STATE_RACH = 0, // Wait for RACH
	STATE_IMM_ASS, // Wait for IMMEDIATE ASSIGNMENT
	STATE_SABM_SERVICE_REQ, // Wait for SABM with CM SERVICE REQUEST
	STATE_SABM_UA, // Wait for UA for SABM
	STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD, // Wait for either SERVICE ACCEPT or CIPHERING MODE COMMAND
	/* msgs are probably encrypted from here */
	STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD_RR, // Wait for Lapdm RECEIVE READY after SERVICE ACCEPT or CIPHERING MODE COMMAND
	STATE_SETUP, // Wait for SETUP message
} mitm_state = STATE_RACH;

// history of rancom acces request references sent on RACH
static struct gsm48_req_ref cr_req_ref_hist[3];

static struct chan_desc {
	uint8_t type;
	uint8_t subchan;
	uint8_t timeslot;

} synced_chan;
static int setup_burst_counter = 0;

/* match request reference agains request history */
static int gsm48_match_ra(struct gsm48_req_ref *ref)
{
	int i;
	uint8_t ia_t1, ia_t2, ia_t3;
	uint8_t cr_t1, cr_t2, cr_t3;

	for (i = 0; i < 3; i++) {
		/* filter confirmed RACH requests only */
		if (cr_req_ref_hist[i].ra && ref->ra == cr_req_ref_hist[i].ra) {
		 	ia_t1 = ref->t1;
		 	ia_t2 = ref->t2;
		 	ia_t3 = (ref->t3_high << 3) | ref->t3_low;
			ref = &cr_req_ref_hist[i];
		 	cr_t1 = ref->t1;
		 	cr_t2 = ref->t2;
		 	cr_t3 = (ref->t3_high << 3) | ref->t3_low;
			if (ia_t1 == cr_t1 && ia_t2 == cr_t2
			 && ia_t3 == cr_t3) {
				return 1;
			}
		}
	}

	return 0;
}

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

static void downlink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch (mitm_state) {
	case STATE_IMM_ASS:
		if ((gsmtap_chantype & ~GSMTAP_CHANNEL_ACCH & 0xff) == GSMTAP_CHANNEL_AGCH ||
		    (gsmtap_chantype & ~GSMTAP_CHANNEL_ACCH & 0xff) == GSMTAP_CHANNEL_PCH) {
			struct gsm48_system_information_type_header *sih =
			                msgb_l2(msg);
			struct gsm48_imm_ass *ia;
			struct gsm48_imm_ass_ext *iae;
			int i;
			switch (sih->system_information) {
			case GSM48_MT_RR_IMM_ASS:
					ia = msgb_l2(msg);
					if(gsm48_match_ra(&ia->req_ref)) {
						rsl_dec_chan_nr(ia->chan_desc.chan_nr, &synced_chan.type, &synced_chan.subchan, &synced_chan.timeslot);
						synced_chan.type = chantype_rsl2gsmtap(synced_chan.type, 0);
						mitm_state = STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
					}
					break;
				case GSM48_MT_RR_IMM_ASS_EXT:
					iae = msgb_l2(msg);
					if(gsm48_match_ra(&iae->req_ref1)) {
						rsl_dec_chan_nr(iae->chan_desc1.chan_nr, &synced_chan.type, &synced_chan.subchan, &synced_chan.timeslot);
						mitm_state = STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
					}else if(gsm48_match_ra(&iae->req_ref2)) {
						rsl_dec_chan_nr(iae->chan_desc2.chan_nr, &synced_chan.type, &synced_chan.subchan, &synced_chan.timeslot);
						mitm_state = STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
					}
					break;
				}
			}
			// do nothing if the incoming msg is not on agch or pch
			break;
		case STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD:
			// TODO Implement CIPHERING MODE COMMAND action
			break;
		default:
			break;
	}

	msgb_push(msg, sizeof(*gh));
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

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch(mitm_state) {
		case STATE_RACH:
			// TODO Implement RACH action
			break;
		case STATE_SETUP:
			if(synced_chan.type == gsmtap_chantype && synced_chan.subchan == subslot && synced_chan.timeslot == timeslot) {
				// the third message on uplink after ciphering mode command should be the setup message
				// 1: LAPDM-Receive-Ready, 2: CIPHERING-MODE-COMPLETE, 3: SETUP
				if(++setup_burst_counter == 3) {
					// encode message as virtual layer does not support encoding right now
					xcch_encode(PLAIN, msgb_data(msg), encoded_msg, NULL, NULL, NULL);
					manipulate_setup_message(encoded_msg);
					xcch_decode(BURSTMAP_XCCH, encoded_msg, NULL, NULL, NULL, msgb_data(msg));
					mitm_state = STATE_RACH;
				}
				// TODO: What is if this fails?
			}
			// do nothing if the incoming msg is not on the synced channel
			break;
	}

	msgb_push(msg, sizeof(*gh));
	// Forward msg to uplink
	virt_um_write_msg(uplink, msg);

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

void manipulate_setup_message(uint8_t *msg) {
 // TODO: manipulate message
}
