#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/gsm/lapd_core.h>
#include <coder.h>

#define DEFAULT_DL_RX_GRP DEFAULT_MS_MCAST_GROUP
#define DEFAULT_DL_TX_GRP "226.0.0.1"
#define DEFAULT_UL_RX_GRP "226.0.0.2"
#define DEFAULT_UL_TX_GRP DEFAULT_BTS_MCAST_GROUP
#define DEFAULT_MCAST_PORT 4729 /* IANA-registered port for GSMTAP */

#define RA_EST_CAUSE_ORIG_CALL 0xd0
#define RA_MASK_3 0xd0

/* TS 04.06 Table 4 / Section 3.8.1 */
#define LAPD_U_SABM	0x7
#define LAPD_U_SABME	0xf
#define LAPD_U_DM	0x3
#define LAPD_U_UI	0x0
#define LAPD_U_DISC	0x8
#define LAPD_U_UA	0xC
#define LAPD_U_FRMR	0x11

#define LAPD_S_RR	0x0
#define LAPD_S_RNR	0x1
#define LAPD_S_REJ	0x2

static char* dl_rx_grp = DEFAULT_DL_RX_GRP;
static char* dl_tx_grp = DEFAULT_DL_TX_GRP;
static char* ul_rx_grp = DEFAULT_UL_RX_GRP;
static char* ul_tx_grp = DEFAULT_UL_TX_GRP;
static int port = DEFAULT_MCAST_PORT;

static struct virt_um_inst *downlink = NULL;
static struct virt_um_inst *uplink = NULL;

static enum mitm_states {
	STATE_SABM, // Wait for SABM - CM Service Request
	STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD, // Wait for either SERVICE ACCEPT or CIPHERING MODE COMMAND
	STATE_SETUP, // Wait for SETUP message
} mitm_state = STATE_SABM;

static struct chan_desc {
	uint8_t type;
	uint8_t subchan;
	uint8_t timeslot;

} ded_chan;

static int setup_burst_counter = 0;

static uint32_t victim_tmsi = 0x1ad86f62;
static uint64_t victim_imsi = 0x2926709347452663;

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

static void downlink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{
	struct gsmtap_hdr *gh = msgb_l1(msg);
	uint16_t arfcn = ntohs(gh->arfcn); // arfcn of the received msg
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch (mitm_state) {
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
	uint8_t gsmtap_chantype = gh->sub_type; // gsmtap channel type
	uint8_t subslot = gh->sub_slot; // multiframe subslot to send msg in (tch -> 0-26, bcch/ccch -> 0-51)
	uint8_t timeslot = gh->timeslot; // tdma timeslot to send in (0-7)

	msg->l2h = msgb_pull(msg, sizeof(*gh));

	switch(mitm_state) {
	case STATE_SABM:
		if (gsmtap_chantype == GSMTAP_CHANNEL_SDCCH4 ||
		    gsmtap_chantype == GSMTAP_CHANNEL_SDCCH8) {
			// TODO: parse l2 ctx from l2 hdr in msg
			struct lapd_msg_ctx lctx;

			// check if we have a sabm msg
			if(lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME) {
				// TODO: parse l3 hdr from msg
				struct gsm48_hdr l3_hdr;

				if(l3_hdr.proto_discr == GSM48_PDISC_MM &&
				   l3_hdr.msg_type == GSM48_MT_MM_CM_SERV_REQ) {
					// TODO: parse service request from msg
					struct gsm48_service_request sreq;
					if(sreq.cm_service_type == GSM48_CMSERV_MO_CALL_PACKET
					   && ((*(uint32_t *)sreq.mi) == victim_tmsi || (*(uint64_t *)sreq.mi) == victim_imsi)) { // TODO: Mobile identity is somewhat encoded and cant be compared like this here
						// if we are here, we know that our victim requested a call establisment from the network
						ded_chan.type = gsmtap_chantype;
						ded_chan.timeslot = timeslot;
						ded_chan.subchan = subslot;
						mitm_state = STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD;
					}
				}
			}
		}
		break;
		case STATE_SETUP:
			if(ded_chan.type == gsmtap_chantype && ded_chan.subchan == subslot && ded_chan.timeslot == timeslot) {
				// the third message on uplink after ciphering mode command should be the setup message
				// 1: LAPDM-Receive-Ready, 2: CIPHERING-MODE-COMPLETE, 3: SETUP
				if(++setup_burst_counter == 3) {
					// encode message as virtual layer does not support encoding right now
					xcch_encode(PLAIN, msgb_data(msg), encoded_msg, NULL, NULL, NULL);
					manipulate_setup_message(encoded_msg);
					xcch_decode(BURSTMAP_XCCH, encoded_msg, NULL, NULL, NULL, msgb_data(msg));
					mitm_state = STATE_SABM;
				}
				// TODO: What is if this fails?
			}
			// do nothing if the incoming msg is not on the synced channel
			break;
		default:
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
