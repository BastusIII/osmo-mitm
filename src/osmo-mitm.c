#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap_util.h>
#include <osmocom/gsm/lapd_core.h>
#include <osmocom/gsm/lapdm.h>
#include <coder.h>
#include <errno.h>
#include <string.h>

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

/* TS 04.06 Figure 4 / Section 3.2 */
#define LAPDm_LPD_NORMAL  0
#define LAPDm_LPD_SMSCB	  1
#define LAPDm_SAPI_NORMAL 0
#define LAPDm_SAPI_SMS	  3
#define LAPDm_ADDR(lpd, sapi, cr) ((((lpd) & 0x3) << 5) | (((sapi) & 0x7) << 2) | (((cr) & 0x1) << 1) | 0x1)

#define LAPDm_ADDR_LPD(addr) (((addr) >> 5) & 0x3)
#define LAPDm_ADDR_SAPI(addr) (((addr) >> 2) & 0x7)
#define LAPDm_ADDR_CR(addr) (((addr) >> 1) & 0x1)
#define LAPDm_ADDR_EA(addr) ((addr) & 0x1)

/* TS 04.06 Table 3 / Section 3.4.3 */
#define LAPDm_CTRL_I(nr, ns, p)	((((nr) & 0x7) << 5) | (((p) & 0x1) << 4) | (((ns) & 0x7) << 1))
#define LAPDm_CTRL_S(nr, s, p)	((((nr) & 0x7) << 5) | (((p) & 0x1) << 4) | (((s) & 0x3) << 2) | 0x1)
#define LAPDm_CTRL_U(u, p)	((((u) & 0x1c) << (5-2)) | (((p) & 0x1) << 4) | (((u) & 0x3) << 2) | 0x3)

#define LAPDm_CTRL_is_I(ctrl)	(((ctrl) & 0x1) == 0)
#define LAPDm_CTRL_is_S(ctrl)	(((ctrl) & 0x3) == 1)
#define LAPDm_CTRL_is_U(ctrl)	(((ctrl) & 0x3) == 3)

#define LAPDm_CTRL_U_BITS(ctrl)	((((ctrl) & 0xC) >> 2) | ((ctrl) & 0xE0) >> 3)
#define LAPDm_CTRL_PF_BIT(ctrl)	(((ctrl) >> 4) & 0x1)

#define LAPDm_CTRL_S_BITS(ctrl)	(((ctrl) & 0xC) >> 2)

#define LAPDm_CTRL_I_Ns(ctrl)	(((ctrl) & 0xE) >> 1)
#define LAPDm_CTRL_Nr(ctrl)	(((ctrl) & 0xE0) >> 5)

#define LAPDm_LEN(len)	((len << 2) | 0x1)
#define LAPDm_MORE	0x2
#define LAPDm_EL	0x1

#define LAPDm_U_UI	0x0

/* TS 04.06 Section 5.8.3 */
#define N201_AB_SACCH		18
#define N201_AB_SDCCH		20
#define N201_AB_FACCH		20
#define N201_Bbis		23
#define N201_Bter_SACCH		21
#define N201_Bter_SDCCH		23
#define N201_Bter_FACCH		23
#define N201_B4			19

enum lapdm_format {
	LAPDm_FMT_A,
	LAPDm_FMT_B,
	LAPDm_FMT_Bbis,
	LAPDm_FMT_Bter,
	LAPDm_FMT_B4,
};

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
static uint32_t intercept_arfcn = 666;

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

/* input into layer2 (from layer 1) */
static int pull_lapd_ctx(struct msgb *msg,
	uint8_t chan_nr, uint8_t link_id, enum lapdm_mode mode, struct lapdm_msg_ctx *mctx, struct lapd_msg_ctx *lctx)
{
	uint8_t cbits = chan_nr >> 3;
	int n201;

	/* when we reach here, we have a msgb with l2h pointing to the raw
	 * 23byte mac block. The l1h has already been purged. */

	mctx->chan_nr = chan_nr;
	mctx->link_id = link_id;

	/* check for L1 chan_nr/link_id and determine LAPDm hdr format */
	if (cbits == 0x10 || cbits == 0x12) {
		/* Format Bbis is used on BCCH and CCCH(PCH, NCH and AGCH) */
		mctx->lapdm_fmt = LAPDm_FMT_Bbis;
		n201 = N201_Bbis;
	} else {
		if (mctx->link_id & 0x40) {
			/* It was received from network on SACCH */

			/* If UI on SACCH sent by BTS, lapdm_fmt must be B4 */
			if (mode == LAPDM_MODE_MS
			 && LAPDm_CTRL_is_U(msg->l2h[3])
			 && LAPDm_CTRL_U_BITS(msg->l2h[3]) == 0) {
				n201 = N201_B4;
				mctx->lapdm_fmt = LAPDm_FMT_B4;
			} else {
				n201 = N201_AB_SACCH;
				mctx->lapdm_fmt = LAPDm_FMT_B;
			}
			/* SACCH frames have a two-byte L1 header that
			 * OsmocomBB L1 doesn't strip */
			mctx->tx_power_ind = msg->l2h[0] & 0x1f;
			mctx->ta_ind = msg->l2h[1];
			msg->l2h = msgb_pull(msg, 2);
		} else {
			n201 = N201_AB_SDCCH;
			mctx->lapdm_fmt = LAPDm_FMT_B;
		}
	}

	switch (mctx->lapdm_fmt) {
	case LAPDm_FMT_A:
	case LAPDm_FMT_B:
	case LAPDm_FMT_B4:
		// We are not interested in the actual datalink here
		lctx->dl = NULL;
		/* obtain SAPI from address field */
		mctx->link_id |= LAPDm_ADDR_SAPI(msg->l2h[0]);
		/* G.2.3 EA bit set to "0" is not allowed in GSM */
		if (!LAPDm_ADDR_EA(msg->l2h[0])) {
			return -EINVAL;
		}
		/* adress field */
		lctx->lpd = LAPDm_ADDR_LPD(msg->l2h[0]);
		lctx->sapi = LAPDm_ADDR_SAPI(msg->l2h[0]);
		lctx->cr = LAPDm_ADDR_CR(msg->l2h[0]);
		/* command field */
		if (LAPDm_CTRL_is_I(msg->l2h[1])) {
			lctx->format = LAPD_FORM_I;
			lctx->n_send = LAPDm_CTRL_I_Ns(msg->l2h[1]);
			lctx->n_recv = LAPDm_CTRL_Nr(msg->l2h[1]);
		} else if (LAPDm_CTRL_is_S(msg->l2h[1])) {
			lctx->format = LAPD_FORM_S;
			lctx->n_recv = LAPDm_CTRL_Nr(msg->l2h[1]);
			lctx->s_u = LAPDm_CTRL_S_BITS(msg->l2h[1]);
		} else if (LAPDm_CTRL_is_U(msg->l2h[1])) {
			lctx->format = LAPD_FORM_U;
			lctx->s_u = LAPDm_CTRL_U_BITS(msg->l2h[1]);
		} else
			lctx->format = LAPD_FORM_UKN;
		lctx->p_f = LAPDm_CTRL_PF_BIT(msg->l2h[1]);
		if (lctx->sapi != LAPDm_SAPI_NORMAL
		 && lctx->sapi != LAPDm_SAPI_SMS
		 && lctx->format == LAPD_FORM_U
		 && lctx->s_u == LAPDm_U_UI) {
			/* 5.3.3 UI frames with invalid SAPI values shall be
			 * discarded
			 */
			return -EINVAL;
		}
		if (mctx->lapdm_fmt == LAPDm_FMT_B4) {
			lctx->n201 = n201;
			lctx->length = n201;
			lctx->more = 0;
			msg->l3h = msg->l2h + 2;
			msgb_pull_to_l3(msg);
		} else {
			/* length field */
			if (!(msg->l2h[2] & LAPDm_EL)) {
				/* G.4.1 If the EL bit is set to "0", an
				 * MDL-ERROR-INDICATION primitive with cause
				 * "frame not implemented" is sent to the
				 * mobile management entity. */
				return -EINVAL;
			}
			lctx->n201 = n201;
			lctx->length = msg->l2h[2] >> 2;
			lctx->more = !!(msg->l2h[2] & LAPDm_MORE);
			msg->l3h = msg->l2h + 3;
			msgb_pull_to_l3(msg);
		}
		break;
	case LAPDm_FMT_Bter:
		/* FIXME not implemented */
		return -EINVAL;
	case LAPDm_FMT_Bbis:
		/* directly pass up to layer3, we have no lapdm header in this case */
		msg->l3h = msg->l2h;
		msgb_pull_to_l3(msg);
		return -EINVAL;
	default:
		msgb_free(msg);
	}

	return 0;
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

	// ignore all downlink messages we do not want to intercept
	if (intercept_arfcn != arfcn) {
		goto freemsg;
	}

	switch (mitm_state) {
	case STATE_SERVICE_ACCEPT_CIPHERING_MODE_CMD:
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
						mitm_state = STATE_SETUP;
						setup_burst_counter = 1;
					}
					// or ciphering request
					else if(l3_hdr->msg_type == GSM48_MT_RR_CIPH_M_CMD) {
						mitm_state = STATE_SETUP;
						setup_burst_counter = 2;
					}
				}
			}

		}
		break;
	default:
		break;
	}

	msgb_push(msg, sizeof(*gh));
	// Forward msg to downlink
	virt_um_write_msg(downlink, msg);
	return;

freemsg:
	talloc_free(msg);

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

			// check if we have a unnumbered frame of type SABM
			if(LAPDm_CTRL_is_U(lctx.format) && (lctx.s_u == LAPD_U_SABM || lctx.s_u == LAPD_U_SABME)) {
				struct gsm48_hdr *l3_hdr = msgb_l3(msg);

				// check if we have a MM CM service request
				if(l3_hdr->proto_discr == GSM48_PDISC_MM &&
				   l3_hdr->msg_type == GSM48_MT_MM_CM_SERV_REQ) {
					struct gsm48_service_request *sreq = (struct gsm48_service_request *) l3_hdr->data;

					// check if we have a mobile originated call setup from our victim
					if(sreq->cm_service_type == GSM48_CMSERV_MO_CALL_PACKET
					   && ((*(uint32_t *)sreq->mi) == victim_tmsi || (*(uint64_t *)sreq->mi) == victim_imsi)) { // TODO: Mobile identity is somewhat encoded and cant be compared like this here
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
