#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <virtphy/virtual_um.h>
#include <mitm/osmo_mitm.h>


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

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"dl-rx-grp", 1, 0, 'w'},
			{"dl-tx-grp", 1, 0, 'x'},
		        {"ul-rx-grp", 1, 0, 'y'},
		        {"ul-tx-grp", 1, 0, 'z'},
		        {0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "z:y:x:w:", long_options,
		                &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'w':
			dl_rx_grp = optarg;
			break;
		case 'x':
			dl_tx_grp = optarg;
			break;
		case 'y':
			ul_rx_grp = optarg;
			break;
		case 'z':
			ul_tx_grp = optarg;
			break;
		default:
			break;
		}
	}
}


void log_state_change(uint8_t old_state, uint8_t new_state, const struct value_string *vs_states, struct msgb *msg_in, struct msgb *msg_out, int dump_msgs, char *description) {
	  if(old_state != new_state) {
		  fprintf(stderr, "State changed: %s -> %s\n", get_value_string(vs_states, old_state), get_value_string(vs_states, new_state));
		  if(dump_msgs) {
			  if(msg_in != NULL) {
				  fprintf(stderr, "Msg in:        %s\n", osmo_hexdump(msgb_data(msg_in), msgb_length(msg_in)));
			  }
			  if(msg_out != NULL) {
				  fprintf(stderr, "Msg out:       %s\n", osmo_hexdump(msgb_data(msg_out), msgb_length(msg_out)));
			  }
		  }
		  fprintf(stderr, "Description:   %s\n\n", description);
	  }
}

/**
 * Define a handler for suboptions if you need any. w,x,y,z are already used by mitm!
 */
extern void handle_suboptions(int argc, char **argv);

/*
 * Implement this handler to manipulate the msg received on the downlink before forwarding it.
 */
extern struct msgb* downlink_rcv_cb_handler(struct msgb *msg);

/*
 * Implement this handler to manipulate the msg received on the uplink before forwarding it.
 */
extern struct msgb* uplink_rcv_cb_handler(struct msgb *msg);

/**
 * Manually forward a msg to the uplink.
 */
void mitm_forward_ul_msg(struct msgb * msg) {
	if(msg != NULL) {
		virt_um_write_msg(uplink, msg);
	}
}

/**
 * Manually forward a msg to the downlink.
 */
void mitm_forward_dl_msg(struct msgb * msg) {
	if(msg != NULL) {
		virt_um_write_msg(downlink, msg);
	}
}

static void uplink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg) {
	mitm_forward_ul_msg(uplink_rcv_cb_handler(msg));
}

static void downlink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg) {
	mitm_forward_dl_msg(downlink_rcv_cb_handler(msg));
}

int main(int argc, char **argv)
{
	fprintf(stderr, "STARTUP...\n");

	handle_options(argc, argv);
	handle_suboptions(argc, argv);

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
