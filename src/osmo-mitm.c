#include <stdio.h>
#include <getopt.h>
#include <virtphy/osmo_mcast_sock.h>
#include <virtphy/virtual_um.h>
#include <osmocom/core/gsmtap.h>

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

	// Forward msg to uplink
	virt_um_write_msg(downlink, msg);

}

static void uplink_rcv_cb(struct virt_um_inst *vui, struct msgb *msg)
{

	// TODO: Parse msg, check if SETUP, decode, decipher receiver number, manipulate receiver number
	// Forward msg to downlink
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
