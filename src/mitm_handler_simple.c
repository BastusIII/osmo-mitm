#include <getopt.h>
#include <osmocom/core/msgb.h>

/**
 * No additional options.
 */
void handle_suboptions(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
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

/**
 * Simple forwarding.
 */
struct msgb* downlink_rcv_cb_handler(struct msgb *msg) {
	return msg;
}

/**
 * Simple forwarding.
 */
struct msgb* uplink_rcv_cb_handler(struct msgb *msg) {
	return msg;
}
