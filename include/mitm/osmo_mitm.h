#pragma once

void mitm_forward_ul_msg(struct msgb * msg);

void mitm_forward_dl_msg(struct msgb * msg);

void log_state_change(uint8_t old_state, uint8_t new_state, const struct value_string *vs_states, struct msgb *msg_in, struct msgb *msg_out, int dump_msgs, char *description);
