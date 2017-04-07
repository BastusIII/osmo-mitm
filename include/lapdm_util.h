#pragma once

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

/* pull the layer 2 header and parse it to a lapdm context */
int pull_lapd_ctx(struct msgb *msg,
	uint8_t chan_nr, uint8_t link_id, enum lapdm_mode mode, struct lapdm_msg_ctx *mctx, struct lapd_msg_ctx *lctx);
