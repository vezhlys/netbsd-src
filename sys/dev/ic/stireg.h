/*	$NetBSD: stireg.h,v 1.18 2025/05/30 13:42:33 tsutsui Exp $	*/

/*	$OpenBSD: stireg.h,v 1.14 2015/04/05 23:25:57 miod Exp $	*/

/*
 * Copyright (c) 2000 Michael Shalayeff
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IC_STIREG_H_
#define _IC_STIREG_H_

/* #define	STIDEBUG */

#define	STI_REGION_MAX	8
#define	STI_MONITOR_MAX	256
#define	STI_DEVNAME_LEN	32
#define	STI_NCMAP	256

/* code ROM definitions */
#define	STI_BEGIN	0
#define	STI_INIT_GRAPH	0
#define	STI_STATE_MGMT	1
#define	STI_FONT_UNPMV	2
#define	STI_BLOCK_MOVE	3
#define	STI_SELF_TEST	4
#define	STI_EXCEP_HDLR	5
#define	STI_INQ_CONF	6
#define	STI_SCM_ENT	7
#define	STI_DMA_CTRL	8
#define	STI_FLOW_CTRL	9
#define	STI_UTIMING	10
#define	STI_PROC_MGR	11
#define	STI_UTIL	12
#define	STI_END		13
#define	STI_CODECNT	16

#define	STI_CODEBASE_MAIN	0x40
#define	STI_CODEBASE_ALT	0x80

#define	STI_CODEBASE_PA		STI_CODEBASE_MAIN
#define	STI_CODEBASE_M68K	STI_CODEBASE_ALT
#define	STI_CODEBASE_PA64	STI_CODEBASE_ALT

/* sti returns */
#define	STI_OK		0
#define	STI_FAIL	-1
#define	STI_NRDY	1

/* sti errno */
#define	STI_NOERRNO		0	/* no error */
#define	STI_BADREENTLVL		1	/* bad reentry level */
#define	STI_NOREGIONSDEF	2	/* region table is not setup */
#define	STI_ILLNPLANES		3	/* invalid num of text planes */
#define	STI_ILLINDEX		4	/* invalid font index */
#define	STI_ILLLOC		5	/* invalid font location */
#define	STI_ILLCOLOUR		6	/* invalid colour */
#define	STI_ILLBLKMVFROM	7	/* invalid from in blkmv */
#define	STI_ILLBLKMVTO		8	/* invalid to in blkmv */
#define	STI_ILLBLKMVSIZE	9	/* invalid size in blkmv */
#define	STI_BEIUNSUPP		10	/* bus error ints unsupported */
#define	STI_UNXPBE		11	/* unexpected bus error */
#define	STI_UNXHWF		12	/* unexpected hardware failure */
#define	STI_NEGCFG		13	/* no ext global config struct */
#define	STI_NEIG		14	/* no ext init struct */
#define	STI_ILLSCME		15	/* invalid set cmap entry */
#define	STI_ILLCMVAL		16	/* invalid cmap value */
#define	STI_NORESMEM		17	/* no requested global memory */
#define	STI_RESMEMCORR		18	/* reserved memory corrupted */
#define	STI_ILLNTBLKMV		19	/* invalid non-text blkmv */
#define	STI_ILLMONITOR		20	/* monitor selection is out of range */
#define	STI_ILLEXCADDR		21	/* invalid excpt handler addr */
#define	STI_ILLEXCFLAGS		22	/* invalid excpt handler flags */
#define	STI_NOEHE		23	/* no ext exhdl struct */
#define	STI_NOINQCE		24	/* no ext inq cfg struct */
#define	STI_ILLRGNPTR		25	/* invalid region pointer */
#define	STI_ILLUTLOP		26	/* invalid util opcode */
#define	STI_UNKNOWN		250	/* unknown error */
#define	STI_NOCFGPTR		251	/* no config ptr defined */
#define	STI_NOFLPTR		252	/* no flag ptr defined */
#define	STI_NOINPTR		253	/* no in ptr defined */
#define	STI_NOOUTPTR		254	/* no way you can get it */
#define	STI_NOLOCK		255	/* kernel dishonour graphics lock */

/* colours */
#define	STI_COLOUR_BLACK	0
#define	STI_COLOUR_WHITE	1
#define	STI_COLOUR_RED		2
#define	STI_COLOUR_YELLOW	3
#define	STI_COLOUR_GREEN	4
#define	STI_COLOUR_CYAN		5
#define	STI_COLOUR_BLUE		6
#define	STI_COLOUR_MAGENTA	7

	/* LSB high */
struct	sti_dd {
	uint32_t	dd_type;	/* 0x00 device type */
#define	STI_DEVTYPE1	1
#define	STI_DEVTYPE4	3
	uint8_t		dd_unused;
	uint8_t		dd_nmon;	/* 0x05 number monitor rates */
	uint8_t		dd_grrev;	/* 0x06 global rom revision */
	uint8_t		dd_lrrev;	/* 0x07 local rom revision */
	uint32_t	dd_grid[2];	/* 0x08 graphics id */
#define	STI_DD_CRX		0x26D1482A	/* single-head CRX */
#define	STI_DD_GRX		0x26D1488C	/* gray-scale GRX */
#define	STI_DD_CRX24		0x26D148EE	/* CRX+ */
#define	STI_DD_382C		0x27134C8E	/* 382 on-board mid-res */
#define	STI_DD_EVRX		0x27134C9F	/* 425e on-board */
#define	STI_DD_3X2V		0x27134CB4	/* 362/382 on-board VGA-res */
#define	STI_DD_TIMBER		0x27F12392	/* on-board 710, older 715 */
#define	STI_DD_DUAL_CRX		0x27FCCB6D	/* dual-head CRX */
#define	STI_DD_ARTIST		0x2B4DED6D	/* on-board 712/715, also GSC */
#define	STI_DD_HCRX		0x2BCB015A
#define	STI_DD_EG		0x2D08C0A7	/* Visualize EG */
#define	STI_DD_SUMMIT		0x2FC1066B	/* Visualize FX2, FX4, FX6 */
#define	STI_DD_PINNACLE		0x35ACDA16	/* Visualize FXe */
#define	STI_DD_LEGO		0x35ACDA30	/* Visualize FX5, FX10 */
#define STI_DEV4_DD_GRID	0x08	/* offset for STI_DEVTYPE4 */
#define STI_DEV1_DD_GRID	0x10	/* offset for STI_DEVTYPE1 */
	uint32_t	dd_fntaddr;	/* 0x10 font start address */
	uint32_t	dd_maxst;	/* 0x14 max state storage */
	uint32_t	dd_romend;	/* 0x18 rom last address */
#define STI_DEV4_DD_ROMEND	0x18	/* offset for STI_DEVTYPE4 */
#define STI_DEV1_DD_ROMEND	0x50	/* offset for STI_DEVTYPE1 */
	uint32_t	dd_reglst;	/* 0x1c device region list */
	uint16_t	dd_maxreent;	/* 0x20 max reent storage */
	uint16_t	dd_maxtimo;	/* 0x22 max execution timeout .1 sec */
	uint32_t	dd_montbl;	/* 0x24 mon table address, array of
						names num of dd_nmon */
	uint32_t	dd_udaddr;	/* 0x28 user data address */
	uint32_t	dd_stimemreq;	/* 0x2c sti memory request */
	uint32_t	dd_udsize;	/* 0x30 user data size */
	uint16_t	dd_pwruse;	/* 0x34 power usage */
	uint8_t		dd_bussup;	/* 0x36 bus support */
#define	STI_BUSSUPPORT_GSCINTL	0x01	/*	supports pulling INTL for int */
#define	STI_BUSSUPPORT_GSC15X	0x02	/*	supports GSC 1.5X */
#define	STI_BUSSUPPORT_GSC2X	0x04	/*	supports GSC 2.X */
#define	STI_BUSSUPPORT_PCIIOEIM	0x08	/*	will use directed int */
#define	STI_BUSSUPPORT_PCISTD	0x10	/*	will use std PCI int */
#define	STI_BUSSUPPORT_ILOCK	0x20	/*	supports implicit locking */
#define	STI_BUSSUPPORT_ROMMAP	0x40	/*	rom is only in pci erom space */
#define	STI_BUSSUPPORT_2DECODE	0x80	/*	single address decoder */
	uint8_t		dd_ebussup;	/* 0x37 extended bus support */
#define	STI_EBUSSUPPORT_DMA	0x01	/*	supports dma */
#define	STI_EBUSSUPPORT_PIOLOCK	0x02	/*	no implicit locking for dma */
	uint8_t		dd_altcodet;	/* 0x38 alternate code type */
#define	STI_ALTCODE_UNKNOWN	0x00
#define	STI_ALTCODE_PA64	0x01	/*	alt code is in pa64 */
	uint8_t		dd_eddst[3];	/* 0x39 extended DD struct */
	uint32_t	dd_cfbaddr;	/* 0x3c CFB address, location of
						X11 driver to be used for
						servers w/o accel */
	uint32_t	dd_pacode[16];	/* 0x40 routines for pa-risc */
	uint32_t	dd_altcode[16];	/* 0x80 routines for m68k/i386 */
} __packed;

#define	STI_REVISION(maj, min)	(((maj) << 4) | ((min) & 0x0f))

/* after the last region there is one indirect list ptr */
struct sti_region {
	u_int	offset  :14;	/* page offset dev io space relative */
	u_int	sys_only: 1;	/* whether allow user access */
	u_int	cache   : 1;	/* map in cache */
	u_int	btlb    : 1;	/* should use BTLB if available */
	u_int	last    : 1;	/* last region in the list */
	u_int	length  :14;	/* size in pages */
}  __packed;

#define	STI_PGSHIFT	12	/* sti(4) assumes 4KB/page for offset/length */

struct sti_font {
	uint16_t	first;
	uint16_t	last;
	uint8_t		width;
	uint8_t		height;
	uint8_t		type;
#define	STI_FONT_HPROMAN8	1
#define	STI_FONT_KANA8		2
	uint8_t		bpc;
	uint32_t	next;
	uint8_t		uheight;
	uint8_t		uoffset;
	uint8_t		unused[2];
}  __packed;

struct sti_fontcfg {
	uint16_t	first;
	uint16_t	last;
	uint8_t		width;
	uint8_t		height;
	uint8_t		type;
	uint8_t		bpc;
	uint8_t		uheight;
	uint8_t		uoffset;
}  __packed;

typedef struct sti_mon {
	uint32_t	width: 12;
	uint32_t	height: 12;
	uint32_t	hz: 7;		/* low 7 bits of refresh rate */
	uint32_t	flat: 1;	/* flatpanel */
	uint32_t	vesa: 1;	/* vesa mode */
	uint32_t	grey: 1;	/* greyscale */
	uint32_t	dblbuf: 1;	/* double buffered */
	uint32_t	user: 1;	/* user-defined mode */
	uint32_t	stereo: 1;	/* stereo display */
	uint32_t	sam: 1;		/* ? */
	uint32_t	: 15;
	uint32_t	hz_upper: 3;	/* upper 3 bits of refresh rate */
	uint32_t	font: 8;	/* rom font index */
} __packed *sti_mon_t;

typedef struct sti_ecfg {
	uint8_t		current_monitor;
	uint8_t		uf_boot;
	uint16_t	power;		/* power dissipation Watts */
	uint32_t	freq_ref;
	uint32_t	*addr;		/* memory block of size dd_stimemreq */
	void		*future;
} __packed *sti_ecfg_t;

typedef struct sti_cfg {
	uint32_t	text_planes;
	uint16_t	scr_width;
	uint16_t	scr_height;
	uint16_t	oscr_width;
	uint16_t	oscr_height;
	uint16_t	fb_width;
	uint16_t	fb_height;
	uint32_t	regions[STI_REGION_MAX];
	uint32_t	reent_level;
	uint32_t	*save_addr;
	sti_ecfg_t	ext_cfg;
}  __packed *sti_cfg_t;


/* routine types */
#define	STI_DEP(n) \
	typedef int (*sti_##n##_t)( \
	  sti_##n##flags_t, sti_##n##in_t, sti_##n##out_t, sti_cfg_t);

typedef struct sti_initflags {
	uint32_t	flags;
#define	STI_INITF_WAIT	0x80000000
#define	STI_INITF_RESET	0x40000000
#define	STI_INITF_TEXT	0x20000000
#define	STI_INITF_NTEXT	0x10000000
#define	STI_INITF_CLEAR	0x08000000
#define	STI_INITF_CMB	0x04000000	/* non-text planes cmap black */
#define	STI_INITF_EBET	0x02000000	/* enable bus error timer */
#define	STI_INITF_EBETI	0x01000000	/* enable bus error timer interrupt */
#define	STI_INITF_PTS	0x00800000	/* preserve text settings */
#define	STI_INITF_PNTS	0x00400000	/* preserve non-text settings */
#define	STI_INITF_PBET	0x00200000	/* preserve BET settings */
#define	STI_INITF_PBETI	0x00100000	/* preserve BETI settings */
#define	STI_INITF_ICMT	0x00080000	/* init cmap for text planes */
#define	STI_INITF_SCMT	0x00040000	/* change current monitor type */
#define	STI_INITF_RIE	0x00020000	/* retain int enables */
	void *future;
} __packed *sti_initflags_t;

typedef struct sti_einitin {
	uint8_t		mon_type;
	uint8_t		pad;
	uint16_t	inflight;	/* possible on pci */
	void		*future;
} __packed *sti_einitin_t;

typedef struct sti_initin {
	uint32_t	text_planes;	/* number of planes for text */
	sti_einitin_t	ext_in;
} __packed *sti_initin_t;

typedef struct sti_initout {
	int32_t		errno;
	uint32_t	text_planes;	/* number of planes used for text */
	void		*future;
} __packed *sti_initout_t;

STI_DEP(init);

typedef struct sti_mgmtflags {
	uint32_t	flags;
#define	STI_MGMTF_WAIT	0x80000000
#define	STI_MGMTF_SAVE	0x40000000
#define	STI_MGMTF_RALL	0x20000000	/* restore all display planes */
	void *future;
} __packed *sti_mgmtflags_t;

typedef struct sti_mgmtin {
	void	*addr;
	void	*future;
} __packed *sti_mgmtin_t;

typedef struct sti_mgmtout {
	int32_t		errno;
	void		*future;
} __packed *sti_mgmtout_t;

STI_DEP(mgmt);

typedef struct sti_unpmvflags {
	uint32_t	flags;
#define	STI_UNPMVF_WAIT	0x80000000
#define	STI_UNPMVF_NTXT	0x40000000	/* intp non-text planes */
	void		*future;
} __packed *sti_unpmvflags_t;

typedef struct sti_unpmvin {
	uint32_t	*font_addr;	/* font */
	uint16_t	index;		/* character index in the font */
	uint8_t		fg_colour;
	uint8_t		bg_colour;
	uint16_t	x, y;
	void		*future;
} __packed *sti_unpmvin_t;

typedef struct sti_unpmvout {
	uint32_t	errno;
	void		*future;
} __packed *sti_unpmvout_t;

STI_DEP(unpmv);

typedef struct sti_blkmvflags {
	uint32_t	flags;
#define	STI_BLKMVF_WAIT	0x80000000
#define	STI_BLKMVF_COLR	0x40000000	/* change colour on move */
#define	STI_BLKMVF_CLR	0x20000000	/* clear on move */
#define	STI_BLKMVF_NTXT	0x10000000	/* move in non-text planes */
	void		*future;
} __packed *sti_blkmvflags_t;

typedef struct sti_blkmvin {
	uint8_t		fg_colour;
	uint8_t		bg_colour;
	uint16_t	srcx, srcy, dstx, dsty;
	uint16_t	width, height;
	uint16_t	pad;
	void		*future;
} __packed *sti_blkmvin_t;

typedef struct sti_blkmvout {
	uint32_t	errno;
	void		*future;
} __packed *sti_blkmvout_t;

STI_DEP(blkmv);

typedef struct sti_testflags {
	uint32_t	flags;
#define	STI_TESTF_WAIT	0x80000000
#define	STI_TESTF_ETST	0x40000000
	void		*future;
} __packed *sti_testflags_t;

typedef struct sti_testin {
	void		*future;
} __packed *sti_testin_t;

typedef struct sti_testout {
	uint32_t	errno;
	uint32_t	result;
	void		*future;
} __packed *sti_testout_t;

STI_DEP(test);

typedef struct sti_exhdlflags {
	uint32_t	flags;
#define	STI_EXHDLF_WAIT	0x80000000
#define	STI_EXHDLF_CINT	0x40000000	/* clear int */
#define	STI_EXHDLF_CBE	0x20000000	/* clear BE */
#define	STI_EXHDLF_PINT	0x10000000	/* preserve int */
#define	STI_EXHDLF_RINT	0x08000000	/* restore int */
#define	STI_EXHDLF_WEIM	0x04000000	/* write eim w/ sti_eexhdlin */
#define	STI_EXHDLF_REIM	0x02000000	/* read eim to sti_eexhdlout */
#define	STI_EXHDLF_GIE	0x01000000	/* global int enable */
#define	STI_EXHDLF_PGIE	0x00800000
#define	STI_EXHDLF_WIEM	0x00400000
#define	STI_EXHDLF_EIEM	0x00200000
#define	STI_EXHDLF_BIC	0x00100000	/* begin int cycle */
#define	STI_EXHDLF_EIC	0x00080000	/* end int cycle */
#define	STI_EXHDLF_RIE	0x00040000	/* reset do not clear int enables */
	void		*future;
} __packed *sti_exhdlflags_t;

typedef struct sti_eexhdlin {
	uint32_t	eim_addr;
	uint32_t	eim_data;
	uint32_t	iem;		/* enable mask */
	uint32_t	icm;		/* clear mask */
	void		*future;
} __packed *sti_eexhdlin_t;

typedef struct sti_exhdlint {
	uint32_t	flags;
#define	STI_EXHDLINT_BET	0x80000000	/* bus error timer */
#define	STI_EXHDLINT_HW		0x40000000	/* high water */
#define	STI_EXHDLINT_LW		0x20000000	/* low water */
#define	STI_EXHDLINT_TM		0x10000000	/* texture map */
#define	STI_EXHDLINT_VB		0x08000000	/* vertical blank */
#define	STI_EXHDLINT_UDC	0x04000000	/* unbuffered dma complete */
#define	STI_EXHDLINT_BDC	0x02000000	/* buffered dma complete */
#define	STI_EXHDLINT_UDPC	0x01000000	/* unbuf priv dma complete */
#define	STI_EXHDLINT_BDPC	0x00800000	/* buffered priv dma complete */
} __packed *sti_exhdlint_t;

typedef struct sti_exhdlin {
	sti_exhdlint_t	addr;
	sti_eexhdlin_t	ext;
} __packed *sti_exhdlin_t;

typedef struct sti_eexhdlout {
	uint32_t	eim_addr;
	uint32_t	eim_data;
	uint32_t	iem;		/* enable mask */
	uint32_t	icm;		/* clear mask */
	void		*future;
} __packed *sti_eexhdlout_t;

typedef struct sti_exhdlout {
	uint32_t	errno;
	uint32_t	flags;
#define	STI_EXHDLO_BE	0x80000000	/* BE was intercepted */
#define	STI_EXHDLO_IP	0x40000000	/* there is int pending */
#define	STI_EXHDLO_IE	0x20000000	/* global enable set */
	sti_eexhdlout_t	ext;
} __packed *sti_exhdlout_t;

STI_DEP(exhdl);

typedef struct sti_inqconfflags {
	uint32_t	flags;
#define	STI_INQCONFF_WAIT	0x80000000
	void		*future;
} __packed *sti_inqconfflags_t;

typedef struct sti_inqconfin {
	void	*future;
} __packed *sti_inqconfin_t;

typedef struct sti_einqconfout {
	uint32_t	crt_config[3];
	uint32_t	crt_hw[3];
	void		*future;
} __packed *sti_einqconfout_t;

typedef struct sti_inqconfout {
	uint32_t	errno;
	uint16_t	width, height, owidth, oheight, fbwidth, fbheight;
	uint32_t	bpp;	/* bits per pixel */
	uint32_t	bppu;	/* accessible bpp */
	uint32_t	planes;
	uint8_t		name[STI_DEVNAME_LEN];
	uint32_t	attributes;
#define	STI_INQCONF_Y2X		0x0001	/* pixel is higher than wider */
#define	STI_INQCONF_HWBLKMV	0x0002	/* hw blkmv is present */
#define	STI_INQCONF_AHW		0x0004	/* adv hw accel */
#define	STI_INQCONF_INT		0x0008	/* can interrupt */
#define	STI_INQCONF_GONOFF	0x0010	/* supports on/off */
#define	STI_INQCONF_AONOFF	0x0020	/* supports alpha on/off */
#define	STI_INQCONF_VARY	0x0040	/* variable fb height */
#define	STI_INQCONF_ODDBYTES	0x0080	/* use only odd fb bytes */
#define	STI_INQCONF_FLUSH	0x0100	/* fb cache requires flushing */
#define	STI_INQCONF_DMA		0x0200	/* supports dma */
#define	STI_INQCONF_VDMA	0x0400	/* supports vdma */
#define	STI_INQCONF_YUV1	0x2000	/* supports YUV type 1 */
#define	STI_INQCONF_YUV2	0x4000	/* supports YUV type 2 */
#define	STI_INQCONF_BITS \
    "\020\001y2x\002hwblkmv\003ahw\004int\005gonoff\006aonoff\007vary"\
    "\010oddb\011flush\012dma\013vdma\016yuv1\017yuv2"
	sti_einqconfout_t ext;
} __packed *sti_inqconfout_t;

STI_DEP(inqconf);

typedef struct sti_scmentflags {
	uint32_t	flags;
#define	STI_SCMENTF_WAIT	0x80000000
	void		*future;
} __packed *sti_scmentflags_t;

typedef struct sti_scmentin {
	uint32_t	entry;
	uint32_t	value;
	void		*future;
} __packed *sti_scmentin_t;

typedef struct sti_scmentout {
	uint32_t	errno;
	void		*future;
} __packed *sti_scmentout_t;

STI_DEP(scment);

typedef struct sti_dmacflags {
	uint32_t	flags;
#define	STI_DMACF_WAIT	0x80000000
#define	STI_DMACF_PRIV	0x40000000	/* priv dma */
#define	STI_DMACF_DIS	0x20000000	/* disable */
#define	STI_DMACF_BUF	0x10000000	/* buffered */
#define	STI_DMACF_MRK	0x08000000	/* write a marker */
#define	STI_DMACF_ABRT	0x04000000	/* abort dma xfer */
	void		*future;
} __packed *sti_dmacflags_t;

typedef struct sti_dmacin {
	uint32_t	pa_upper;
	uint32_t	pa_lower;
	uint32_t	len;
	uint32_t	mrk_data;
	uint32_t	mrk_off;
	void		*future;
} __packed *sti_dmacin_t;

typedef struct sti_dmacout {
	uint32_t	errno;
	void		*future;
} __packed *sti_dmacout_t;

STI_DEP(dmac);

typedef struct sti_flowcflags {
	uint32_t	flags;
#define	STI_FLOWCF_WAIT	0x80000000
#define	STI_FLOWCF_CHW	0x40000000	/* check high water */
#define	STI_FLOWCF_WHW	0x20000000	/* write high water */
#define	STI_FLOWCF_WLW	0x10000000	/* write low water */
#define	STI_FLOWCF_PCSE	0x08000000	/* preserve cse */
#define	STI_FLOWCF_CSE	0x04000000
#define	STI_FLOWCF_CSWF	0x02000000	/* cs write fine */
#define	STI_FLOWCF_CSWC	0x01000000	/* cs write coarse */
#define	STI_FLOWCF_CSWQ	0x00800000	/* cs write fifo */
	void		*future;
} __packed *sti_flowcflags_t;

typedef struct sti_flowcin {
	uint32_t	retry;
	uint32_t	bufz;
	uint32_t	hwcnt;
	uint32_t	lwcnt;
	uint32_t	csfv;	/* cs fine value */
	uint32_t	cscv;	/* cs coarse value */
	uint32_t	csqc;	/* cs fifo count */
	void		*future;
} __packed *sti_flowcin_t;

typedef struct sti_flowcout {
	uint32_t	errno;
	uint32_t	retry_result;
	uint32_t	fifo_size;
	void		*future;
} __packed *sti_flowcout_t;

STI_DEP(flowc);

typedef struct sti_utimingflags {
	uint32_t	flags;
#define	STI_UTIMF_WAIT	0x80000000
#define	STI_UTIMF_HKS	0x40000000	/* has kbuf_size */
	void		*future;
} __packed *sti_utimingflags_t;

typedef struct sti_utimingin {
	void		*data;
	void		*kbuf;
	void		*future;
} __packed *sti_utimingin_t;

typedef struct sti_utimingout {
	uint32_t	errno;
	uint32_t	kbuf_size;	/* buffer required size */
	void		*future;
} __packed *sti_utimingout_t;

STI_DEP(utiming);

typedef struct sti_pmgrflags {
	uint32_t	flags;
#define	STI_UTIMF_WAIT	0x80000000
#define	STI_UTIMOP_CLEANUP	0x00000000
#define	STI_UTIMOP_BAC		0x10000000
#define	STI_UTIMF_CRIT	0x04000000
#define	STI_UTIMF_BUFF	0x02000000
#define	STI_UTIMF_IBUFF	0x01000000
	void		*future;
} __packed *sti_pmgrflags_t;

typedef struct sti_pmgrin {
	uint32_t	reserved[4];
	void		*future;
} __packed *sti_pmgrin_t;

typedef struct sti_pmgrout {
	int32_t		errno;
	void		*future;
} __packed *sti_pmgrout_t;

STI_DEP(pmgr);

typedef struct sti_utilflags {
	uint32_t	flags;
#define	STI_UTILF_ROOT	0x80000000	/* was called as root */
	void		*future;
} __packed *sti_utilflags_t;

typedef struct sti_utilin {
	uint32_t	in_size;
	uint32_t	out_size;
	uint8_t		*buf;
} __packed *sti_utilin_t;

typedef struct sti_utilout {
	int32_t		errno;
	void		*future;
} __packed *sti_utilout_t;

STI_DEP(util);

/*
 * NGLE register layout.
 * Based upon xc/programs/Xserver/hw/hp/ngle/dregs.h
 */

#define BA(F,C,S,A,J,B,I)						\
	(((F)<<31)|((C)<<27)|((S)<<24)|((A)<<21)|((J)<<16)|((B)<<12)|(I))
	/* FCCC CSSS AAAJ JJJJ BBBB IIII IIII IIII */

/* F */
#define	    IndexedDcd	0	/* Pixel data is indexed (pseudo) color */
#define	    FractDcd	1	/* Pixel data is Fractional 8-8-8 */
/* C */
#define	    Otc04	2	/* Pixels in each longword transfer (4) */
#define	    Otc32	5	/* Pixels in each longword transfer (32) */
#define	    Otc24	7	/* NGLE uses this for 24bit blits */
/* S */
#define	    Ots08	3	/* Each pixel is size (8)d transfer (1) */
#define	    OtsIndirect	6	/* Each bit goes through FG/BG color(8) */
/* A */
#define	    AddrByte	3	/* byte access? Used by NGLE for direct fb */
#define	    AddrLong	5	/* FB address is Long aligned (pixel) */
#define     Addr24	7	/* used for colour map access */
/* B */
#define	    BINapp0I	0x0	/* Application Buffer 0, Indexed */
#define	    BINapp1I	0x1	/* Application Buffer 1, Indexed */
#define	    BINovly	0x2	/* 8 bit overlay */
#define	    BINcursor	0x6	/* cursor bitmap on EG */
#define	    BINcmask	0x7	/* cursor mask on EG */
#define	    BINapp0F8	0xa	/* Application Buffer 0, Fractional 8-8-8 */
#define	    BINattr	0xd	/* Attribute Bitmap */
#define	    BINcmap	0xf	/* colour map(s) */
/* other buffers are unknown */
/* J - 'BA just point' - function unknown */
/* I - 'BA index base' - function unknown */

#define IBOvals(R,M,X,S,D,L,B,F)					\
	(((R)<<8)|((M)<<16)|((X)<<24)|((S)<<29)|((D)<<28)|((L)<<31)|((B)<<1)|(F))
	/* LSSD XXXX MMMM MMMM RRRR RRRR ???? ??BF */

/* R is a standard X11 ROP, no idea if the other bits areused for anything  */
#define	    RopClr 	0x0
#define	    RopSrc 	0x3
#define	    RopInv 	0xc
#define	    RopSet 	0xf
/* M: 'mask addr offset' - function unknown */
/* X */
#define	    BitmapExtent08  3	/* Each write hits ( 8) bits in depth */
#define	    BitmapExtent32  5	/* Each write hits (32) bits in depth */
/* S: 'static reg' flag, NGLE sets it for blits, function is unknown but
      we get occasional garbage in 8bit blits without it  */
/* D */
#define	    DataDynamic	    0	/* Data register reloaded by direct access */
/* L */
#define	    MaskDynamic	    1	/* Mask register reloaded by direct access */
#define	    MaskOtc	    0	/* Mask contains Object Count valid bits */
/* B = 1 -> background transparency for masked fills */
/* F probably the same for foreground */

#define	NGLE_REG_1		0x000118	/* Artist LUT blt ctrl */
#define	NGLE_REG_28		0x000420	/* HCRX video bus access */
#define	NGLE_REG_2		0x000480	/* BINC src */
#define	NGLE_REG_3		0x0004a0	/* BINC dst */
#define	NGLE_REG_22		0x0005a0	/* BINC dst mask */
#define	NGLE_REG_23		0x0005c0	/* BINC data */
#define	NGLE_REG_4		0x000600	/* palette data */
#define	NGLE_REG_5		0x0006a0	/* cursor data */
#define	NGLE_REG_6		0x000800	/* rectfill XY */
#define	NGLE_REG_7		0x000804	/* bitblt size WH */
#define	NGLE_REG_24		0x000808	/* bitblt src XY */
#define	NGLE_REG_8		0x000820	/* 'transfer data' - this is */
						/* a pixel mask on fills */
#define	NGLE_REG_37		0x000944	/* HCRX fast rect fill, size */
#define	NGLE_REG_9		0x000a04	/* rect fill size, start */
#define	NGLE_REG_25		0x000b00	/* bitblt dst XY, start */
#define	NGLE_REG_RAMDAC		0x001000
#define	NGLE_REG_10		0x018000	/* buffer ctl */
#define	NGLE_REG_11		0x018004	/* dest bitmap access */
#define	NGLE_REG_12		0x01800c	/* control plane register */
#define	NGLE_REG_35		0x018010	/* fg colour */
#define	NGLE_REG_36		0x018014	/* bg colour */
#define	NGLE_REG_13		0x018018	/* image planemask */
#define	NGLE_REG_14		0x01801c	/* raster op */
#define	NGLE_REG_15		0x200000	/* 'busy dodger' idle */
	#define DODGER_IDLE	0x1000	/* or 0x10000, likely tpyo */
#define	NGLE_REG_15b0		0x200000	/* busy register */
#define	NGLE_REG_16		0x200004
#define	NGLE_REG_16b1		0x200005	/* setup copyarea */
#define	NGLE_REG_16b3		0x200007	/* ROM table index on CRX */
#define	NGLE_REG_34		0x200008	/* # of fifo slots */
#define	NGLE_REG_17		0x200100	/* cursor coordinates */
#define	NGLE_REG_18		0x200104	/* cursor enable */
#define	NGLE_REG_26		0x200118	/* EG LUT blt ctrl */
#define	NGLE_REG_19		0x200200	/* artist sprite size */
#define	NGLE_REG_20		0x200208	/* cursor geometry */
#define	NGLE_REG_21		0x200218	/* Artist misc video */
#define	NGLE_REG_27		0x200308	/* Artist misc ctrl */
#define	NGLE_REG_29		0x210000	/* HCRX cursor coord & enable */
	#define HCRX_ENABLE_CURSOR	0x80000000
#define	NGLE_REG_30		0x210004	/* HCRX cursor address */
#define	NGLE_REG_31		0x210008	/* HCRX cursor data */
#define	NGLE_REG_38		0x210020	/* HCRX LUT blt ctrl */
	/* EWRRRROO OOOOOOOO TTRRRRLL LLLLLLLL */
	#define LBC_ENABLE	0x80000000
	#define LBC_WAIT_BLANK	0x40000000
	#define LBS_OFFSET_SHIFT	16
	#define LBC_TYPE_MASK		0xc000
	#define LBC_TYPE_CMAP		0
	#define LBC_TYPE_CURSOR		0x8000
	#define LBC_TYPE_OVERLAY	0xc000
	#define LBC_LENGTH_SHIFT	0
#define	NGLE_REG_41		0x210024
#define	NGLE_REG_42		0x210028	/* these seem to control */
#define	NGLE_REG_43		0x21002c	/* how the 24bit planes */
#define	NGLE_REG_44		0x210030	/* are displayed on HCRX - */
#define	NGLE_REG_45		0x210034	/* no info on bits */
#define	NGLE_REG_32		0x21003c	/* HCRX plane enable */ 
#define	NGLE_REG_33		0x210040	/* HCRX misc video */
	#define HCRX_VIDEO_ENABLE	0x0A000000
#define	NGLE_REG_39		0x210120	/* HCRX 'hyperbowl' mode 2 */
	#define HYPERBOWL_MODE2_8_24					15
#define	NGLE_REG_40		0x210130	/* HCRX 'hyperbowl' */
	#define HYPERBOWL_MODE_FOR_8_OVER_88_LUT0_NO_TRANSPARENCIES	4
	#define HYPERBOWL_MODE01_8_24_LUT0_TRANSPARENT_LUT1_OPAQUE	8
	#define HYPERBOWL_MODE01_8_24_LUT0_OPAQUE_LUT1_OPAQUE		10

#define	NGLE_BUFF0_CMAP0	0x00001e02
#define	NGLE_BUFF1_CMAP0	0x02001e02
#define	NGLE_BUFF1_CMAP3	0x0c001e02
#define	NGLE_ARTIST_CMAP0	0x00000102

/* mimic HP/UX, this will return the device's graphics ID */
#define	GCID	_IOR('G', 40, u_int)

#endif /* _IC_STIREG_H_ */
