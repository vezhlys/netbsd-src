/*	$NetBSD: mopprobe.c,v 1.17 2025/05/04 19:54:05 rillig Exp $	*/

/*
 * Copyright (c) 1993-96 Mats O Jansson.  All rights reserved.
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
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "port.h"
__RCSID("$NetBSD: mopprobe.c,v 1.17 2025/05/04 19:54:05 rillig Exp $");

#include "os.h"
#include "cmp.h"
#include "common.h"
#include "device.h"
#include "get.h"
#include "mopdef.h"
#include "nmadef.h"
#include "pf.h"
#include "print.h"
#include "log.h"

/*
 * The list of all interfaces that are being listened to.  rarp_loop()
 * "selects" on the descriptors in this list.
 */
extern struct if_info *iflist;

__dead static void	Usage(void);
void	mopProcess(struct if_info *, u_char *);

int	promisc = 1;		/* Need promisc mode           */

int
main(int argc, char  **argv)
{
	int     op, AllFlag = 0;
	char   *interface;

	mopInteractive = 1;

	while ((op = getopt(argc, argv, "a")) != -1) {
		switch (op) {
		case 'a':
			AllFlag++;
			break;

		default:
			Usage();
		}
	}
	interface = argv[optind++];

	if ((AllFlag != 0) == (interface != NULL))
		Usage();

	if (AllFlag)
 		deviceInitAll();
	else
		deviceInitOne(interface);

	Loop();
}

static void
Usage(void)
{
	(void)fprintf(stderr, "usage: %s -a|interface\n", getprogname());
	exit(1);
}

/*
 * Process incoming packages.
 */
void
mopProcess(struct if_info *ii, u_char *pkt)
{
	u_char  *dst, *src, *p, mopcode, tmpc, ilen;
	u_short *ptype, moplen, itype, len;
	int	idx, i, trans;

	dst	= pkt;
	src	= pkt+6;
	ptype   = (u_short *)(pkt+12);
	idx   = 0;

	if (*ptype < 1600) {
		len = *ptype;
		trans = TRANS_8023;
		ptype = (u_short *)(pkt+20);
		p = pkt+22;
	} else {
		len = 0;
		trans = TRANS_ETHER;
		p = pkt+14;
	}

	/* Ignore our own messages */

	if (mopCmpEAddr(ii->eaddr,src) == 0) {
		return;
	}

	/* Just check multicast */

	if (mopCmpEAddr(rc_mcst,dst) != 0) {
		return;
	}

	switch (trans) {
	case TRANS_8023:
		moplen = len;
		break;
	default:
		moplen = mopGetShort(pkt,&idx);
	}
	mopcode	= mopGetChar(p,&idx);

	/* Just process System Information */

	if (mopcode != MOP_K_CODE_SID) {
		return;
	}

	tmpc	= mopGetChar(pkt,&idx);		/* Reserved  */
	(void)mopGetShort(pkt,&idx);		/* Receipt # */

	itype	= mopGetShort(pkt,&idx);

	while (idx < (int)(moplen + 2)) {
		ilen	= mopGetChar(pkt,&idx);
		switch (itype) {
		case 0:
			tmpc  = mopGetChar(pkt,&idx);
			idx = idx + tmpc;
			break;
	        case MOP_K_INFO_VER:
			idx = idx + 3;
			break;
		case MOP_K_INFO_MFCT:
			idx = idx + 2;
			break;
		case MOP_K_INFO_CNU:
			idx = idx + 6;
			break;
		case MOP_K_INFO_RTM:
			idx = idx + 2;
			break;
		case MOP_K_INFO_CSZ:
			idx = idx + 2;
			break;
		case MOP_K_INFO_RSZ:
			idx = idx + 2;
			break;
		case MOP_K_INFO_HWA:
			idx = idx + 6;
			break;
		case MOP_K_INFO_TIME:
			idx = idx + 10;
			break;
	        case MOP_K_INFO_SOFD:
			(void)mopGetChar(pkt, &idx);
			break;
		case MOP_K_INFO_SFID:
			tmpc = mopGetChar(pkt,&idx);
			if ((idx > 0) && (idx < 17))
			  idx = idx + tmpc;
			break;
		case MOP_K_INFO_PRTY:
			idx = idx + 1;
			break;
		case MOP_K_INFO_DLTY:
			idx = idx + 1;
			break;
	        case MOP_K_INFO_DLBSZ:
			idx = idx + 2;
			break;
		default:
			if (itype > 101 && itype < 107) {
				switch (itype) {
				case 102:
					idx = idx + ilen;
					break;
				case 103:
					idx = idx + ilen;
					break;
				case 104:
					idx = idx + 2;
					break;
				case 105:
					(void)fprintf(stdout,"%x:%x:%x:%x:%x:%x\t",
						      src[0],src[1],src[2],src[3],src[4],src[5]);
					for (i = 0; i < ilen; i++) {
					  (void)fprintf(stdout, "%c",pkt[idx+i]);
					}
					idx = idx + ilen;
					(void)fprintf(stdout, "\n");
					break;
				case 106:
					idx = idx + ilen;
					break;
				}
			} else {
				idx = idx + ilen;
			}
		}
		itype = mopGetShort(pkt,&idx);
	}
}
