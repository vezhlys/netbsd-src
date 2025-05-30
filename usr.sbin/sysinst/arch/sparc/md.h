/*	$NetBSD: md.h,v 1.6 2025/04/26 03:49:33 tsutsui Exp $	*/

/*
 * Copyright 1997 Piermont Information Systems Inc.
 * All rights reserved.
 *
 * Based on code written by Philip A. Nelson for Piermont Information
 * Systems Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of Piermont Information Systems Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PIERMONT INFORMATION SYSTEMS INC. ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PIERMONT INFORMATION SYSTEMS INC. BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* md.h -- Machine specific definitions for the sparc */

/* Constants and defines */

#define DEFROOTSIZE	48	/* Default root size */
#define DEFSWAPSIZE	32	/* Default swap size */
#define DEFVARSIZE	32	/* Default /var size, if created */
#define DEFUSRSIZE	700	/* Default /usr size, if /home */
#define XNEEDMB		256	/* Extra megs for full X installation */
#define DEBNEEDMB	800	/* Extra megs for debug sets */

/* have support for booting from UFS2 */
#define	HAVE_UFS2_BOOT

/* sunlabels force track alignment (true = no further processing) */
#define	MD_DISKLABEL_SET_ALIGN_PRE(align, track)	\
	(align) = (track), true

/*
 * Default filesets to fetch and install during installation
 * or upgrade.
 */
#define SET_KERNEL_1_NAME	"kern-GENERIC"
#define SET_KERNEL_2_NAME	"kern-GENERIC_SCSI3"
#define SET_KERNEL_3_NAME	"kern-GENERIC_SUN4U"
#define SET_KERNEL_4_NAME	"kern-GENERIC.MP"

/*
 * Machine-specific command to write a new label to a disk.
 * If not defined, we assume the port does not support disklabels and
 * the hand-edited disklabel will NOT be written by MI code.
 */
#define	DISKLABEL_CMD	"disklabel -w -r"
