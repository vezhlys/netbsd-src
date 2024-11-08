/*	$NetBSD: sifive-fu540-prci.h,v 1.2 2024/08/12 10:55:56 skrll Exp $	*/

/* SPDX-License-Identifier: (GPL-2.0 OR MIT) */
/*
 * Copyright (C) 2018-2019 SiFive, Inc.
 * Wesley Terpstra
 * Paul Walmsley
 */

#ifndef __DT_BINDINGS_CLOCK_SIFIVE_FU540_PRCI_H
#define __DT_BINDINGS_CLOCK_SIFIVE_FU540_PRCI_H

/* Clock indexes for use by Device Tree data and the PRCI driver */

#define FU540_PRCI_CLK_COREPLL		0
#define FU540_PRCI_CLK_DDRPLL		1
#define FU540_PRCI_CLK_GEMGXLPLL	2
#define FU540_PRCI_CLK_TLCLK		3

#endif
