/*	$NetBSD: tsig_250.h,v 1.8 2025/01/26 16:25:30 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*% RFC2845 */
typedef struct dns_rdata_any_tsig {
	dns_rdatacommon_t common;
	isc_mem_t *mctx;
	dns_name_t algorithm;
	uint64_t timesigned;
	uint16_t fudge;
	uint16_t siglen;
	unsigned char *signature;
	uint16_t originalid;
	uint16_t error;
	uint16_t otherlen;
	unsigned char *other;
} dns_rdata_any_tsig_t;
