/*	$NetBSD: sink_40.h,v 1.8 2025/01/26 16:25:33 christos Exp $	*/

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

typedef struct dns_rdata_sink_t {
	dns_rdatacommon_t common;
	isc_mem_t *mctx;
	uint8_t meaning;
	uint8_t coding;
	uint8_t subcoding;
	uint16_t datalen;
	unsigned char *data;
} dns_rdata_sink_t;
