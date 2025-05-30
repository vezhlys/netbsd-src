/*	$NetBSD: parseint.c,v 1.1 2024/02/18 20:57:49 christos Exp $	*/

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

/*! \file */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include <isc/parseint.h>
#include <isc/result.h>

isc_result_t
isc_parse_uint32(uint32_t *uip, const char *string, int base) {
	unsigned long n;
	uint32_t r;
	char *e;
	if (!isalnum((unsigned char)(string[0]))) {
		return (ISC_R_BADNUMBER);
	}
	errno = 0;
	n = strtoul(string, &e, base);
	if (*e != '\0') {
		return (ISC_R_BADNUMBER);
	}
	/*
	 * Where long is 64 bits we need to convert to 32 bits then test for
	 * equality.  This is a no-op on 32 bit machines and a good compiler
	 * will optimise it away.
	 */
	r = (uint32_t)n;
	if ((n == ULONG_MAX && errno == ERANGE) || (n != (unsigned long)r)) {
		return (ISC_R_RANGE);
	}
	*uip = r;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_parse_uint16(uint16_t *uip, const char *string, int base) {
	uint32_t val;
	isc_result_t result;
	result = isc_parse_uint32(&val, string, base);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	if (val > 0xFFFF) {
		return (ISC_R_RANGE);
	}
	*uip = (uint16_t)val;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_parse_uint8(uint8_t *uip, const char *string, int base) {
	uint32_t val;
	isc_result_t result;
	result = isc_parse_uint32(&val, string, base);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}
	if (val > 0xFF) {
		return (ISC_R_RANGE);
	}
	*uip = (uint8_t)val;
	return (ISC_R_SUCCESS);
}
