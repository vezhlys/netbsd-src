/*	$NetBSD: safe.c,v 1.7 2025/01/26 16:25:38 christos Exp $	*/

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

#include <openssl/crypto.h>

#include <isc/safe.h>

int
isc_safe_memequal(const void *s1, const void *s2, size_t len) {
	return !CRYPTO_memcmp(s1, s2, len);
}

void
isc_safe_memwipe(void *ptr, size_t len) {
	OPENSSL_cleanse(ptr, len);
}
