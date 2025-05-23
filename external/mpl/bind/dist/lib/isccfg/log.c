/*	$NetBSD: log.c,v 1.7 2025/01/26 16:25:45 christos Exp $	*/

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

#include <isc/util.h>

#include <isccfg/log.h>

/*%
 * When adding a new category, be sure to add the appropriate
 * \#define to <isccfg/log.h>.
 */
isc_logcategory_t cfg_categories[] = { { "config", 0 }, { NULL, 0 } };

/*%
 * When adding a new module, be sure to add the appropriate
 * \#define to <isccfg/log.h>.
 */
isc_logmodule_t cfg_modules[] = { { "isccfg/parser", 0 }, { NULL, 0 } };

void
cfg_log_init(isc_log_t *lctx) {
	REQUIRE(lctx != NULL);

	isc_log_registercategories(lctx, cfg_categories);
	isc_log_registermodules(lctx, cfg_modules);
}
