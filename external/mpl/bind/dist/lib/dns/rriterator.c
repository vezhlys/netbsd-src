/*	$NetBSD: rriterator.c,v 1.9 2025/01/26 16:25:25 christos Exp $	*/

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

/***
 *** Imports
 ***/

#include <inttypes.h>

#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rriterator.h>

/***
 *** RRiterator methods
 ***/

isc_result_t
dns_rriterator_init(dns_rriterator_t *it, dns_db_t *db, dns_dbversion_t *ver,
		    isc_stdtime_t now) {
	isc_result_t result;
	it->magic = RRITERATOR_MAGIC;
	it->db = db;
	it->dbit = NULL;
	it->ver = ver;
	it->now = now;
	it->node = NULL;
	result = dns_db_createiterator(it->db, 0, &it->dbit);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	it->rdatasetit = NULL;
	dns_rdata_init(&it->rdata);
	dns_rdataset_init(&it->rdataset);
	dns_fixedname_init(&it->fixedname);
	INSIST(!dns_rdataset_isassociated(&it->rdataset));
	it->result = ISC_R_SUCCESS;
	return it->result;
}

isc_result_t
dns_rriterator_first(dns_rriterator_t *it) {
	REQUIRE(VALID_RRITERATOR(it));
	/* Reset state */
	if (dns_rdataset_isassociated(&it->rdataset)) {
		dns_rdataset_disassociate(&it->rdataset);
	}
	if (it->rdatasetit != NULL) {
		dns_rdatasetiter_destroy(&it->rdatasetit);
	}
	if (it->node != NULL) {
		dns_db_detachnode(it->db, &it->node);
	}
	it->result = dns_dbiterator_first(it->dbit);

	/*
	 * The top node may be empty when out of zone glue exists.
	 * Walk the tree to find the first node with data.
	 */
	while (it->result == ISC_R_SUCCESS) {
		it->result = dns_dbiterator_current(
			it->dbit, &it->node,
			dns_fixedname_name(&it->fixedname));
		if (it->result != ISC_R_SUCCESS) {
			return it->result;
		}

		it->result = dns_db_allrdatasets(it->db, it->node, it->ver, 0,
						 it->now, &it->rdatasetit);
		if (it->result != ISC_R_SUCCESS) {
			return it->result;
		}

		it->result = dns_rdatasetiter_first(it->rdatasetit);
		if (it->result != ISC_R_SUCCESS) {
			/*
			 * This node is empty. Try next node.
			 */
			dns_rdatasetiter_destroy(&it->rdatasetit);
			dns_db_detachnode(it->db, &it->node);
			it->result = dns_dbiterator_next(it->dbit);
			continue;
		}
		dns_rdatasetiter_current(it->rdatasetit, &it->rdataset);
		dns_rdataset_getownercase(&it->rdataset,
					  dns_fixedname_name(&it->fixedname));
		it->rdataset.attributes |= DNS_RDATASETATTR_LOADORDER;
		it->result = dns_rdataset_first(&it->rdataset);
		return it->result;
	}
	return it->result;
}

isc_result_t
dns_rriterator_nextrrset(dns_rriterator_t *it) {
	REQUIRE(VALID_RRITERATOR(it));
	if (dns_rdataset_isassociated(&it->rdataset)) {
		dns_rdataset_disassociate(&it->rdataset);
	}
	it->result = dns_rdatasetiter_next(it->rdatasetit);
	/*
	 * The while loop body is executed more than once
	 * only when an empty dbnode needs to be skipped.
	 */
	while (it->result == ISC_R_NOMORE) {
		dns_rdatasetiter_destroy(&it->rdatasetit);
		dns_db_detachnode(it->db, &it->node);
		it->result = dns_dbiterator_next(it->dbit);
		if (it->result == ISC_R_NOMORE) {
			/* We are at the end of the entire database. */
			return it->result;
		}
		if (it->result != ISC_R_SUCCESS) {
			return it->result;
		}
		it->result = dns_dbiterator_current(
			it->dbit, &it->node,
			dns_fixedname_name(&it->fixedname));
		if (it->result != ISC_R_SUCCESS) {
			return it->result;
		}
		it->result = dns_db_allrdatasets(it->db, it->node, it->ver, 0,
						 it->now, &it->rdatasetit);
		if (it->result != ISC_R_SUCCESS) {
			return it->result;
		}
		it->result = dns_rdatasetiter_first(it->rdatasetit);
	}
	if (it->result != ISC_R_SUCCESS) {
		return it->result;
	}
	dns_rdatasetiter_current(it->rdatasetit, &it->rdataset);
	dns_rdataset_getownercase(&it->rdataset,
				  dns_fixedname_name(&it->fixedname));
	it->rdataset.attributes |= DNS_RDATASETATTR_LOADORDER;
	it->result = dns_rdataset_first(&it->rdataset);
	return it->result;
}

isc_result_t
dns_rriterator_next(dns_rriterator_t *it) {
	REQUIRE(VALID_RRITERATOR(it));
	if (it->result != ISC_R_SUCCESS) {
		return it->result;
	}

	INSIST(it->dbit != NULL);
	INSIST(it->node != NULL);
	INSIST(it->rdatasetit != NULL);

	it->result = dns_rdataset_next(&it->rdataset);
	if (it->result == ISC_R_NOMORE) {
		return dns_rriterator_nextrrset(it);
	}
	return it->result;
}

void
dns_rriterator_pause(dns_rriterator_t *it) {
	REQUIRE(VALID_RRITERATOR(it));
	RUNTIME_CHECK(dns_dbiterator_pause(it->dbit) == ISC_R_SUCCESS);
}

void
dns_rriterator_destroy(dns_rriterator_t *it) {
	REQUIRE(VALID_RRITERATOR(it));
	if (dns_rdataset_isassociated(&it->rdataset)) {
		dns_rdataset_disassociate(&it->rdataset);
	}
	if (it->rdatasetit != NULL) {
		dns_rdatasetiter_destroy(&it->rdatasetit);
	}
	if (it->node != NULL) {
		dns_db_detachnode(it->db, &it->node);
	}
	dns_dbiterator_destroy(&it->dbit);
}

void
dns_rriterator_current(dns_rriterator_t *it, dns_name_t **name, uint32_t *ttl,
		       dns_rdataset_t **rdataset, dns_rdata_t **rdata) {
	REQUIRE(name != NULL && *name == NULL);
	REQUIRE(VALID_RRITERATOR(it));
	REQUIRE(it->result == ISC_R_SUCCESS);
	REQUIRE(rdataset == NULL || *rdataset == NULL);
	REQUIRE(rdata == NULL || *rdata == NULL);

	*name = dns_fixedname_name(&it->fixedname);
	*ttl = it->rdataset.ttl;

	dns_rdata_reset(&it->rdata);
	dns_rdataset_current(&it->rdataset, &it->rdata);

	SET_IF_NOT_NULL(rdataset, &it->rdataset);

	SET_IF_NOT_NULL(rdata, &it->rdata);
}
