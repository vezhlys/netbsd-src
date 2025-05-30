/*	$NetBSD: master.h,v 1.9 2025/05/21 14:48:04 christos Exp $	*/

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

/*! \file dns/master.h */

/***
 ***	Imports
 ***/

#include <inttypes.h>
#include <stdio.h>

#include <isc/lang.h>

#include <dns/types.h>

/*
 * Flags to be passed in the 'options' argument in the functions below.
 */
#define DNS_MASTER_AGETTL 0x00000001 /*%< Age the ttl based on $DATE. */
#define DNS_MASTER_MANYERRORS                                               \
	0x00000002			/*%< Continue processing on errors. \
					 */
#define DNS_MASTER_NOINCLUDE 0x00000004 /*%< Disallow $INCLUDE directives. */
#define DNS_MASTER_ZONE	     0x00000008 /*%< Loading a zone master file. */
#define DNS_MASTER_HINT	     0x00000010 /*%< Loading a hint master file. */
#define DNS_MASTER_SECONDARY 0x00000020 /*%< Secondary master file. */
#define DNS_MASTER_CHECKNS                    \
	0x00000040 /*%<                       \
		    * Check NS records to see \
		    * if they are an address  \
		    */
#define DNS_MASTER_FATALNS                     \
	0x00000080 /*%<                        \
		    * Treat DNS_MASTER_CHECKNS \
		    * matches as fatal         \
		    */
#define DNS_MASTER_CHECKNAMES	  0x00000100
#define DNS_MASTER_CHECKNAMESFAIL 0x00000200
#define DNS_MASTER_CHECKWILDCARD                    \
	0x00000400 /* Check for internal wildcards. \
		    */
#define DNS_MASTER_CHECKMX     0x00000800
#define DNS_MASTER_CHECKMXFAIL 0x00001000

#define DNS_MASTER_RESIGN    0x00002000
#define DNS_MASTER_KEY	     0x00004000 /*%< Loading a key zone master file. */
#define DNS_MASTER_NOTTL     0x00008000 /*%< Don't require ttl. */
#define DNS_MASTER_CHECKTTL  0x00010000 /*%< Check max-zone-ttl */
#define DNS_MASTER_CHECKSVCB 0x00020000 /*%< Check SVBC records */

ISC_LANG_BEGINDECLS

/*
 * Structures that implement the "raw" format for master dump.
 * These are provided for a reference purpose only; in the actual
 * encoding, we directly read/write each field so that the encoded data
 * is always "packed", regardless of the hardware architecture.
 */
#define DNS_RAWFORMAT_VERSION 1

/*
 * Flags to indicate the status of the data in the raw file header
 */
#define DNS_MASTERRAW_COMPAT	      0x01
#define DNS_MASTERRAW_SOURCESERIALSET 0x02
#define DNS_MASTERRAW_LASTXFRINSET    0x04

/* Common header */
struct dns_masterrawheader {
	uint32_t format;       /* must be
				* dns_masterformat_raw */
	uint32_t version;      /* compatibility for future
				* extensions */
	uint32_t dumptime;     /* timestamp on creation
				* (currently unused) */
	uint32_t flags;	       /* Flags */
	uint32_t sourceserial; /* Source serial number (used
				* by inline-signing zones) */
	uint32_t lastxfrin;    /* timestamp of last transfer
				* (used by secondary zones) */
};

/* The structure for each RRset */
typedef struct {
	uint32_t totallen;	  /* length of the data for this
				   * RRset, including the
				   * "header" part */
	dns_rdataclass_t rdclass; /* 16-bit class */
	dns_rdatatype_t	 type;	  /* 16-bit type */
	dns_rdatatype_t	 covers;  /* same as type */
	dns_ttl_t	 ttl;	  /* 32-bit TTL */
	uint32_t	 nrdata;  /* number of RRs in this set */
	/* followed by encoded owner name, and then rdata */
} dns_masterrawrdataset_t;

/*
 * Method prototype: a callback to register each include file as
 * it is encountered.
 */
typedef void (*dns_masterincludecb_t)(const char *file, void *arg);

/***
 ***	Function
 ***/

isc_result_t
dns_master_loadfile(const char *master_file, dns_name_t *top,
		    dns_name_t *origin, dns_rdataclass_t zclass,
		    unsigned int options, uint32_t resign,
		    dns_rdatacallbacks_t *callbacks,
		    dns_masterincludecb_t include_cb, void *include_arg,
		    isc_mem_t *mctx, dns_masterformat_t format,
		    dns_ttl_t maxttl);

isc_result_t
dns_master_loadstream(FILE *stream, dns_name_t *top, dns_name_t *origin,
		      dns_rdataclass_t zclass, unsigned int options,
		      dns_rdatacallbacks_t *callbacks, isc_mem_t *mctx);

isc_result_t
dns_master_loadbuffer(isc_buffer_t *buffer, dns_name_t *top, dns_name_t *origin,
		      dns_rdataclass_t zclass, unsigned int options,
		      dns_rdatacallbacks_t *callbacks, isc_mem_t *mctx);

isc_result_t
dns_master_loadfileasync(const char *master_file, dns_name_t *top,
			 dns_name_t *origin, dns_rdataclass_t zclass,
			 unsigned int options, uint32_t resign,
			 dns_rdatacallbacks_t *callbacks, isc_loop_t *loop,
			 dns_loaddonefunc_t done, void *done_arg,
			 dns_loadctx_t **ctxp, dns_masterincludecb_t include_cb,
			 void *include_arg, isc_mem_t *mctx,
			 dns_masterformat_t format, uint32_t maxttl);

/*%<
 * Loads a RFC1035 master file from a file, stream, or buffer
 * into rdatasets and then calls 'callbacks->commit' to commit the
 * rdatasets.  Rdata memory belongs to dns_master_load and will be
 * reused / released when the callback completes.  dns_load_master will
 * abort if callbacks->commit returns any value other than ISC_R_SUCCESS.
 *
 * If 'DNS_MASTER_AGETTL' is set and the master file contains one or more
 * $DATE directives, the TTLs of the data will be aged accordingly.
 *
 * 'callbacks->commit' is assumed to call 'callbacks->error' or
 * 'callbacks->warn' to generate any error messages required.
 *
 * 'done' is called with 'done_arg' and a result code when the loading
 * is completed or has failed.  If the initial setup fails 'done' is
 * not called.
 *
 * 'resign' the number of seconds before a RRSIG expires that it should
 * be re-signed.  0 is used if not provided.
 *
 * Requires:
 *\li	'master_file' points to a valid string.
 *\li	'top' points to a valid name.
 *\li	'origin' points to a valid name.
 *\li	'callbacks->commit' points to a valid function.
 *\li	'callbacks->error' points to a valid function.
 *\li	'callbacks->warn' points to a valid function.
 *\li	'mctx' points to a valid memory context.
 *\li	'loop' and 'done' to be valid.
 *\li	'lmgr' to be valid.
 *\li	'ctxp != NULL && ctxp == NULL'.
 *
 * Returns:
 *\li	ISC_R_SUCCESS upon successfully loading the master file.
 *\li	DNS_R_SEENINCLUDE upon successfully loading the master file with
 *		a $INCLUDE statement.
 *\li	ISC_R_NOMEMORY out of memory.
 *\li	ISC_R_UNEXPECTEDEND expected to be able to read a input token and
 *		there was not one.
 *\li	ISC_R_UNEXPECTED
 *\li	DNS_R_NOOWNER failed to specify a ownername.
 *\li	DNS_R_NOTTL failed to specify a ttl.
 *\li	DNS_R_BADCLASS record class did not match zone class.
 *\li	Any dns_rdata_fromtext() error code.
 *\li	Any error code from callbacks->commit().
 */

void
dns_loadctx_detach(dns_loadctx_t **ctxp);
/*%<
 * Detach from the load context.
 *
 * Requires:
 *\li	'*ctxp' to be valid.
 *
 * Ensures:
 *\li	'*ctxp == NULL'
 */

void
dns_loadctx_attach(dns_loadctx_t *source, dns_loadctx_t **target);
/*%<
 * Attach to the load context.
 *
 * Requires:
 *\li	'source' to be valid.
 *\li	'target != NULL && *target == NULL'.
 */

void
dns_loadctx_cancel(dns_loadctx_t *ctx);
/*%<
 * Cancel loading the zone file associated with this load context.
 *
 * Requires:
 *\li	'ctx' to be valid
 */

void
dns_master_initrawheader(dns_masterrawheader_t *header);
/*%<
 * Initializes the header for a raw master file, setting all
 * values to zero.
 */
ISC_LANG_ENDDECLS
