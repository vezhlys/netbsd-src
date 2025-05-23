/*	$NetBSD: ncache.c,v 1.1 2024/02/18 20:57:32 christos Exp $	*/

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

#include <inttypes.h>
#include <stdbool.h>

#include <isc/buffer.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/message.h>
#include <dns/ncache.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>

#define DNS_NCACHE_RDATA 100U

/*
 * The format of an ncache rdata is a sequence of zero or more records of
 * the following format:
 *
 *	owner name
 *	type
 *	trust
 *	rdata count
 *		rdata length			These two occur 'rdata count'
 *		rdata				times.
 *
 */

static isc_result_t
addoptout(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
	  dns_rdatatype_t covers, isc_stdtime_t now, dns_ttl_t minttl,
	  dns_ttl_t maxttl, bool optout, bool secure,
	  dns_rdataset_t *addedrdataset);

static isc_result_t
copy_rdataset(dns_rdataset_t *rdataset, isc_buffer_t *buffer) {
	isc_result_t result;
	unsigned int count;
	isc_region_t ar, r;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	/*
	 * Copy the rdataset count to the buffer.
	 */
	isc_buffer_availableregion(buffer, &ar);
	if (ar.length < 2) {
		return (ISC_R_NOSPACE);
	}
	count = dns_rdataset_count(rdataset);
	INSIST(count <= 65535);
	isc_buffer_putuint16(buffer, (uint16_t)count);

	result = dns_rdataset_first(rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(rdataset, &rdata);
		dns_rdata_toregion(&rdata, &r);
		INSIST(r.length <= 65535);
		isc_buffer_availableregion(buffer, &ar);
		if (ar.length < 2) {
			return (ISC_R_NOSPACE);
		}
		/*
		 * Copy the rdata length to the buffer.
		 */
		isc_buffer_putuint16(buffer, (uint16_t)r.length);
		/*
		 * Copy the rdata to the buffer.
		 */
		result = isc_buffer_copyregion(buffer, &r);
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
		dns_rdata_reset(&rdata);
		result = dns_rdataset_next(rdataset);
	}
	if (result != ISC_R_NOMORE) {
		return (result);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_ncache_add(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
	       dns_rdatatype_t covers, isc_stdtime_t now, dns_ttl_t minttl,
	       dns_ttl_t maxttl, dns_rdataset_t *addedrdataset) {
	return (addoptout(message, cache, node, covers, now, minttl, maxttl,
			  false, false, addedrdataset));
}

isc_result_t
dns_ncache_addoptout(dns_message_t *message, dns_db_t *cache,
		     dns_dbnode_t *node, dns_rdatatype_t covers,
		     isc_stdtime_t now, dns_ttl_t minttl, dns_ttl_t maxttl,
		     bool optout, dns_rdataset_t *addedrdataset) {
	return (addoptout(message, cache, node, covers, now, minttl, maxttl,
			  optout, true, addedrdataset));
}

static isc_result_t
addoptout(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
	  dns_rdatatype_t covers, isc_stdtime_t now, dns_ttl_t minttl,
	  dns_ttl_t maxttl, bool optout, bool secure,
	  dns_rdataset_t *addedrdataset) {
	isc_result_t result;
	isc_buffer_t buffer;
	isc_region_t r;
	dns_rdataset_t *rdataset;
	dns_rdatatype_t type;
	dns_name_t *name;
	dns_ttl_t ttl;
	dns_trust_t trust;
	dns_rdata_t rdata[DNS_NCACHE_RDATA];
	dns_rdataset_t ncrdataset;
	dns_rdatalist_t ncrdatalist;
	unsigned char data[65536];
	unsigned int next = 0;

	/*
	 * Convert the authority data from 'message' into a negative cache
	 * rdataset, and store it in 'cache' at 'node'.
	 */

	REQUIRE(message != NULL);

	/*
	 * We assume that all data in the authority section has been
	 * validated by the caller.
	 */

	/*
	 * Initialize the list.
	 */
	dns_rdatalist_init(&ncrdatalist);
	ncrdatalist.rdclass = dns_db_class(cache);
	ncrdatalist.covers = covers;
	ncrdatalist.ttl = maxttl;

	/*
	 * Build an ncache rdatas into buffer.
	 */
	ttl = maxttl;
	trust = 0xffff;
	isc_buffer_init(&buffer, data, sizeof(data));
	if (message->counts[DNS_SECTION_AUTHORITY]) {
		result = dns_message_firstname(message, DNS_SECTION_AUTHORITY);
	} else {
		result = ISC_R_NOMORE;
	}
	while (result == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(message, DNS_SECTION_AUTHORITY, &name);
		if ((name->attributes & DNS_NAMEATTR_NCACHE) != 0) {
			for (rdataset = ISC_LIST_HEAD(name->list);
			     rdataset != NULL;
			     rdataset = ISC_LIST_NEXT(rdataset, link))
			{
				if ((rdataset->attributes &
				     DNS_RDATASETATTR_NCACHE) == 0)
				{
					continue;
				}
				type = rdataset->type;
				if (type == dns_rdatatype_rrsig) {
					type = rdataset->covers;
				}
				if (type == dns_rdatatype_soa ||
				    type == dns_rdatatype_nsec ||
				    type == dns_rdatatype_nsec3)
				{
					if (ttl > rdataset->ttl) {
						ttl = rdataset->ttl;
					}
					if (ttl < minttl) {
						ttl = minttl;
					}
					if (trust > rdataset->trust) {
						trust = rdataset->trust;
					}
					/*
					 * Copy the owner name to the buffer.
					 */
					dns_name_toregion(name, &r);
					result = isc_buffer_copyregion(&buffer,
								       &r);
					if (result != ISC_R_SUCCESS) {
						return (result);
					}
					/*
					 * Copy the type to the buffer.
					 */
					isc_buffer_availableregion(&buffer, &r);
					if (r.length < 3) {
						return (ISC_R_NOSPACE);
					}
					isc_buffer_putuint16(&buffer,
							     rdataset->type);
					isc_buffer_putuint8(
						&buffer,
						(unsigned char)rdataset->trust);
					/*
					 * Copy the rdataset into the buffer.
					 */
					result = copy_rdataset(rdataset,
							       &buffer);
					if (result != ISC_R_SUCCESS) {
						return (result);
					}

					if (next >= DNS_NCACHE_RDATA) {
						return (ISC_R_NOSPACE);
					}
					dns_rdata_init(&rdata[next]);
					isc_buffer_remainingregion(&buffer, &r);
					rdata[next].data = r.base;
					rdata[next].length = r.length;
					rdata[next].rdclass =
						ncrdatalist.rdclass;
					rdata[next].type = 0;
					rdata[next].flags = 0;
					ISC_LIST_APPEND(ncrdatalist.rdata,
							&rdata[next], link);
					isc_buffer_forward(&buffer, r.length);
					next++;
				}
			}
		}
		result = dns_message_nextname(message, DNS_SECTION_AUTHORITY);
	}
	if (result != ISC_R_NOMORE) {
		return (result);
	}

	if (trust == 0xffff) {
		if ((message->flags & DNS_MESSAGEFLAG_AA) != 0 &&
		    message->counts[DNS_SECTION_ANSWER] == 0)
		{
			/*
			 * The response has aa set and we haven't followed
			 * any CNAME or DNAME chains.
			 */
			trust = dns_trust_authauthority;
		} else {
			trust = dns_trust_additional;
		}
		ttl = 0;
	}

	INSIST(trust != 0xffff);

	ncrdatalist.ttl = ttl;

	dns_rdataset_init(&ncrdataset);
	RUNTIME_CHECK(dns_rdatalist_tordataset(&ncrdatalist, &ncrdataset) ==
		      ISC_R_SUCCESS);
	if (!secure && trust > dns_trust_answer) {
		trust = dns_trust_answer;
	}
	ncrdataset.trust = trust;
	ncrdataset.attributes |= DNS_RDATASETATTR_NEGATIVE;
	if (message->rcode == dns_rcode_nxdomain) {
		ncrdataset.attributes |= DNS_RDATASETATTR_NXDOMAIN;
	}
	if (optout) {
		ncrdataset.attributes |= DNS_RDATASETATTR_OPTOUT;
	}

	return (dns_db_addrdataset(cache, node, NULL, now, &ncrdataset, 0,
				   addedrdataset));
}

isc_result_t
dns_ncache_towire(dns_rdataset_t *rdataset, dns_compress_t *cctx,
		  isc_buffer_t *target, unsigned int options,
		  unsigned int *countp) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_result_t result;
	isc_region_t remaining, tavailable;
	isc_buffer_t source, savedbuffer, rdlen;
	dns_name_t name;
	dns_rdatatype_t type;
	unsigned int i, rcount, count;

	/*
	 * Convert the negative caching rdataset 'rdataset' to wire format,
	 * compressing names as specified in 'cctx', and storing the result in
	 * 'target'.
	 */

	REQUIRE(rdataset != NULL);
	REQUIRE(rdataset->type == 0);
	REQUIRE((rdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0);

	savedbuffer = *target;
	count = 0;

	result = dns_rdataset_first(rdataset);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(rdataset, &rdata);
		isc_buffer_init(&source, rdata.data, rdata.length);
		isc_buffer_add(&source, rdata.length);
		dns_name_init(&name, NULL);
		isc_buffer_remainingregion(&source, &remaining);
		dns_name_fromregion(&name, &remaining);
		INSIST(remaining.length >= name.length);
		isc_buffer_forward(&source, name.length);
		remaining.length -= name.length;

		INSIST(remaining.length >= 5);
		type = isc_buffer_getuint16(&source);
		isc_buffer_forward(&source, 1);
		rcount = isc_buffer_getuint16(&source);

		for (i = 0; i < rcount; i++) {
			/*
			 * Get the length of this rdata and set up an
			 * rdata structure for it.
			 */
			isc_buffer_remainingregion(&source, &remaining);
			INSIST(remaining.length >= 2);
			dns_rdata_reset(&rdata);
			rdata.length = isc_buffer_getuint16(&source);
			isc_buffer_remainingregion(&source, &remaining);
			rdata.data = remaining.base;
			rdata.type = type;
			rdata.rdclass = rdataset->rdclass;
			INSIST(remaining.length >= rdata.length);
			isc_buffer_forward(&source, rdata.length);

			if ((options & DNS_NCACHETOWIRE_OMITDNSSEC) != 0 &&
			    dns_rdatatype_isdnssec(type))
			{
				continue;
			}

			/*
			 * Write the name.
			 */
			dns_compress_setmethods(cctx, DNS_COMPRESS_GLOBAL14);
			result = dns_name_towire(&name, cctx, target);
			if (result != ISC_R_SUCCESS) {
				goto rollback;
			}

			/*
			 * See if we have space for type, class, ttl, and
			 * rdata length.  Write the type, class, and ttl.
			 */
			isc_buffer_availableregion(target, &tavailable);
			if (tavailable.length < 10) {
				result = ISC_R_NOSPACE;
				goto rollback;
			}
			isc_buffer_putuint16(target, type);
			isc_buffer_putuint16(target, rdataset->rdclass);
			isc_buffer_putuint32(target, rdataset->ttl);

			/*
			 * Save space for rdata length.
			 */
			rdlen = *target;
			isc_buffer_add(target, 2);

			/*
			 * Write the rdata.
			 */
			result = dns_rdata_towire(&rdata, cctx, target);
			if (result != ISC_R_SUCCESS) {
				goto rollback;
			}

			/*
			 * Set the rdata length field to the compressed
			 * length.
			 */
			INSIST((target->used >= rdlen.used + 2) &&
			       (target->used - rdlen.used - 2 < 65536));
			isc_buffer_putuint16(
				&rdlen,
				(uint16_t)(target->used - rdlen.used - 2));

			count++;
		}
		INSIST(isc_buffer_remaininglength(&source) == 0);
		result = dns_rdataset_next(rdataset);
		dns_rdata_reset(&rdata);
	}
	if (result != ISC_R_NOMORE) {
		goto rollback;
	}

	*countp = count;

	return (ISC_R_SUCCESS);

rollback:
	INSIST(savedbuffer.used < 65536);
	dns_compress_rollback(cctx, (uint16_t)savedbuffer.used);
	*countp = 0;
	*target = savedbuffer;

	return (result);
}

static void
rdataset_disassociate(dns_rdataset_t *rdataset) {
	UNUSED(rdataset);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3;
	unsigned int count;

	count = raw[0] * 256 + raw[1];
	if (count == 0) {
		rdataset->private5 = NULL;
		return (ISC_R_NOMORE);
	}
	raw += 2;
	/*
	 * The privateuint4 field is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before storing
	 * it.
	 */
	count--;
	rdataset->privateuint4 = count;
	rdataset->private5 = raw;

	return (ISC_R_SUCCESS);
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	unsigned int count;
	unsigned int length;
	unsigned char *raw;

	count = rdataset->privateuint4;
	if (count == 0) {
		return (ISC_R_NOMORE);
	}
	count--;
	rdataset->privateuint4 = count;
	raw = rdataset->private5;
	length = raw[0] * 256 + raw[1];
	raw += length + 2;
	rdataset->private5 = raw;

	return (ISC_R_SUCCESS);
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = rdataset->private5;
	isc_region_t r;

	REQUIRE(raw != NULL);

	r.length = raw[0] * 256 + raw[1];
	raw += 2;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target) {
	*target = *source;

	/*
	 * Reset iterator state.
	 */
	target->privateuint4 = 0;
	target->private5 = NULL;
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->private3;
	unsigned int count;

	count = raw[0] * 256 + raw[1];

	return (count);
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	unsigned char *raw = rdataset->private3;

	raw[-1] = (unsigned char)trust;
	rdataset->trust = trust;
}

static dns_rdatasetmethods_t rdataset_methods = {
	rdataset_disassociate,
	rdataset_first,
	rdataset_next,
	rdataset_current,
	rdataset_clone,
	rdataset_count,
	NULL,		   /* addnoqname */
	NULL,		   /* getnoqname */
	NULL,		   /* addclosest */
	NULL,		   /* getclosest */
	rdataset_settrust, /* settrust */
	NULL,		   /* expire */
	NULL,		   /* clearprefetch */
	NULL,		   /* setownercase */
	NULL,		   /* getownercase */
	NULL		   /* addglue */
};

isc_result_t
dns_ncache_getrdataset(dns_rdataset_t *ncacherdataset, dns_name_t *name,
		       dns_rdatatype_t type, dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_region_t remaining;
	isc_buffer_t source;
	dns_name_t tname;
	dns_rdatatype_t ttype;
	dns_trust_t trust = dns_trust_none;
	dns_rdataset_t rclone;

	REQUIRE(ncacherdataset != NULL);
	REQUIRE(ncacherdataset->type == 0);
	REQUIRE((ncacherdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0);
	REQUIRE(name != NULL);
	REQUIRE(!dns_rdataset_isassociated(rdataset));
	REQUIRE(type != dns_rdatatype_rrsig);

	dns_rdataset_init(&rclone);
	dns_rdataset_clone(ncacherdataset, &rclone);
	result = dns_rdataset_first(&rclone);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&rclone, &rdata);
		isc_buffer_init(&source, rdata.data, rdata.length);
		isc_buffer_add(&source, rdata.length);
		dns_name_init(&tname, NULL);
		isc_buffer_remainingregion(&source, &remaining);
		dns_name_fromregion(&tname, &remaining);
		INSIST(remaining.length >= tname.length);
		isc_buffer_forward(&source, tname.length);
		remaining.length -= tname.length;

		INSIST(remaining.length >= 3);
		ttype = isc_buffer_getuint16(&source);

		if (ttype == type && dns_name_equal(&tname, name)) {
			trust = isc_buffer_getuint8(&source);
			INSIST(trust <= dns_trust_ultimate);
			isc_buffer_remainingregion(&source, &remaining);
			break;
		}
		result = dns_rdataset_next(&rclone);
		dns_rdata_reset(&rdata);
	}
	dns_rdataset_disassociate(&rclone);
	if (result == ISC_R_NOMORE) {
		return (ISC_R_NOTFOUND);
	}
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	INSIST(remaining.length != 0);

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = ncacherdataset->rdclass;
	rdataset->type = type;
	rdataset->covers = 0;
	rdataset->ttl = ncacherdataset->ttl;
	rdataset->trust = trust;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;

	rdataset->private3 = remaining.base;

	/*
	 * Reset iterator state.
	 */
	rdataset->privateuint4 = 0;
	rdataset->private5 = NULL;
	rdataset->private6 = NULL;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_ncache_getsigrdataset(dns_rdataset_t *ncacherdataset, dns_name_t *name,
			  dns_rdatatype_t covers, dns_rdataset_t *rdataset) {
	dns_name_t tname;
	dns_rdata_rrsig_t rrsig;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_rdataset_t rclone;
	dns_rdatatype_t type;
	dns_trust_t trust = dns_trust_none;
	isc_buffer_t source;
	isc_region_t remaining, sigregion;
	isc_result_t result;
	unsigned char *raw;
	unsigned int count;

	REQUIRE(ncacherdataset != NULL);
	REQUIRE(ncacherdataset->type == 0);
	REQUIRE((ncacherdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0);
	REQUIRE(name != NULL);
	REQUIRE(!dns_rdataset_isassociated(rdataset));

	dns_rdataset_init(&rclone);
	dns_rdataset_clone(ncacherdataset, &rclone);
	result = dns_rdataset_first(&rclone);
	while (result == ISC_R_SUCCESS) {
		dns_rdataset_current(&rclone, &rdata);
		isc_buffer_init(&source, rdata.data, rdata.length);
		isc_buffer_add(&source, rdata.length);
		dns_name_init(&tname, NULL);
		isc_buffer_remainingregion(&source, &remaining);
		dns_name_fromregion(&tname, &remaining);
		INSIST(remaining.length >= tname.length);
		isc_buffer_forward(&source, tname.length);
		isc_region_consume(&remaining, tname.length);

		INSIST(remaining.length >= 2);
		type = isc_buffer_getuint16(&source);
		isc_region_consume(&remaining, 2);

		if (type != dns_rdatatype_rrsig ||
		    !dns_name_equal(&tname, name))
		{
			result = dns_rdataset_next(&rclone);
			dns_rdata_reset(&rdata);
			continue;
		}

		INSIST(remaining.length >= 1);
		trust = isc_buffer_getuint8(&source);
		INSIST(trust <= dns_trust_ultimate);
		isc_region_consume(&remaining, 1);

		raw = remaining.base;
		count = raw[0] * 256 + raw[1];
		INSIST(count > 0);
		raw += 2;
		sigregion.length = raw[0] * 256 + raw[1];
		raw += 2;
		sigregion.base = raw;
		dns_rdata_reset(&rdata);
		dns_rdata_fromregion(&rdata, rdataset->rdclass,
				     dns_rdatatype_rrsig, &sigregion);
		(void)dns_rdata_tostruct(&rdata, &rrsig, NULL);
		if (rrsig.covered == covers) {
			isc_buffer_remainingregion(&source, &remaining);
			break;
		}

		result = dns_rdataset_next(&rclone);
		dns_rdata_reset(&rdata);
	}
	dns_rdataset_disassociate(&rclone);
	if (result == ISC_R_NOMORE) {
		return (ISC_R_NOTFOUND);
	}
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	INSIST(remaining.length != 0);

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = ncacherdataset->rdclass;
	rdataset->type = dns_rdatatype_rrsig;
	rdataset->covers = covers;
	rdataset->ttl = ncacherdataset->ttl;
	rdataset->trust = trust;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;

	rdataset->private3 = remaining.base;

	/*
	 * Reset iterator state.
	 */
	rdataset->privateuint4 = 0;
	rdataset->private5 = NULL;
	rdataset->private6 = NULL;
	return (ISC_R_SUCCESS);
}

void
dns_ncache_current(dns_rdataset_t *ncacherdataset, dns_name_t *found,
		   dns_rdataset_t *rdataset) {
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_trust_t trust;
	isc_region_t remaining, sigregion;
	isc_buffer_t source;
	dns_name_t tname;
	dns_rdatatype_t type;
	unsigned int count;
	dns_rdata_rrsig_t rrsig;
	unsigned char *raw;

	REQUIRE(ncacherdataset != NULL);
	REQUIRE(ncacherdataset->type == 0);
	REQUIRE((ncacherdataset->attributes & DNS_RDATASETATTR_NEGATIVE) != 0);
	REQUIRE(found != NULL);
	REQUIRE(!dns_rdataset_isassociated(rdataset));

	dns_rdataset_current(ncacherdataset, &rdata);
	isc_buffer_init(&source, rdata.data, rdata.length);
	isc_buffer_add(&source, rdata.length);

	dns_name_init(&tname, NULL);
	isc_buffer_remainingregion(&source, &remaining);
	dns_name_fromregion(found, &remaining);
	INSIST(remaining.length >= found->length);
	isc_buffer_forward(&source, found->length);
	remaining.length -= found->length;

	INSIST(remaining.length >= 5);
	type = isc_buffer_getuint16(&source);
	trust = isc_buffer_getuint8(&source);
	INSIST(trust <= dns_trust_ultimate);
	isc_buffer_remainingregion(&source, &remaining);

	rdataset->methods = &rdataset_methods;
	rdataset->rdclass = ncacherdataset->rdclass;
	rdataset->type = type;
	if (type == dns_rdatatype_rrsig) {
		/*
		 * Extract covers from RRSIG.
		 */
		raw = remaining.base;
		count = raw[0] * 256 + raw[1];
		INSIST(count > 0);
		raw += 2;
		sigregion.length = raw[0] * 256 + raw[1];
		raw += 2;
		sigregion.base = raw;
		dns_rdata_reset(&rdata);
		dns_rdata_fromregion(&rdata, rdataset->rdclass, rdataset->type,
				     &sigregion);
		(void)dns_rdata_tostruct(&rdata, &rrsig, NULL);
		rdataset->covers = rrsig.covered;
	} else {
		rdataset->covers = 0;
	}
	rdataset->ttl = ncacherdataset->ttl;
	rdataset->trust = trust;
	rdataset->private1 = NULL;
	rdataset->private2 = NULL;

	rdataset->private3 = remaining.base;

	/*
	 * Reset iterator state.
	 */
	rdataset->privateuint4 = 0;
	rdataset->private5 = NULL;
	rdataset->private6 = NULL;
}
