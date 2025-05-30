/*	$NetBSD: ht.c,v 1.11 2025/01/26 16:25:37 christos Exp $	*/

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

#include <inttypes.h>
#include <string.h>

#include <isc/ascii.h>
#include <isc/hash.h>
#include <isc/ht.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

typedef struct isc_ht_node isc_ht_node_t;

#define ISC_HT_MAGIC	 ISC_MAGIC('H', 'T', 'a', 'b')
#define ISC_HT_VALID(ht) ISC_MAGIC_VALID(ht, ISC_HT_MAGIC)

#define HT_NO_BITS    0
#define HT_MIN_BITS   1
#define HT_MAX_BITS   32
#define HT_OVERCOMMIT 3

#define HT_NEXTTABLE(idx)      ((idx == 0) ? 1 : 0)
#define TRY_NEXTTABLE(idx, ht) (idx == ht->hindex && rehashing_in_progress(ht))

#define GOLDEN_RATIO_32 0x61C88647

#define HASHSIZE(bits) (UINT64_C(1) << (bits))

struct isc_ht_node {
	void *value;
	isc_ht_node_t *next;
	uint32_t hashval;
	size_t keysize;
	unsigned char key[];
};

struct isc_ht {
	unsigned int magic;
	isc_mem_t *mctx;
	size_t count;
	bool case_sensitive;
	size_t size[2];
	uint8_t hashbits[2];
	isc_ht_node_t **table[2];
	uint8_t hindex;
	uint32_t hiter; /* rehashing iterator */
};

struct isc_ht_iter {
	isc_ht_t *ht;
	size_t i;
	uint8_t hindex;
	isc_ht_node_t *cur;
};

static isc_ht_node_t *
isc__ht_find(const isc_ht_t *ht, const unsigned char *key,
	     const uint32_t keysize, const uint32_t hashval, const uint8_t idx);
static void
isc__ht_add(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize,
	    const uint32_t hashval, const uint8_t idx, void *value);
static isc_result_t
isc__ht_delete(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize,
	       const uint32_t hashval, const uint8_t idx);

static uint32_t
rehash_bits(isc_ht_t *ht, size_t newcount);

static void
hashtable_new(isc_ht_t *ht, const uint8_t idx, const uint8_t bits);
static void
hashtable_free(isc_ht_t *ht, const uint8_t idx);
static void
hashtable_rehash(isc_ht_t *ht, uint32_t newbits);
static void
hashtable_rehash_one(isc_ht_t *ht);
static void
maybe_rehash(isc_ht_t *ht, size_t newcount);

static isc_result_t
isc__ht_iter_next(isc_ht_iter_t *it);

static bool
isc__ht_node_match(isc_ht_node_t *node, const uint32_t hashval,
		   const uint8_t *key, uint32_t keysize, bool case_sensitive) {
	return node->hashval == hashval && node->keysize == keysize &&
	       (case_sensitive
			? (memcmp(node->key, key, keysize) == 0)
			: (isc_ascii_lowerequal(node->key, key, keysize)));
}

static uint32_t
hash_32(uint32_t val, unsigned int bits) {
	REQUIRE(bits <= HT_MAX_BITS);
	/* High bits are more random. */
	return val * GOLDEN_RATIO_32 >> (32 - bits);
}

static bool
rehashing_in_progress(const isc_ht_t *ht) {
	return ht->table[HT_NEXTTABLE(ht->hindex)] != NULL;
}

static bool
hashtable_is_overcommited(isc_ht_t *ht) {
	return ht->count >= (ht->size[ht->hindex] * HT_OVERCOMMIT);
}

static uint32_t
rehash_bits(isc_ht_t *ht, size_t newcount) {
	uint32_t newbits = ht->hashbits[ht->hindex];

	while (newcount >= HASHSIZE(newbits) && newbits <= HT_MAX_BITS) {
		newbits += 1;
	}

	return newbits;
}

/*
 * Rebuild the hashtable to reduce the load factor
 */
static void
hashtable_rehash(isc_ht_t *ht, uint32_t newbits) {
	uint8_t oldindex = ht->hindex;
	uint32_t oldbits = ht->hashbits[oldindex];
	uint8_t newindex = HT_NEXTTABLE(oldindex);

	REQUIRE(ht->hashbits[oldindex] >= HT_MIN_BITS);
	REQUIRE(ht->hashbits[oldindex] <= HT_MAX_BITS);
	REQUIRE(ht->table[oldindex] != NULL);

	REQUIRE(newbits <= HT_MAX_BITS);
	REQUIRE(ht->hashbits[newindex] == HT_NO_BITS);
	REQUIRE(ht->table[newindex] == NULL);

	REQUIRE(newbits > oldbits);

	hashtable_new(ht, newindex, newbits);

	ht->hindex = newindex;

	hashtable_rehash_one(ht);
}

static void
hashtable_rehash_one(isc_ht_t *ht) {
	isc_ht_node_t **newtable = ht->table[ht->hindex];
	uint32_t oldsize = ht->size[HT_NEXTTABLE(ht->hindex)];
	isc_ht_node_t **oldtable = ht->table[HT_NEXTTABLE(ht->hindex)];
	isc_ht_node_t *node = NULL;
	isc_ht_node_t *nextnode;

	/* Find first non-empty node */
	while (ht->hiter < oldsize && oldtable[ht->hiter] == NULL) {
		ht->hiter++;
	}

	/* Rehashing complete */
	if (ht->hiter == oldsize) {
		hashtable_free(ht, HT_NEXTTABLE(ht->hindex));
		ht->hiter = 0;
		return;
	}

	/* Move the first non-empty node from old hashtable to new hashtable */
	for (node = oldtable[ht->hiter]; node != NULL; node = nextnode) {
		uint32_t hash = hash_32(node->hashval,
					ht->hashbits[ht->hindex]);
		nextnode = node->next;
		node->next = newtable[hash];
		newtable[hash] = node;
	}

	oldtable[ht->hiter] = NULL;

	ht->hiter++;
}

static void
maybe_rehash(isc_ht_t *ht, size_t newcount) {
	uint32_t newbits = rehash_bits(ht, newcount);

	if (ht->hashbits[ht->hindex] < newbits && newbits <= HT_MAX_BITS) {
		hashtable_rehash(ht, newbits);
	}
}

static void
hashtable_new(isc_ht_t *ht, const uint8_t idx, const uint8_t bits) {
	REQUIRE(ht->hashbits[idx] == HT_NO_BITS);
	REQUIRE(ht->table[idx] == NULL);
	REQUIRE(bits >= HT_MIN_BITS);
	REQUIRE(bits <= HT_MAX_BITS);

	ht->hashbits[idx] = bits;
	ht->size[idx] = HASHSIZE(ht->hashbits[idx]);

	ht->table[idx] = isc_mem_cget(ht->mctx, ht->size[idx],
				      sizeof(isc_ht_node_t *));
}

static void
hashtable_free(isc_ht_t *ht, const uint8_t idx) {
	for (size_t i = 0; i < ht->size[idx]; i++) {
		isc_ht_node_t *node = ht->table[idx][i];
		while (node != NULL) {
			isc_ht_node_t *next = node->next;
			ht->count--;
			isc_mem_put(ht->mctx, node,
				    sizeof(*node) + node->keysize);
			node = next;
		}
	}

	isc_mem_cput(ht->mctx, ht->table[idx], ht->size[idx],
		     sizeof(isc_ht_node_t *));

	ht->hashbits[idx] = HT_NO_BITS;
	ht->table[idx] = NULL;
}

void
isc_ht_init(isc_ht_t **htp, isc_mem_t *mctx, uint8_t bits,
	    unsigned int options) {
	isc_ht_t *ht = NULL;
	bool case_sensitive = ((options & ISC_HT_CASE_INSENSITIVE) == 0);

	REQUIRE(htp != NULL && *htp == NULL);
	REQUIRE(mctx != NULL);
	REQUIRE(bits >= 1 && bits <= HT_MAX_BITS);

	ht = isc_mem_get(mctx, sizeof(*ht));
	*ht = (isc_ht_t){
		.case_sensitive = case_sensitive,
	};

	isc_mem_attach(mctx, &ht->mctx);

	hashtable_new(ht, 0, bits);

	ht->magic = ISC_HT_MAGIC;

	*htp = ht;
}

void
isc_ht_destroy(isc_ht_t **htp) {
	isc_ht_t *ht;

	REQUIRE(htp != NULL);
	REQUIRE(ISC_HT_VALID(*htp));

	ht = *htp;
	*htp = NULL;
	ht->magic = 0;

	for (size_t i = 0; i <= 1; i++) {
		if (ht->table[i] != NULL) {
			hashtable_free(ht, i);
		}
	}

	INSIST(ht->count == 0);

	isc_mem_putanddetach(&ht->mctx, ht, sizeof(*ht));
}

static void
isc__ht_add(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize,
	    const uint32_t hashval, const uint8_t idx, void *value) {
	isc_ht_node_t *node;
	uint32_t hash;

	hash = hash_32(hashval, ht->hashbits[idx]);

	node = isc_mem_get(ht->mctx, STRUCT_FLEX_SIZE(node, key, keysize));
	*node = (isc_ht_node_t){
		.keysize = keysize,
		.hashval = hashval,
		.next = ht->table[idx][hash],
		.value = value,
	};

	memmove(node->key, key, keysize);

	ht->count++;
	ht->table[idx][hash] = node;
}

isc_result_t
isc_ht_add(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize,
	   void *value) {
	uint32_t hashval;

	REQUIRE(ISC_HT_VALID(ht));
	REQUIRE(key != NULL && keysize > 0);

	if (rehashing_in_progress(ht)) {
		/* Rehash in progress */
		hashtable_rehash_one(ht);
	} else if (hashtable_is_overcommited(ht)) {
		/* Rehash requested */
		maybe_rehash(ht, ht->count);
	}

	hashval = isc_hash32(key, keysize, ht->case_sensitive);

	if (isc__ht_find(ht, key, keysize, hashval, ht->hindex) != NULL) {
		return ISC_R_EXISTS;
	}

	isc__ht_add(ht, key, keysize, hashval, ht->hindex, value);

	return ISC_R_SUCCESS;
}

static isc_ht_node_t *
isc__ht_find(const isc_ht_t *ht, const unsigned char *key,
	     const uint32_t keysize, const uint32_t hashval,
	     const uint8_t idx) {
	uint32_t hash;
	uint8_t findex = idx;

nexttable:
	hash = hash_32(hashval, ht->hashbits[findex]);
	for (isc_ht_node_t *node = ht->table[findex][hash]; node != NULL;
	     node = node->next)
	{
		if (isc__ht_node_match(node, hashval, key, keysize,
				       ht->case_sensitive))
		{
			return node;
		}
	}
	if (TRY_NEXTTABLE(findex, ht)) {
		/*
		 * Rehashing in progress, check the other table
		 */
		findex = HT_NEXTTABLE(findex);
		goto nexttable;
	}

	return NULL;
}

isc_result_t
isc_ht_find(const isc_ht_t *ht, const unsigned char *key,
	    const uint32_t keysize, void **valuep) {
	uint32_t hashval;
	isc_ht_node_t *node;

	REQUIRE(ISC_HT_VALID(ht));
	REQUIRE(key != NULL && keysize > 0);
	REQUIRE(valuep == NULL || *valuep == NULL);

	hashval = isc_hash32(key, keysize, ht->case_sensitive);

	node = isc__ht_find(ht, key, keysize, hashval, ht->hindex);
	if (node == NULL) {
		return ISC_R_NOTFOUND;
	}

	SET_IF_NOT_NULL(valuep, node->value);
	return ISC_R_SUCCESS;
}

static isc_result_t
isc__ht_delete(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize,
	       const uint32_t hashval, const uint8_t idx) {
	isc_ht_node_t *prev = NULL;
	uint32_t hash;

	hash = hash_32(hashval, ht->hashbits[idx]);

	for (isc_ht_node_t *node = ht->table[idx][hash]; node != NULL;
	     prev = node, node = node->next)
	{
		if (isc__ht_node_match(node, hashval, key, keysize,
				       ht->case_sensitive))
		{
			if (prev == NULL) {
				ht->table[idx][hash] = node->next;
			} else {
				prev->next = node->next;
			}
			isc_mem_put(ht->mctx, node,
				    STRUCT_FLEX_SIZE(node, key, node->keysize));
			ht->count--;

			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}

isc_result_t
isc_ht_delete(isc_ht_t *ht, const unsigned char *key, const uint32_t keysize) {
	uint32_t hashval;
	uint8_t hindex;
	isc_result_t result;

	REQUIRE(ISC_HT_VALID(ht));
	REQUIRE(key != NULL && keysize > 0);

	if (rehashing_in_progress(ht)) {
		/* Rehash in progress */
		hashtable_rehash_one(ht);
	}

	hindex = ht->hindex;
	hashval = isc_hash32(key, keysize, ht->case_sensitive);
nexttable:
	result = isc__ht_delete(ht, key, keysize, hashval, hindex);

	if (result == ISC_R_NOTFOUND && TRY_NEXTTABLE(hindex, ht)) {
		/*
		 * Rehashing in progress, check the other table
		 */
		hindex = HT_NEXTTABLE(hindex);
		goto nexttable;
	}

	return result;
}

void
isc_ht_iter_create(isc_ht_t *ht, isc_ht_iter_t **itp) {
	isc_ht_iter_t *it;

	REQUIRE(ISC_HT_VALID(ht));
	REQUIRE(itp != NULL && *itp == NULL);

	it = isc_mem_get(ht->mctx, sizeof(isc_ht_iter_t));
	*it = (isc_ht_iter_t){
		.ht = ht,
		.hindex = ht->hindex,
	};

	*itp = it;
}

void
isc_ht_iter_destroy(isc_ht_iter_t **itp) {
	isc_ht_iter_t *it;
	isc_ht_t *ht;

	REQUIRE(itp != NULL && *itp != NULL);

	it = *itp;
	*itp = NULL;
	ht = it->ht;
	isc_mem_put(ht->mctx, it, sizeof(*it));
}

isc_result_t
isc_ht_iter_first(isc_ht_iter_t *it) {
	isc_ht_t *ht;

	REQUIRE(it != NULL);

	ht = it->ht;

	it->hindex = ht->hindex;
	it->i = 0;

	return isc__ht_iter_next(it);
}

static isc_result_t
isc__ht_iter_next(isc_ht_iter_t *it) {
	isc_ht_t *ht = it->ht;

	while (it->i < ht->size[it->hindex] &&
	       ht->table[it->hindex][it->i] == NULL)
	{
		it->i++;
	}

	if (it->i < ht->size[it->hindex]) {
		it->cur = ht->table[it->hindex][it->i];

		return ISC_R_SUCCESS;
	}

	if (TRY_NEXTTABLE(it->hindex, ht)) {
		it->hindex = HT_NEXTTABLE(it->hindex);
		it->i = 0;
		return isc__ht_iter_next(it);
	}

	return ISC_R_NOMORE;
}

isc_result_t
isc_ht_iter_next(isc_ht_iter_t *it) {
	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);

	it->cur = it->cur->next;

	if (it->cur != NULL) {
		return ISC_R_SUCCESS;
	}

	it->i++;

	return isc__ht_iter_next(it);
}

isc_result_t
isc_ht_iter_delcurrent_next(isc_ht_iter_t *it) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_ht_node_t *dnode = NULL;
	uint8_t dindex;
	isc_ht_t *ht;
	isc_result_t dresult;

	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);

	ht = it->ht;
	dnode = it->cur;
	dindex = it->hindex;

	result = isc_ht_iter_next(it);

	dresult = isc__ht_delete(ht, dnode->key, dnode->keysize, dnode->hashval,
				 dindex);
	INSIST(dresult == ISC_R_SUCCESS);

	return result;
}

void
isc_ht_iter_current(isc_ht_iter_t *it, void **valuep) {
	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);
	REQUIRE(valuep != NULL && *valuep == NULL);

	*valuep = it->cur->value;
}

void
isc_ht_iter_currentkey(isc_ht_iter_t *it, unsigned char **key,
		       size_t *keysize) {
	REQUIRE(it != NULL);
	REQUIRE(it->cur != NULL);
	REQUIRE(key != NULL && *key == NULL);

	*key = it->cur->key;
	*keysize = it->cur->keysize;
}

size_t
isc_ht_count(const isc_ht_t *ht) {
	REQUIRE(ISC_HT_VALID(ht));

	return ht->count;
}
