/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: print-ftp.c,v 1.5 2024/09/02 16:15:31 christos Exp $");
#endif

/* \summary: File Transfer Protocol (FTP) printer */

#include <config.h>

#include "netdissect-stdinc.h"

#include "netdissect.h"

void
ftp_print(netdissect_options *ndo, const u_char *pptr, u_int len)
{
	ndo->ndo_protocol = "ftp";
	txtproto_print(ndo, pptr, len, NULL, 0);
}
