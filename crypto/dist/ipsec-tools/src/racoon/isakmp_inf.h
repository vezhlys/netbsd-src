/*	$NetBSD: isakmp_inf.h,v 1.6 2025/03/07 15:55:29 christos Exp $	*/

/* Id: isakmp_inf.h,v 1.6 2005/05/07 14:15:59 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _ISAKMP_INF_H
#define _ISAKMP_INF_H

struct saproto;
extern int isakmp_info_recv(struct ph1handle *, vchar_t *);
extern int isakmp_info_send_d1(struct ph1handle *);
extern int isakmp_info_send_d2(struct ph2handle *);
extern int isakmp_info_send_nx(struct isakmp *, struct sockaddr *,
    struct sockaddr *, int, vchar_t *);
extern int isakmp_info_send_n1(struct ph1handle *, int, vchar_t *);
extern int isakmp_info_send_n2(struct ph2handle *, int, vchar_t *);
extern int isakmp_info_send_common(struct ph1handle *, vchar_t *, uint32_t,
    int);

extern vchar_t * isakmp_add_pl_n(vchar_t *, uint8_t **, int, struct saproto *,
    vchar_t *);

extern int isakmp_log_notify(struct ph1handle *, struct isakmp_pl_n *, const char *exchange);
extern int isakmp_info_recv_initialcontact(struct ph1handle *, struct ph2handle *);

#ifdef ENABLE_DPD
extern int isakmp_sched_r_u(struct ph1handle *, int);
#endif

extern void purge_ipsec_spi(struct sockaddr *, int,	uint32_t *, size_t);
extern int tunnel_mode_prop(struct saprop *);

#endif /* _ISAKMP_INF_H */
