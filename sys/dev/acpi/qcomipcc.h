/* $NetBS$ */
/*	$OpenBSD: qcipcc.c,v 1.2 2023/05/19 20:54:55 patrick Exp $	*/
/*
 * Copyright (c) 2023 Patrick Wildt <patrick@blueri.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

void	*qcipcc_intr_establish(uint16_t, uint16_t, int,
	    int (*)(void *), void *);
void	qcipcc_intr_disestablish(void *);
void	qcipcc_intr_enable(void *);
void	qcipcc_intr_disable(void *);

void	*qcipcc_channel(uint16_t, uint16_t);
int	qcipcc_send(void *);
