/*	$NetBSD: fsm.h,v 1.6 2025/01/08 19:59:39 christos Exp $	*/

/*
 * fsm.h - {Link, IP} Control Protocol Finite State Machine definitions.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef PPP_FSM_H
#define PPP_FSM_H

#include "pppdconf.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Packet header = Code, id, length.
 */
#define HEADERLEN	4

/*
 *  CP (LCP, IPCP, etc.) codes.
 */
#define CONFREQ		1	/* Configuration Request */
#define CONFACK		2	/* Configuration Ack */
#define CONFNAK		3	/* Configuration Nak */
#define CONFREJ		4	/* Configuration Reject */
#define TERMREQ		5	/* Termination Request */
#define TERMACK		6	/* Termination Ack */
#define CODEREJ		7	/* Code Reject */


/*
 * Each FSM is described by an fsm structure and fsm callbacks.
 */
typedef struct fsm {
    int unit;			/* Interface unit number */
    int protocol;		/* Data Link Layer Protocol field value */
    int state;			/* State */
    int flags;			/* Contains option bits */
    unsigned char id;			/* Current id */
    unsigned char reqid;		/* Current request id */
    unsigned char seen_ack;		/* Have received valid Ack/Nak/Rej to Req */
    int timeouttime;		/* Timeout time in milliseconds */
    int maxconfreqtransmits;	/* Maximum Configure-Request transmissions */
    int retransmits;		/* Number of retransmissions left */
    int maxtermtransmits;	/* Maximum Terminate-Request transmissions */
    int nakloops;		/* Number of nak loops since last ack */
    int rnakloops;		/* Number of naks received */
    int maxnakloops;		/* Maximum number of nak loops tolerated */
    struct fsm_callbacks *callbacks;	/* Callback routines */
    char *term_reason;		/* Reason for closing protocol */
    int term_reason_len;	/* Length of term_reason */
} fsm;


typedef struct fsm_callbacks {
    void (*resetci)(fsm *);	/* Reset our Configuration Information */
    int  (*cilen)(fsm *);	/* Length of our Configuration Information */
    void (*addci) 		/* Add our Configuration Information */
		(fsm *, unsigned char *, int *);
    int  (*ackci)		/* ACK our Configuration Information */
		(fsm *, unsigned char *, int);
    int  (*nakci)		/* NAK our Configuration Information */
		(fsm *, unsigned char *, int, int);
    int  (*rejci)		/* Reject our Configuration Information */
		(fsm *, unsigned char *, int);
    int  (*reqci)		/* Request peer's Configuration Information */
		(fsm *, unsigned char *, int *, int);
    void (*up)(fsm *);		/* Called when fsm reaches OPENED state */
    void (*down)(fsm *);	/* Called when fsm leaves OPENED state */
    void (*starting)(fsm *);	/* Called when we want the lower layer */
    void (*finished)(fsm *);	/* Called when we don't want the lower layer */
    void (*protreject)(int);	/* Called when Protocol-Reject received */
    void (*retransmit)(fsm *);	/* Retransmission is necessary */
    int  (*extcode)		/* Called when unknown code received */
		(fsm *, int, int, unsigned char *, int);
    char *proto_name;		/* String name for protocol (for messages) */
} fsm_callbacks;


/*
 * Link states.
 */
#define INITIAL		0	/* Down, hasn't been opened */
#define STARTING	1	/* Down, been opened */
#define CLOSED		2	/* Up, hasn't been opened */
#define STOPPED		3	/* Open, waiting for down event */
#define CLOSING		4	/* Terminating the connection, not open */
#define STOPPING	5	/* Terminating, but open */
#define REQSENT		6	/* We've sent a Config Request */
#define ACKRCVD		7	/* We've received a Config Ack */
#define ACKSENT		8	/* We've sent a Config Ack */
#define OPENED		9	/* Connection available */


/*
 * Flags - indicate options controlling FSM operation
 */
#define OPT_PASSIVE	1	/* Don't die if we don't get a response */
#define OPT_RESTART	2	/* Treat 2nd OPEN as DOWN, UP */
#define OPT_SILENT	4	/* Wait for peer to speak first */


/*
 * Timeouts.
 */
#define DEFTIMEOUT	3	/* Timeout time in seconds */
#define DEFMAXTERMREQS	2	/* Maximum Terminate-Request transmissions */
#define DEFMAXCONFREQS	10	/* Maximum Configure-Request transmissions */
#define DEFMAXNAKLOOPS	5	/* Maximum number of nak loops */


/*
 * Prototypes
 */
void fsm_init (fsm *);
void fsm_lowerup (fsm *);
void fsm_lowerdown (fsm *);
void fsm_open (fsm *);
void fsm_close (fsm *, char *);
void fsm_input (fsm *, unsigned char *, int);
void fsm_protreject (fsm *);
void fsm_sdata (fsm *, int, int, unsigned char *, int);


/*
 * Variables
 */
extern int peer_mru[];		/* currently negotiated peer MRU (per unit) */

#ifdef __cplusplus
}
#endif

#endif // PPP_FSM_H
