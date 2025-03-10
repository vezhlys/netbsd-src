/*	$NetBSD: if_wm.c,v 1.801 2024/11/10 11:46:24 mlelstv Exp $	*/

/*
 * Copyright (c) 2001, 2002, 2003, 2004 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*******************************************************************************

  Copyright (c) 2001-2005, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

*******************************************************************************/
/*
 * Device driver for the Intel i8254x family of Gigabit Ethernet chips.
 *
 * TODO (in order of importance):
 *
 *	- Check XXX'ed comments
 *	- TX Multi queue improvement (refine queue selection logic)
 *	- Split header buffer for newer descriptors
 *	- EEE (Energy Efficiency Ethernet) for I354
 *	- Virtual Function
 *	- Set LED correctly (based on contents in EEPROM)
 *	- Rework how parameters are loaded from the EEPROM.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_wm.c,v 1.801 2024/11/10 11:46:24 mlelstv Exp $");

#ifdef _KERNEL_OPT
#include "opt_if_wm.h"
#endif

#include <sys/param.h>

#include <sys/atomic.h>
#include <sys/callout.h>
#include <sys/cpu.h>
#include <sys/device.h>
#include <sys/errno.h>
#include <sys/interrupt.h>
#include <sys/ioctl.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/pcq.h>
#include <sys/queue.h>
#include <sys/rndsource.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/workqueue.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_ether.h>

#include <net/bpf.h>

#include <net/rss_config.h>

#include <netinet/in.h>			/* XXX for struct ip */
#include <netinet/in_systm.h>		/* XXX for struct ip */
#include <netinet/ip.h>			/* XXX for struct ip */
#include <netinet/ip6.h>		/* XXX for struct ip6_hdr */
#include <netinet/tcp.h>		/* XXX for struct tcphdr */

#include <sys/bus.h>
#include <sys/intr.h>
#include <machine/endian.h>

#include <dev/mii/mii.h>
#include <dev/mii/mdio.h>
#include <dev/mii/miivar.h>
#include <dev/mii/miidevs.h>
#include <dev/mii/mii_bitbang.h>
#include <dev/mii/ikphyreg.h>
#include <dev/mii/igphyreg.h>
#include <dev/mii/igphyvar.h>
#include <dev/mii/inbmphyreg.h>
#include <dev/mii/ihphyreg.h>
#include <dev/mii/makphyreg.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/pci/if_wmreg.h>
#include <dev/pci/if_wmvar.h>

#ifdef WM_DEBUG
#define	WM_DEBUG_LINK		__BIT(0)
#define	WM_DEBUG_TX		__BIT(1)
#define	WM_DEBUG_RX		__BIT(2)
#define	WM_DEBUG_GMII		__BIT(3)
#define	WM_DEBUG_MANAGE		__BIT(4)
#define	WM_DEBUG_NVM		__BIT(5)
#define	WM_DEBUG_INIT		__BIT(6)
#define	WM_DEBUG_LOCK		__BIT(7)

#if 0
#define WM_DEBUG_DEFAULT	WM_DEBUG_TX | WM_DEBUG_RX | WM_DEBUG_LINK | \
	WM_DEBUG_GMII | WM_DEBUG_MANAGE | WM_DEBUG_NVM | WM_DEBUG_INIT |    \
	WM_DEBUG_LOCK
#endif

#define	DPRINTF(sc, x, y)			  \
	do {					  \
		if ((sc)->sc_debug & (x))	  \
			printf y;		  \
	} while (0)
#else
#define	DPRINTF(sc, x, y)	__nothing
#endif /* WM_DEBUG */

#define WM_WORKQUEUE_PRI PRI_SOFTNET

/*
 * This device driver's max interrupt numbers.
 */
#define WM_MAX_NQUEUEINTR	16
#define WM_MAX_NINTR		(WM_MAX_NQUEUEINTR + 1)

#ifndef WM_DISABLE_MSI
#define	WM_DISABLE_MSI 0
#endif
#ifndef WM_DISABLE_MSIX
#define	WM_DISABLE_MSIX 0
#endif

int wm_disable_msi = WM_DISABLE_MSI;
int wm_disable_msix = WM_DISABLE_MSIX;

#ifndef WM_WATCHDOG_TIMEOUT
#define WM_WATCHDOG_TIMEOUT 5
#endif
static int wm_watchdog_timeout = WM_WATCHDOG_TIMEOUT;

/*
 * Transmit descriptor list size.  Due to errata, we can only have
 * 256 hardware descriptors in the ring on < 82544, but we use 4096
 * on >= 82544. We tell the upper layers that they can queue a lot
 * of packets, and we go ahead and manage up to 64 (16 for the i82547)
 * of them at a time.
 *
 * We allow up to 64 DMA segments per packet.  Pathological packet
 * chains containing many small mbufs have been observed in zero-copy
 * situations with jumbo frames. If a mbuf chain has more than 64 DMA segments,
 * m_defrag() is called to reduce it.
 */
#define	WM_NTXSEGS		64
#define	WM_IFQUEUELEN		256
#define	WM_TXQUEUELEN_MAX	64
#define	WM_TXQUEUELEN_MAX_82547	16
#define	WM_TXQUEUELEN(txq)	((txq)->txq_num)
#define	WM_TXQUEUELEN_MASK(txq)	(WM_TXQUEUELEN(txq) - 1)
#define	WM_TXQUEUE_GC(txq)	(WM_TXQUEUELEN(txq) / 8)
#define	WM_NTXDESC_82542	256
#define	WM_NTXDESC_82544	4096
#define	WM_NTXDESC(txq)		((txq)->txq_ndesc)
#define	WM_NTXDESC_MASK(txq)	(WM_NTXDESC(txq) - 1)
#define	WM_TXDESCS_SIZE(txq)	(WM_NTXDESC(txq) * (txq)->txq_descsize)
#define	WM_NEXTTX(txq, x)	(((x) + 1) & WM_NTXDESC_MASK(txq))
#define	WM_NEXTTXS(txq, x)	(((x) + 1) & WM_TXQUEUELEN_MASK(txq))

#define	WM_MAXTXDMA		 (2 * round_page(IP_MAXPACKET)) /* for TSO */

#define	WM_TXINTERQSIZE		256

#ifndef WM_TX_PROCESS_LIMIT_DEFAULT
#define	WM_TX_PROCESS_LIMIT_DEFAULT		100U
#endif
#ifndef WM_TX_INTR_PROCESS_LIMIT_DEFAULT
#define	WM_TX_INTR_PROCESS_LIMIT_DEFAULT	0U
#endif

/*
 * Receive descriptor list size.  We have one Rx buffer for normal
 * sized packets.  Jumbo packets consume 5 Rx buffers for a full-sized
 * packet.  We allocate 256 receive descriptors, each with a 2k
 * buffer (MCLBYTES), which gives us room for 50 jumbo packets.
 */
#define	WM_NRXDESC		256U
#define	WM_NRXDESC_MASK		(WM_NRXDESC - 1)
#define	WM_NEXTRX(x)		(((x) + 1) & WM_NRXDESC_MASK)
#define	WM_PREVRX(x)		(((x) - 1) & WM_NRXDESC_MASK)

#ifndef WM_RX_PROCESS_LIMIT_DEFAULT
#define	WM_RX_PROCESS_LIMIT_DEFAULT		100U
#endif
#ifndef WM_RX_INTR_PROCESS_LIMIT_DEFAULT
#define	WM_RX_INTR_PROCESS_LIMIT_DEFAULT	0U
#endif

typedef union txdescs {
	wiseman_txdesc_t sctxu_txdescs[WM_NTXDESC_82544];
	nq_txdesc_t	 sctxu_nq_txdescs[WM_NTXDESC_82544];
} txdescs_t;

typedef union rxdescs {
	wiseman_rxdesc_t sctxu_rxdescs[WM_NRXDESC];
	ext_rxdesc_t	 sctxu_ext_rxdescs[WM_NRXDESC]; /* 82574 only */
	nq_rxdesc_t	 sctxu_nq_rxdescs[WM_NRXDESC]; /* 82575 and newer */
} rxdescs_t;

#define	WM_CDTXOFF(txq, x)	((txq)->txq_descsize * (x))
#define	WM_CDRXOFF(rxq, x)	((rxq)->rxq_descsize * (x))

/*
 * Software state for transmit jobs.
 */
struct wm_txsoft {
	struct mbuf *txs_mbuf;		/* head of our mbuf chain */
	bus_dmamap_t txs_dmamap;	/* our DMA map */
	int txs_firstdesc;		/* first descriptor in packet */
	int txs_lastdesc;		/* last descriptor in packet */
	int txs_ndesc;			/* # of descriptors used */
};

/*
 * Software state for receive buffers. Each descriptor gets a 2k (MCLBYTES)
 * buffer and a DMA map. For packets which fill more than one buffer, we chain
 * them together.
 */
struct wm_rxsoft {
	struct mbuf *rxs_mbuf;		/* head of our mbuf chain */
	bus_dmamap_t rxs_dmamap;	/* our DMA map */
};

#define WM_LINKUP_TIMEOUT	50

static uint16_t swfwphysem[] = {
	SWFW_PHY0_SM,
	SWFW_PHY1_SM,
	SWFW_PHY2_SM,
	SWFW_PHY3_SM
};

static const uint32_t wm_82580_rxpbs_table[] = {
	36, 72, 144, 1, 2, 4, 8, 16, 35, 70, 140
};

struct wm_softc;

#if defined(_LP64) && !defined(WM_DISABLE_EVENT_COUNTERS)
#if !defined(WM_EVENT_COUNTERS)
#define WM_EVENT_COUNTERS 1
#endif
#endif

#ifdef WM_EVENT_COUNTERS
#define WM_Q_EVCNT_DEFINE(qname, evname)				 \
	char qname##_##evname##_evcnt_name[sizeof("qname##XX##evname")]; \
	struct evcnt qname##_ev_##evname

#define WM_Q_EVCNT_ATTACH(qname, evname, q, qnum, xname, evtype)	\
	do {								\
		snprintf((q)->qname##_##evname##_evcnt_name,		\
		    sizeof((q)->qname##_##evname##_evcnt_name),		\
		    "%s%02d%s", #qname, (qnum), #evname);		\
		evcnt_attach_dynamic(&(q)->qname##_ev_##evname,		\
		    (evtype), NULL, (xname),				\
		    (q)->qname##_##evname##_evcnt_name);		\
	} while (0)

#define WM_Q_MISC_EVCNT_ATTACH(qname, evname, q, qnum, xname)		\
	WM_Q_EVCNT_ATTACH(qname, evname, q, qnum, xname, EVCNT_TYPE_MISC)

#define WM_Q_INTR_EVCNT_ATTACH(qname, evname, q, qnum, xname)		\
	WM_Q_EVCNT_ATTACH(qname, evname, q, qnum, xname, EVCNT_TYPE_INTR)

#define WM_Q_EVCNT_DETACH(qname, evname, q, qnum)	\
	evcnt_detach(&(q)->qname##_ev_##evname)
#endif /* WM_EVENT_COUNTERS */

struct wm_txqueue {
	kmutex_t *txq_lock;		/* lock for tx operations */

	struct wm_softc *txq_sc;	/* shortcut (skip struct wm_queue) */

	/* Software state for the transmit descriptors. */
	int txq_num;			/* must be a power of two */
	struct wm_txsoft txq_soft[WM_TXQUEUELEN_MAX];

	/* TX control data structures. */
	int txq_ndesc;			/* must be a power of two */
	size_t txq_descsize;		/* a tx descriptor size */
	txdescs_t *txq_descs_u;
	bus_dmamap_t txq_desc_dmamap;	/* control data DMA map */
	bus_dma_segment_t txq_desc_seg;	/* control data segment */
	int txq_desc_rseg;		/* real number of control segment */
#define	txq_desc_dma	txq_desc_dmamap->dm_segs[0].ds_addr
#define	txq_descs	txq_descs_u->sctxu_txdescs
#define	txq_nq_descs	txq_descs_u->sctxu_nq_txdescs

	bus_addr_t txq_tdt_reg;		/* offset of TDT register */

	int txq_free;			/* number of free Tx descriptors */
	int txq_next;			/* next ready Tx descriptor */

	int txq_sfree;			/* number of free Tx jobs */
	int txq_snext;			/* next free Tx job */
	int txq_sdirty;			/* dirty Tx jobs */

	/* These 4 variables are used only on the 82547. */
	int txq_fifo_size;		/* Tx FIFO size */
	int txq_fifo_head;		/* current head of FIFO */
	uint32_t txq_fifo_addr;		/* internal address of start of FIFO */
	int txq_fifo_stall;		/* Tx FIFO is stalled */

	/*
	 * When ncpu > number of Tx queues, a Tx queue is shared by multiple
	 * CPUs. This queue intermediate them without block.
	 */
	pcq_t *txq_interq;

	/*
	 * NEWQUEUE devices must use not ifp->if_flags but txq->txq_flags
	 * to manage Tx H/W queue's busy flag.
	 */
	int txq_flags;			/* flags for H/W queue, see below */
#define	WM_TXQ_NO_SPACE		0x1
#define	WM_TXQ_LINKDOWN_DISCARD	0x2

	bool txq_stopping;

	bool txq_sending;
	time_t txq_lastsent;

	/* Checksum flags used for previous packet */
	uint32_t	txq_last_hw_cmd;
	uint8_t		txq_last_hw_fields;
	uint16_t	txq_last_hw_ipcs;
	uint16_t	txq_last_hw_tucs;

	uint32_t txq_packets;		/* for AIM */
	uint32_t txq_bytes;		/* for AIM */
#ifdef WM_EVENT_COUNTERS
	/* TX event counters */
	WM_Q_EVCNT_DEFINE(txq, txsstall);   /* Stalled due to no txs */
	WM_Q_EVCNT_DEFINE(txq, txdstall);   /* Stalled due to no txd */
	WM_Q_EVCNT_DEFINE(txq, fifo_stall); /* FIFO stalls (82547) */
	WM_Q_EVCNT_DEFINE(txq, txdw);	    /* Tx descriptor interrupts */
	WM_Q_EVCNT_DEFINE(txq, txqe);	    /* Tx queue empty interrupts */
					    /* XXX not used? */

	WM_Q_EVCNT_DEFINE(txq, ipsum);	    /* IP checksums comp. */
	WM_Q_EVCNT_DEFINE(txq, tusum);	    /* TCP/UDP cksums comp. */
	WM_Q_EVCNT_DEFINE(txq, tusum6);	    /* TCP/UDP v6 cksums comp. */
	WM_Q_EVCNT_DEFINE(txq, tso);	    /* TCP seg offload (IPv4) */
	WM_Q_EVCNT_DEFINE(txq, tso6);	    /* TCP seg offload (IPv6) */
	WM_Q_EVCNT_DEFINE(txq, tsopain);    /* Painful header manip. for TSO */
	WM_Q_EVCNT_DEFINE(txq, pcqdrop);    /* Pkt dropped in pcq */
	WM_Q_EVCNT_DEFINE(txq, descdrop);   /* Pkt dropped in MAC desc ring */
					    /* other than toomanyseg */

	WM_Q_EVCNT_DEFINE(txq, toomanyseg); /* Pkt dropped(toomany DMA segs) */
	WM_Q_EVCNT_DEFINE(txq, defrag);	    /* m_defrag() */
	WM_Q_EVCNT_DEFINE(txq, underrun);   /* Tx underrun */
	WM_Q_EVCNT_DEFINE(txq, skipcontext); /* Tx skip wrong cksum context */

	char txq_txseg_evcnt_names[WM_NTXSEGS][sizeof("txqXXtxsegXXX")];
	struct evcnt txq_ev_txseg[WM_NTXSEGS]; /* Tx packets w/ N segments */
#endif /* WM_EVENT_COUNTERS */
};

struct wm_rxqueue {
	kmutex_t *rxq_lock;		/* lock for rx operations */

	struct wm_softc *rxq_sc;	/* shortcut (skip struct wm_queue) */

	/* Software state for the receive descriptors. */
	struct wm_rxsoft rxq_soft[WM_NRXDESC];

	/* RX control data structures. */
	int rxq_ndesc;			/* must be a power of two */
	size_t rxq_descsize;		/* a rx descriptor size */
	rxdescs_t *rxq_descs_u;
	bus_dmamap_t rxq_desc_dmamap;	/* control data DMA map */
	bus_dma_segment_t rxq_desc_seg;	/* control data segment */
	int rxq_desc_rseg;		/* real number of control segment */
#define	rxq_desc_dma	rxq_desc_dmamap->dm_segs[0].ds_addr
#define	rxq_descs	rxq_descs_u->sctxu_rxdescs
#define	rxq_ext_descs	rxq_descs_u->sctxu_ext_rxdescs
#define	rxq_nq_descs	rxq_descs_u->sctxu_nq_rxdescs

	bus_addr_t rxq_rdt_reg;		/* offset of RDT register */

	int rxq_ptr;			/* next ready Rx desc/queue ent */
	int rxq_discard;
	int rxq_len;
	struct mbuf *rxq_head;
	struct mbuf *rxq_tail;
	struct mbuf **rxq_tailp;

	bool rxq_stopping;

	uint32_t rxq_packets;		/* for AIM */
	uint32_t rxq_bytes;		/* for AIM */
#ifdef WM_EVENT_COUNTERS
	/* RX event counters */
	WM_Q_EVCNT_DEFINE(rxq, intr);	/* Interrupts */
	WM_Q_EVCNT_DEFINE(rxq, defer);	/* Rx deferred processing */
	WM_Q_EVCNT_DEFINE(rxq, ipsum);	/* IP checksums checked */
	WM_Q_EVCNT_DEFINE(rxq, tusum);	/* TCP/UDP cksums checked */
	WM_Q_EVCNT_DEFINE(rxq, qdrop);	/* Rx queue drop packet */
#endif
};

struct wm_queue {
	int wmq_id;			/* index of TX/RX queues */
	int wmq_intr_idx;		/* index of MSI-X tables */

	uint32_t wmq_itr;		/* interrupt interval per queue. */
	bool wmq_set_itr;

	struct wm_txqueue wmq_txq;
	struct wm_rxqueue wmq_rxq;
	char sysctlname[32];		/* Name for sysctl */

	bool wmq_txrx_use_workqueue;
	bool wmq_wq_enqueued;
	struct work wmq_cookie;
	void *wmq_si;
};

struct wm_phyop {
	int (*acquire)(struct wm_softc *) __attribute__((warn_unused_result));
	void (*release)(struct wm_softc *);
	int (*readreg_locked)(device_t, int, int, uint16_t *);
	int (*writereg_locked)(device_t, int, int, uint16_t);
	int reset_delay_us;
	bool no_errprint;
};

struct wm_nvmop {
	int (*acquire)(struct wm_softc *) __attribute__((warn_unused_result));
	void (*release)(struct wm_softc *);
	int (*read)(struct wm_softc *, int, int, uint16_t *);
};

/*
 * Software state per device.
 */
struct wm_softc {
	device_t sc_dev;		/* generic device information */
	bus_space_tag_t sc_st;		/* bus space tag */
	bus_space_handle_t sc_sh;	/* bus space handle */
	bus_size_t sc_ss;		/* bus space size */
	bus_space_tag_t sc_iot;		/* I/O space tag */
	bus_space_handle_t sc_ioh;	/* I/O space handle */
	bus_size_t sc_ios;		/* I/O space size */
	bus_space_tag_t sc_flasht;	/* flash registers space tag */
	bus_space_handle_t sc_flashh;	/* flash registers space handle */
	bus_size_t sc_flashs;		/* flash registers space size */
	off_t sc_flashreg_offset;	/*
					 * offset to flash registers from
					 * start of BAR
					 */
	bus_dma_tag_t sc_dmat;		/* bus DMA tag */

	struct ethercom sc_ethercom;	/* Ethernet common data */
	struct mii_data sc_mii;		/* MII/media information */

	pci_chipset_tag_t sc_pc;
	pcitag_t sc_pcitag;
	int sc_bus_speed;		/* PCI/PCIX bus speed */
	int sc_pcixe_capoff;		/* PCI[Xe] capability reg offset */

	uint16_t sc_pcidevid;		/* PCI device ID */
	wm_chip_type sc_type;		/* MAC type */
	int sc_rev;			/* MAC revision */
	wm_phy_type sc_phytype;		/* PHY type */
	uint8_t sc_sfptype;		/* SFP type */
	uint32_t sc_mediatype;		/* Media type (Copper, Fiber, SERDES)*/
#define	WM_MEDIATYPE_UNKNOWN		0x00
#define	WM_MEDIATYPE_FIBER		0x01
#define	WM_MEDIATYPE_COPPER		0x02
#define	WM_MEDIATYPE_SERDES		0x03 /* Internal SERDES */
	int sc_funcid;			/* unit number of the chip (0 to 3) */
	u_int sc_flags;			/* flags; see below */
	u_short sc_if_flags;		/* last if_flags */
	int sc_ec_capenable;		/* last ec_capenable */
	int sc_flowflags;		/* 802.3x flow control flags */
	uint16_t eee_lp_ability;	/* EEE link partner's ability */
	int sc_align_tweak;

	void *sc_ihs[WM_MAX_NINTR];	/*
					 * interrupt cookie.
					 * - legacy and msi use sc_ihs[0] only
					 * - msix use sc_ihs[0] to sc_ihs[nintrs-1]
					 */
	pci_intr_handle_t *sc_intrs;	/*
					 * legacy and msi use sc_intrs[0] only
					 * msix use sc_intrs[0] to sc_ihs[nintrs-1]
					 */
	int sc_nintrs;			/* number of interrupts */

	int sc_link_intr_idx;		/* index of MSI-X tables */

	callout_t sc_tick_ch;		/* tick callout */
	bool sc_core_stopping;

	int sc_nvm_ver_major;
	int sc_nvm_ver_minor;
	int sc_nvm_ver_build;
	int sc_nvm_addrbits;		/* NVM address bits */
	unsigned int sc_nvm_wordsize;	/* NVM word size */
	int sc_ich8_flash_base;
	int sc_ich8_flash_bank_size;
	int sc_nvm_k1_enabled;

	int sc_nqueues;
	struct wm_queue *sc_queue;
	u_int sc_tx_process_limit;	/* Tx proc. repeat limit in softint */
	u_int sc_tx_intr_process_limit;	/* Tx proc. repeat limit in H/W intr */
	u_int sc_rx_process_limit;	/* Rx proc. repeat limit in softint */
	u_int sc_rx_intr_process_limit;	/* Rx proc. repeat limit in H/W intr */
	struct workqueue *sc_queue_wq;
	bool sc_txrx_use_workqueue;

	int sc_affinity_offset;

#ifdef WM_EVENT_COUNTERS
	/* Event counters. */
	struct evcnt sc_ev_linkintr;	/* Link interrupts */

	/* >= WM_T_82542_2_1 */
	struct evcnt sc_ev_rx_xon;	/* Rx PAUSE(0) frames */
	struct evcnt sc_ev_tx_xon;	/* Tx PAUSE(0) frames */
	struct evcnt sc_ev_rx_xoff;	/* Rx PAUSE(!0) frames */
	struct evcnt sc_ev_tx_xoff;	/* Tx PAUSE(!0) frames */
	struct evcnt sc_ev_rx_macctl;	/* Rx Unsupported */

	struct evcnt sc_ev_crcerrs;	/* CRC Error */
	struct evcnt sc_ev_algnerrc;	/* Alignment Error */
	struct evcnt sc_ev_symerrc;	/* Symbol Error */
	struct evcnt sc_ev_rxerrc;	/* Receive Error */
	struct evcnt sc_ev_mpc;		/* Missed Packets */
	struct evcnt sc_ev_scc;		/* Single Collision */
	struct evcnt sc_ev_ecol;	/* Excessive Collision */
	struct evcnt sc_ev_mcc;		/* Multiple Collision */
	struct evcnt sc_ev_latecol;	/* Late Collision */
	struct evcnt sc_ev_colc;	/* Collision */
	struct evcnt sc_ev_cbtmpc;	/* Circuit Breaker Tx Mng. Packet */
	struct evcnt sc_ev_dc;		/* Defer */
	struct evcnt sc_ev_tncrs;	/* Tx-No CRS */
	struct evcnt sc_ev_sec;		/* Sequence Error */

	/* Old */
	struct evcnt sc_ev_cexterr;	/* Carrier Extension Error */
	/* New */
	struct evcnt sc_ev_htdpmc;	/* Host Tx Discarded Pkts by MAC */

	struct evcnt sc_ev_rlec;	/* Receive Length Error */
	struct evcnt sc_ev_cbrdpc;	/* Circuit Breaker Rx Dropped Packet */
	struct evcnt sc_ev_prc64;	/* Packets Rx (64 bytes) */
	struct evcnt sc_ev_prc127;	/* Packets Rx (65-127 bytes) */
	struct evcnt sc_ev_prc255;	/* Packets Rx (128-255 bytes) */
	struct evcnt sc_ev_prc511;	/* Packets Rx (256-511 bytes) */
	struct evcnt sc_ev_prc1023;	/* Packets Rx (512-1023 bytes) */
	struct evcnt sc_ev_prc1522;	/* Packets Rx (1024-1522 bytes) */
	struct evcnt sc_ev_gprc;	/* Good Packets Rx */
	struct evcnt sc_ev_bprc;	/* Broadcast Packets Rx */
	struct evcnt sc_ev_mprc;	/* Multicast Packets Rx */
	struct evcnt sc_ev_gptc;	/* Good Packets Tx */
	struct evcnt sc_ev_gorc;	/* Good Octets Rx */
	struct evcnt sc_ev_gotc;	/* Good Octets Tx */
	struct evcnt sc_ev_rnbc;	/* Rx No Buffers */
	struct evcnt sc_ev_ruc;		/* Rx Undersize */
	struct evcnt sc_ev_rfc;		/* Rx Fragment */
	struct evcnt sc_ev_roc;		/* Rx Oversize */
	struct evcnt sc_ev_rjc;		/* Rx Jabber */
	struct evcnt sc_ev_mgtprc;	/* Management Packets RX */
	struct evcnt sc_ev_mgtpdc;	/* Management Packets Dropped */
	struct evcnt sc_ev_mgtptc;	/* Management Packets TX */
	struct evcnt sc_ev_tor;		/* Total Octets Rx */
	struct evcnt sc_ev_tot;		/* Total Octets Tx */
	struct evcnt sc_ev_tpr;		/* Total Packets Rx */
	struct evcnt sc_ev_tpt;		/* Total Packets Tx */
	struct evcnt sc_ev_ptc64;	/* Packets Tx (64 bytes) */
	struct evcnt sc_ev_ptc127;	/* Packets Tx (65-127 bytes) */
	struct evcnt sc_ev_ptc255;	/* Packets Tx (128-255 bytes) */
	struct evcnt sc_ev_ptc511;	/* Packets Tx (256-511 bytes) */
	struct evcnt sc_ev_ptc1023;	/* Packets Tx (512-1023 bytes) */
	struct evcnt sc_ev_ptc1522;	/* Packets Tx (1024-1522 Bytes) */
	struct evcnt sc_ev_mptc;	/* Multicast Packets Tx */
	struct evcnt sc_ev_bptc;	/* Broadcast Packets Tx */
	struct evcnt sc_ev_tsctc;	/* TCP Segmentation Context Tx */

	/* Old */
	struct evcnt sc_ev_tsctfc;	/* TCP Segmentation Context Tx Fail */
	/* New */
	struct evcnt sc_ev_cbrmpc;	/* Circuit Breaker Rx Mng. Packet */

	struct evcnt sc_ev_iac;		/* Interrupt Assertion */

	/* Old */
	struct evcnt sc_ev_icrxptc;	/* Intr. Cause Rx Pkt Timer Expire */
	struct evcnt sc_ev_icrxatc;	/* Intr. Cause Rx Abs Timer Expire */
	struct evcnt sc_ev_ictxptc;	/* Intr. Cause Tx Pkt Timer Expire */
	struct evcnt sc_ev_ictxatc;	/* Intr. Cause Tx Abs Timer Expire */
	struct evcnt sc_ev_ictxqec;	/* Intr. Cause Tx Queue Empty */
	struct evcnt sc_ev_ictxqmtc;	/* Intr. Cause Tx Queue Min Thresh */
	/*
	 * sc_ev_rxdmtc is shared with both "Intr. cause" and
	 * non "Intr. cause" register.
	 */
	struct evcnt sc_ev_rxdmtc;	/* (Intr. Cause) Rx Desc Min Thresh */
	struct evcnt sc_ev_icrxoc;	/* Intr. Cause Receiver Overrun */
	/* New */
	struct evcnt sc_ev_rpthc;	/* Rx Packets To Host */
	struct evcnt sc_ev_debug1;	/* Debug Counter 1 */
	struct evcnt sc_ev_debug2;	/* Debug Counter 2 */
	struct evcnt sc_ev_debug3;	/* Debug Counter 3 */
	struct evcnt sc_ev_hgptc;	/* Host Good Packets TX */
	struct evcnt sc_ev_debug4;	/* Debug Counter 4 */
	struct evcnt sc_ev_htcbdpc;	/* Host Tx Circuit Breaker Drp. Pkts */
	struct evcnt sc_ev_hgorc;	/* Host Good Octets Rx */
	struct evcnt sc_ev_hgotc;	/* Host Good Octets Tx */
	struct evcnt sc_ev_lenerrs;	/* Length Error */
	struct evcnt sc_ev_tlpic;	/* EEE Tx LPI */
	struct evcnt sc_ev_rlpic;	/* EEE Rx LPI */
	struct evcnt sc_ev_b2ogprc;	/* BMC2OS pkts received by host */
	struct evcnt sc_ev_o2bspc;	/* OS2BMC pkts transmitted by host */
	struct evcnt sc_ev_b2ospc;	/* BMC2OS pkts sent by BMC */
	struct evcnt sc_ev_o2bgptc;	/* OS2BMC pkts received by BMC */
	struct evcnt sc_ev_scvpc;	/* SerDes/SGMII Code Violation Pkt. */
	struct evcnt sc_ev_hrmpc;	/* Header Redirection Missed Packet */
#endif /* WM_EVENT_COUNTERS */

	struct sysctllog *sc_sysctllog;

	/* This variable are used only on the 82547. */
	callout_t sc_txfifo_ch;		/* Tx FIFO stall work-around timer */

	uint32_t sc_ctrl;		/* prototype CTRL register */
#if 0
	uint32_t sc_ctrl_ext;		/* prototype CTRL_EXT register */
#endif
	uint32_t sc_icr;		/* prototype interrupt bits */
	uint32_t sc_itr_init;		/* prototype intr throttling reg */
	uint32_t sc_tctl;		/* prototype TCTL register */
	uint32_t sc_rctl;		/* prototype RCTL register */
	uint32_t sc_txcw;		/* prototype TXCW register */
	uint32_t sc_tipg;		/* prototype TIPG register */
	uint32_t sc_fcrtl;		/* prototype FCRTL register */
	uint32_t sc_pba;		/* prototype PBA register */

	int sc_tbi_linkup;		/* TBI link status */
	int sc_tbi_serdes_anegticks;	/* autonegotiation ticks */
	int sc_tbi_serdes_ticks;	/* tbi ticks */
	struct timeval sc_linkup_delay_time; /* delay LINK_STATE_UP */

	int sc_mchash_type;		/* multicast filter offset */

	krndsource_t rnd_source;	/* random source */

	struct if_percpuq *sc_ipq;	/* softint-based input queues */

	kmutex_t *sc_core_lock;		/* lock for softc operations */
	kmutex_t *sc_ich_phymtx;	/*
					 * 82574/82583/ICH/PCH specific PHY
					 * mutex. For 82574/82583, the mutex
					 * is used for both PHY and NVM.
					 */
	kmutex_t *sc_ich_nvmmtx;	/* ICH/PCH specific NVM mutex */

	struct wm_phyop phy;
	struct wm_nvmop nvm;

	struct workqueue *sc_reset_wq;
	struct work sc_reset_work;
	volatile unsigned sc_reset_pending;

	bool sc_dying;

#ifdef WM_DEBUG
	uint32_t sc_debug;
	bool sc_trigger_reset;
#endif
};

#define	WM_RXCHAIN_RESET(rxq)						\
do {									\
	(rxq)->rxq_tailp = &(rxq)->rxq_head;				\
	*(rxq)->rxq_tailp = NULL;					\
	(rxq)->rxq_len = 0;						\
} while (/*CONSTCOND*/0)

#define	WM_RXCHAIN_LINK(rxq, m)						\
do {									\
	*(rxq)->rxq_tailp = (rxq)->rxq_tail = (m);			\
	(rxq)->rxq_tailp = &(m)->m_next;				\
} while (/*CONSTCOND*/0)

#ifdef WM_EVENT_COUNTERS
#ifdef __HAVE_ATOMIC64_LOADSTORE
#define	WM_EVCNT_INCR(ev)						\
	atomic_store_relaxed(&((ev)->ev_count),				\
	    atomic_load_relaxed(&(ev)->ev_count) + 1)
#define	WM_EVCNT_STORE(ev, val)						\
	atomic_store_relaxed(&((ev)->ev_count), (val))
#define	WM_EVCNT_ADD(ev, val)						\
	atomic_store_relaxed(&((ev)->ev_count),				\
	    atomic_load_relaxed(&(ev)->ev_count) + (val))
#else
#define	WM_EVCNT_INCR(ev)						\
	((ev)->ev_count)++
#define	WM_EVCNT_STORE(ev, val)						\
	((ev)->ev_count = (val))
#define	WM_EVCNT_ADD(ev, val)						\
	(ev)->ev_count += (val)
#endif

#define WM_Q_EVCNT_INCR(qname, evname)			\
	WM_EVCNT_INCR(&(qname)->qname##_ev_##evname)
#define WM_Q_EVCNT_STORE(qname, evname, val)		\
	WM_EVCNT_STORE(&(qname)->qname##_ev_##evname, (val))
#define WM_Q_EVCNT_ADD(qname, evname, val)		\
	WM_EVCNT_ADD(&(qname)->qname##_ev_##evname, (val))
#else /* !WM_EVENT_COUNTERS */
#define	WM_EVCNT_INCR(ev)	__nothing
#define	WM_EVCNT_STORE(ev, val)	__nothing
#define	WM_EVCNT_ADD(ev, val)	__nothing

#define WM_Q_EVCNT_INCR(qname, evname)		__nothing
#define WM_Q_EVCNT_STORE(qname, evname, val)	__nothing
#define WM_Q_EVCNT_ADD(qname, evname, val)	__nothing
#endif /* !WM_EVENT_COUNTERS */

#define	CSR_READ(sc, reg)						\
	bus_space_read_4((sc)->sc_st, (sc)->sc_sh, (reg))
#define	CSR_WRITE(sc, reg, val)						\
	bus_space_write_4((sc)->sc_st, (sc)->sc_sh, (reg), (val))
#define	CSR_WRITE_FLUSH(sc)						\
	(void)CSR_READ((sc), WMREG_STATUS)

#define ICH8_FLASH_READ32(sc, reg)					\
	bus_space_read_4((sc)->sc_flasht, (sc)->sc_flashh,		\
	    (reg) + sc->sc_flashreg_offset)
#define ICH8_FLASH_WRITE32(sc, reg, data)				\
	bus_space_write_4((sc)->sc_flasht, (sc)->sc_flashh,		\
	    (reg) + sc->sc_flashreg_offset, (data))

#define ICH8_FLASH_READ16(sc, reg)					\
	bus_space_read_2((sc)->sc_flasht, (sc)->sc_flashh,		\
	    (reg) + sc->sc_flashreg_offset)
#define ICH8_FLASH_WRITE16(sc, reg, data)				\
	bus_space_write_2((sc)->sc_flasht, (sc)->sc_flashh,		\
	    (reg) + sc->sc_flashreg_offset, (data))

#define	WM_CDTXADDR(txq, x)	((txq)->txq_desc_dma + WM_CDTXOFF((txq), (x)))
#define	WM_CDRXADDR(rxq, x)	((rxq)->rxq_desc_dma + WM_CDRXOFF((rxq), (x)))

#define	WM_CDTXADDR_LO(txq, x)	(WM_CDTXADDR((txq), (x)) & 0xffffffffU)
#define	WM_CDTXADDR_HI(txq, x)						\
	(sizeof(bus_addr_t) == 8 ?					\
	 (uint64_t)WM_CDTXADDR((txq), (x)) >> 32 : 0)

#define	WM_CDRXADDR_LO(rxq, x)	(WM_CDRXADDR((rxq), (x)) & 0xffffffffU)
#define	WM_CDRXADDR_HI(rxq, x)						\
	(sizeof(bus_addr_t) == 8 ?					\
	 (uint64_t)WM_CDRXADDR((rxq), (x)) >> 32 : 0)

/*
 * Register read/write functions.
 * Other than CSR_{READ|WRITE}().
 */
#if 0
static inline uint32_t wm_io_read(struct wm_softc *, int);
#endif
static inline void wm_io_write(struct wm_softc *, int, uint32_t);
static inline void wm_82575_write_8bit_ctlr_reg(struct wm_softc *, uint32_t,
    uint32_t, uint32_t);
static inline void wm_set_dma_addr(volatile wiseman_addr_t *, bus_addr_t);

/*
 * Descriptor sync/init functions.
 */
static inline void wm_cdtxsync(struct wm_txqueue *, int, int, int);
static inline void wm_cdrxsync(struct wm_rxqueue *, int, int);
static inline void wm_init_rxdesc(struct wm_rxqueue *, int);

/*
 * Device driver interface functions and commonly used functions.
 * match, attach, detach, init, start, stop, ioctl, watchdog and so on.
 */
static const struct wm_product *wm_lookup(const struct pci_attach_args *);
static int	wm_match(device_t, cfdata_t, void *);
static void	wm_attach(device_t, device_t, void *);
static int	wm_detach(device_t, int);
static bool	wm_suspend(device_t, const pmf_qual_t *);
static bool	wm_resume(device_t, const pmf_qual_t *);
static bool	wm_watchdog(struct ifnet *);
static void	wm_watchdog_txq(struct ifnet *, struct wm_txqueue *,
    uint16_t *);
static void	wm_watchdog_txq_locked(struct ifnet *, struct wm_txqueue *,
    uint16_t *);
static void	wm_tick(void *);
static int	wm_ifflags_cb(struct ethercom *);
static int	wm_ioctl(struct ifnet *, u_long, void *);
/* MAC address related */
static uint16_t	wm_check_alt_mac_addr(struct wm_softc *);
static int	wm_read_mac_addr(struct wm_softc *, uint8_t *);
static void	wm_set_ral(struct wm_softc *, const uint8_t *, int);
static uint32_t	wm_mchash(struct wm_softc *, const uint8_t *);
static int	wm_rar_count(struct wm_softc *);
static void	wm_set_filter(struct wm_softc *);
/* Reset and init related */
static void	wm_set_vlan(struct wm_softc *);
static void	wm_set_pcie_completion_timeout(struct wm_softc *);
static void	wm_get_auto_rd_done(struct wm_softc *);
static void	wm_lan_init_done(struct wm_softc *);
static void	wm_get_cfg_done(struct wm_softc *);
static int	wm_phy_post_reset(struct wm_softc *);
static int	wm_write_smbus_addr(struct wm_softc *);
static int	wm_init_lcd_from_nvm(struct wm_softc *);
static int	wm_oem_bits_config_ich8lan(struct wm_softc *, bool);
static void	wm_initialize_hardware_bits(struct wm_softc *);
static uint32_t	wm_rxpbs_adjust_82580(uint32_t);
static int	wm_reset_phy(struct wm_softc *);
static void	wm_flush_desc_rings(struct wm_softc *);
static void	wm_reset(struct wm_softc *);
static int	wm_add_rxbuf(struct wm_rxqueue *, int);
static void	wm_rxdrain(struct wm_rxqueue *);
static void	wm_init_rss(struct wm_softc *);
static void	wm_adjust_qnum(struct wm_softc *, int);
static inline bool	wm_is_using_msix(struct wm_softc *);
static inline bool	wm_is_using_multiqueue(struct wm_softc *);
static int	wm_softint_establish_queue(struct wm_softc *, int, int);
static int	wm_setup_legacy(struct wm_softc *);
static int	wm_setup_msix(struct wm_softc *);
static int	wm_init(struct ifnet *);
static int	wm_init_locked(struct ifnet *);
static void	wm_init_sysctls(struct wm_softc *);
static void	wm_update_stats(struct wm_softc *);
static void	wm_clear_evcnt(struct wm_softc *);
static void	wm_unset_stopping_flags(struct wm_softc *);
static void	wm_set_stopping_flags(struct wm_softc *);
static void	wm_stop(struct ifnet *, int);
static void	wm_stop_locked(struct ifnet *, bool, bool);
static void	wm_dump_mbuf_chain(struct wm_softc *, struct mbuf *);
static void	wm_82547_txfifo_stall(void *);
static int	wm_82547_txfifo_bugchk(struct wm_softc *, struct mbuf *);
static void	wm_itrs_writereg(struct wm_softc *, struct wm_queue *);
/* DMA related */
static int	wm_alloc_tx_descs(struct wm_softc *, struct wm_txqueue *);
static void	wm_free_tx_descs(struct wm_softc *, struct wm_txqueue *);
static void	wm_init_tx_descs(struct wm_softc *, struct wm_txqueue *);
static void	wm_init_tx_regs(struct wm_softc *, struct wm_queue *,
    struct wm_txqueue *);
static int	wm_alloc_rx_descs(struct wm_softc *, struct wm_rxqueue *);
static void	wm_free_rx_descs(struct wm_softc *, struct wm_rxqueue *);
static void	wm_init_rx_regs(struct wm_softc *, struct wm_queue *,
    struct wm_rxqueue *);
static int	wm_alloc_tx_buffer(struct wm_softc *, struct wm_txqueue *);
static void	wm_free_tx_buffer(struct wm_softc *, struct wm_txqueue *);
static void	wm_init_tx_buffer(struct wm_softc *, struct wm_txqueue *);
static int	wm_alloc_rx_buffer(struct wm_softc *, struct wm_rxqueue *);
static void	wm_free_rx_buffer(struct wm_softc *, struct wm_rxqueue *);
static int	wm_init_rx_buffer(struct wm_softc *, struct wm_rxqueue *);
static void	wm_init_tx_queue(struct wm_softc *, struct wm_queue *,
    struct wm_txqueue *);
static int	wm_init_rx_queue(struct wm_softc *, struct wm_queue *,
    struct wm_rxqueue *);
static int	wm_alloc_txrx_queues(struct wm_softc *);
static void	wm_free_txrx_queues(struct wm_softc *);
static int	wm_init_txrx_queues(struct wm_softc *);
/* Start */
static void	wm_tx_offload(struct wm_softc *, struct wm_txqueue *,
    struct wm_txsoft *, uint32_t *, uint8_t *);
static inline int	wm_select_txqueue(struct ifnet *, struct mbuf *);
static void	wm_start(struct ifnet *);
static void	wm_start_locked(struct ifnet *);
static int	wm_transmit(struct ifnet *, struct mbuf *);
static void	wm_transmit_locked(struct ifnet *, struct wm_txqueue *);
static void	wm_send_common_locked(struct ifnet *, struct wm_txqueue *,
    bool);
static void	wm_nq_tx_offload(struct wm_softc *, struct wm_txqueue *,
    struct wm_txsoft *, uint32_t *, uint32_t *, bool *);
static void	wm_nq_start(struct ifnet *);
static void	wm_nq_start_locked(struct ifnet *);
static int	wm_nq_transmit(struct ifnet *, struct mbuf *);
static void	wm_nq_transmit_locked(struct ifnet *, struct wm_txqueue *);
static void	wm_nq_send_common_locked(struct ifnet *, struct wm_txqueue *,
    bool);
static void	wm_deferred_start_locked(struct wm_txqueue *);
static void	wm_handle_queue(void *);
static void	wm_handle_queue_work(struct work *, void *);
static void	wm_handle_reset_work(struct work *, void *);
/* Interrupt */
static bool	wm_txeof(struct wm_txqueue *, u_int);
static bool	wm_rxeof(struct wm_rxqueue *, u_int);
static void	wm_linkintr_gmii(struct wm_softc *, uint32_t);
static void	wm_linkintr_tbi(struct wm_softc *, uint32_t);
static void	wm_linkintr_serdes(struct wm_softc *, uint32_t);
static void	wm_linkintr(struct wm_softc *, uint32_t);
static int	wm_intr_legacy(void *);
static inline void	wm_txrxintr_disable(struct wm_queue *);
static inline void	wm_txrxintr_enable(struct wm_queue *);
static void	wm_itrs_calculate(struct wm_softc *, struct wm_queue *);
static int	wm_txrxintr_msix(void *);
static int	wm_linkintr_msix(void *);

/*
 * Media related.
 * GMII, SGMII, TBI, SERDES and SFP.
 */
/* Common */
static void	wm_tbi_serdes_set_linkled(struct wm_softc *);
/* GMII related */
static void	wm_gmii_reset(struct wm_softc *);
static void	wm_gmii_setup_phytype(struct wm_softc *, uint32_t, uint16_t);
static int	wm_get_phy_id_82575(struct wm_softc *);
static void	wm_gmii_mediainit(struct wm_softc *, pci_product_id_t);
static int	wm_gmii_mediachange(struct ifnet *);
static void	wm_gmii_mediastatus(struct ifnet *, struct ifmediareq *);
static void	wm_i82543_mii_sendbits(struct wm_softc *, uint32_t, int);
static uint16_t	wm_i82543_mii_recvbits(struct wm_softc *);
static int	wm_gmii_i82543_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_i82543_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_mdic_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_mdic_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_i82544_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_i82544_readreg_locked(device_t, int, int, uint16_t *);
static int	wm_gmii_i82544_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_i82544_writereg_locked(device_t, int, int, uint16_t);
static int	wm_gmii_i80003_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_i80003_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_bm_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_bm_writereg(device_t, int, int, uint16_t);
static int	wm_enable_phy_wakeup_reg_access_bm(device_t, uint16_t *);
static int	wm_disable_phy_wakeup_reg_access_bm(device_t, uint16_t *);
static int	wm_access_phy_wakeup_reg_bm(device_t, int, int16_t *, int,
	bool);
static int	wm_gmii_hv_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_hv_readreg_locked(device_t, int, int, uint16_t *);
static int	wm_gmii_hv_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_hv_writereg_locked(device_t, int, int, uint16_t);
static int	wm_gmii_82580_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_82580_writereg(device_t, int, int, uint16_t);
static int	wm_gmii_gs40g_readreg(device_t, int, int, uint16_t *);
static int	wm_gmii_gs40g_writereg(device_t, int, int, uint16_t);
static void	wm_gmii_statchg(struct ifnet *);
/*
 * kumeran related (80003, ICH* and PCH*).
 * These functions are not for accessing MII registers but for accessing
 * kumeran specific registers.
 */
static int	wm_kmrn_readreg(struct wm_softc *, int, uint16_t *);
static int	wm_kmrn_readreg_locked(struct wm_softc *, int, uint16_t *);
static int	wm_kmrn_writereg(struct wm_softc *, int, uint16_t);
static int	wm_kmrn_writereg_locked(struct wm_softc *, int, uint16_t);
/* EMI register related */
static int	wm_access_emi_reg_locked(device_t, int, uint16_t *, bool);
static int	wm_read_emi_reg_locked(device_t, int, uint16_t *);
static int	wm_write_emi_reg_locked(device_t, int, uint16_t);
/* SGMII */
static bool	wm_sgmii_uses_mdio(struct wm_softc *);
static void	wm_sgmii_sfp_preconfig(struct wm_softc *);
static int	wm_sgmii_readreg(device_t, int, int, uint16_t *);
static int	wm_sgmii_readreg_locked(device_t, int, int, uint16_t *);
static int	wm_sgmii_writereg(device_t, int, int, uint16_t);
static int	wm_sgmii_writereg_locked(device_t, int, int, uint16_t);
/* TBI related */
static bool	wm_tbi_havesignal(struct wm_softc *, uint32_t);
static void	wm_tbi_mediainit(struct wm_softc *);
static int	wm_tbi_mediachange(struct ifnet *);
static void	wm_tbi_mediastatus(struct ifnet *, struct ifmediareq *);
static int	wm_check_for_link(struct wm_softc *);
static void	wm_tbi_tick(struct wm_softc *);
/* SERDES related */
static void	wm_serdes_power_up_link_82575(struct wm_softc *);
static int	wm_serdes_mediachange(struct ifnet *);
static void	wm_serdes_mediastatus(struct ifnet *, struct ifmediareq *);
static void	wm_serdes_tick(struct wm_softc *);
/* SFP related */
static int	wm_sfp_read_data_byte(struct wm_softc *, uint16_t, uint8_t *);
static uint32_t	wm_sfp_get_media_type(struct wm_softc *);

/*
 * NVM related.
 * Microwire, SPI (w/wo EERD) and Flash.
 */
/* Misc functions */
static void	wm_eeprom_sendbits(struct wm_softc *, uint32_t, int);
static void	wm_eeprom_recvbits(struct wm_softc *, uint32_t *, int);
static int	wm_nvm_set_addrbits_size_eecd(struct wm_softc *);
/* Microwire */
static int	wm_nvm_read_uwire(struct wm_softc *, int, int, uint16_t *);
/* SPI */
static int	wm_nvm_ready_spi(struct wm_softc *);
static int	wm_nvm_read_spi(struct wm_softc *, int, int, uint16_t *);
/* Using with EERD */
static int	wm_poll_eerd_eewr_done(struct wm_softc *, int);
static int	wm_nvm_read_eerd(struct wm_softc *, int, int, uint16_t *);
/* Flash */
static int	wm_nvm_valid_bank_detect_ich8lan(struct wm_softc *,
    unsigned int *);
static int32_t	wm_ich8_cycle_init(struct wm_softc *);
static int32_t	wm_ich8_flash_cycle(struct wm_softc *, uint32_t);
static int32_t	wm_read_ich8_data(struct wm_softc *, uint32_t, uint32_t,
    uint32_t *);
static int32_t	wm_read_ich8_byte(struct wm_softc *, uint32_t, uint8_t *);
static int32_t	wm_read_ich8_word(struct wm_softc *, uint32_t, uint16_t *);
static int32_t	wm_read_ich8_dword(struct wm_softc *, uint32_t, uint32_t *);
static int	wm_nvm_read_ich8(struct wm_softc *, int, int, uint16_t *);
static int	wm_nvm_read_spt(struct wm_softc *, int, int, uint16_t *);
/* iNVM */
static int	wm_nvm_read_word_invm(struct wm_softc *, uint16_t, uint16_t *);
static int	wm_nvm_read_invm(struct wm_softc *, int, int, uint16_t *);
/* Lock, detecting NVM type, validate checksum and read */
static int	wm_nvm_is_onboard_eeprom(struct wm_softc *);
static int	wm_nvm_flash_presence_i210(struct wm_softc *);
static int	wm_nvm_validate_checksum(struct wm_softc *);
static void	wm_nvm_version_invm(struct wm_softc *);
static void	wm_nvm_version(struct wm_softc *);
static int	wm_nvm_read(struct wm_softc *, int, int, uint16_t *);

/*
 * Hardware semaphores.
 * Very complexed...
 */
static int	wm_get_null(struct wm_softc *);
static void	wm_put_null(struct wm_softc *);
static int	wm_get_eecd(struct wm_softc *);
static void	wm_put_eecd(struct wm_softc *);
static int	wm_get_swsm_semaphore(struct wm_softc *); /* 8257[123] */
static void	wm_put_swsm_semaphore(struct wm_softc *);
static int	wm_get_swfw_semaphore(struct wm_softc *, uint16_t);
static void	wm_put_swfw_semaphore(struct wm_softc *, uint16_t);
static int	wm_get_nvm_80003(struct wm_softc *);
static void	wm_put_nvm_80003(struct wm_softc *);
static int	wm_get_nvm_82571(struct wm_softc *);
static void	wm_put_nvm_82571(struct wm_softc *);
static int	wm_get_phy_82575(struct wm_softc *);
static void	wm_put_phy_82575(struct wm_softc *);
static int	wm_get_swfwhw_semaphore(struct wm_softc *); /* For 574/583 */
static void	wm_put_swfwhw_semaphore(struct wm_softc *);
static int	wm_get_swflag_ich8lan(struct wm_softc *);	/* For PHY */
static void	wm_put_swflag_ich8lan(struct wm_softc *);
static int	wm_get_nvm_ich8lan(struct wm_softc *);
static void	wm_put_nvm_ich8lan(struct wm_softc *);
static int	wm_get_hw_semaphore_82573(struct wm_softc *);
static void	wm_put_hw_semaphore_82573(struct wm_softc *);

/*
 * Management mode and power management related subroutines.
 * BMC, AMT, suspend/resume and EEE.
 */
#if 0
static int	wm_check_mng_mode(struct wm_softc *);
static int	wm_check_mng_mode_ich8lan(struct wm_softc *);
static int	wm_check_mng_mode_82574(struct wm_softc *);
static int	wm_check_mng_mode_generic(struct wm_softc *);
#endif
static int	wm_enable_mng_pass_thru(struct wm_softc *);
static bool	wm_phy_resetisblocked(struct wm_softc *);
static void	wm_get_hw_control(struct wm_softc *);
static void	wm_release_hw_control(struct wm_softc *);
static void	wm_gate_hw_phy_config_ich8lan(struct wm_softc *, bool);
static int	wm_init_phy_workarounds_pchlan(struct wm_softc *);
static void	wm_init_manageability(struct wm_softc *);
static void	wm_release_manageability(struct wm_softc *);
static void	wm_get_wakeup(struct wm_softc *);
static int	wm_ulp_disable(struct wm_softc *);
static int	wm_enable_phy_wakeup(struct wm_softc *);
static void	wm_igp3_phy_powerdown_workaround_ich8lan(struct wm_softc *);
static void	wm_suspend_workarounds_ich8lan(struct wm_softc *);
static int	wm_resume_workarounds_pchlan(struct wm_softc *);
static void	wm_enable_wakeup(struct wm_softc *);
static void	wm_disable_aspm(struct wm_softc *);
/* LPLU (Low Power Link Up) */
static void	wm_lplu_d0_disable(struct wm_softc *);
/* EEE */
static int	wm_set_eee_i350(struct wm_softc *);
static int	wm_set_eee_pchlan(struct wm_softc *);
static int	wm_set_eee(struct wm_softc *);

/*
 * Workarounds (mainly PHY related).
 * Basically, PHY's workarounds are in the PHY drivers.
 */
static int	wm_kmrn_lock_loss_workaround_ich8lan(struct wm_softc *);
static void	wm_gig_downshift_workaround_ich8lan(struct wm_softc *);
static int	wm_hv_phy_workarounds_ich8lan(struct wm_softc *);
static void	wm_copy_rx_addrs_to_phy_ich8lan(struct wm_softc *);
static void	wm_copy_rx_addrs_to_phy_ich8lan_locked(struct wm_softc *);
static int	wm_lv_jumbo_workaround_ich8lan(struct wm_softc *, bool);
static int	wm_lv_phy_workarounds_ich8lan(struct wm_softc *);
static int	wm_k1_workaround_lpt_lp(struct wm_softc *, bool);
static int	wm_k1_gig_workaround_hv(struct wm_softc *, int);
static int	wm_k1_workaround_lv(struct wm_softc *);
static int	wm_link_stall_workaround_hv(struct wm_softc *);
static int	wm_set_mdio_slow_mode_hv(struct wm_softc *);
static int	wm_set_mdio_slow_mode_hv_locked(struct wm_softc *);
static void	wm_configure_k1_ich8lan(struct wm_softc *, int);
static void	wm_reset_init_script_82575(struct wm_softc *);
static void	wm_reset_mdicnfg_82580(struct wm_softc *);
static bool	wm_phy_is_accessible_pchlan(struct wm_softc *);
static void	wm_toggle_lanphypc_pch_lpt(struct wm_softc *);
static int	wm_platform_pm_pch_lpt(struct wm_softc *, bool);
static int	wm_pll_workaround_i210(struct wm_softc *);
static void	wm_legacy_irq_quirk_spt(struct wm_softc *);
static bool	wm_phy_need_linkdown_discard(struct wm_softc *);
static void	wm_set_linkdown_discard(struct wm_softc *);
static void	wm_clear_linkdown_discard(struct wm_softc *);

static int	wm_sysctl_tdh_handler(SYSCTLFN_PROTO);
static int	wm_sysctl_tdt_handler(SYSCTLFN_PROTO);
#ifdef WM_DEBUG
static int	wm_sysctl_debug(SYSCTLFN_PROTO);
#endif

CFATTACH_DECL3_NEW(wm, sizeof(struct wm_softc),
    wm_match, wm_attach, wm_detach, NULL, NULL, NULL, DVF_DETACH_SHUTDOWN);

/*
 * Devices supported by this driver.
 */
static const struct wm_product {
	pci_vendor_id_t		wmp_vendor;
	pci_product_id_t	wmp_product;
	const char		*wmp_name;
	wm_chip_type		wmp_type;
	uint32_t		wmp_flags;
#define	WMP_F_UNKNOWN		WM_MEDIATYPE_UNKNOWN
#define	WMP_F_FIBER		WM_MEDIATYPE_FIBER
#define	WMP_F_COPPER		WM_MEDIATYPE_COPPER
#define	WMP_F_SERDES		WM_MEDIATYPE_SERDES
#define WMP_MEDIATYPE(x)	((x) & 0x03)
} wm_products[] = {
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82542,
	  "Intel i82542 1000BASE-X Ethernet",
	  WM_T_82542_2_1,	WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82543GC_FIBER,
	  "Intel i82543GC 1000BASE-X Ethernet",
	  WM_T_82543,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82543GC_COPPER,
	  "Intel i82543GC 1000BASE-T Ethernet",
	  WM_T_82543,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82544EI_COPPER,
	  "Intel i82544EI 1000BASE-T Ethernet",
	  WM_T_82544,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82544EI_FIBER,
	  "Intel i82544EI 1000BASE-X Ethernet",
	  WM_T_82544,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82544GC_COPPER,
	  "Intel i82544GC 1000BASE-T Ethernet",
	  WM_T_82544,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82544GC_LOM,
	  "Intel i82544GC (LOM) 1000BASE-T Ethernet",
	  WM_T_82544,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82540EM,
	  "Intel i82540EM 1000BASE-T Ethernet",
	  WM_T_82540,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82540EM_LOM,
	  "Intel i82540EM (LOM) 1000BASE-T Ethernet",
	  WM_T_82540,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82540EP_LOM,
	  "Intel i82540EP 1000BASE-T Ethernet",
	  WM_T_82540,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82540EP,
	  "Intel i82540EP 1000BASE-T Ethernet",
	  WM_T_82540,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82540EP_LP,
	  "Intel i82540EP 1000BASE-T Ethernet",
	  WM_T_82540,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82545EM_COPPER,
	  "Intel i82545EM 1000BASE-T Ethernet",
	  WM_T_82545,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82545GM_COPPER,
	  "Intel i82545GM 1000BASE-T Ethernet",
	  WM_T_82545_3,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82545GM_FIBER,
	  "Intel i82545GM 1000BASE-X Ethernet",
	  WM_T_82545_3,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82545GM_SERDES,
	  "Intel i82545GM Gigabit Ethernet (SERDES)",
	  WM_T_82545_3,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546EB_COPPER,
	  "Intel i82546EB 1000BASE-T Ethernet",
	  WM_T_82546,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546EB_QUAD,
	  "Intel i82546EB 1000BASE-T Ethernet",
	  WM_T_82546,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82545EM_FIBER,
	  "Intel i82545EM 1000BASE-X Ethernet",
	  WM_T_82545,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546EB_FIBER,
	  "Intel i82546EB 1000BASE-X Ethernet",
	  WM_T_82546,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_COPPER,
	  "Intel i82546GB 1000BASE-T Ethernet",
	  WM_T_82546_3,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_FIBER,
	  "Intel i82546GB 1000BASE-X Ethernet",
	  WM_T_82546_3,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_SERDES,
	  "Intel i82546GB Gigabit Ethernet (SERDES)",
	  WM_T_82546_3,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_QUAD_COPPER,
	  "i82546GB quad-port Gigabit Ethernet",
	  WM_T_82546_3,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_QUAD_COPPER_KSP3,
	  "i82546GB quad-port Gigabit Ethernet (KSP3)",
	  WM_T_82546_3,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82546GB_PCIE,
	  "Intel PRO/1000MT (82546GB)",
	  WM_T_82546_3,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541EI,
	  "Intel i82541EI 1000BASE-T Ethernet",
	  WM_T_82541,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541ER_LOM,
	  "Intel i82541ER (LOM) 1000BASE-T Ethernet",
	  WM_T_82541,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541EI_MOBILE,
	  "Intel i82541EI Mobile 1000BASE-T Ethernet",
	  WM_T_82541,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541ER,
	  "Intel i82541ER 1000BASE-T Ethernet",
	  WM_T_82541_2,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541GI,
	  "Intel i82541GI 1000BASE-T Ethernet",
	  WM_T_82541_2,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541GI_MOBILE,
	  "Intel i82541GI Mobile 1000BASE-T Ethernet",
	  WM_T_82541_2,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82541PI,
	  "Intel i82541PI 1000BASE-T Ethernet",
	  WM_T_82541_2,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82547EI,
	  "Intel i82547EI 1000BASE-T Ethernet",
	  WM_T_82547,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82547EI_MOBILE,
	  "Intel i82547EI Mobile 1000BASE-T Ethernet",
	  WM_T_82547,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82547GI,
	  "Intel i82547GI 1000BASE-T Ethernet",
	  WM_T_82547_2,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_COPPER,
	  "Intel PRO/1000 PT (82571EB)",
	  WM_T_82571,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_FIBER,
	  "Intel PRO/1000 PF (82571EB)",
	  WM_T_82571,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_SERDES,
	  "Intel PRO/1000 PB (82571EB)",
	  WM_T_82571,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_QUAD_COPPER,
	  "Intel PRO/1000 QT (82571EB)",
	  WM_T_82571,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571GB_QUAD_COPPER,
	  "Intel PRO/1000 PT Quad Port Server Adapter",
	  WM_T_82571,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571PT_QUAD_COPPER,
	  "Intel Gigabit PT Quad Port Server ExpressModule",
	  WM_T_82571,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_DUAL_SERDES,
	  "Intel 82571EB Dual Gigabit Ethernet (SERDES)",
	  WM_T_82571,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_QUAD_SERDES,
	  "Intel 82571EB Quad Gigabit Ethernet (SERDES)",
	  WM_T_82571,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82571EB_QUAD_FIBER,
	  "Intel 82571EB Quad 1000baseX Ethernet",
	  WM_T_82571,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82572EI_COPPER,
	  "Intel i82572EI 1000baseT Ethernet",
	  WM_T_82572,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82572EI_FIBER,
	  "Intel i82572EI 1000baseX Ethernet",
	  WM_T_82572,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82572EI_SERDES,
	  "Intel i82572EI Gigabit Ethernet (SERDES)",
	  WM_T_82572,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82572EI,
	  "Intel i82572EI 1000baseT Ethernet",
	  WM_T_82572,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82573E,
	  "Intel i82573E",
	  WM_T_82573,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82573E_IAMT,
	  "Intel i82573E IAMT",
	  WM_T_82573,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82573L,
	  "Intel i82573L Gigabit Ethernet",
	  WM_T_82573,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82574L,
	  "Intel i82574L",
	  WM_T_82574,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82574LA,
	  "Intel i82574L",
	  WM_T_82574,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82583V,
	  "Intel i82583V",
	  WM_T_82583,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_80K3LAN_CPR_DPT,
	  "i80003 dual 1000baseT Ethernet",
	  WM_T_80003,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_80K3LAN_FIB_DPT,
	  "i80003 dual 1000baseX Ethernet",
	  WM_T_80003,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_80K3LAN_SDS_DPT,
	  "Intel i80003ES2 dual Gigabit Ethernet (SERDES)",
	  WM_T_80003,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_80K3LAN_CPR_SPT,
	  "Intel i80003 1000baseT Ethernet",
	  WM_T_80003,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_80K3LAN_SDS_SPT,
	  "Intel i80003 Gigabit Ethernet (SERDES)",
	  WM_T_80003,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_M_AMT,
	  "Intel i82801H (M_AMT) LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_AMT,
	  "Intel i82801H (AMT) LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_LAN,
	  "Intel i82801H LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_IFE_LAN,
	  "Intel i82801H (IFE) 10/100 LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_M_LAN,
	  "Intel i82801H (M) LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_IFE_GT,
	  "Intel i82801H IFE (GT) 10/100 LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_IFE_G,
	  "Intel i82801H IFE (G) 10/100 LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801H_82567V_3,
	  "82567V-3 LAN Controller",
	  WM_T_ICH8,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IGP_AMT,
	  "82801I (AMT) LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IFE,
	  "82801I 10/100 LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IFE_G,
	  "82801I (G) 10/100 LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IFE_GT,
	  "82801I (GT) 10/100 LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IGP_C,
	  "82801I (C) LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IGP_M,
	  "82801I mobile LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IGP_M_V,
	  "82801I mobile (V) LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_IGP_M_AMT,
	  "82801I mobile (AMT) LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801I_BM,
	  "82567LM-4 LAN Controller",
	  WM_T_ICH9,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_R_BM_LM,
	  "82567LM-2 LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_R_BM_LF,
	  "82567LF-2 LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_D_BM_LM,
	  "82567LM-3 LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_D_BM_LF,
	  "82567LF-3 LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_R_BM_V,
	  "82567V-2 LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82801J_D_BM_V,
	  "82567V-3? LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_HANKSVILLE,
	  "HANKSVILLE LAN Controller",
	  WM_T_ICH10,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH_M_LM,
	  "PCH LAN (82577LM) Controller",
	  WM_T_PCH,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH_M_LC,
	  "PCH LAN (82577LC) Controller",
	  WM_T_PCH,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH_D_DM,
	  "PCH LAN (82578DM) Controller",
	  WM_T_PCH,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH_D_DC,
	  "PCH LAN (82578DC) Controller",
	  WM_T_PCH,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH2_LV_LM,
	  "PCH2 LAN (82579LM) Controller",
	  WM_T_PCH2,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_PCH2_LV_V,
	  "PCH2 LAN (82579V) Controller",
	  WM_T_PCH2,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82575EB_COPPER,
	  "82575EB dual-1000baseT Ethernet",
	  WM_T_82575,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82575EB_FIBER_SERDES,
	  "82575EB dual-1000baseX Ethernet (SERDES)",
	  WM_T_82575,		WMP_F_SERDES },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82575GB_QUAD_COPPER,
	  "82575GB quad-1000baseT Ethernet",
	  WM_T_82575,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82575GB_QUAD_COPPER_PM,
	  "82575GB quad-1000baseT Ethernet (PM)",
	  WM_T_82575,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_COPPER,
	  "82576 1000BaseT Ethernet",
	  WM_T_82576,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_FIBER,
	  "82576 1000BaseX Ethernet",
	  WM_T_82576,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_SERDES,
	  "82576 gigabit Ethernet (SERDES)",
	  WM_T_82576,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_QUAD_COPPER,
	  "82576 quad-1000BaseT Ethernet",
	  WM_T_82576,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_QUAD_COPPER_ET2,
	  "82576 Gigabit ET2 Quad Port Server Adapter",
	  WM_T_82576,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_NS,
	  "82576 gigabit Ethernet",
	  WM_T_82576,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_NS_SERDES,
	  "82576 gigabit Ethernet (SERDES)",
	  WM_T_82576,		WMP_F_SERDES },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82576_SERDES_QUAD,
	  "82576 quad-gigabit Ethernet (SERDES)",
	  WM_T_82576,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_COPPER,
	  "82580 1000BaseT Ethernet",
	  WM_T_82580,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_FIBER,
	  "82580 1000BaseX Ethernet",
	  WM_T_82580,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_SERDES,
	  "82580 1000BaseT Ethernet (SERDES)",
	  WM_T_82580,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_SGMII,
	  "82580 gigabit Ethernet (SGMII)",
	  WM_T_82580,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_COPPER_DUAL,
	  "82580 dual-1000BaseT Ethernet",
	  WM_T_82580,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_82580_QUAD_FIBER,
	  "82580 quad-1000BaseX Ethernet",
	  WM_T_82580,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_DH89XXCC_SGMII,
	  "DH89XXCC Gigabit Ethernet (SGMII)",
	  WM_T_82580,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_DH89XXCC_SERDES,
	  "DH89XXCC Gigabit Ethernet (SERDES)",
	  WM_T_82580,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_DH89XXCC_BPLANE,
	  "DH89XXCC 1000BASE-KX Ethernet",
	  WM_T_82580,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_DH89XXCC_SFP,
	  "DH89XXCC Gigabit Ethernet (SFP)",
	  WM_T_82580,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I350_COPPER,
	  "I350 Gigabit Network Connection",
	  WM_T_I350,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I350_FIBER,
	  "I350 Gigabit Fiber Network Connection",
	  WM_T_I350,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I350_SERDES,
	  "I350 Gigabit Backplane Connection",
	  WM_T_I350,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I350_DA4,
	  "I350 Quad Port Gigabit Ethernet",
	  WM_T_I350,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I350_SGMII,
	  "I350 Gigabit Connection",
	  WM_T_I350,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_C2000_1000KX,
	  "I354 Gigabit Ethernet (KX)",
	  WM_T_I354,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_C2000_SGMII,
	  "I354 Gigabit Ethernet (SGMII)",
	  WM_T_I354,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_C2000_25GBE,
	  "I354 Gigabit Ethernet (2.5G)",
	  WM_T_I354,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_T1,
	  "I210-T1 Ethernet Server Adapter",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_COPPER_OEM1,
	  "I210 Ethernet (Copper OEM)",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_COPPER_IT,
	  "I210 Ethernet (Copper IT)",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_COPPER_WOF,
	  "I210 Ethernet (Copper, FLASH less)",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_FIBER,
	  "I210 Gigabit Ethernet (Fiber)",
	  WM_T_I210,		WMP_F_FIBER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_SERDES,
	  "I210 Gigabit Ethernet (SERDES)",
	  WM_T_I210,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_SERDES_WOF,
	  "I210 Gigabit Ethernet (SERDES, FLASH less)",
	  WM_T_I210,		WMP_F_SERDES },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_SGMII,
	  "I210 Gigabit Ethernet (SGMII)",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I210_SGMII_WOF,
	  "I210 Gigabit Ethernet (SGMII, FLASH less)",
	  WM_T_I210,		WMP_F_COPPER },

	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I211_COPPER,
	  "I211 Ethernet (COPPER)",
	  WM_T_I211,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I217_V,
	  "I217 V Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I217_LM,
	  "I217 LM Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_V,
	  "I218 V Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_V2,
	  "I218 V Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_V3,
	  "I218 V Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_LM,
	  "I218 LM Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_LM2,
	  "I218 LM Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I218_LM3,
	  "I218 LM Ethernet Connection",
	  WM_T_PCH_LPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM,
	  "I219 LM Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM2,
	  "I219 LM (2) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM3,
	  "I219 LM (3) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM4,
	  "I219 LM (4) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM5,
	  "I219 LM (5) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM6,
	  "I219 LM (6) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM7,
	  "I219 LM (7) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM8,
	  "I219 LM (8) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM9,
	  "I219 LM (9) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM10,
	  "I219 LM (10) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM11,
	  "I219 LM (11) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM12,
	  "I219 LM (12) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM13,
	  "I219 LM (13) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM14,
	  "I219 LM (14) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM15,
	  "I219 LM (15) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM16,
	  "I219 LM (16) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM17,
	  "I219 LM (17) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM18,
	  "I219 LM (18) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM19,
	  "I219 LM (19) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM20,
	  "I219 LM (20) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM21,
	  "I219 LM (21) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM22,
	  "I219 LM (22) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP(RPL) */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_LM23,
	  "I219 LM (23) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP(RPL) */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V,
	  "I219 V Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V2,
	  "I219 V (2) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V4,
	  "I219 V (4) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V5,
	  "I219 V (5) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V6,
	  "I219 V (6) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V7,
	  "I219 V (7) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V8,
	  "I219 V (8) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V9,
	  "I219 V (9) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V10,
	  "I219 V (10) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V11,
	  "I219 V (11) Ethernet Connection",
	  WM_T_PCH_CNP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V12,
	  "I219 V (12) Ethernet Connection",
	  WM_T_PCH_SPT,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V13,
	  "I219 V (13) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V14,
	  "I219 V (14) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V15,
	  "I219 V (15) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER },
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V16,
	  "I219 V (16) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V17,
	  "I219 V (17) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V18,
	  "I219 V (18) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V19,
	  "I219 V (19) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V20,
	  "I219 V (20) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V21,
	  "I219 V (21) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* MTP */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V22,
	  "I219 V (22) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP(RPL) */
	{ PCI_VENDOR_INTEL,	PCI_PRODUCT_INTEL_I219_V23,
	  "I219 V (23) Ethernet Connection",
	  WM_T_PCH_TGP,		WMP_F_COPPER }, /* ADP(RPL) */
	{ 0,			0,
	  NULL,
	  0,			0 },
};

/*
 * Register read/write functions.
 * Other than CSR_{READ|WRITE}().
 */

#if 0 /* Not currently used */
static inline uint32_t
wm_io_read(struct wm_softc *sc, int reg)
{

	bus_space_write_4(sc->sc_iot, sc->sc_ioh, 0, reg);
	return (bus_space_read_4(sc->sc_iot, sc->sc_ioh, 4));
}
#endif

static inline void
wm_io_write(struct wm_softc *sc, int reg, uint32_t val)
{

	bus_space_write_4(sc->sc_iot, sc->sc_ioh, 0, reg);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, 4, val);
}

static inline void
wm_82575_write_8bit_ctlr_reg(struct wm_softc *sc, uint32_t reg, uint32_t off,
    uint32_t data)
{
	uint32_t regval;
	int i;

	regval = (data & SCTL_CTL_DATA_MASK) | (off << SCTL_CTL_ADDR_SHIFT);

	CSR_WRITE(sc, reg, regval);

	for (i = 0; i < SCTL_CTL_POLL_TIMEOUT; i++) {
		delay(5);
		if (CSR_READ(sc, reg) & SCTL_CTL_READY)
			break;
	}
	if (i == SCTL_CTL_POLL_TIMEOUT) {
		aprint_error("%s: WARNING:"
		    " i82575 reg 0x%08x setup did not indicate ready\n",
		    device_xname(sc->sc_dev), reg);
	}
}

static inline void
wm_set_dma_addr(volatile wiseman_addr_t *wa, bus_addr_t v)
{
	wa->wa_low = htole32(BUS_ADDR_LO32(v));
	wa->wa_high = htole32(BUS_ADDR_HI32(v));
}

/*
 * Descriptor sync/init functions.
 */
static inline void
wm_cdtxsync(struct wm_txqueue *txq, int start, int num, int ops)
{
	struct wm_softc *sc = txq->txq_sc;

	/* If it will wrap around, sync to the end of the ring. */
	if ((start + num) > WM_NTXDESC(txq)) {
		bus_dmamap_sync(sc->sc_dmat, txq->txq_desc_dmamap,
		    WM_CDTXOFF(txq, start), txq->txq_descsize *
		    (WM_NTXDESC(txq) - start), ops);
		num -= (WM_NTXDESC(txq) - start);
		start = 0;
	}

	/* Now sync whatever is left. */
	bus_dmamap_sync(sc->sc_dmat, txq->txq_desc_dmamap,
	    WM_CDTXOFF(txq, start), txq->txq_descsize * num, ops);
}

static inline void
wm_cdrxsync(struct wm_rxqueue *rxq, int start, int ops)
{
	struct wm_softc *sc = rxq->rxq_sc;

	bus_dmamap_sync(sc->sc_dmat, rxq->rxq_desc_dmamap,
	    WM_CDRXOFF(rxq, start), rxq->rxq_descsize, ops);
}

static inline void
wm_init_rxdesc(struct wm_rxqueue *rxq, int start)
{
	struct wm_softc *sc = rxq->rxq_sc;
	struct wm_rxsoft *rxs = &rxq->rxq_soft[start];
	struct mbuf *m = rxs->rxs_mbuf;

	/*
	 * Note: We scoot the packet forward 2 bytes in the buffer
	 * so that the payload after the Ethernet header is aligned
	 * to a 4-byte boundary.

	 * XXX BRAINDAMAGE ALERT!
	 * The stupid chip uses the same size for every buffer, which
	 * is set in the Receive Control register.  We are using the 2K
	 * size option, but what we REALLY want is (2K - 2)!  For this
	 * reason, we can't "scoot" packets longer than the standard
	 * Ethernet MTU.  On strict-alignment platforms, if the total
	 * size exceeds (2K - 2) we set align_tweak to 0 and let
	 * the upper layer copy the headers.
	 */
	m->m_data = m->m_ext.ext_buf + sc->sc_align_tweak;

	if (sc->sc_type == WM_T_82574) {
		ext_rxdesc_t *rxd = &rxq->rxq_ext_descs[start];
		rxd->erx_data.erxd_addr =
		    htole64(rxs->rxs_dmamap->dm_segs[0].ds_addr + sc->sc_align_tweak);
		rxd->erx_data.erxd_dd = 0;
	} else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		nq_rxdesc_t *rxd = &rxq->rxq_nq_descs[start];

		rxd->nqrx_data.nrxd_paddr =
		    htole64(rxs->rxs_dmamap->dm_segs[0].ds_addr + sc->sc_align_tweak);
		/* Currently, split header is not supported. */
		rxd->nqrx_data.nrxd_haddr = 0;
	} else {
		wiseman_rxdesc_t *rxd = &rxq->rxq_descs[start];

		wm_set_dma_addr(&rxd->wrx_addr,
		    rxs->rxs_dmamap->dm_segs[0].ds_addr + sc->sc_align_tweak);
		rxd->wrx_len = 0;
		rxd->wrx_cksum = 0;
		rxd->wrx_status = 0;
		rxd->wrx_errors = 0;
		rxd->wrx_special = 0;
	}
	wm_cdrxsync(rxq, start, BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	CSR_WRITE(sc, rxq->rxq_rdt_reg, start);
}

/*
 * Device driver interface functions and commonly used functions.
 * match, attach, detach, init, start, stop, ioctl, watchdog and so on.
 */

/* Lookup supported device table */
static const struct wm_product *
wm_lookup(const struct pci_attach_args *pa)
{
	const struct wm_product *wmp;

	for (wmp = wm_products; wmp->wmp_name != NULL; wmp++) {
		if (PCI_VENDOR(pa->pa_id) == wmp->wmp_vendor &&
		    PCI_PRODUCT(pa->pa_id) == wmp->wmp_product)
			return wmp;
	}
	return NULL;
}

/* The match function (ca_match) */
static int
wm_match(device_t parent, cfdata_t cf, void *aux)
{
	struct pci_attach_args *pa = aux;

	if (wm_lookup(pa) != NULL)
		return 1;

	return 0;
}

/* The attach function (ca_attach) */
static void
wm_attach(device_t parent, device_t self, void *aux)
{
	struct wm_softc *sc = device_private(self);
	struct pci_attach_args *pa = aux;
	prop_dictionary_t dict;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	pci_chipset_tag_t pc = pa->pa_pc;
	int counts[PCI_INTR_TYPE_SIZE];
	pci_intr_type_t max_type;
	const char *eetype, *xname;
	bus_space_tag_t memt;
	bus_space_handle_t memh;
	bus_size_t memsize;
	int memh_valid;
	int i, error;
	const struct wm_product *wmp;
	prop_data_t ea;
	prop_number_t pn;
	uint8_t enaddr[ETHER_ADDR_LEN];
	char buf[256];
	char wqname[MAXCOMLEN];
	uint16_t cfg1, cfg2, swdpin, nvmword;
	pcireg_t preg, memtype;
	uint16_t eeprom_data, apme_mask;
	bool force_clear_smbi;
	uint32_t link_mode;
	uint32_t reg;

#if defined(WM_DEBUG) && defined(WM_DEBUG_DEFAULT)
	sc->sc_debug = WM_DEBUG_DEFAULT;
#endif
	sc->sc_dev = self;
	callout_init(&sc->sc_tick_ch, CALLOUT_MPSAFE);
	callout_setfunc(&sc->sc_tick_ch, wm_tick, sc);
	sc->sc_core_stopping = false;

	wmp = wm_lookup(pa);
#ifdef DIAGNOSTIC
	if (wmp == NULL) {
		printf("\n");
		panic("wm_attach: impossible");
	}
#endif
	sc->sc_mediatype = WMP_MEDIATYPE(wmp->wmp_flags);

	sc->sc_pc = pa->pa_pc;
	sc->sc_pcitag = pa->pa_tag;

	if (pci_dma64_available(pa)) {
		aprint_verbose(", 64-bit DMA");
		sc->sc_dmat = pa->pa_dmat64;
	} else {
		aprint_verbose(", 32-bit DMA");
		sc->sc_dmat = pa->pa_dmat;
	}

	sc->sc_pcidevid = PCI_PRODUCT(pa->pa_id);
	sc->sc_rev = PCI_REVISION(pci_conf_read(pc, pa->pa_tag,PCI_CLASS_REG));
	pci_aprint_devinfo_fancy(pa, "Ethernet controller", wmp->wmp_name, 1);

	sc->sc_type = wmp->wmp_type;

	/* Set default function pointers */
	sc->phy.acquire = sc->nvm.acquire = wm_get_null;
	sc->phy.release = sc->nvm.release = wm_put_null;
	sc->phy.reset_delay_us = (sc->sc_type >= WM_T_82571) ? 100 : 10000;

	if (sc->sc_type < WM_T_82543) {
		if (sc->sc_rev < 2) {
			aprint_error_dev(sc->sc_dev,
			    "i82542 must be at least rev. 2\n");
			return;
		}
		if (sc->sc_rev < 3)
			sc->sc_type = WM_T_82542_2_0;
	}

	/*
	 * Disable MSI for Errata:
	 * "Message Signaled Interrupt Feature May Corrupt Write Transactions"
	 *
	 *  82544: Errata 25
	 *  82540: Errata  6 (easy to reproduce device timeout)
	 *  82545: Errata  4 (easy to reproduce device timeout)
	 *  82546: Errata 26 (easy to reproduce device timeout)
	 *  82541: Errata  7 (easy to reproduce device timeout)
	 *
	 * "Byte Enables 2 and 3 are not set on MSI writes"
	 *
	 *  82571 & 82572: Errata 63
	 */
	if ((sc->sc_type <= WM_T_82541_2) || (sc->sc_type == WM_T_82571)
	    || (sc->sc_type == WM_T_82572))
		pa->pa_flags &= ~PCI_FLAGS_MSI_OKAY;

	if ((sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)
	    || (sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354)
	    || (sc->sc_type == WM_T_I210) || (sc->sc_type == WM_T_I211))
		sc->sc_flags |= WM_F_NEWQUEUE;

	/* Set device properties (mactype) */
	dict = device_properties(sc->sc_dev);
	prop_dictionary_set_uint32(dict, "mactype", sc->sc_type);

	/*
	 * Map the device.  All devices support memory-mapped acccess,
	 * and it is really required for normal operation.
	 */
	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, WM_PCI_MMBA);
	switch (memtype) {
	case PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_32BIT:
	case PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_64BIT:
		memh_valid = (pci_mapreg_map(pa, WM_PCI_MMBA,
			memtype, 0, &memt, &memh, NULL, &memsize) == 0);
		break;
	default:
		memh_valid = 0;
		break;
	}

	if (memh_valid) {
		sc->sc_st = memt;
		sc->sc_sh = memh;
		sc->sc_ss = memsize;
	} else {
		aprint_error_dev(sc->sc_dev,
		    "unable to map device registers\n");
		return;
	}

	/*
	 * In addition, i82544 and later support I/O mapped indirect
	 * register access.  It is not desirable (nor supported in
	 * this driver) to use it for normal operation, though it is
	 * required to work around bugs in some chip versions.
	 */
	switch (sc->sc_type) {
	case WM_T_82544:
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
		/* First we have to find the I/O BAR. */
		for (i = PCI_MAPREG_START; i < PCI_MAPREG_END; i += 4) {
			memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, i);
			if (memtype == PCI_MAPREG_TYPE_IO)
				break;
			if (PCI_MAPREG_MEM_TYPE(memtype) ==
			    PCI_MAPREG_MEM_TYPE_64BIT)
				i += 4;	/* skip high bits, too */
		}
		if (i < PCI_MAPREG_END) {
			/*
			 * We found PCI_MAPREG_TYPE_IO. Note that 82580
			 * (and newer?) chip has no PCI_MAPREG_TYPE_IO.
			 * It's no problem because newer chips has no this
			 * bug.
			 *
			 * The i8254x doesn't apparently respond when the
			 * I/O BAR is 0, which looks somewhat like it's not
			 * been configured.
			 */
			preg = pci_conf_read(pc, pa->pa_tag, i);
			if (PCI_MAPREG_MEM_ADDR(preg) == 0) {
				aprint_error_dev(sc->sc_dev,
				    "WARNING: I/O BAR at zero.\n");
			} else if (pci_mapreg_map(pa, i, PCI_MAPREG_TYPE_IO,
			    0, &sc->sc_iot, &sc->sc_ioh, NULL, &sc->sc_ios)
			    == 0) {
				sc->sc_flags |= WM_F_IOH_VALID;
			} else
				aprint_error_dev(sc->sc_dev,
				    "WARNING: unable to map I/O space\n");
		}
		break;
	default:
		break;
	}

	/* Enable bus mastering.  Disable MWI on the i82542 2.0. */
	preg = pci_conf_read(pc, pa->pa_tag, PCI_COMMAND_STATUS_REG);
	preg |= PCI_COMMAND_MASTER_ENABLE;
	if (sc->sc_type < WM_T_82542_2_1)
		preg &= ~PCI_COMMAND_INVALIDATE_ENABLE;
	pci_conf_write(pc, pa->pa_tag, PCI_COMMAND_STATUS_REG, preg);

	/* Power up chip */
	if ((error = pci_activate(pa->pa_pc, pa->pa_tag, self, NULL))
	    && error != EOPNOTSUPP) {
		aprint_error_dev(sc->sc_dev, "cannot activate %d\n", error);
		return;
	}

	wm_adjust_qnum(sc, pci_msix_count(pa->pa_pc, pa->pa_tag));
	/*
	 *  Don't use MSI-X if we can use only one queue to save interrupt
	 * resource.
	 */
	if (sc->sc_nqueues > 1) {
		max_type = PCI_INTR_TYPE_MSIX;
		/*
		 *  82583 has a MSI-X capability in the PCI configuration space
		 * but it doesn't support it. At least the document doesn't
		 * say anything about MSI-X.
		 */
		counts[PCI_INTR_TYPE_MSIX]
		    = (sc->sc_type == WM_T_82583) ? 0 : sc->sc_nqueues + 1;
	} else {
		max_type = PCI_INTR_TYPE_MSI;
		counts[PCI_INTR_TYPE_MSIX] = 0;
	}

	/* Allocation settings */
	counts[PCI_INTR_TYPE_MSI] = 1;
	counts[PCI_INTR_TYPE_INTX] = 1;
	/* overridden by disable flags */
	if (wm_disable_msi != 0) {
		counts[PCI_INTR_TYPE_MSI] = 0;
		if (wm_disable_msix != 0) {
			max_type = PCI_INTR_TYPE_INTX;
			counts[PCI_INTR_TYPE_MSIX] = 0;
		}
	} else if (wm_disable_msix != 0) {
		max_type = PCI_INTR_TYPE_MSI;
		counts[PCI_INTR_TYPE_MSIX] = 0;
	}

alloc_retry:
	if (pci_intr_alloc(pa, &sc->sc_intrs, counts, max_type) != 0) {
		aprint_error_dev(sc->sc_dev, "failed to allocate interrupt\n");
		return;
	}

	if (pci_intr_type(pc, sc->sc_intrs[0]) == PCI_INTR_TYPE_MSIX) {
		error = wm_setup_msix(sc);
		if (error) {
			pci_intr_release(pc, sc->sc_intrs,
			    counts[PCI_INTR_TYPE_MSIX]);

			/* Setup for MSI: Disable MSI-X */
			max_type = PCI_INTR_TYPE_MSI;
			counts[PCI_INTR_TYPE_MSI] = 1;
			counts[PCI_INTR_TYPE_INTX] = 1;
			goto alloc_retry;
		}
	} else if (pci_intr_type(pc, sc->sc_intrs[0]) == PCI_INTR_TYPE_MSI) {
		wm_adjust_qnum(sc, 0);	/* Must not use multiqueue */
		error = wm_setup_legacy(sc);
		if (error) {
			pci_intr_release(sc->sc_pc, sc->sc_intrs,
			    counts[PCI_INTR_TYPE_MSI]);

			/* The next try is for INTx: Disable MSI */
			max_type = PCI_INTR_TYPE_INTX;
			counts[PCI_INTR_TYPE_INTX] = 1;
			goto alloc_retry;
		}
	} else {
		wm_adjust_qnum(sc, 0);	/* Must not use multiqueue */
		error = wm_setup_legacy(sc);
		if (error) {
			pci_intr_release(sc->sc_pc, sc->sc_intrs,
			    counts[PCI_INTR_TYPE_INTX]);
			return;
		}
	}

	snprintf(wqname, sizeof(wqname), "%sTxRx", device_xname(sc->sc_dev));
	error = workqueue_create(&sc->sc_queue_wq, wqname,
	    wm_handle_queue_work, sc, WM_WORKQUEUE_PRI, IPL_NET,
	    WQ_PERCPU | WQ_MPSAFE);
	if (error) {
		aprint_error_dev(sc->sc_dev,
		    "unable to create TxRx workqueue\n");
		goto out;
	}

	snprintf(wqname, sizeof(wqname), "%sReset", device_xname(sc->sc_dev));
	error = workqueue_create(&sc->sc_reset_wq, wqname,
	    wm_handle_reset_work, sc, WM_WORKQUEUE_PRI, IPL_SOFTCLOCK,
	    WQ_MPSAFE);
	if (error) {
		workqueue_destroy(sc->sc_queue_wq);
		aprint_error_dev(sc->sc_dev,
		    "unable to create reset workqueue\n");
		goto out;
	}

	/*
	 * Check the function ID (unit number of the chip).
	 */
	if ((sc->sc_type == WM_T_82546) || (sc->sc_type == WM_T_82546_3)
	    || (sc->sc_type == WM_T_82571) || (sc->sc_type == WM_T_80003)
	    || (sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)
	    || (sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354))
		sc->sc_funcid = (CSR_READ(sc, WMREG_STATUS)
		    >> STATUS_FUNCID_SHIFT) & STATUS_FUNCID_MASK;
	else
		sc->sc_funcid = 0;

	/*
	 * Determine a few things about the bus we're connected to.
	 */
	if (sc->sc_type < WM_T_82543) {
		/* We don't really know the bus characteristics here. */
		sc->sc_bus_speed = 33;
	} else if (sc->sc_type == WM_T_82547 || sc->sc_type == WM_T_82547_2) {
		/*
		 * CSA (Communication Streaming Architecture) is about as fast
		 * a 32-bit 66MHz PCI Bus.
		 */
		sc->sc_flags |= WM_F_CSA;
		sc->sc_bus_speed = 66;
		aprint_verbose_dev(sc->sc_dev,
		    "Communication Streaming Architecture\n");
		if (sc->sc_type == WM_T_82547) {
			callout_init(&sc->sc_txfifo_ch, CALLOUT_MPSAFE);
			callout_setfunc(&sc->sc_txfifo_ch,
			    wm_82547_txfifo_stall, sc);
			aprint_verbose_dev(sc->sc_dev,
			    "using 82547 Tx FIFO stall work-around\n");
		}
	} else if (sc->sc_type >= WM_T_82571) {
		sc->sc_flags |= WM_F_PCIE;
		if ((sc->sc_type != WM_T_ICH8) && (sc->sc_type != WM_T_ICH9)
		    && (sc->sc_type != WM_T_ICH10)
		    && (sc->sc_type != WM_T_PCH)
		    && (sc->sc_type != WM_T_PCH2)
		    && (sc->sc_type != WM_T_PCH_LPT)
		    && (sc->sc_type != WM_T_PCH_SPT)
		    && (sc->sc_type != WM_T_PCH_CNP)
		    && (sc->sc_type != WM_T_PCH_TGP)) {
			/* ICH* and PCH* have no PCIe capability registers */
			if (pci_get_capability(pa->pa_pc, pa->pa_tag,
				PCI_CAP_PCIEXPRESS, &sc->sc_pcixe_capoff,
				NULL) == 0)
				aprint_error_dev(sc->sc_dev,
				    "unable to find PCIe capability\n");
		}
		aprint_verbose_dev(sc->sc_dev, "PCI-Express bus\n");
	} else {
		reg = CSR_READ(sc, WMREG_STATUS);
		if (reg & STATUS_BUS64)
			sc->sc_flags |= WM_F_BUS64;
		if ((reg & STATUS_PCIX_MODE) != 0) {
			pcireg_t pcix_cmd, pcix_sts, bytecnt, maxb;

			sc->sc_flags |= WM_F_PCIX;
			if (pci_get_capability(pa->pa_pc, pa->pa_tag,
				PCI_CAP_PCIX, &sc->sc_pcixe_capoff, NULL) == 0)
				aprint_error_dev(sc->sc_dev,
				    "unable to find PCIX capability\n");
			else if (sc->sc_type != WM_T_82545_3 &&
			    sc->sc_type != WM_T_82546_3) {
				/*
				 * Work around a problem caused by the BIOS
				 * setting the max memory read byte count
				 * incorrectly.
				 */
				pcix_cmd = pci_conf_read(pa->pa_pc, pa->pa_tag,
				    sc->sc_pcixe_capoff + PCIX_CMD);
				pcix_sts = pci_conf_read(pa->pa_pc, pa->pa_tag,
				    sc->sc_pcixe_capoff + PCIX_STATUS);

				bytecnt = (pcix_cmd & PCIX_CMD_BYTECNT_MASK) >>
				    PCIX_CMD_BYTECNT_SHIFT;
				maxb = (pcix_sts & PCIX_STATUS_MAXB_MASK) >>
				    PCIX_STATUS_MAXB_SHIFT;
				if (bytecnt > maxb) {
					aprint_verbose_dev(sc->sc_dev,
					    "resetting PCI-X MMRBC: %d -> %d\n",
					    512 << bytecnt, 512 << maxb);
					pcix_cmd = (pcix_cmd &
					    ~PCIX_CMD_BYTECNT_MASK) |
					    (maxb << PCIX_CMD_BYTECNT_SHIFT);
					pci_conf_write(pa->pa_pc, pa->pa_tag,
					    sc->sc_pcixe_capoff + PCIX_CMD,
					    pcix_cmd);
				}
			}
		}
		/*
		 * The quad port adapter is special; it has a PCIX-PCIX
		 * bridge on the board, and can run the secondary bus at
		 * a higher speed.
		 */
		if (wmp->wmp_product == PCI_PRODUCT_INTEL_82546EB_QUAD) {
			sc->sc_bus_speed = (sc->sc_flags & WM_F_PCIX) ? 120
								      : 66;
		} else if (sc->sc_flags & WM_F_PCIX) {
			switch (reg & STATUS_PCIXSPD_MASK) {
			case STATUS_PCIXSPD_50_66:
				sc->sc_bus_speed = 66;
				break;
			case STATUS_PCIXSPD_66_100:
				sc->sc_bus_speed = 100;
				break;
			case STATUS_PCIXSPD_100_133:
				sc->sc_bus_speed = 133;
				break;
			default:
				aprint_error_dev(sc->sc_dev,
				    "unknown PCIXSPD %d; assuming 66MHz\n",
				    reg & STATUS_PCIXSPD_MASK);
				sc->sc_bus_speed = 66;
				break;
			}
		} else
			sc->sc_bus_speed = (reg & STATUS_PCI66) ? 66 : 33;
		aprint_verbose_dev(sc->sc_dev, "%d-bit %dMHz %s bus\n",
		    (sc->sc_flags & WM_F_BUS64) ? 64 : 32, sc->sc_bus_speed,
		    (sc->sc_flags & WM_F_PCIX) ? "PCIX" : "PCI");
	}

	/* clear interesting stat counters */
	CSR_READ(sc, WMREG_COLC);
	CSR_READ(sc, WMREG_RXERRC);

	if ((sc->sc_type == WM_T_82574) || (sc->sc_type == WM_T_82583)
	    || (sc->sc_type >= WM_T_ICH8))
		sc->sc_ich_phymtx = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);
	if (sc->sc_type >= WM_T_ICH8)
		sc->sc_ich_nvmmtx = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);

	/* Set PHY, NVM mutex related stuff */
	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
	case WM_T_82544:
		/* Microwire */
		sc->nvm.read = wm_nvm_read_uwire;
		sc->sc_nvm_wordsize = 64;
		sc->sc_nvm_addrbits = 6;
		break;
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82545_3:
	case WM_T_82546:
	case WM_T_82546_3:
		/* Microwire */
		sc->nvm.read = wm_nvm_read_uwire;
		reg = CSR_READ(sc, WMREG_EECD);
		if (reg & EECD_EE_SIZE) {
			sc->sc_nvm_wordsize = 256;
			sc->sc_nvm_addrbits = 8;
		} else {
			sc->sc_nvm_wordsize = 64;
			sc->sc_nvm_addrbits = 6;
		}
		sc->sc_flags |= WM_F_LOCK_EECD;
		sc->nvm.acquire = wm_get_eecd;
		sc->nvm.release = wm_put_eecd;
		break;
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
		reg = CSR_READ(sc, WMREG_EECD);
		/*
		 * wm_nvm_set_addrbits_size_eecd() accesses SPI in it only
		 * on 8254[17], so set flags and functios before calling it.
		 */
		sc->sc_flags |= WM_F_LOCK_EECD;
		sc->nvm.acquire = wm_get_eecd;
		sc->nvm.release = wm_put_eecd;
		if (reg & EECD_EE_TYPE) {
			/* SPI */
			sc->nvm.read = wm_nvm_read_spi;
			sc->sc_flags |= WM_F_EEPROM_SPI;
			wm_nvm_set_addrbits_size_eecd(sc);
		} else {
			/* Microwire */
			sc->nvm.read = wm_nvm_read_uwire;
			if ((reg & EECD_EE_ABITS) != 0) {
				sc->sc_nvm_wordsize = 256;
				sc->sc_nvm_addrbits = 8;
			} else {
				sc->sc_nvm_wordsize = 64;
				sc->sc_nvm_addrbits = 6;
			}
		}
		break;
	case WM_T_82571:
	case WM_T_82572:
		/* SPI */
		sc->nvm.read = wm_nvm_read_eerd;
		/* Not use WM_F_LOCK_EECD because we use EERD */
		sc->sc_flags |= WM_F_EEPROM_SPI;
		wm_nvm_set_addrbits_size_eecd(sc);
		sc->phy.acquire = wm_get_swsm_semaphore;
		sc->phy.release = wm_put_swsm_semaphore;
		sc->nvm.acquire = wm_get_nvm_82571;
		sc->nvm.release = wm_put_nvm_82571;
		break;
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		sc->nvm.read = wm_nvm_read_eerd;
		/* Not use WM_F_LOCK_EECD because we use EERD */
		if (sc->sc_type == WM_T_82573) {
			sc->phy.acquire = wm_get_swsm_semaphore;
			sc->phy.release = wm_put_swsm_semaphore;
			sc->nvm.acquire = wm_get_nvm_82571;
			sc->nvm.release = wm_put_nvm_82571;
		} else {
			/* Both PHY and NVM use the same semaphore. */
			sc->phy.acquire = sc->nvm.acquire
			    = wm_get_swfwhw_semaphore;
			sc->phy.release = sc->nvm.release
			    = wm_put_swfwhw_semaphore;
		}
		if (wm_nvm_is_onboard_eeprom(sc) == 0) {
			sc->sc_flags |= WM_F_EEPROM_FLASH;
			sc->sc_nvm_wordsize = 2048;
		} else {
			/* SPI */
			sc->sc_flags |= WM_F_EEPROM_SPI;
			wm_nvm_set_addrbits_size_eecd(sc);
		}
		break;
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_80003:
		/* SPI */
		sc->sc_flags |= WM_F_EEPROM_SPI;
		wm_nvm_set_addrbits_size_eecd(sc);
		if ((sc->sc_type == WM_T_80003)
		    || (sc->sc_nvm_wordsize < (1 << 15))) {
			sc->nvm.read = wm_nvm_read_eerd;
			/* Don't use WM_F_LOCK_EECD because we use EERD */
		} else {
			sc->nvm.read = wm_nvm_read_spi;
			sc->sc_flags |= WM_F_LOCK_EECD;
		}
		sc->phy.acquire = wm_get_phy_82575;
		sc->phy.release = wm_put_phy_82575;
		sc->nvm.acquire = wm_get_nvm_80003;
		sc->nvm.release = wm_put_nvm_80003;
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
		sc->nvm.read = wm_nvm_read_ich8;
		/* FLASH */
		sc->sc_flags |= WM_F_EEPROM_FLASH;
		sc->sc_nvm_wordsize = 2048;
		memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag,WM_ICH8_FLASH);
		if (pci_mapreg_map(pa, WM_ICH8_FLASH, memtype, 0,
		    &sc->sc_flasht, &sc->sc_flashh, NULL, &sc->sc_flashs)) {
			aprint_error_dev(sc->sc_dev,
			    "can't map FLASH registers\n");
			goto out;
		}
		reg = ICH8_FLASH_READ32(sc, ICH_FLASH_GFPREG);
		sc->sc_ich8_flash_base = (reg & ICH_GFPREG_BASE_MASK) *
		    ICH_FLASH_SECTOR_SIZE;
		sc->sc_ich8_flash_bank_size =
		    ((reg >> 16) & ICH_GFPREG_BASE_MASK) + 1;
		sc->sc_ich8_flash_bank_size -= (reg & ICH_GFPREG_BASE_MASK);
		sc->sc_ich8_flash_bank_size *= ICH_FLASH_SECTOR_SIZE;
		sc->sc_ich8_flash_bank_size /= 2 * sizeof(uint16_t);
		sc->sc_flashreg_offset = 0;
		sc->phy.acquire = wm_get_swflag_ich8lan;
		sc->phy.release = wm_put_swflag_ich8lan;
		sc->nvm.acquire = wm_get_nvm_ich8lan;
		sc->nvm.release = wm_put_nvm_ich8lan;
		break;
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		sc->nvm.read = wm_nvm_read_spt;
		/* SPT has no GFPREG; flash registers mapped through BAR0 */
		sc->sc_flags |= WM_F_EEPROM_FLASH;
		sc->sc_flasht = sc->sc_st;
		sc->sc_flashh = sc->sc_sh;
		sc->sc_ich8_flash_base = 0;
		sc->sc_nvm_wordsize =
		    (((CSR_READ(sc, WMREG_STRAP) >> 1) & 0x1F) + 1)
		    * NVM_SIZE_MULTIPLIER;
		/* It is size in bytes, we want words */
		sc->sc_nvm_wordsize /= 2;
		/* Assume 2 banks */
		sc->sc_ich8_flash_bank_size = sc->sc_nvm_wordsize / 2;
		sc->sc_flashreg_offset = WM_PCH_SPT_FLASHOFFSET;
		sc->phy.acquire = wm_get_swflag_ich8lan;
		sc->phy.release = wm_put_swflag_ich8lan;
		sc->nvm.acquire = wm_get_nvm_ich8lan;
		sc->nvm.release = wm_put_nvm_ich8lan;
		break;
	case WM_T_I210:
	case WM_T_I211:
		/* Allow a single clear of the SW semaphore on I210 and newer*/
		sc->sc_flags |= WM_F_WA_I210_CLSEM;
		if (wm_nvm_flash_presence_i210(sc)) {
			sc->nvm.read = wm_nvm_read_eerd;
			/* Don't use WM_F_LOCK_EECD because we use EERD */
			sc->sc_flags |= WM_F_EEPROM_FLASH_HW;
			wm_nvm_set_addrbits_size_eecd(sc);
		} else {
			sc->nvm.read = wm_nvm_read_invm;
			sc->sc_flags |= WM_F_EEPROM_INVM;
			sc->sc_nvm_wordsize = INVM_SIZE;
		}
		sc->phy.acquire = wm_get_phy_82575;
		sc->phy.release = wm_put_phy_82575;
		sc->nvm.acquire = wm_get_nvm_80003;
		sc->nvm.release = wm_put_nvm_80003;
		break;
	default:
		break;
	}

	/* Ensure the SMBI bit is clear before first NVM or PHY access */
	switch (sc->sc_type) {
	case WM_T_82571:
	case WM_T_82572:
		reg = CSR_READ(sc, WMREG_SWSM2);
		if ((reg & SWSM2_LOCK) == 0) {
			CSR_WRITE(sc, WMREG_SWSM2, reg | SWSM2_LOCK);
			force_clear_smbi = true;
		} else
			force_clear_smbi = false;
		break;
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		force_clear_smbi = true;
		break;
	default:
		force_clear_smbi = false;
		break;
	}
	if (force_clear_smbi) {
		reg = CSR_READ(sc, WMREG_SWSM);
		if ((reg & SWSM_SMBI) != 0)
			aprint_error_dev(sc->sc_dev,
			    "Please update the Bootagent\n");
		CSR_WRITE(sc, WMREG_SWSM, reg & ~SWSM_SMBI);
	}

	/*
	 * Defer printing the EEPROM type until after verifying the checksum
	 * This allows the EEPROM type to be printed correctly in the case
	 * that no EEPROM is attached.
	 */
	/*
	 * Validate the EEPROM checksum. If the checksum fails, flag
	 * this for later, so we can fail future reads from the EEPROM.
	 */
	if (wm_nvm_validate_checksum(sc)) {
		/*
		 * Read twice again because some PCI-e parts fail the
		 * first check due to the link being in sleep state.
		 */
		if (wm_nvm_validate_checksum(sc))
			sc->sc_flags |= WM_F_EEPROM_INVALID;
	}

	if (sc->sc_flags & WM_F_EEPROM_INVALID)
		aprint_verbose_dev(sc->sc_dev, "No EEPROM");
	else {
		aprint_verbose_dev(sc->sc_dev, "%u words ",
		    sc->sc_nvm_wordsize);
		if (sc->sc_flags & WM_F_EEPROM_INVM)
			aprint_verbose("iNVM");
		else if (sc->sc_flags & WM_F_EEPROM_FLASH_HW)
			aprint_verbose("FLASH(HW)");
		else if (sc->sc_flags & WM_F_EEPROM_FLASH)
			aprint_verbose("FLASH");
		else {
			if (sc->sc_flags & WM_F_EEPROM_SPI)
				eetype = "SPI";
			else
				eetype = "MicroWire";
			aprint_verbose("(%d address bits) %s EEPROM",
			    sc->sc_nvm_addrbits, eetype);
		}
	}
	wm_nvm_version(sc);
	aprint_verbose("\n");

	/*
	 * XXX The first call of wm_gmii_setup_phytype. The result might be
	 * incorrect.
	 */
	wm_gmii_setup_phytype(sc, 0, 0);

	/* Check for WM_F_WOL on some chips before wm_reset() */
	switch (sc->sc_type) {
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		apme_mask = WUC_APME;
		eeprom_data = CSR_READ(sc, WMREG_WUC);
		if ((eeprom_data & apme_mask) != 0)
			sc->sc_flags |= WM_F_WOL;
		break;
	default:
		break;
	}

	/* Reset the chip to a known state. */
	wm_reset(sc);

	/* sc->sc_pba is set in wm_reset(). */
	aprint_verbose_dev(sc->sc_dev, "RX packet buffer size: %uKB\n",
	    sc->sc_pba);

	/*
	 * Check for I21[01] PLL workaround.
	 *
	 * Three cases:
	 * a) Chip is I211.
	 * b) Chip is I210 and it uses INVM (not FLASH).
	 * c) Chip is I210 (and it uses FLASH) and the NVM image version < 3.25
	 */
	if (sc->sc_type == WM_T_I211)
		sc->sc_flags |= WM_F_PLL_WA_I210;
	if (sc->sc_type == WM_T_I210) {
		if (!wm_nvm_flash_presence_i210(sc))
			sc->sc_flags |= WM_F_PLL_WA_I210;
		else if ((sc->sc_nvm_ver_major < 3)
		    || ((sc->sc_nvm_ver_major == 3)
			&& (sc->sc_nvm_ver_minor < 25))) {
			aprint_verbose_dev(sc->sc_dev,
			    "ROM image version %d.%d is older than 3.25\n",
			    sc->sc_nvm_ver_major, sc->sc_nvm_ver_minor);
			sc->sc_flags |= WM_F_PLL_WA_I210;
		}
	}
	if ((sc->sc_flags & WM_F_PLL_WA_I210) != 0)
		wm_pll_workaround_i210(sc);

	wm_get_wakeup(sc);

	/* Non-AMT based hardware can now take control from firmware */
	if ((sc->sc_flags & WM_F_HAS_AMT) == 0)
		wm_get_hw_control(sc);

	/*
	 * Read the Ethernet address from the EEPROM, if not first found
	 * in device properties.
	 */
	ea = prop_dictionary_get(dict, "mac-address");
	if (ea != NULL) {
		KASSERT(prop_object_type(ea) == PROP_TYPE_DATA);
		KASSERT(prop_data_size(ea) == ETHER_ADDR_LEN);
		memcpy(enaddr, prop_data_value(ea), ETHER_ADDR_LEN);
	} else {
		if (wm_read_mac_addr(sc, enaddr) != 0) {
			aprint_error_dev(sc->sc_dev,
			    "unable to read Ethernet address\n");
			goto out;
		}
	}

	aprint_normal_dev(sc->sc_dev, "Ethernet address %s\n",
	    ether_sprintf(enaddr));

	/*
	 * Read the config info from the EEPROM, and set up various
	 * bits in the control registers based on their contents.
	 */
	pn = prop_dictionary_get(dict, "i82543-cfg1");
	if (pn != NULL) {
		KASSERT(prop_object_type(pn) == PROP_TYPE_NUMBER);
		cfg1 = (uint16_t) prop_number_signed_value(pn);
	} else {
		if (wm_nvm_read(sc, NVM_OFF_CFG1, 1, &cfg1)) {
			aprint_error_dev(sc->sc_dev, "unable to read CFG1\n");
			goto out;
		}
	}

	pn = prop_dictionary_get(dict, "i82543-cfg2");
	if (pn != NULL) {
		KASSERT(prop_object_type(pn) == PROP_TYPE_NUMBER);
		cfg2 = (uint16_t) prop_number_signed_value(pn);
	} else {
		if (wm_nvm_read(sc, NVM_OFF_CFG2, 1, &cfg2)) {
			aprint_error_dev(sc->sc_dev, "unable to read CFG2\n");
			goto out;
		}
	}

	/* check for WM_F_WOL */
	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
		/* dummy? */
		eeprom_data = 0;
		apme_mask = NVM_CFG3_APME;
		break;
	case WM_T_82544:
		apme_mask = NVM_CFG2_82544_APM_EN;
		eeprom_data = cfg2;
		break;
	case WM_T_82546:
	case WM_T_82546_3:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_80003:
	case WM_T_82575:
	case WM_T_82576:
		apme_mask = NVM_CFG3_APME;
		wm_nvm_read(sc, (sc->sc_funcid == 1) ? NVM_OFF_CFG3_PORTB
		    : NVM_OFF_CFG3_PORTA, 1, &eeprom_data);
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		apme_mask = NVM_CFG3_APME;
		wm_nvm_read(sc,
		    NVM_OFF_LAN_FUNC_82580(sc->sc_funcid) + NVM_OFF_CFG3_PORTA,
		    1, &eeprom_data);
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		/* Already checked before wm_reset () */
		apme_mask = eeprom_data = 0;
		break;
	default: /* XXX 82540 */
		apme_mask = NVM_CFG3_APME;
		wm_nvm_read(sc, NVM_OFF_CFG3_PORTA, 1, &eeprom_data);
		break;
	}
	/* Check for WM_F_WOL flag after the setting of the EEPROM stuff */
	if ((eeprom_data & apme_mask) != 0)
		sc->sc_flags |= WM_F_WOL;

	/*
	 * We have the eeprom settings, now apply the special cases
	 * where the eeprom may be wrong or the board won't support
	 * wake on lan on a particular port
	 */
	switch (sc->sc_pcidevid) {
	case PCI_PRODUCT_INTEL_82546GB_PCIE:
		sc->sc_flags &= ~WM_F_WOL;
		break;
	case PCI_PRODUCT_INTEL_82546EB_FIBER:
	case PCI_PRODUCT_INTEL_82546GB_FIBER:
		/* Wake events only supported on port A for dual fiber
		 * regardless of eeprom setting */
		if (sc->sc_funcid == 1)
			sc->sc_flags &= ~WM_F_WOL;
		break;
	case PCI_PRODUCT_INTEL_82546GB_QUAD_COPPER_KSP3:
		/* If quad port adapter, disable WoL on all but port A */
		if (sc->sc_funcid != 0)
			sc->sc_flags &= ~WM_F_WOL;
		break;
	case PCI_PRODUCT_INTEL_82571EB_FIBER:
		/* Wake events only supported on port A for dual fiber
		 * regardless of eeprom setting */
		if (sc->sc_funcid == 1)
			sc->sc_flags &= ~WM_F_WOL;
		break;
	case PCI_PRODUCT_INTEL_82571EB_QUAD_COPPER:
	case PCI_PRODUCT_INTEL_82571EB_QUAD_FIBER:
	case PCI_PRODUCT_INTEL_82571GB_QUAD_COPPER:
		/* If quad port adapter, disable WoL on all but port A */
		if (sc->sc_funcid != 0)
			sc->sc_flags &= ~WM_F_WOL;
		break;
	}

	if (sc->sc_type >= WM_T_82575) {
		if (wm_nvm_read(sc, NVM_OFF_COMPAT, 1, &nvmword) == 0) {
			aprint_debug_dev(sc->sc_dev, "COMPAT = %hx\n",
			    nvmword);
			if ((sc->sc_type == WM_T_82575) ||
			    (sc->sc_type == WM_T_82576)) {
				/* Check NVM for autonegotiation */
				if ((nvmword & NVM_COMPAT_SERDES_FORCE_MODE)
				    != 0)
					sc->sc_flags |= WM_F_PCS_DIS_AUTONEGO;
			}
			if ((sc->sc_type == WM_T_82575) ||
			    (sc->sc_type == WM_T_I350)) {
				if (nvmword & NVM_COMPAT_MAS_EN(sc->sc_funcid))
					sc->sc_flags |= WM_F_MAS;
			}
		}
	}

	/*
	 * XXX need special handling for some multiple port cards
	 * to disable a paticular port.
	 */

	if (sc->sc_type >= WM_T_82544) {
		pn = prop_dictionary_get(dict, "i82543-swdpin");
		if (pn != NULL) {
			KASSERT(prop_object_type(pn) == PROP_TYPE_NUMBER);
			swdpin = (uint16_t) prop_number_signed_value(pn);
		} else {
			if (wm_nvm_read(sc, NVM_OFF_SWDPIN, 1, &swdpin)) {
				aprint_error_dev(sc->sc_dev,
				    "unable to read SWDPIN\n");
				goto out;
			}
		}
	}

	if (cfg1 & NVM_CFG1_ILOS)
		sc->sc_ctrl |= CTRL_ILOS;

	/*
	 * XXX
	 * This code isn't correct because pin 2 and 3 are located
	 * in different position on newer chips. Check all datasheet.
	 *
	 * Until resolve this problem, check if a chip < 82580
	 */
	if (sc->sc_type <= WM_T_82580) {
		if (sc->sc_type >= WM_T_82544) {
			sc->sc_ctrl |=
			    ((swdpin >> NVM_SWDPIN_SWDPIO_SHIFT) & 0xf) <<
			    CTRL_SWDPIO_SHIFT;
			sc->sc_ctrl |=
			    ((swdpin >> NVM_SWDPIN_SWDPIN_SHIFT) & 0xf) <<
			    CTRL_SWDPINS_SHIFT;
		} else {
			sc->sc_ctrl |=
			    ((cfg1 >> NVM_CFG1_SWDPIO_SHIFT) & 0xf) <<
			    CTRL_SWDPIO_SHIFT;
		}
	}

	if ((sc->sc_type >= WM_T_82580) && (sc->sc_type <= WM_T_I211)) {
		wm_nvm_read(sc,
		    NVM_OFF_LAN_FUNC_82580(sc->sc_funcid) + NVM_OFF_CFG3_PORTA,
		    1, &nvmword);
		if (nvmword & NVM_CFG3_ILOS)
			sc->sc_ctrl |= CTRL_ILOS;
	}

#if 0
	if (sc->sc_type >= WM_T_82544) {
		if (cfg1 & NVM_CFG1_IPS0)
			sc->sc_ctrl_ext |= CTRL_EXT_IPS;
		if (cfg1 & NVM_CFG1_IPS1)
			sc->sc_ctrl_ext |= CTRL_EXT_IPS1;
		sc->sc_ctrl_ext |=
		    ((swdpin >> (NVM_SWDPIN_SWDPIO_SHIFT + 4)) & 0xd) <<
		    CTRL_EXT_SWDPIO_SHIFT;
		sc->sc_ctrl_ext |=
		    ((swdpin >> (NVM_SWDPIN_SWDPIN_SHIFT + 4)) & 0xd) <<
		    CTRL_EXT_SWDPINS_SHIFT;
	} else {
		sc->sc_ctrl_ext |=
		    ((cfg2 >> NVM_CFG2_SWDPIO_SHIFT) & 0xf) <<
		    CTRL_EXT_SWDPIO_SHIFT;
	}
#endif

	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
#if 0
	CSR_WRITE(sc, WMREG_CTRL_EXT, sc->sc_ctrl_ext);
#endif

	if (sc->sc_type == WM_T_PCH) {
		uint16_t val;

		/* Save the NVM K1 bit setting */
		wm_nvm_read(sc, NVM_OFF_K1_CONFIG, 1, &val);

		if ((val & NVM_K1_CONFIG_ENABLE) != 0)
			sc->sc_nvm_k1_enabled = 1;
		else
			sc->sc_nvm_k1_enabled = 0;
	}

	/* Determine if we're GMII, TBI, SERDES or SGMII mode */
	if (sc->sc_type == WM_T_ICH8 || sc->sc_type == WM_T_ICH9
	    || sc->sc_type == WM_T_ICH10 || sc->sc_type == WM_T_PCH
	    || sc->sc_type == WM_T_PCH2 || sc->sc_type == WM_T_PCH_LPT
	    || sc->sc_type == WM_T_PCH_SPT || sc->sc_type == WM_T_PCH_CNP
	    || sc->sc_type == WM_T_PCH_TGP
	    || sc->sc_type == WM_T_82573
	    || sc->sc_type == WM_T_82574 || sc->sc_type == WM_T_82583) {
		/* Copper only */
	} else if ((sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)
	    || (sc->sc_type ==WM_T_82580) || (sc->sc_type ==WM_T_I350)
	    || (sc->sc_type ==WM_T_I354) || (sc->sc_type ==WM_T_I210)
	    || (sc->sc_type ==WM_T_I211)) {
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		link_mode = reg & CTRL_EXT_LINK_MODE_MASK;
		switch (link_mode) {
		case CTRL_EXT_LINK_MODE_1000KX:
			aprint_normal_dev(sc->sc_dev, "1000KX\n");
			sc->sc_mediatype = WM_MEDIATYPE_SERDES;
			break;
		case CTRL_EXT_LINK_MODE_SGMII:
			if (wm_sgmii_uses_mdio(sc)) {
				aprint_normal_dev(sc->sc_dev,
				    "SGMII(MDIO)\n");
				sc->sc_flags |= WM_F_SGMII;
				sc->sc_mediatype = WM_MEDIATYPE_COPPER;
				break;
			}
			aprint_verbose_dev(sc->sc_dev, "SGMII(I2C)\n");
			/*FALLTHROUGH*/
		case CTRL_EXT_LINK_MODE_PCIE_SERDES:
			sc->sc_mediatype = wm_sfp_get_media_type(sc);
			if (sc->sc_mediatype == WM_MEDIATYPE_UNKNOWN) {
				if (link_mode
				    == CTRL_EXT_LINK_MODE_SGMII) {
					sc->sc_mediatype = WM_MEDIATYPE_COPPER;
					sc->sc_flags |= WM_F_SGMII;
					aprint_verbose_dev(sc->sc_dev,
					    "SGMII\n");
				} else {
					sc->sc_mediatype = WM_MEDIATYPE_SERDES;
					aprint_verbose_dev(sc->sc_dev,
					    "SERDES\n");
				}
				break;
			}
			if (sc->sc_mediatype == WM_MEDIATYPE_SERDES)
				aprint_normal_dev(sc->sc_dev, "SERDES(SFP)\n");
			else if (sc->sc_mediatype == WM_MEDIATYPE_COPPER) {
				aprint_normal_dev(sc->sc_dev, "SGMII(SFP)\n");
				sc->sc_flags |= WM_F_SGMII;
			}
			/* Do not change link mode for 100BaseFX */
			if (sc->sc_sfptype == SFF_SFP_ETH_FLAGS_100FX)
				break;

			/* Change current link mode setting */
			reg &= ~CTRL_EXT_LINK_MODE_MASK;
			if (sc->sc_mediatype == WM_MEDIATYPE_COPPER)
				reg |= CTRL_EXT_LINK_MODE_SGMII;
			else
				reg |= CTRL_EXT_LINK_MODE_PCIE_SERDES;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
			break;
		case CTRL_EXT_LINK_MODE_GMII:
		default:
			aprint_normal_dev(sc->sc_dev, "Copper\n");
			sc->sc_mediatype = WM_MEDIATYPE_COPPER;
			break;
		}

		reg &= ~CTRL_EXT_I2C_ENA;
		if ((sc->sc_flags & WM_F_SGMII) != 0)
			reg |= CTRL_EXT_I2C_ENA;
		else
			reg &= ~CTRL_EXT_I2C_ENA;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
		if ((sc->sc_flags & WM_F_SGMII) != 0) {
			if (!wm_sgmii_uses_mdio(sc))
				wm_gmii_setup_phytype(sc, 0, 0);
			wm_reset_mdicnfg_82580(sc);
		}
	} else if (sc->sc_type < WM_T_82543 ||
	    (CSR_READ(sc, WMREG_STATUS) & STATUS_TBIMODE) != 0) {
		if (sc->sc_mediatype == WM_MEDIATYPE_COPPER) {
			aprint_error_dev(sc->sc_dev,
			    "WARNING: TBIMODE set on 1000BASE-T product!\n");
			sc->sc_mediatype = WM_MEDIATYPE_FIBER;
		}
	} else {
		if (sc->sc_mediatype == WM_MEDIATYPE_FIBER) {
			aprint_error_dev(sc->sc_dev,
			    "WARNING: TBIMODE clear on 1000BASE-X product!\n");
			sc->sc_mediatype = WM_MEDIATYPE_COPPER;
		}
	}

	if (sc->sc_type >= WM_T_PCH2)
		sc->sc_flags |= WM_F_EEE;
	else if ((sc->sc_type >= WM_T_I350) && (sc->sc_type <= WM_T_I211)
	    && (sc->sc_mediatype == WM_MEDIATYPE_COPPER)) {
		/* XXX: Need special handling for I354. (not yet) */
		if (sc->sc_type != WM_T_I354)
			sc->sc_flags |= WM_F_EEE;
	}

	/*
	 * The I350 has a bug where it always strips the CRC whether
	 * asked to or not. So ask for stripped CRC here and cope in rxeof
	 */
	if ((sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354)
	    || (sc->sc_type == WM_T_I210) || (sc->sc_type == WM_T_I211))
		sc->sc_flags |= WM_F_CRC_STRIP;

	/*
	 * Workaround for some chips to delay sending LINK_STATE_UP.
	 * Some systems can't send packet soon after linkup. See also
	 * wm_linkintr_gmii(), wm_tick() and wm_gmii_mediastatus().
	 */
	switch (sc->sc_type) {
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		if (sc->sc_mediatype == WM_MEDIATYPE_COPPER)
			sc->sc_flags |= WM_F_DELAY_LINKUP;
		break;
	default:
		break;
	}

	/* Set device properties (macflags) */
	prop_dictionary_set_uint32(dict, "macflags", sc->sc_flags);

	if (sc->sc_flags != 0) {
		snprintb(buf, sizeof(buf), WM_FLAGS, sc->sc_flags);
		aprint_verbose_dev(sc->sc_dev, "%s\n", buf);
	}

	sc->sc_core_lock = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);

	/* Initialize the media structures accordingly. */
	if (sc->sc_mediatype == WM_MEDIATYPE_COPPER)
		wm_gmii_mediainit(sc, wmp->wmp_product);
	else
		wm_tbi_mediainit(sc); /* All others */

	ifp = &sc->sc_ethercom.ec_if;
	xname = device_xname(sc->sc_dev);
	strlcpy(ifp->if_xname, xname, IFNAMSIZ);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_extflags = IFEF_MPSAFE;
	ifp->if_ioctl = wm_ioctl;
	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		ifp->if_start = wm_nq_start;
		/*
		 * When the number of CPUs is one and the controller can use
		 * MSI-X, wm(4) use MSI-X but *does not* use multiqueue.
		 * That is, wm(4) use two interrupts, one is used for Tx/Rx
		 * and the other is used for link status changing.
		 * In this situation, wm_nq_transmit() is disadvantageous
		 * because of wm_select_txqueue() and pcq(9) overhead.
		 */
		if (wm_is_using_multiqueue(sc))
			ifp->if_transmit = wm_nq_transmit;
	} else {
		ifp->if_start = wm_start;
		/*
		 * wm_transmit() has the same disadvantages as wm_nq_transmit()
		 * described above.
		 */
		if (wm_is_using_multiqueue(sc))
			ifp->if_transmit = wm_transmit;
	}
	/* wm(4) doest not use ifp->if_watchdog, use wm_tick as watchdog. */
	ifp->if_init = wm_init;
	ifp->if_stop = wm_stop;
	IFQ_SET_MAXLEN(&ifp->if_snd, uimax(WM_IFQUEUELEN, IFQ_MAXLEN));
	IFQ_SET_READY(&ifp->if_snd);

	/* Check for jumbo frame */
	switch (sc->sc_type) {
	case WM_T_82573:
		/* XXX limited to 9234 if ASPM is disabled */
		wm_nvm_read(sc, NVM_OFF_INIT_3GIO_3, 1, &nvmword);
		if ((nvmword & NVM_3GIO_3_ASPM_MASK) != 0)
			sc->sc_ethercom.ec_capabilities |= ETHERCAP_JUMBO_MTU;
		break;
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
	case WM_T_80003:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH2:	/* PCH2 supports 9K frame size */
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		/* XXX limited to 9234 */
		sc->sc_ethercom.ec_capabilities |= ETHERCAP_JUMBO_MTU;
		break;
	case WM_T_PCH:
		/* XXX limited to 4096 */
		sc->sc_ethercom.ec_capabilities |= ETHERCAP_JUMBO_MTU;
		break;
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_ICH8:
		/* No support for jumbo frame */
		break;
	default:
		/* ETHER_MAX_LEN_JUMBO */
		sc->sc_ethercom.ec_capabilities |= ETHERCAP_JUMBO_MTU;
		break;
	}

	/* If we're a i82543 or greater, we can support VLANs. */
	if (sc->sc_type >= WM_T_82543) {
		sc->sc_ethercom.ec_capabilities |=
		    ETHERCAP_VLAN_MTU | ETHERCAP_VLAN_HWTAGGING;
		sc->sc_ethercom.ec_capenable |= ETHERCAP_VLAN_HWTAGGING;
	}

	if ((sc->sc_flags & WM_F_EEE) != 0)
		sc->sc_ethercom.ec_capabilities |= ETHERCAP_EEE;

	/*
	 * We can perform TCPv4 and UDPv4 checksums in-bound.  Only
	 * on i82543 and later.
	 */
	if (sc->sc_type >= WM_T_82543) {
		ifp->if_capabilities |=
		    IFCAP_CSUM_IPv4_Tx | IFCAP_CSUM_IPv4_Rx |
		    IFCAP_CSUM_TCPv4_Tx | IFCAP_CSUM_TCPv4_Rx |
		    IFCAP_CSUM_UDPv4_Tx | IFCAP_CSUM_UDPv4_Rx |
		    IFCAP_CSUM_TCPv6_Tx |
		    IFCAP_CSUM_UDPv6_Tx;
	}

	/*
	 * XXXyamt: i'm not sure which chips support RXCSUM_IPV6OFL.
	 *
	 *	82541GI (8086:1076) ... no
	 *	82572EI (8086:10b9) ... yes
	 */
	if (sc->sc_type >= WM_T_82571) {
		ifp->if_capabilities |=
		    IFCAP_CSUM_TCPv6_Rx | IFCAP_CSUM_UDPv6_Rx;
	}

	/*
	 * If we're a i82544 or greater (except i82547), we can do
	 * TCP segmentation offload.
	 */
	if (sc->sc_type >= WM_T_82544 && sc->sc_type != WM_T_82547)
		ifp->if_capabilities |= IFCAP_TSOv4;

	if (sc->sc_type >= WM_T_82571)
		ifp->if_capabilities |= IFCAP_TSOv6;

	sc->sc_tx_process_limit = WM_TX_PROCESS_LIMIT_DEFAULT;
	sc->sc_tx_intr_process_limit = WM_TX_INTR_PROCESS_LIMIT_DEFAULT;
	sc->sc_rx_process_limit = WM_RX_PROCESS_LIMIT_DEFAULT;
	sc->sc_rx_intr_process_limit = WM_RX_INTR_PROCESS_LIMIT_DEFAULT;

	/* Attach the interface. */
	if_initialize(ifp);
	sc->sc_ipq = if_percpuq_create(&sc->sc_ethercom.ec_if);
	ether_ifattach(ifp, enaddr);
	ether_set_ifflags_cb(&sc->sc_ethercom, wm_ifflags_cb);
	if_register(ifp);
	rnd_attach_source(&sc->rnd_source, xname, RND_TYPE_NET,
	    RND_FLAG_DEFAULT);

#ifdef WM_EVENT_COUNTERS
	/* Attach event counters. */
	evcnt_attach_dynamic(&sc->sc_ev_linkintr, EVCNT_TYPE_INTR,
	    NULL, xname, "linkintr");

	evcnt_attach_dynamic(&sc->sc_ev_crcerrs, EVCNT_TYPE_MISC,
	    NULL, xname, "CRC Error");
	evcnt_attach_dynamic(&sc->sc_ev_symerrc, EVCNT_TYPE_MISC,
	    NULL, xname, "Symbol Error");
	evcnt_attach_dynamic(&sc->sc_ev_mpc, EVCNT_TYPE_MISC,
	    NULL, xname, "Missed Packets");
	evcnt_attach_dynamic(&sc->sc_ev_colc, EVCNT_TYPE_MISC,
	    NULL, xname, "Collision");
	evcnt_attach_dynamic(&sc->sc_ev_sec, EVCNT_TYPE_MISC,
	    NULL, xname, "Sequence Error");
	evcnt_attach_dynamic(&sc->sc_ev_rlec, EVCNT_TYPE_MISC,
	    NULL, xname, "Receive Length Error");

	if (sc->sc_type >= WM_T_82543) {
		evcnt_attach_dynamic(&sc->sc_ev_algnerrc, EVCNT_TYPE_MISC,
		    NULL, xname, "Alignment Error");
		evcnt_attach_dynamic(&sc->sc_ev_rxerrc, EVCNT_TYPE_MISC,
		    NULL, xname, "Receive Error");
		/* XXX Does 82575 have HTDPMC? */
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			evcnt_attach_dynamic(&sc->sc_ev_cexterr,
			    EVCNT_TYPE_MISC, NULL, xname,
			    "Carrier Extension Error");
		else
			evcnt_attach_dynamic(&sc->sc_ev_htdpmc,
			    EVCNT_TYPE_MISC, NULL, xname,
			    "Host Transmit Discarded Packets by MAC");

		evcnt_attach_dynamic(&sc->sc_ev_tncrs, EVCNT_TYPE_MISC,
		    NULL, xname, "Tx with No CRS");
		evcnt_attach_dynamic(&sc->sc_ev_tsctc, EVCNT_TYPE_MISC,
		    NULL, xname, "TCP Segmentation Context Tx");
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			evcnt_attach_dynamic(&sc->sc_ev_tsctfc,
			    EVCNT_TYPE_MISC, NULL, xname,
			    "TCP Segmentation Context Tx Fail");
		else {
			/* XXX Is the circuit breaker only for 82576? */
			evcnt_attach_dynamic(&sc->sc_ev_cbrdpc,
			    EVCNT_TYPE_MISC, NULL, xname,
			    "Circuit Breaker Rx Dropped Packet");
			evcnt_attach_dynamic(&sc->sc_ev_cbrmpc,
			    EVCNT_TYPE_MISC, NULL, xname,
			    "Circuit Breaker Rx Manageability Packet");
		}
	}

	if (sc->sc_type >= WM_T_82542_2_1) {
		evcnt_attach_dynamic(&sc->sc_ev_tx_xoff, EVCNT_TYPE_MISC,
		    NULL, xname, "XOFF Transmitted");
		evcnt_attach_dynamic(&sc->sc_ev_tx_xon, EVCNT_TYPE_MISC,
		    NULL, xname, "XON Transmitted");
		evcnt_attach_dynamic(&sc->sc_ev_rx_xoff, EVCNT_TYPE_MISC,
		    NULL, xname, "XOFF Received");
		evcnt_attach_dynamic(&sc->sc_ev_rx_xon, EVCNT_TYPE_MISC,
		    NULL, xname, "XON Received");
		evcnt_attach_dynamic(&sc->sc_ev_rx_macctl, EVCNT_TYPE_MISC,
		    NULL, xname, "FC Received Unsupported");
	}

	evcnt_attach_dynamic(&sc->sc_ev_scc, EVCNT_TYPE_MISC,
	    NULL, xname, "Single Collision");
	evcnt_attach_dynamic(&sc->sc_ev_ecol, EVCNT_TYPE_MISC,
	    NULL, xname, "Excessive Collisions");
	evcnt_attach_dynamic(&sc->sc_ev_mcc, EVCNT_TYPE_MISC,
	    NULL, xname, "Multiple Collision");
	evcnt_attach_dynamic(&sc->sc_ev_latecol, EVCNT_TYPE_MISC,
	    NULL, xname, "Late Collisions");

	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc))
		evcnt_attach_dynamic(&sc->sc_ev_cbtmpc, EVCNT_TYPE_MISC,
		    NULL, xname, "Circuit Breaker Tx Manageability Packet");

	evcnt_attach_dynamic(&sc->sc_ev_dc, EVCNT_TYPE_MISC,
	    NULL, xname, "Defer");
	evcnt_attach_dynamic(&sc->sc_ev_prc64, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (64 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_prc127, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (65-127 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_prc255, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (128-255 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_prc511, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (256-511 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_prc1023, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (512-1023 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_prc1522, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Rx (1024-1522 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_gprc, EVCNT_TYPE_MISC,
	    NULL, xname, "Good Packets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_bprc, EVCNT_TYPE_MISC,
	    NULL, xname, "Broadcast Packets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_mprc, EVCNT_TYPE_MISC,
	    NULL, xname, "Multicast Packets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_gptc, EVCNT_TYPE_MISC,
	    NULL, xname, "Good Packets Tx");
	evcnt_attach_dynamic(&sc->sc_ev_gorc, EVCNT_TYPE_MISC,
	    NULL, xname, "Good Octets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_gotc, EVCNT_TYPE_MISC,
	    NULL, xname, "Good Octets Tx");
	evcnt_attach_dynamic(&sc->sc_ev_rnbc, EVCNT_TYPE_MISC,
	    NULL, xname, "Rx No Buffers");
	evcnt_attach_dynamic(&sc->sc_ev_ruc, EVCNT_TYPE_MISC,
	    NULL, xname, "Rx Undersize (valid CRC)");
	evcnt_attach_dynamic(&sc->sc_ev_rfc, EVCNT_TYPE_MISC,
	    NULL, xname, "Rx Fragment (bad CRC)");
	evcnt_attach_dynamic(&sc->sc_ev_roc, EVCNT_TYPE_MISC,
	    NULL, xname, "Rx Oversize (valid CRC)");
	evcnt_attach_dynamic(&sc->sc_ev_rjc, EVCNT_TYPE_MISC,
	    NULL, xname, "Rx Jabber (bad CRC)");
	if (sc->sc_type >= WM_T_82540) {
		evcnt_attach_dynamic(&sc->sc_ev_mgtprc, EVCNT_TYPE_MISC,
		    NULL, xname, "Management Packets RX");
		evcnt_attach_dynamic(&sc->sc_ev_mgtpdc, EVCNT_TYPE_MISC,
		    NULL, xname, "Management Packets Dropped");
		evcnt_attach_dynamic(&sc->sc_ev_mgtptc, EVCNT_TYPE_MISC,
		    NULL, xname, "Management Packets TX");
	}
	evcnt_attach_dynamic(&sc->sc_ev_tor, EVCNT_TYPE_MISC,
	    NULL, xname, "Total Octets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_tot, EVCNT_TYPE_MISC,
	    NULL, xname, "Total Octets Tx");
	evcnt_attach_dynamic(&sc->sc_ev_tpr, EVCNT_TYPE_MISC,
	    NULL, xname, "Total Packets Rx");
	evcnt_attach_dynamic(&sc->sc_ev_tpt, EVCNT_TYPE_MISC,
	    NULL, xname, "Total Packets Tx");
	evcnt_attach_dynamic(&sc->sc_ev_ptc64, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (64 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_ptc127, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (65-127 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_ptc255, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (128-255 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_ptc511, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (256-511 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_ptc1023, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (512-1023 bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_ptc1522, EVCNT_TYPE_MISC,
	    NULL, xname, "Packets Tx (1024-1522 Bytes)");
	evcnt_attach_dynamic(&sc->sc_ev_mptc, EVCNT_TYPE_MISC,
	    NULL, xname, "Multicast Packets Tx");
	evcnt_attach_dynamic(&sc->sc_ev_bptc, EVCNT_TYPE_MISC,
	    NULL, xname, "Broadcast Packets Tx");
	if (sc->sc_type >= WM_T_82571) /* PCIe, 80003 and ICH/PCHs */
		evcnt_attach_dynamic(&sc->sc_ev_iac, EVCNT_TYPE_MISC,
		    NULL, xname, "Interrupt Assertion");
	if (sc->sc_type < WM_T_82575) {
		evcnt_attach_dynamic(&sc->sc_ev_icrxptc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Rx Pkt Timer Expire");
		evcnt_attach_dynamic(&sc->sc_ev_icrxatc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Rx Abs Timer Expire");
		evcnt_attach_dynamic(&sc->sc_ev_ictxptc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Tx Pkt Timer Expire");
		evcnt_attach_dynamic(&sc->sc_ev_ictxatc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Tx Abs Timer Expire");
		evcnt_attach_dynamic(&sc->sc_ev_ictxqec, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Tx Queue Empty");
		evcnt_attach_dynamic(&sc->sc_ev_ictxqmtc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Tx Queue Min Thresh");
		evcnt_attach_dynamic(&sc->sc_ev_rxdmtc, EVCNT_TYPE_MISC,
		    NULL, xname, "Intr. Cause Rx Desc Min Thresh");

		/* XXX 82575 document says it has ICRXOC. Is that right? */
		evcnt_attach_dynamic(&sc->sc_ev_icrxoc, EVCNT_TYPE_MISC,
		    NULL, xname, "Interrupt Cause Receiver Overrun");
	} else if (!WM_IS_ICHPCH(sc)) {
		/*
		 * For 82575 and newer.
		 *
		 * On 80003, ICHs and PCHs, it seems all of the following
		 * registers are zero.
		 */
		evcnt_attach_dynamic(&sc->sc_ev_rpthc, EVCNT_TYPE_MISC,
		    NULL, xname, "Rx Packets To Host");
		evcnt_attach_dynamic(&sc->sc_ev_debug1, EVCNT_TYPE_MISC,
		    NULL, xname, "Debug Counter 1");
		evcnt_attach_dynamic(&sc->sc_ev_debug2, EVCNT_TYPE_MISC,
		    NULL, xname, "Debug Counter 2");
		evcnt_attach_dynamic(&sc->sc_ev_debug3, EVCNT_TYPE_MISC,
		    NULL, xname, "Debug Counter 3");

		/*
		 * 82575 datasheet says 0x4118 is for TXQEC(Tx Queue Empty).
		 * I think it's wrong. The real count I observed is the same
		 * as GPTC(Good Packets Tx) and TPT(Total Packets Tx).
		 * It's HGPTC(Host Good Packets Tx) which is described in
		 * 82576's datasheet.
		 */
		evcnt_attach_dynamic(&sc->sc_ev_hgptc, EVCNT_TYPE_MISC,
		    NULL, xname, "Host Good Packets TX");

		evcnt_attach_dynamic(&sc->sc_ev_debug4, EVCNT_TYPE_MISC,
		    NULL, xname, "Debug Counter 4");
		evcnt_attach_dynamic(&sc->sc_ev_rxdmtc, EVCNT_TYPE_MISC,
		    NULL, xname, "Rx Desc Min Thresh");
		/* XXX Is the circuit breaker only for 82576? */
		evcnt_attach_dynamic(&sc->sc_ev_htcbdpc, EVCNT_TYPE_MISC,
		    NULL, xname, "Host Tx Circuit Breaker Dropped Packets");

		evcnt_attach_dynamic(&sc->sc_ev_hgorc, EVCNT_TYPE_MISC,
		    NULL, xname, "Host Good Octets Rx");
		evcnt_attach_dynamic(&sc->sc_ev_hgotc, EVCNT_TYPE_MISC,
		    NULL, xname, "Host Good Octets Tx");
		evcnt_attach_dynamic(&sc->sc_ev_lenerrs, EVCNT_TYPE_MISC,
		    NULL, xname, "Length Errors (length/type <= 1500)");
		evcnt_attach_dynamic(&sc->sc_ev_scvpc, EVCNT_TYPE_MISC,
		    NULL, xname, "SerDes/SGMII Code Violation Packet");
		evcnt_attach_dynamic(&sc->sc_ev_hrmpc, EVCNT_TYPE_MISC,
		    NULL, xname, "Header Redirection Missed Packet");
	}
	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc)) {
		evcnt_attach_dynamic(&sc->sc_ev_tlpic, EVCNT_TYPE_MISC,
		    NULL, xname, "EEE Tx LPI");
		evcnt_attach_dynamic(&sc->sc_ev_rlpic, EVCNT_TYPE_MISC,
		    NULL, xname, "EEE Rx LPI");
		evcnt_attach_dynamic(&sc->sc_ev_b2ogprc, EVCNT_TYPE_MISC,
		    NULL, xname, "BMC2OS Packets received by host");
		evcnt_attach_dynamic(&sc->sc_ev_o2bspc, EVCNT_TYPE_MISC,
		    NULL, xname, "OS2BMC Packets transmitted by host");
		evcnt_attach_dynamic(&sc->sc_ev_b2ospc, EVCNT_TYPE_MISC,
		    NULL, xname, "BMC2OS Packets sent by BMC");
		evcnt_attach_dynamic(&sc->sc_ev_o2bgptc, EVCNT_TYPE_MISC,
		    NULL, xname, "OS2BMC Packets received by BMC");
	}
#endif /* WM_EVENT_COUNTERS */

	sc->sc_txrx_use_workqueue = false;

	if (wm_phy_need_linkdown_discard(sc)) {
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: %s: Set linkdown discard flag\n",
			device_xname(sc->sc_dev), __func__));
		wm_set_linkdown_discard(sc);
	}

	wm_init_sysctls(sc);

	if (pmf_device_register(self, wm_suspend, wm_resume))
		pmf_class_network_register(self, ifp);
	else
		aprint_error_dev(self, "couldn't establish power handler\n");

	sc->sc_flags |= WM_F_ATTACHED;
out:
	return;
}

/* The detach function (ca_detach) */
static int
wm_detach(device_t self, int flags __unused)
{
	struct wm_softc *sc = device_private(self);
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int i;

	if ((sc->sc_flags & WM_F_ATTACHED) == 0)
		return 0;

	/* Stop the interface. Callouts are stopped in it. */
	IFNET_LOCK(ifp);
	sc->sc_dying = true;
	wm_stop(ifp, 1);
	IFNET_UNLOCK(ifp);

	pmf_device_deregister(self);

	sysctl_teardown(&sc->sc_sysctllog);

#ifdef WM_EVENT_COUNTERS
	evcnt_detach(&sc->sc_ev_linkintr);

	evcnt_detach(&sc->sc_ev_crcerrs);
	evcnt_detach(&sc->sc_ev_symerrc);
	evcnt_detach(&sc->sc_ev_mpc);
	evcnt_detach(&sc->sc_ev_colc);
	evcnt_detach(&sc->sc_ev_sec);
	evcnt_detach(&sc->sc_ev_rlec);

	if (sc->sc_type >= WM_T_82543) {
		evcnt_detach(&sc->sc_ev_algnerrc);
		evcnt_detach(&sc->sc_ev_rxerrc);
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			evcnt_detach(&sc->sc_ev_cexterr);
		else
			evcnt_detach(&sc->sc_ev_htdpmc);

		evcnt_detach(&sc->sc_ev_tncrs);
		evcnt_detach(&sc->sc_ev_tsctc);
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			evcnt_detach(&sc->sc_ev_tsctfc);
		else {
			evcnt_detach(&sc->sc_ev_cbrdpc);
			evcnt_detach(&sc->sc_ev_cbrmpc);
		}
	}

	if (sc->sc_type >= WM_T_82542_2_1) {
		evcnt_detach(&sc->sc_ev_tx_xoff);
		evcnt_detach(&sc->sc_ev_tx_xon);
		evcnt_detach(&sc->sc_ev_rx_xoff);
		evcnt_detach(&sc->sc_ev_rx_xon);
		evcnt_detach(&sc->sc_ev_rx_macctl);
	}

	evcnt_detach(&sc->sc_ev_scc);
	evcnt_detach(&sc->sc_ev_ecol);
	evcnt_detach(&sc->sc_ev_mcc);
	evcnt_detach(&sc->sc_ev_latecol);

	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc))
		evcnt_detach(&sc->sc_ev_cbtmpc);

	evcnt_detach(&sc->sc_ev_dc);
	evcnt_detach(&sc->sc_ev_prc64);
	evcnt_detach(&sc->sc_ev_prc127);
	evcnt_detach(&sc->sc_ev_prc255);
	evcnt_detach(&sc->sc_ev_prc511);
	evcnt_detach(&sc->sc_ev_prc1023);
	evcnt_detach(&sc->sc_ev_prc1522);
	evcnt_detach(&sc->sc_ev_gprc);
	evcnt_detach(&sc->sc_ev_bprc);
	evcnt_detach(&sc->sc_ev_mprc);
	evcnt_detach(&sc->sc_ev_gptc);
	evcnt_detach(&sc->sc_ev_gorc);
	evcnt_detach(&sc->sc_ev_gotc);
	evcnt_detach(&sc->sc_ev_rnbc);
	evcnt_detach(&sc->sc_ev_ruc);
	evcnt_detach(&sc->sc_ev_rfc);
	evcnt_detach(&sc->sc_ev_roc);
	evcnt_detach(&sc->sc_ev_rjc);
	if (sc->sc_type >= WM_T_82540) {
		evcnt_detach(&sc->sc_ev_mgtprc);
		evcnt_detach(&sc->sc_ev_mgtpdc);
		evcnt_detach(&sc->sc_ev_mgtptc);
	}
	evcnt_detach(&sc->sc_ev_tor);
	evcnt_detach(&sc->sc_ev_tot);
	evcnt_detach(&sc->sc_ev_tpr);
	evcnt_detach(&sc->sc_ev_tpt);
	evcnt_detach(&sc->sc_ev_ptc64);
	evcnt_detach(&sc->sc_ev_ptc127);
	evcnt_detach(&sc->sc_ev_ptc255);
	evcnt_detach(&sc->sc_ev_ptc511);
	evcnt_detach(&sc->sc_ev_ptc1023);
	evcnt_detach(&sc->sc_ev_ptc1522);
	evcnt_detach(&sc->sc_ev_mptc);
	evcnt_detach(&sc->sc_ev_bptc);
	if (sc->sc_type >= WM_T_82571)
		evcnt_detach(&sc->sc_ev_iac);
	if (sc->sc_type < WM_T_82575) {
		evcnt_detach(&sc->sc_ev_icrxptc);
		evcnt_detach(&sc->sc_ev_icrxatc);
		evcnt_detach(&sc->sc_ev_ictxptc);
		evcnt_detach(&sc->sc_ev_ictxatc);
		evcnt_detach(&sc->sc_ev_ictxqec);
		evcnt_detach(&sc->sc_ev_ictxqmtc);
		evcnt_detach(&sc->sc_ev_rxdmtc);
		evcnt_detach(&sc->sc_ev_icrxoc);
	} else if (!WM_IS_ICHPCH(sc)) {
		evcnt_detach(&sc->sc_ev_rpthc);
		evcnt_detach(&sc->sc_ev_debug1);
		evcnt_detach(&sc->sc_ev_debug2);
		evcnt_detach(&sc->sc_ev_debug3);
		evcnt_detach(&sc->sc_ev_hgptc);
		evcnt_detach(&sc->sc_ev_debug4);
		evcnt_detach(&sc->sc_ev_rxdmtc);
		evcnt_detach(&sc->sc_ev_htcbdpc);

		evcnt_detach(&sc->sc_ev_hgorc);
		evcnt_detach(&sc->sc_ev_hgotc);
		evcnt_detach(&sc->sc_ev_lenerrs);
		evcnt_detach(&sc->sc_ev_scvpc);
		evcnt_detach(&sc->sc_ev_hrmpc);
	}
	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc)) {
		evcnt_detach(&sc->sc_ev_tlpic);
		evcnt_detach(&sc->sc_ev_rlpic);
		evcnt_detach(&sc->sc_ev_b2ogprc);
		evcnt_detach(&sc->sc_ev_o2bspc);
		evcnt_detach(&sc->sc_ev_b2ospc);
		evcnt_detach(&sc->sc_ev_o2bgptc);
	}
#endif /* WM_EVENT_COUNTERS */

	rnd_detach_source(&sc->rnd_source);

	/* Tell the firmware about the release */
	mutex_enter(sc->sc_core_lock);
	wm_release_manageability(sc);
	wm_release_hw_control(sc);
	wm_enable_wakeup(sc);
	mutex_exit(sc->sc_core_lock);

	mii_detach(&sc->sc_mii, MII_PHY_ANY, MII_OFFSET_ANY);

	ether_ifdetach(ifp);
	if_detach(ifp);
	if_percpuq_destroy(sc->sc_ipq);

	/* Delete all remaining media. */
	ifmedia_fini(&sc->sc_mii.mii_media);

	/* Unload RX dmamaps and free mbufs */
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
		mutex_enter(rxq->rxq_lock);
		wm_rxdrain(rxq);
		mutex_exit(rxq->rxq_lock);
	}
	/* Must unlock here */

	/* Disestablish the interrupt handler */
	for (i = 0; i < sc->sc_nintrs; i++) {
		if (sc->sc_ihs[i] != NULL) {
			pci_intr_disestablish(sc->sc_pc, sc->sc_ihs[i]);
			sc->sc_ihs[i] = NULL;
		}
	}
	pci_intr_release(sc->sc_pc, sc->sc_intrs, sc->sc_nintrs);

	/* wm_stop() ensured that the workqueues are stopped. */
	workqueue_destroy(sc->sc_queue_wq);
	workqueue_destroy(sc->sc_reset_wq);

	for (i = 0; i < sc->sc_nqueues; i++)
		softint_disestablish(sc->sc_queue[i].wmq_si);

	wm_free_txrx_queues(sc);

	/* Unmap the registers */
	if (sc->sc_ss) {
		bus_space_unmap(sc->sc_st, sc->sc_sh, sc->sc_ss);
		sc->sc_ss = 0;
	}
	if (sc->sc_ios) {
		bus_space_unmap(sc->sc_iot, sc->sc_ioh, sc->sc_ios);
		sc->sc_ios = 0;
	}
	if (sc->sc_flashs) {
		bus_space_unmap(sc->sc_flasht, sc->sc_flashh, sc->sc_flashs);
		sc->sc_flashs = 0;
	}

	if (sc->sc_core_lock)
		mutex_obj_free(sc->sc_core_lock);
	if (sc->sc_ich_phymtx)
		mutex_obj_free(sc->sc_ich_phymtx);
	if (sc->sc_ich_nvmmtx)
		mutex_obj_free(sc->sc_ich_nvmmtx);

	return 0;
}

static bool
wm_suspend(device_t self, const pmf_qual_t *qual)
{
	struct wm_softc *sc = device_private(self);

	wm_release_manageability(sc);
	wm_release_hw_control(sc);
	wm_enable_wakeup(sc);

	return true;
}

static bool
wm_resume(device_t self, const pmf_qual_t *qual)
{
	struct wm_softc *sc = device_private(self);
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	pcireg_t reg;
	char buf[256];

	reg = CSR_READ(sc, WMREG_WUS);
	if (reg != 0) {
		snprintb(buf, sizeof(buf), WUS_FLAGS, reg);
		device_printf(sc->sc_dev, "wakeup status %s\n", buf);
		CSR_WRITE(sc, WMREG_WUS, 0xffffffff); /* W1C */
	}

	if (sc->sc_type >= WM_T_PCH2)
		wm_resume_workarounds_pchlan(sc);
	IFNET_LOCK(ifp);
	if ((ifp->if_flags & IFF_UP) == 0) {
		/* >= PCH_SPT hardware workaround before reset. */
		if (sc->sc_type >= WM_T_PCH_SPT)
			wm_flush_desc_rings(sc);

		wm_reset(sc);
		/* Non-AMT based hardware can now take control from firmware */
		if ((sc->sc_flags & WM_F_HAS_AMT) == 0)
			wm_get_hw_control(sc);
		wm_init_manageability(sc);
	} else {
		/*
		 * We called pmf_class_network_register(), so if_init() is
		 * automatically called when IFF_UP. wm_reset(),
		 * wm_get_hw_control() and wm_init_manageability() are called
		 * via wm_init().
		 */
	}
	IFNET_UNLOCK(ifp);

	return true;
}

/*
 * wm_watchdog:
 *
 *	Watchdog checker.
 */
static bool
wm_watchdog(struct ifnet *ifp)
{
	int qid;
	struct wm_softc *sc = ifp->if_softc;
	uint16_t hang_queue = 0; /* Max queue number of wm(4) is 82576's 16. */

	for (qid = 0; qid < sc->sc_nqueues; qid++) {
		struct wm_txqueue *txq = &sc->sc_queue[qid].wmq_txq;

		wm_watchdog_txq(ifp, txq, &hang_queue);
	}

#ifdef WM_DEBUG
	if (sc->sc_trigger_reset) {
		/* debug operation, no need for atomicity or reliability */
		sc->sc_trigger_reset = 0;
		hang_queue++;
	}
#endif

	if (hang_queue == 0)
		return true;

	if (atomic_swap_uint(&sc->sc_reset_pending, 1) == 0)
		workqueue_enqueue(sc->sc_reset_wq, &sc->sc_reset_work, NULL);

	return false;
}

/*
 * Perform an interface watchdog reset.
 */
static void
wm_handle_reset_work(struct work *work, void *arg)
{
	struct wm_softc * const sc = arg;
	struct ifnet * const ifp = &sc->sc_ethercom.ec_if;

	/* Don't want ioctl operations to happen */
	IFNET_LOCK(ifp);

	/* reset the interface. */
	wm_init(ifp);

	IFNET_UNLOCK(ifp);

	/*
	 * There are still some upper layer processing which call
	 * ifp->if_start(). e.g. ALTQ or one CPU system
	 */
	/* Try to get more packets going. */
	ifp->if_start(ifp);

	atomic_store_relaxed(&sc->sc_reset_pending, 0);
}


static void
wm_watchdog_txq(struct ifnet *ifp, struct wm_txqueue *txq, uint16_t *hang)
{

	mutex_enter(txq->txq_lock);
	if (txq->txq_sending &&
	    time_uptime - txq->txq_lastsent > wm_watchdog_timeout)
		wm_watchdog_txq_locked(ifp, txq, hang);

	mutex_exit(txq->txq_lock);
}

static void
wm_watchdog_txq_locked(struct ifnet *ifp, struct wm_txqueue *txq,
    uint16_t *hang)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_queue *wmq = container_of(txq, struct wm_queue, wmq_txq);

	KASSERT(mutex_owned(txq->txq_lock));

	/*
	 * Since we're using delayed interrupts, sweep up
	 * before we report an error.
	 */
	wm_txeof(txq, UINT_MAX);

	if (txq->txq_sending)
		*hang |= __BIT(wmq->wmq_id);

	if (txq->txq_free == WM_NTXDESC(txq)) {
		log(LOG_ERR, "%s: device timeout (lost interrupt)\n",
		    device_xname(sc->sc_dev));
	} else {
#ifdef WM_DEBUG
		int i, j;
		struct wm_txsoft *txs;
#endif
		log(LOG_ERR,
		    "%s: device timeout (txfree %d txsfree %d txnext %d)\n",
		    device_xname(sc->sc_dev), txq->txq_free, txq->txq_sfree,
		    txq->txq_next);
		if_statinc(ifp, if_oerrors);
#ifdef WM_DEBUG
		for (i = txq->txq_sdirty; i != txq->txq_snext;
		     i = WM_NEXTTXS(txq, i)) {
			txs = &txq->txq_soft[i];
			printf("txs %d tx %d -> %d\n",
			    i, txs->txs_firstdesc, txs->txs_lastdesc);
			for (j = txs->txs_firstdesc; ; j = WM_NEXTTX(txq, j)) {
				if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
					printf("\tdesc %d: 0x%" PRIx64 "\n", j,
					    txq->txq_nq_descs[j].nqtx_data.nqtxd_addr);
					printf("\t %#08x%08x\n",
					    txq->txq_nq_descs[j].nqtx_data.nqtxd_fields,
					    txq->txq_nq_descs[j].nqtx_data.nqtxd_cmdlen);
				} else {
					printf("\tdesc %d: 0x%" PRIx64 "\n", j,
					    (uint64_t)txq->txq_descs[j].wtx_addr.wa_high << 32 |
					    txq->txq_descs[j].wtx_addr.wa_low);
					printf("\t %#04x%02x%02x%08x\n",
					    txq->txq_descs[j].wtx_fields.wtxu_vlan,
					    txq->txq_descs[j].wtx_fields.wtxu_options,
					    txq->txq_descs[j].wtx_fields.wtxu_status,
					    txq->txq_descs[j].wtx_cmdlen);
				}
				if (j == txs->txs_lastdesc)
					break;
			}
		}
#endif
	}
}

/*
 * wm_tick:
 *
 *	One second timer, used to check link status, sweep up
 *	completed transmit jobs, etc.
 */
static void
wm_tick(void *arg)
{
	struct wm_softc *sc = arg;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;

	mutex_enter(sc->sc_core_lock);

	if (sc->sc_core_stopping) {
		mutex_exit(sc->sc_core_lock);
		return;
	}

	wm_update_stats(sc);

	if (sc->sc_flags & WM_F_HAS_MII) {
		bool dotick = true;

		/*
		 * Workaround for some chips to delay sending LINK_STATE_UP.
		 * See also wm_linkintr_gmii() and wm_gmii_mediastatus().
		 */
		if ((sc->sc_flags & WM_F_DELAY_LINKUP) != 0) {
			struct timeval now;

			getmicrotime(&now);
			if (timercmp(&now, &sc->sc_linkup_delay_time, <))
				dotick = false;
			else if (sc->sc_linkup_delay_time.tv_sec != 0) {
				/* Simplify by checking tv_sec only. */

				sc->sc_linkup_delay_time.tv_sec = 0;
				sc->sc_linkup_delay_time.tv_usec = 0;
			}
		}
		if (dotick)
			mii_tick(&sc->sc_mii);
	} else if ((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211)
	    && (sc->sc_mediatype == WM_MEDIATYPE_SERDES))
		wm_serdes_tick(sc);
	else
		wm_tbi_tick(sc);

	mutex_exit(sc->sc_core_lock);

	if (wm_watchdog(ifp))
		callout_schedule(&sc->sc_tick_ch, hz);
}

static int
wm_ifflags_cb(struct ethercom *ec)
{
	struct ifnet *ifp = &ec->ec_if;
	struct wm_softc *sc = ifp->if_softc;
	u_short iffchange;
	int ecchange;
	bool needreset = false;
	int rc = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	KASSERT(IFNET_LOCKED(ifp));

	mutex_enter(sc->sc_core_lock);

	/*
	 * Check for if_flags.
	 * Main usage is to prevent linkdown when opening bpf.
	 */
	iffchange = ifp->if_flags ^ sc->sc_if_flags;
	sc->sc_if_flags = ifp->if_flags;
	if ((iffchange & ~(IFF_CANTCHANGE | IFF_DEBUG)) != 0) {
		needreset = true;
		goto ec;
	}

	/* iff related updates */
	if ((iffchange & IFF_PROMISC) != 0)
		wm_set_filter(sc);

	wm_set_vlan(sc);

ec:
	/* Check for ec_capenable. */
	ecchange = ec->ec_capenable ^ sc->sc_ec_capenable;
	sc->sc_ec_capenable = ec->ec_capenable;
	if ((ecchange & ~ETHERCAP_EEE) != 0) {
		needreset = true;
		goto out;
	}

	/* ec related updates */
	wm_set_eee(sc);

out:
	if (needreset)
		rc = ENETRESET;
	mutex_exit(sc->sc_core_lock);

	return rc;
}

static bool
wm_phy_need_linkdown_discard(struct wm_softc *sc)
{

	switch (sc->sc_phytype) {
	case WMPHY_82577: /* ihphy */
	case WMPHY_82578: /* atphy */
	case WMPHY_82579: /* ihphy */
	case WMPHY_I217: /* ihphy */
	case WMPHY_82580: /* ihphy */
	case WMPHY_I350: /* ihphy */
		return true;
	default:
		return false;
	}
}

static void
wm_set_linkdown_discard(struct wm_softc *sc)
{

	for (int i = 0; i < sc->sc_nqueues; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;

		mutex_enter(txq->txq_lock);
		txq->txq_flags |= WM_TXQ_LINKDOWN_DISCARD;
		mutex_exit(txq->txq_lock);
	}
}

static void
wm_clear_linkdown_discard(struct wm_softc *sc)
{

	for (int i = 0; i < sc->sc_nqueues; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;

		mutex_enter(txq->txq_lock);
		txq->txq_flags &= ~WM_TXQ_LINKDOWN_DISCARD;
		mutex_exit(txq->txq_lock);
	}
}

/*
 * wm_ioctl:		[ifnet interface function]
 *
 *	Handle control requests from the operator.
 */
static int
wm_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct wm_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifaddr *ifa = (struct ifaddr *)data;
	struct sockaddr_dl *sdl;
	int error;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	switch (cmd) {
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		KASSERT(IFNET_LOCKED(ifp));
	}

	if (cmd == SIOCZIFDATA) {
		/*
		 * Special handling for SIOCZIFDATA.
		 * Copying and clearing the if_data structure is done with
		 * ether_ioctl() below.
		 */
		mutex_enter(sc->sc_core_lock);
		wm_update_stats(sc);
		wm_clear_evcnt(sc);
		mutex_exit(sc->sc_core_lock);
	}

	switch (cmd) {
	case SIOCSIFMEDIA:
		mutex_enter(sc->sc_core_lock);
		/* Flow control requires full-duplex mode. */
		if (IFM_SUBTYPE(ifr->ifr_media) == IFM_AUTO ||
		    (ifr->ifr_media & IFM_FDX) == 0)
			ifr->ifr_media &= ~IFM_ETH_FMASK;
		if (IFM_SUBTYPE(ifr->ifr_media) != IFM_AUTO) {
			if ((ifr->ifr_media & IFM_ETH_FMASK) == IFM_FLOW) {
				/* We can do both TXPAUSE and RXPAUSE. */
				ifr->ifr_media |=
				    IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE;
			}
			sc->sc_flowflags = ifr->ifr_media & IFM_ETH_FMASK;
		}
		mutex_exit(sc->sc_core_lock);
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_mii.mii_media, cmd);
		if (error == 0 && wm_phy_need_linkdown_discard(sc)) {
			if (IFM_SUBTYPE(ifr->ifr_media) == IFM_NONE) {
				DPRINTF(sc, WM_DEBUG_LINK,
				    ("%s: %s: Set linkdown discard flag\n",
					device_xname(sc->sc_dev), __func__));
				wm_set_linkdown_discard(sc);
			}
		}
		break;
	case SIOCINITIFADDR:
		mutex_enter(sc->sc_core_lock);
		if (ifa->ifa_addr->sa_family == AF_LINK) {
			sdl = satosdl(ifp->if_dl->ifa_addr);
			(void)sockaddr_dl_setaddr(sdl, sdl->sdl_len,
			    LLADDR(satosdl(ifa->ifa_addr)), ifp->if_addrlen);
			/* Unicast address is the first multicast entry */
			wm_set_filter(sc);
			error = 0;
			mutex_exit(sc->sc_core_lock);
			break;
		}
		mutex_exit(sc->sc_core_lock);
		/*FALLTHROUGH*/
	default:
		if (cmd == SIOCSIFFLAGS && wm_phy_need_linkdown_discard(sc)) {
			if (((ifp->if_flags & IFF_UP) != 0) &&
			    ((ifr->ifr_flags & IFF_UP) == 0)) {
				DPRINTF(sc, WM_DEBUG_LINK,
				    ("%s: %s: Set linkdown discard flag\n",
					device_xname(sc->sc_dev), __func__));
				wm_set_linkdown_discard(sc);
			}
		}
		const int s = splnet();
		/* It may call wm_start, so unlock here */
		error = ether_ioctl(ifp, cmd, data);
		splx(s);
		if (error != ENETRESET)
			break;

		error = 0;

		if (cmd == SIOCSIFCAP)
			error = if_init(ifp);
		else if (cmd == SIOCADDMULTI || cmd == SIOCDELMULTI) {
			mutex_enter(sc->sc_core_lock);
			if (sc->sc_if_flags & IFF_RUNNING) {
				/*
				 * Multicast list has changed; set the
				 * hardware filter accordingly.
				 */
				wm_set_filter(sc);
			}
			mutex_exit(sc->sc_core_lock);
		}
		break;
	}

	return error;
}

/* MAC address related */

/*
 * Get the offset of MAC address and return it.
 * If error occured, use offset 0.
 */
static uint16_t
wm_check_alt_mac_addr(struct wm_softc *sc)
{
	uint16_t myea[ETHER_ADDR_LEN / 2];
	uint16_t offset = NVM_OFF_MACADDR;

	/* Try to read alternative MAC address pointer */
	if (wm_nvm_read(sc, NVM_OFF_ALT_MAC_ADDR_PTR, 1, &offset) != 0)
		return 0;

	/* Check pointer if it's valid or not. */
	if ((offset == 0x0000) || (offset == 0xffff))
		return 0;

	offset += NVM_OFF_MACADDR_82571(sc->sc_funcid);
	/*
	 * Check whether alternative MAC address is valid or not.
	 * Some cards have non 0xffff pointer but those don't use
	 * alternative MAC address in reality.
	 *
	 * Check whether the broadcast bit is set or not.
	 */
	if (wm_nvm_read(sc, offset, 1, myea) == 0)
		if (((myea[0] & 0xff) & 0x01) == 0)
			return offset; /* Found */

	/* Not found */
	return 0;
}

static int
wm_read_mac_addr(struct wm_softc *sc, uint8_t *enaddr)
{
	uint16_t myea[ETHER_ADDR_LEN / 2];
	uint16_t offset = NVM_OFF_MACADDR;
	int do_invert = 0;

	switch (sc->sc_type) {
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
		/* EEPROM Top Level Partitioning */
		offset = NVM_OFF_LAN_FUNC_82580(sc->sc_funcid) + 0;
		break;
	case WM_T_82571:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_80003:
	case WM_T_I210:
	case WM_T_I211:
		offset = wm_check_alt_mac_addr(sc);
		if (offset == 0)
			if ((sc->sc_funcid & 0x01) == 1)
				do_invert = 1;
		break;
	default:
		if ((sc->sc_funcid & 0x01) == 1)
			do_invert = 1;
		break;
	}

	if (wm_nvm_read(sc, offset, sizeof(myea) / sizeof(myea[0]), myea) != 0)
		goto bad;

	enaddr[0] = myea[0] & 0xff;
	enaddr[1] = myea[0] >> 8;
	enaddr[2] = myea[1] & 0xff;
	enaddr[3] = myea[1] >> 8;
	enaddr[4] = myea[2] & 0xff;
	enaddr[5] = myea[2] >> 8;

	/*
	 * Toggle the LSB of the MAC address on the second port
	 * of some dual port cards.
	 */
	if (do_invert != 0)
		enaddr[5] ^= 1;

	return 0;

bad:
	return -1;
}

/*
 * wm_set_ral:
 *
 *	Set an entery in the receive address list.
 */
static void
wm_set_ral(struct wm_softc *sc, const uint8_t *enaddr, int idx)
{
	uint32_t ral_lo, ral_hi, addrl, addrh;
	uint32_t wlock_mac;
	int rv;

	if (enaddr != NULL) {
		ral_lo = (uint32_t)enaddr[0] | ((uint32_t)enaddr[1] << 8) |
		    ((uint32_t)enaddr[2] << 16) | ((uint32_t)enaddr[3] << 24);
		ral_hi = (uint32_t)enaddr[4] | ((uint32_t)enaddr[5] << 8);
		ral_hi |= RAL_AV;
	} else {
		ral_lo = 0;
		ral_hi = 0;
	}

	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
		CSR_WRITE(sc, WMREG_RAL(idx), ral_lo);
		CSR_WRITE_FLUSH(sc);
		CSR_WRITE(sc, WMREG_RAH(idx), ral_hi);
		CSR_WRITE_FLUSH(sc);
		break;
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		if (idx == 0) {
			CSR_WRITE(sc, WMREG_CORDOVA_RAL(idx), ral_lo);
			CSR_WRITE_FLUSH(sc);
			CSR_WRITE(sc, WMREG_CORDOVA_RAH(idx), ral_hi);
			CSR_WRITE_FLUSH(sc);
			return;
		}
		if (sc->sc_type != WM_T_PCH2) {
			wlock_mac = __SHIFTOUT(CSR_READ(sc, WMREG_FWSM),
			    FWSM_WLOCK_MAC);
			addrl = WMREG_SHRAL(idx - 1);
			addrh = WMREG_SHRAH(idx - 1);
		} else {
			wlock_mac = 0;
			addrl = WMREG_PCH_LPT_SHRAL(idx - 1);
			addrh = WMREG_PCH_LPT_SHRAH(idx - 1);
		}

		if ((wlock_mac == 0) || (idx <= wlock_mac)) {
			rv = wm_get_swflag_ich8lan(sc);
			if (rv != 0)
				return;
			CSR_WRITE(sc, addrl, ral_lo);
			CSR_WRITE_FLUSH(sc);
			CSR_WRITE(sc, addrh, ral_hi);
			CSR_WRITE_FLUSH(sc);
			wm_put_swflag_ich8lan(sc);
		}

		break;
	default:
		CSR_WRITE(sc, WMREG_CORDOVA_RAL(idx), ral_lo);
		CSR_WRITE_FLUSH(sc);
		CSR_WRITE(sc, WMREG_CORDOVA_RAH(idx), ral_hi);
		CSR_WRITE_FLUSH(sc);
		break;
	}
}

/*
 * wm_mchash:
 *
 *	Compute the hash of the multicast address for the 4096-bit
 *	multicast filter.
 */
static uint32_t
wm_mchash(struct wm_softc *sc, const uint8_t *enaddr)
{
	static const int lo_shift[4] = { 4, 3, 2, 0 };
	static const int hi_shift[4] = { 4, 5, 6, 8 };
	static const int ich8_lo_shift[4] = { 6, 5, 4, 2 };
	static const int ich8_hi_shift[4] = { 2, 3, 4, 6 };
	uint32_t hash;

	if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
	    || (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
	    || (sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT)
	    || (sc->sc_type == WM_T_PCH_SPT) || (sc->sc_type == WM_T_PCH_CNP)
	    || (sc->sc_type == WM_T_PCH_TGP)) {
		hash = (enaddr[4] >> ich8_lo_shift[sc->sc_mchash_type]) |
		    (((uint16_t)enaddr[5]) << ich8_hi_shift[sc->sc_mchash_type]);
		return (hash & 0x3ff);
	}
	hash = (enaddr[4] >> lo_shift[sc->sc_mchash_type]) |
	    (((uint16_t)enaddr[5]) << hi_shift[sc->sc_mchash_type]);

	return (hash & 0xfff);
}

/*
 *
 *
 */
static int
wm_rar_count(struct wm_softc *sc)
{
	int size;

	switch (sc->sc_type) {
	case WM_T_ICH8:
		size = WM_RAL_TABSIZE_ICH8 -1;
		break;
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
		size = WM_RAL_TABSIZE_ICH8;
		break;
	case WM_T_PCH2:
		size = WM_RAL_TABSIZE_PCH2;
		break;
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		size = WM_RAL_TABSIZE_PCH_LPT;
		break;
	case WM_T_82575:
	case WM_T_I210:
	case WM_T_I211:
		size = WM_RAL_TABSIZE_82575;
		break;
	case WM_T_82576:
	case WM_T_82580:
		size = WM_RAL_TABSIZE_82576;
		break;
	case WM_T_I350:
	case WM_T_I354:
		size = WM_RAL_TABSIZE_I350;
		break;
	default:
		size = WM_RAL_TABSIZE;
	}

	return size;
}

/*
 * wm_set_filter:
 *
 *	Set up the receive filter.
 */
static void
wm_set_filter(struct wm_softc *sc)
{
	struct ethercom *ec = &sc->sc_ethercom;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct ether_multi *enm;
	struct ether_multistep step;
	bus_addr_t mta_reg;
	uint32_t hash, reg, bit;
	int i, size, ralmax, rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(mutex_owned(sc->sc_core_lock));

	if (sc->sc_type >= WM_T_82544)
		mta_reg = WMREG_CORDOVA_MTA;
	else
		mta_reg = WMREG_MTA;

	sc->sc_rctl &= ~(RCTL_BAM | RCTL_UPE | RCTL_MPE);

	if (sc->sc_if_flags & IFF_BROADCAST)
		sc->sc_rctl |= RCTL_BAM;
	if (sc->sc_if_flags & IFF_PROMISC) {
		sc->sc_rctl |= RCTL_UPE;
		ETHER_LOCK(ec);
		ec->ec_flags |= ETHER_F_ALLMULTI;
		ETHER_UNLOCK(ec);
		goto allmulti;
	}

	/*
	 * Set the station address in the first RAL slot, and
	 * clear the remaining slots.
	 */
	size = wm_rar_count(sc);
	wm_set_ral(sc, CLLADDR(ifp->if_sadl), 0);

	if ((sc->sc_type == WM_T_PCH_LPT) || (sc->sc_type == WM_T_PCH_SPT) ||
	    (sc->sc_type == WM_T_PCH_CNP) || (sc->sc_type == WM_T_PCH_TGP)) {
		i = __SHIFTOUT(CSR_READ(sc, WMREG_FWSM), FWSM_WLOCK_MAC);
		switch (i) {
		case 0:
			/* We can use all entries */
			ralmax = size;
			break;
		case 1:
			/* Only RAR[0] */
			ralmax = 1;
			break;
		default:
			/* Available SHRA + RAR[0] */
			ralmax = i + 1;
		}
	} else
		ralmax = size;
	for (i = 1; i < size; i++) {
		if (i < ralmax)
			wm_set_ral(sc, NULL, i);
	}

	if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
	    || (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
	    || (sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT)
	    || (sc->sc_type == WM_T_PCH_SPT) || (sc->sc_type == WM_T_PCH_CNP)
	    || (sc->sc_type == WM_T_PCH_TGP))
		size = WM_ICH8_MC_TABSIZE;
	else
		size = WM_MC_TABSIZE;
	/* Clear out the multicast table. */
	for (i = 0; i < size; i++) {
		CSR_WRITE(sc, mta_reg + (i << 2), 0);
		CSR_WRITE_FLUSH(sc);
	}

	ETHER_LOCK(ec);
	ETHER_FIRST_MULTI(step, ec, enm);
	while (enm != NULL) {
		if (memcmp(enm->enm_addrlo, enm->enm_addrhi, ETHER_ADDR_LEN)) {
			ec->ec_flags |= ETHER_F_ALLMULTI;
			ETHER_UNLOCK(ec);
			/*
			 * We must listen to a range of multicast addresses.
			 * For now, just accept all multicasts, rather than
			 * trying to set only those filter bits needed to match
			 * the range.  (At this time, the only use of address
			 * ranges is for IP multicast routing, for which the
			 * range is big enough to require all bits set.)
			 */
			goto allmulti;
		}

		hash = wm_mchash(sc, enm->enm_addrlo);

		reg = (hash >> 5);
		if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
		    || (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
		    || (sc->sc_type == WM_T_PCH2)
		    || (sc->sc_type == WM_T_PCH_LPT)
		    || (sc->sc_type == WM_T_PCH_SPT)
		    || (sc->sc_type == WM_T_PCH_CNP)
		    || (sc->sc_type == WM_T_PCH_TGP))
			reg &= 0x1f;
		else
			reg &= 0x7f;
		bit = hash & 0x1f;

		hash = CSR_READ(sc, mta_reg + (reg << 2));
		hash |= 1U << bit;

		if (sc->sc_type == WM_T_82544 && (reg & 1) != 0) {
			/*
			 * 82544 Errata 9: Certain register cannot be written
			 * with particular alignments in PCI-X bus operation
			 * (FCAH, MTA and VFTA).
			 */
			bit = CSR_READ(sc, mta_reg + ((reg - 1) << 2));
			CSR_WRITE(sc, mta_reg + (reg << 2), hash);
			CSR_WRITE_FLUSH(sc);
			CSR_WRITE(sc, mta_reg + ((reg - 1) << 2), bit);
			CSR_WRITE_FLUSH(sc);
		} else {
			CSR_WRITE(sc, mta_reg + (reg << 2), hash);
			CSR_WRITE_FLUSH(sc);
		}

		ETHER_NEXT_MULTI(step, enm);
	}
	ec->ec_flags &= ~ETHER_F_ALLMULTI;
	ETHER_UNLOCK(ec);

	goto setit;

allmulti:
	sc->sc_rctl |= RCTL_MPE;

setit:
	if (sc->sc_type >= WM_T_PCH2) {
		if (((ec->ec_capabilities & ETHERCAP_JUMBO_MTU) != 0)
		    && (ifp->if_mtu > ETHERMTU))
			rv = wm_lv_jumbo_workaround_ich8lan(sc, true);
		else
			rv = wm_lv_jumbo_workaround_ich8lan(sc, false);
		if (rv != 0)
			device_printf(sc->sc_dev,
			    "Failed to do workaround for jumbo frame.\n");
	}

	CSR_WRITE(sc, WMREG_RCTL, sc->sc_rctl);
}

/* Reset and init related */

static void
wm_set_vlan(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* Deal with VLAN enables. */
	if (VLAN_ATTACHED(&sc->sc_ethercom))
		sc->sc_ctrl |= CTRL_VME;
	else
		sc->sc_ctrl &= ~CTRL_VME;

	/* Write the control registers. */
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
}

static void
wm_set_pcie_completion_timeout(struct wm_softc *sc)
{
	uint32_t gcr;
	pcireg_t ctrl2;

	gcr = CSR_READ(sc, WMREG_GCR);

	/* Only take action if timeout value is defaulted to 0 */
	if ((gcr & GCR_CMPL_TMOUT_MASK) != 0)
		goto out;

	if ((gcr & GCR_CAP_VER2) == 0) {
		gcr |= GCR_CMPL_TMOUT_10MS;
		goto out;
	}

	ctrl2 = pci_conf_read(sc->sc_pc, sc->sc_pcitag,
	    sc->sc_pcixe_capoff + PCIE_DCSR2);
	ctrl2 |= WM_PCIE_DCSR2_16MS;
	pci_conf_write(sc->sc_pc, sc->sc_pcitag,
	    sc->sc_pcixe_capoff + PCIE_DCSR2, ctrl2);

out:
	/* Disable completion timeout resend */
	gcr &= ~GCR_CMPL_TMOUT_RESEND;

	CSR_WRITE(sc, WMREG_GCR, gcr);
}

void
wm_get_auto_rd_done(struct wm_softc *sc)
{
	int i;

	/* wait for eeprom to reload */
	switch (sc->sc_type) {
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
	case WM_T_80003:
	case WM_T_ICH8:
	case WM_T_ICH9:
		for (i = 0; i < 10; i++) {
			if (CSR_READ(sc, WMREG_EECD) & EECD_EE_AUTORD)
				break;
			delay(1000);
		}
		if (i == 10) {
			log(LOG_ERR, "%s: auto read from eeprom failed to "
			    "complete\n", device_xname(sc->sc_dev));
		}
		break;
	default:
		break;
	}
}

void
wm_lan_init_done(struct wm_softc *sc)
{
	uint32_t reg = 0;
	int i;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* Wait for eeprom to reload */
	switch (sc->sc_type) {
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		for (i = 0; i < WM_ICH8_LAN_INIT_TIMEOUT; i++) {
			reg = CSR_READ(sc, WMREG_STATUS);
			if ((reg & STATUS_LAN_INIT_DONE) != 0)
				break;
			delay(100);
		}
		if (i >= WM_ICH8_LAN_INIT_TIMEOUT) {
			log(LOG_ERR, "%s: %s: lan_init_done failed to "
			    "complete\n", device_xname(sc->sc_dev), __func__);
		}
		break;
	default:
		panic("%s: %s: unknown type\n", device_xname(sc->sc_dev),
		    __func__);
		break;
	}

	reg &= ~STATUS_LAN_INIT_DONE;
	CSR_WRITE(sc, WMREG_STATUS, reg);
}

void
wm_get_cfg_done(struct wm_softc *sc)
{
	int mask;
	uint32_t reg;
	int i;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* Wait for eeprom to reload */
	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
		/* null */
		break;
	case WM_T_82543:
	case WM_T_82544:
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82545_3:
	case WM_T_82546:
	case WM_T_82546_3:
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		/* generic */
		delay(10*1000);
		break;
	case WM_T_80003:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		if (sc->sc_type == WM_T_82571) {
			/* Only 82571 shares port 0 */
			mask = EEMNGCTL_CFGDONE_0;
		} else
			mask = EEMNGCTL_CFGDONE_0 << sc->sc_funcid;
		for (i = 0; i < WM_PHY_CFG_TIMEOUT; i++) {
			if (CSR_READ(sc, WMREG_EEMNGCTL) & mask)
				break;
			delay(1000);
		}
		if (i >= WM_PHY_CFG_TIMEOUT)
			DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s failed\n",
				device_xname(sc->sc_dev), __func__));
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		delay(10*1000);
		if (sc->sc_type >= WM_T_ICH10)
			wm_lan_init_done(sc);
		else
			wm_get_auto_rd_done(sc);

		/* Clear PHY Reset Asserted bit */
		reg = CSR_READ(sc, WMREG_STATUS);
		if ((reg & STATUS_PHYRA) != 0)
			CSR_WRITE(sc, WMREG_STATUS, reg & ~STATUS_PHYRA);
		break;
	default:
		panic("%s: %s: unknown type\n", device_xname(sc->sc_dev),
		    __func__);
		break;
	}
}

int
wm_phy_post_reset(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint16_t reg;
	int rv = 0;

	/* This function is only for ICH8 and newer. */
	if (sc->sc_type < WM_T_ICH8)
		return 0;

	if (wm_phy_resetisblocked(sc)) {
		/* XXX */
		device_printf(dev, "PHY is blocked\n");
		return -1;
	}

	/* Allow time for h/w to get to quiescent state after reset */
	delay(10*1000);

	/* Perform any necessary post-reset workarounds */
	if (sc->sc_type == WM_T_PCH)
		rv = wm_hv_phy_workarounds_ich8lan(sc);
	else if (sc->sc_type == WM_T_PCH2)
		rv = wm_lv_phy_workarounds_ich8lan(sc);
	if (rv != 0)
		return rv;

	/* Clear the host wakeup bit after lcd reset */
	if (sc->sc_type >= WM_T_PCH) {
		wm_gmii_hv_readreg(dev, 2, BM_PORT_GEN_CFG, &reg);
		reg &= ~BM_WUC_HOST_WU_BIT;
		wm_gmii_hv_writereg(dev, 2, BM_PORT_GEN_CFG, reg);
	}

	/* Configure the LCD with the extended configuration region in NVM */
	if ((rv = wm_init_lcd_from_nvm(sc)) != 0)
		return rv;

	/* Configure the LCD with the OEM bits in NVM */
	rv = wm_oem_bits_config_ich8lan(sc, true);

	if (sc->sc_type == WM_T_PCH2) {
		/* Ungate automatic PHY configuration on non-managed 82579 */
		if ((CSR_READ(sc, WMREG_FWSM) & FWSM_FW_VALID) == 0) {
			delay(10 * 1000);
			wm_gate_hw_phy_config_ich8lan(sc, false);
		}
		/* Set EEE LPI Update Timer to 200usec */
		rv = sc->phy.acquire(sc);
		if (rv)
			return rv;
		rv = wm_write_emi_reg_locked(dev,
		    I82579_LPI_UPDATE_TIMER, 0x1387);
		sc->phy.release(sc);
	}

	return rv;
}

/* Only for PCH and newer */
static int
wm_write_smbus_addr(struct wm_softc *sc)
{
	uint32_t strap, freq;
	uint16_t phy_data;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(CSR_READ(sc, WMREG_EXTCNFCTR) & EXTCNFCTR_MDIO_SW_OWNERSHIP);

	strap = CSR_READ(sc, WMREG_STRAP);
	freq = __SHIFTOUT(strap, STRAP_FREQ);

	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, HV_SMB_ADDR, &phy_data);
	if (rv != 0)
		return rv;

	phy_data &= ~HV_SMB_ADDR_ADDR;
	phy_data |= __SHIFTOUT(strap, STRAP_SMBUSADDR);
	phy_data |= HV_SMB_ADDR_PEC_EN | HV_SMB_ADDR_VALID;

	if (sc->sc_phytype == WMPHY_I217) {
		/* Restore SMBus frequency */
		if (freq --) {
			phy_data &= ~(HV_SMB_ADDR_FREQ_LOW
			    | HV_SMB_ADDR_FREQ_HIGH);
			phy_data |= __SHIFTIN((freq & 0x01) != 0,
			    HV_SMB_ADDR_FREQ_LOW);
			phy_data |= __SHIFTIN((freq & 0x02) != 0,
			    HV_SMB_ADDR_FREQ_HIGH);
		} else
			DPRINTF(sc, WM_DEBUG_INIT,
			    ("%s: %s Unsupported SMB frequency in PHY\n",
				device_xname(sc->sc_dev), __func__));
	}

	return wm_gmii_hv_writereg_locked(sc->sc_dev, 2, HV_SMB_ADDR,
	    phy_data);
}

static int
wm_init_lcd_from_nvm(struct wm_softc *sc)
{
	uint32_t extcnfctr, sw_cfg_mask, cnf_size, word_addr, i, reg;
	uint16_t phy_page = 0;
	int rv = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	switch (sc->sc_type) {
	case WM_T_ICH8:
		if ((sc->sc_phytype == WMPHY_UNKNOWN)
		    || (sc->sc_phytype != WMPHY_IGP_3))
			return 0;

		if ((sc->sc_pcidevid == PCI_PRODUCT_INTEL_82801H_AMT)
		    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_82801H_LAN)) {
			sw_cfg_mask = FEXTNVM_SW_CONFIG;
			break;
		}
		/* FALLTHROUGH */
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		sw_cfg_mask = FEXTNVM_SW_CONFIG_ICH8M;
		break;
	default:
		return 0;
	}

	if ((rv = sc->phy.acquire(sc)) != 0)
		return rv;

	reg = CSR_READ(sc, WMREG_FEXTNVM);
	if ((reg & sw_cfg_mask) == 0)
		goto release;

	/*
	 * Make sure HW does not configure LCD from PHY extended configuration
	 * before SW configuration
	 */
	extcnfctr = CSR_READ(sc, WMREG_EXTCNFCTR);
	if ((sc->sc_type < WM_T_PCH2)
	    && ((extcnfctr & EXTCNFCTR_PCIE_WRITE_ENABLE) != 0))
		goto release;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s: Configure LCD by software\n",
		device_xname(sc->sc_dev), __func__));
	/* word_addr is in DWORD */
	word_addr = __SHIFTOUT(extcnfctr, EXTCNFCTR_EXT_CNF_POINTER) << 1;

	reg = CSR_READ(sc, WMREG_EXTCNFSIZE);
	cnf_size = __SHIFTOUT(reg, EXTCNFSIZE_LENGTH);
	if (cnf_size == 0)
		goto release;

	if (((sc->sc_type == WM_T_PCH)
		&& ((extcnfctr & EXTCNFCTR_OEM_WRITE_ENABLE) == 0))
	    || (sc->sc_type > WM_T_PCH)) {
		/*
		 * HW configures the SMBus address and LEDs when the OEM and
		 * LCD Write Enable bits are set in the NVM. When both NVM bits
		 * are cleared, SW will configure them instead.
		 */
		DPRINTF(sc, WM_DEBUG_INIT,
		    ("%s: %s: Configure SMBus and LED\n",
			device_xname(sc->sc_dev), __func__));
		if ((rv = wm_write_smbus_addr(sc)) != 0)
			goto release;

		reg = CSR_READ(sc, WMREG_LEDCTL);
		rv = wm_gmii_hv_writereg_locked(sc->sc_dev, 1, HV_LED_CONFIG,
		    (uint16_t)reg);
		if (rv != 0)
			goto release;
	}

	/* Configure LCD from extended configuration region. */
	for (i = 0; i < cnf_size; i++) {
		uint16_t reg_data, reg_addr;

		if (wm_nvm_read(sc, (word_addr + i * 2), 1, &reg_data) != 0)
			goto release;

		if (wm_nvm_read(sc, (word_addr + i * 2 + 1), 1, &reg_addr) !=0)
			goto release;

		if (reg_addr == IGPHY_PAGE_SELECT)
			phy_page = reg_data;

		reg_addr &= IGPHY_MAXREGADDR;
		reg_addr |= phy_page;

		KASSERT(sc->phy.writereg_locked != NULL);
		rv = sc->phy.writereg_locked(sc->sc_dev, 1, reg_addr,
		    reg_data);
	}

release:
	sc->phy.release(sc);
	return rv;
}

/*
 *  wm_oem_bits_config_ich8lan - SW-based LCD Configuration
 *  @sc:       pointer to the HW structure
 *  @d0_state: boolean if entering d0 or d3 device state
 *
 *  SW will configure Gbe Disable and LPLU based on the NVM. The four bits are
 *  collectively called OEM bits.  The OEM Write Enable bit and SW Config bit
 *  in NVM determines whether HW should configure LPLU and Gbe Disable.
 */
int
wm_oem_bits_config_ich8lan(struct wm_softc *sc, bool d0_state)
{
	uint32_t mac_reg;
	uint16_t oem_reg;
	int rv;

	if (sc->sc_type < WM_T_PCH)
		return 0;

	rv = sc->phy.acquire(sc);
	if (rv != 0)
		return rv;

	if (sc->sc_type == WM_T_PCH) {
		mac_reg = CSR_READ(sc, WMREG_EXTCNFCTR);
		if ((mac_reg & EXTCNFCTR_OEM_WRITE_ENABLE) != 0)
			goto release;
	}

	mac_reg = CSR_READ(sc, WMREG_FEXTNVM);
	if ((mac_reg & FEXTNVM_SW_CONFIG_ICH8M) == 0)
		goto release;

	mac_reg = CSR_READ(sc, WMREG_PHY_CTRL);

	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 1, HV_OEM_BITS, &oem_reg);
	if (rv != 0)
		goto release;
	oem_reg &= ~(HV_OEM_BITS_A1KDIS | HV_OEM_BITS_LPLU);

	if (d0_state) {
		if ((mac_reg & PHY_CTRL_GBE_DIS) != 0)
			oem_reg |= HV_OEM_BITS_A1KDIS;
		if ((mac_reg & PHY_CTRL_D0A_LPLU) != 0)
			oem_reg |= HV_OEM_BITS_LPLU;
	} else {
		if ((mac_reg & (PHY_CTRL_GBE_DIS | PHY_CTRL_NOND0A_GBE_DIS))
		    != 0)
			oem_reg |= HV_OEM_BITS_A1KDIS;
		if ((mac_reg & (PHY_CTRL_D0A_LPLU | PHY_CTRL_NOND0A_LPLU))
		    != 0)
			oem_reg |= HV_OEM_BITS_LPLU;
	}

	/* Set Restart auto-neg to activate the bits */
	if ((d0_state || (sc->sc_type != WM_T_PCH))
	    && (wm_phy_resetisblocked(sc) == false))
		oem_reg |= HV_OEM_BITS_ANEGNOW;

	rv = wm_gmii_hv_writereg_locked(sc->sc_dev, 1, HV_OEM_BITS, oem_reg);

release:
	sc->phy.release(sc);

	return rv;
}

/* Init hardware bits */
void
wm_initialize_hardware_bits(struct wm_softc *sc)
{
	uint32_t tarc0, tarc1, reg;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* For 82571 variant, 80003 and ICHs */
	if (((sc->sc_type >= WM_T_82571) && (sc->sc_type <= WM_T_82583))
	    || WM_IS_ICHPCH(sc)) {

		/* Transmit Descriptor Control 0 */
		reg = CSR_READ(sc, WMREG_TXDCTL(0));
		reg |= TXDCTL_COUNT_DESC;
		CSR_WRITE(sc, WMREG_TXDCTL(0), reg);

		/* Transmit Descriptor Control 1 */
		reg = CSR_READ(sc, WMREG_TXDCTL(1));
		reg |= TXDCTL_COUNT_DESC;
		CSR_WRITE(sc, WMREG_TXDCTL(1), reg);

		/* TARC0 */
		tarc0 = CSR_READ(sc, WMREG_TARC0);
		switch (sc->sc_type) {
		case WM_T_82571:
		case WM_T_82572:
		case WM_T_82573:
		case WM_T_82574:
		case WM_T_82583:
		case WM_T_80003:
			/* Clear bits 30..27 */
			tarc0 &= ~__BITS(30, 27);
			break;
		default:
			break;
		}

		switch (sc->sc_type) {
		case WM_T_82571:
		case WM_T_82572:
			tarc0 |= __BITS(26, 23); /* TARC0 bits 23-26 */

			tarc1 = CSR_READ(sc, WMREG_TARC1);
			tarc1 &= ~__BITS(30, 29); /* Clear bits 30 and 29 */
			tarc1 |= __BITS(26, 24); /* TARC1 bits 26-24 */
			/* 8257[12] Errata No.7 */
			tarc1 |= __BIT(22); /* TARC1 bits 22 */

			/* TARC1 bit 28 */
			if ((CSR_READ(sc, WMREG_TCTL) & TCTL_MULR) != 0)
				tarc1 &= ~__BIT(28);
			else
				tarc1 |= __BIT(28);
			CSR_WRITE(sc, WMREG_TARC1, tarc1);

			/*
			 * 8257[12] Errata No.13
			 * Disable Dyamic Clock Gating.
			 */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg &= ~CTRL_EXT_DMA_DYN_CLK;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
			break;
		case WM_T_82573:
		case WM_T_82574:
		case WM_T_82583:
			if ((sc->sc_type == WM_T_82574)
			    || (sc->sc_type == WM_T_82583))
				tarc0 |= __BIT(26); /* TARC0 bit 26 */

			/* Extended Device Control */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg &= ~__BIT(23);	/* Clear bit 23 */
			reg |= __BIT(22);	/* Set bit 22 */
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			/* Device Control */
			sc->sc_ctrl &= ~__BIT(29);	/* Clear bit 29 */
			CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

			/* PCIe Control Register */
			/*
			 * 82573 Errata (unknown).
			 *
			 * 82574 Errata 25 and 82583 Errata 12
			 * "Dropped Rx Packets":
			 *   NVM Image Version 2.1.4 and newer has no this bug.
			 */
			reg = CSR_READ(sc, WMREG_GCR);
			reg |= GCR_L1_ACT_WITHOUT_L0S_RX;
			CSR_WRITE(sc, WMREG_GCR, reg);

			if ((sc->sc_type == WM_T_82574)
			    || (sc->sc_type == WM_T_82583)) {
				/*
				 * Document says this bit must be set for
				 * proper operation.
				 */
				reg = CSR_READ(sc, WMREG_GCR);
				reg |= __BIT(22);
				CSR_WRITE(sc, WMREG_GCR, reg);

				/*
				 * Apply workaround for hardware errata
				 * documented in errata docs Fixes issue where
				 * some error prone or unreliable PCIe
				 * completions are occurring, particularly
				 * with ASPM enabled. Without fix, issue can
				 * cause Tx timeouts.
				 */
				reg = CSR_READ(sc, WMREG_GCR2);
				reg |= __BIT(0);
				CSR_WRITE(sc, WMREG_GCR2, reg);
			}
			break;
		case WM_T_80003:
			/* TARC0 */
			if ((sc->sc_mediatype == WM_MEDIATYPE_FIBER)
			    || (sc->sc_mediatype == WM_MEDIATYPE_SERDES))
				tarc0 &= ~__BIT(20); /* Clear bits 20 */

			/* TARC1 bit 28 */
			tarc1 = CSR_READ(sc, WMREG_TARC1);
			if ((CSR_READ(sc, WMREG_TCTL) & TCTL_MULR) != 0)
				tarc1 &= ~__BIT(28);
			else
				tarc1 |= __BIT(28);
			CSR_WRITE(sc, WMREG_TARC1, tarc1);
			break;
		case WM_T_ICH8:
		case WM_T_ICH9:
		case WM_T_ICH10:
		case WM_T_PCH:
		case WM_T_PCH2:
		case WM_T_PCH_LPT:
		case WM_T_PCH_SPT:
		case WM_T_PCH_CNP:
		case WM_T_PCH_TGP:
			/* TARC0 */
			if (sc->sc_type == WM_T_ICH8) {
				/* Set TARC0 bits 29 and 28 */
				tarc0 |= __BITS(29, 28);
			} else if (sc->sc_type == WM_T_PCH_SPT) {
				tarc0 |= __BIT(29);
				/*
				 *  Drop bit 28. From Linux.
				 * See I218/I219 spec update
				 * "5. Buffer Overrun While the I219 is
				 * Processing DMA Transactions"
				 */
				tarc0 &= ~__BIT(28);
			}
			/* Set TARC0 bits 23,24,26,27 */
			tarc0 |= __BITS(27, 26) | __BITS(24, 23);

			/* CTRL_EXT */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg |= __BIT(22);	/* Set bit 22 */
			/*
			 * Enable PHY low-power state when MAC is at D3
			 * w/o WoL
			 */
			if (sc->sc_type >= WM_T_PCH)
				reg |= CTRL_EXT_PHYPDEN;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			/* TARC1 */
			tarc1 = CSR_READ(sc, WMREG_TARC1);
			/* bit 28 */
			if ((CSR_READ(sc, WMREG_TCTL) & TCTL_MULR) != 0)
				tarc1 &= ~__BIT(28);
			else
				tarc1 |= __BIT(28);
			tarc1 |= __BIT(24) | __BIT(26) | __BIT(30);
			CSR_WRITE(sc, WMREG_TARC1, tarc1);

			/* Device Status */
			if (sc->sc_type == WM_T_ICH8) {
				reg = CSR_READ(sc, WMREG_STATUS);
				reg &= ~__BIT(31);
				CSR_WRITE(sc, WMREG_STATUS, reg);

			}

			/* IOSFPC */
			if (sc->sc_type == WM_T_PCH_SPT) {
				reg = CSR_READ(sc, WMREG_IOSFPC);
				reg |= RCTL_RDMTS_HEX; /* XXX RTCL bit? */
				CSR_WRITE(sc, WMREG_IOSFPC, reg);
			}
			/*
			 * Work-around descriptor data corruption issue during
			 * NFS v2 UDP traffic, just disable the NFS filtering
			 * capability.
			 */
			reg = CSR_READ(sc, WMREG_RFCTL);
			reg |= WMREG_RFCTL_NFSWDIS | WMREG_RFCTL_NFSRDIS;
			CSR_WRITE(sc, WMREG_RFCTL, reg);
			break;
		default:
			break;
		}
		CSR_WRITE(sc, WMREG_TARC0, tarc0);

		switch (sc->sc_type) {
		case WM_T_82571:
		case WM_T_82572:
		case WM_T_82573:
		case WM_T_80003:
		case WM_T_ICH8:
			/*
			 * 8257[12] Errata No.52, 82573 Errata No.43 and some
			 * others to avoid RSS Hash Value bug.
			 */
			reg = CSR_READ(sc, WMREG_RFCTL);
			reg |= WMREG_RFCTL_NEWIPV6EXDIS |WMREG_RFCTL_IPV6EXDIS;
			CSR_WRITE(sc, WMREG_RFCTL, reg);
			break;
		case WM_T_82574:
			/* Use extened Rx descriptor. */
			reg = CSR_READ(sc, WMREG_RFCTL);
			reg |= WMREG_RFCTL_EXSTEN;
			CSR_WRITE(sc, WMREG_RFCTL, reg);
			break;
		default:
			break;
		}
	} else if ((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211)) {
		/*
		 * 82575 Errata XXX, 82576 Errata 46, 82580 Errata 24,
		 * I350 Errata 37, I210 Errata No. 31 and I211 Errata No. 11:
		 * "Certain Malformed IPv6 Extension Headers are Not Processed
		 * Correctly by the Device"
		 *
		 * I354(C2000) Errata AVR53:
		 * "Malformed IPv6 Extension Headers May Result in LAN Device
		 * Hang"
		 */
		reg = CSR_READ(sc, WMREG_RFCTL);
		reg |= WMREG_RFCTL_IPV6EXDIS;
		CSR_WRITE(sc, WMREG_RFCTL, reg);
	}
}

static uint32_t
wm_rxpbs_adjust_82580(uint32_t val)
{
	uint32_t rv = 0;

	if (val < __arraycount(wm_82580_rxpbs_table))
		rv = wm_82580_rxpbs_table[val];

	return rv;
}

/*
 * wm_reset_phy:
 *
 *	generic PHY reset function.
 *	Same as e1000_phy_hw_reset_generic()
 */
static int
wm_reset_phy(struct wm_softc *sc)
{
	uint32_t reg;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	if (wm_phy_resetisblocked(sc))
		return -1;

	rv = sc->phy.acquire(sc);
	if (rv) {
		device_printf(sc->sc_dev, "%s: failed to acquire phy: %d\n",
		    __func__, rv);
		return rv;
	}

	reg = CSR_READ(sc, WMREG_CTRL);
	CSR_WRITE(sc, WMREG_CTRL, reg | CTRL_PHY_RESET);
	CSR_WRITE_FLUSH(sc);

	delay(sc->phy.reset_delay_us);

	CSR_WRITE(sc, WMREG_CTRL, reg);
	CSR_WRITE_FLUSH(sc);

	delay(150);

	sc->phy.release(sc);

	wm_get_cfg_done(sc);
	wm_phy_post_reset(sc);

	return 0;
}

/*
 * wm_flush_desc_rings - remove all descriptors from the descriptor rings.
 *
 * In i219, the descriptor rings must be emptied before resetting the HW
 * or before changing the device state to D3 during runtime (runtime PM).
 *
 * Failure to do this will cause the HW to enter a unit hang state which can
 * only be released by PCI reset on the device.
 *
 * I219 does not use multiqueue, so it is enough to check sc->sc_queue[0] only.
 */
static void
wm_flush_desc_rings(struct wm_softc *sc)
{
	pcireg_t preg;
	uint32_t reg;
	struct wm_txqueue *txq;
	wiseman_txdesc_t *txd;
	int nexttx;
	uint32_t rctl;

	KASSERT(IFNET_LOCKED(&sc->sc_ethercom.ec_if));

	/* First, disable MULR fix in FEXTNVM11 */
	reg = CSR_READ(sc, WMREG_FEXTNVM11);
	reg |= FEXTNVM11_DIS_MULRFIX;
	CSR_WRITE(sc, WMREG_FEXTNVM11, reg);

	preg = pci_conf_read(sc->sc_pc, sc->sc_pcitag, WM_PCI_DESCRING_STATUS);
	reg = CSR_READ(sc, WMREG_TDLEN(0));
	if (((preg & DESCRING_STATUS_FLUSH_REQ) == 0) || (reg == 0))
		return;

	/*
	 * Remove all descriptors from the tx_ring.
	 *
	 * We want to clear all pending descriptors from the TX ring. Zeroing
	 * happens when the HW reads the regs. We assign the ring itself as
	 * the data of the next descriptor. We don't care about the data we are
	 * about to reset the HW.
	 */
#ifdef WM_DEBUG
	device_printf(sc->sc_dev, "Need TX flush (reg = %08x)\n", preg);
#endif
	reg = CSR_READ(sc, WMREG_TCTL);
	CSR_WRITE(sc, WMREG_TCTL, reg | TCTL_EN);

	txq = &sc->sc_queue[0].wmq_txq;
	nexttx = txq->txq_next;
	txd = &txq->txq_descs[nexttx];
	wm_set_dma_addr(&txd->wtx_addr, txq->txq_desc_dma);
	txd->wtx_cmdlen = htole32(WTX_CMD_IFCS | 512);
	txd->wtx_fields.wtxu_status = 0;
	txd->wtx_fields.wtxu_options = 0;
	txd->wtx_fields.wtxu_vlan = 0;

	wm_cdtxsync(txq, 0, WM_NTXDESC(txq),
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	txq->txq_next = WM_NEXTTX(txq, txq->txq_next);
	CSR_WRITE(sc, WMREG_TDT(0), txq->txq_next);
	CSR_WRITE_FLUSH(sc);
	delay(250);

	preg = pci_conf_read(sc->sc_pc, sc->sc_pcitag, WM_PCI_DESCRING_STATUS);
	if ((preg & DESCRING_STATUS_FLUSH_REQ) == 0)
		return;

	/*
	 * Mark all descriptors in the RX ring as consumed and disable the
	 * rx ring.
	 */
#ifdef WM_DEBUG
	device_printf(sc->sc_dev, "Need RX flush (reg = %08x)\n", preg);
#endif
	rctl = CSR_READ(sc, WMREG_RCTL);
	CSR_WRITE(sc, WMREG_RCTL, rctl & ~RCTL_EN);
	CSR_WRITE_FLUSH(sc);
	delay(150);

	reg = CSR_READ(sc, WMREG_RXDCTL(0));
	/* Zero the lower 14 bits (prefetch and host thresholds) */
	reg &= 0xffffc000;
	/*
	 * Update thresholds: prefetch threshold to 31, host threshold
	 * to 1 and make sure the granularity is "descriptors" and not
	 * "cache lines"
	 */
	reg |= (0x1f | (1 << 8) | RXDCTL_GRAN);
	CSR_WRITE(sc, WMREG_RXDCTL(0), reg);

	/* Momentarily enable the RX ring for the changes to take effect */
	CSR_WRITE(sc, WMREG_RCTL, rctl | RCTL_EN);
	CSR_WRITE_FLUSH(sc);
	delay(150);
	CSR_WRITE(sc, WMREG_RCTL, rctl & ~RCTL_EN);
}

/*
 * wm_reset:
 *
 *	Reset the i82542 chip.
 */
static void
wm_reset(struct wm_softc *sc)
{
	int phy_reset = 0;
	int i, error = 0;
	uint32_t reg;
	uint16_t kmreg;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(sc->sc_type != 0);

	/*
	 * Allocate on-chip memory according to the MTU size.
	 * The Packet Buffer Allocation register must be written
	 * before the chip is reset.
	 */
	switch (sc->sc_type) {
	case WM_T_82547:
	case WM_T_82547_2:
		sc->sc_pba = sc->sc_ethercom.ec_if.if_mtu > 8192 ?
		    PBA_22K : PBA_30K;
		for (i = 0; i < sc->sc_nqueues; i++) {
			struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
			txq->txq_fifo_head = 0;
			txq->txq_fifo_addr = sc->sc_pba << PBA_ADDR_SHIFT;
			txq->txq_fifo_size =
			    (PBA_40K - sc->sc_pba) << PBA_BYTE_SHIFT;
			txq->txq_fifo_stall = 0;
		}
		break;
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82575:	/* XXX need special handing for jumbo frames */
	case WM_T_80003:
		sc->sc_pba = PBA_32K;
		break;
	case WM_T_82573:
		sc->sc_pba = PBA_12K;
		break;
	case WM_T_82574:
	case WM_T_82583:
		sc->sc_pba = PBA_20K;
		break;
	case WM_T_82576:
		sc->sc_pba = CSR_READ(sc, WMREG_RXPBS);
		sc->sc_pba &= RXPBS_SIZE_MASK_82576;
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
		sc->sc_pba = wm_rxpbs_adjust_82580(CSR_READ(sc, WMREG_RXPBS));
		break;
	case WM_T_I210:
	case WM_T_I211:
		sc->sc_pba = PBA_34K;
		break;
	case WM_T_ICH8:
		/* Workaround for a bit corruption issue in FIFO memory */
		sc->sc_pba = PBA_8K;
		CSR_WRITE(sc, WMREG_PBS, PBA_16K);
		break;
	case WM_T_ICH9:
	case WM_T_ICH10:
		sc->sc_pba = sc->sc_ethercom.ec_if.if_mtu > 4096 ?
		    PBA_14K : PBA_10K;
		break;
	case WM_T_PCH:
	case WM_T_PCH2:	/* XXX 14K? */
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		sc->sc_pba = sc->sc_ethercom.ec_if.if_mtu > 1500 ?
		    PBA_12K : PBA_26K;
		break;
	default:
		sc->sc_pba = sc->sc_ethercom.ec_if.if_mtu > 8192 ?
		    PBA_40K : PBA_48K;
		break;
	}
	/*
	 * Only old or non-multiqueue devices have the PBA register
	 * XXX Need special handling for 82575.
	 */
	if (((sc->sc_flags & WM_F_NEWQUEUE) == 0)
	    || (sc->sc_type == WM_T_82575))
		CSR_WRITE(sc, WMREG_PBA, sc->sc_pba);

	/* Prevent the PCI-E bus from sticking */
	if (sc->sc_flags & WM_F_PCIE) {
		int timeout = 800;

		sc->sc_ctrl |= CTRL_GIO_M_DIS;
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

		while (timeout--) {
			if ((CSR_READ(sc, WMREG_STATUS) & STATUS_GIO_M_ENA)
			    == 0)
				break;
			delay(100);
		}
		if (timeout == 0)
			device_printf(sc->sc_dev,
			    "failed to disable bus mastering\n");
	}

	/* Set the completion timeout for interface */
	if ((sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)
	    || (sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354)
	    || (sc->sc_type == WM_T_I210) || (sc->sc_type == WM_T_I211))
		wm_set_pcie_completion_timeout(sc);

	/* Clear interrupt */
	CSR_WRITE(sc, WMREG_IMC, 0xffffffffU);
	if (wm_is_using_msix(sc)) {
		if (sc->sc_type != WM_T_82574) {
			CSR_WRITE(sc, WMREG_EIMC, 0xffffffffU);
			CSR_WRITE(sc, WMREG_EIAC, 0);
		} else
			CSR_WRITE(sc, WMREG_EIAC_82574, 0);
	}

	/* Stop the transmit and receive processes. */
	CSR_WRITE(sc, WMREG_RCTL, 0);
	sc->sc_rctl &= ~RCTL_EN;
	CSR_WRITE(sc, WMREG_TCTL, TCTL_PSP);
	CSR_WRITE_FLUSH(sc);

	/* XXX set_tbi_sbp_82543() */

	delay(10*1000);

	/* Must acquire the MDIO ownership before MAC reset */
	switch (sc->sc_type) {
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		error = wm_get_hw_semaphore_82573(sc);
		break;
	default:
		break;
	}

	/*
	 * 82541 Errata 29? & 82547 Errata 28?
	 * See also the description about PHY_RST bit in CTRL register
	 * in 8254x_GBe_SDM.pdf.
	 */
	if ((sc->sc_type == WM_T_82541) || (sc->sc_type == WM_T_82547)) {
		CSR_WRITE(sc, WMREG_CTRL,
		    CSR_READ(sc, WMREG_CTRL) | CTRL_PHY_RESET);
		CSR_WRITE_FLUSH(sc);
		delay(5000);
	}

	switch (sc->sc_type) {
	case WM_T_82544: /* XXX check whether WM_F_IOH_VALID is set */
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
		/*
		 * On some chipsets, a reset through a memory-mapped write
		 * cycle can cause the chip to reset before completing the
		 * write cycle. This causes major headache that can be avoided
		 * by issuing the reset via indirect register writes through
		 * I/O space.
		 *
		 * So, if we successfully mapped the I/O BAR at attach time,
		 * use that. Otherwise, try our luck with a memory-mapped
		 * reset.
		 */
		if (sc->sc_flags & WM_F_IOH_VALID)
			wm_io_write(sc, WMREG_CTRL, CTRL_RST);
		else
			CSR_WRITE(sc, WMREG_CTRL, CTRL_RST);
		break;
	case WM_T_82545_3:
	case WM_T_82546_3:
		/* Use the shadow control register on these chips. */
		CSR_WRITE(sc, WMREG_CTRL_SHADOW, CTRL_RST);
		break;
	case WM_T_80003:
		reg = CSR_READ(sc, WMREG_CTRL) | CTRL_RST;
		if (sc->phy.acquire(sc) != 0)
			break;
		CSR_WRITE(sc, WMREG_CTRL, reg);
		sc->phy.release(sc);
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		reg = CSR_READ(sc, WMREG_CTRL) | CTRL_RST;
		if (wm_phy_resetisblocked(sc) == false) {
			/*
			 * Gate automatic PHY configuration by hardware on
			 * non-managed 82579
			 */
			if ((sc->sc_type == WM_T_PCH2)
			    && ((CSR_READ(sc, WMREG_FWSM) & FWSM_FW_VALID)
				== 0))
				wm_gate_hw_phy_config_ich8lan(sc, true);

			reg |= CTRL_PHY_RESET;
			phy_reset = 1;
		} else
			device_printf(sc->sc_dev, "XXX reset is blocked!!!\n");
		if (sc->phy.acquire(sc) != 0)
			break;
		CSR_WRITE(sc, WMREG_CTRL, reg);
		/* Don't insert a completion barrier when reset */
		delay(20*1000);
		/*
		 * The EXTCNFCTR_MDIO_SW_OWNERSHIP bit is cleared by the reset,
		 * so don't use sc->phy.release(sc). Release sc_ich_phymtx
		 * only. See also wm_get_swflag_ich8lan().
		 */
		mutex_exit(sc->sc_ich_phymtx);
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		CSR_WRITE(sc, WMREG_CTRL, CSR_READ(sc, WMREG_CTRL) | CTRL_RST);
		if (sc->sc_pcidevid != PCI_PRODUCT_INTEL_DH89XXCC_SGMII)
			CSR_WRITE_FLUSH(sc);
		delay(5000);
		break;
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82546:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82583:
	default:
		/* Everything else can safely use the documented method. */
		CSR_WRITE(sc, WMREG_CTRL, CSR_READ(sc, WMREG_CTRL) | CTRL_RST);
		break;
	}

	/* Must release the MDIO ownership after MAC reset */
	switch (sc->sc_type) {
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		if (error == 0)
			wm_put_hw_semaphore_82573(sc);
		break;
	default:
		break;
	}

	/* Set Phy Config Counter to 50msec */
	if (sc->sc_type == WM_T_PCH2) {
		reg = CSR_READ(sc, WMREG_FEXTNVM3);
		reg &= ~FEXTNVM3_PHY_CFG_COUNTER_MASK;
		reg |= FEXTNVM3_PHY_CFG_COUNTER_50MS;
		CSR_WRITE(sc, WMREG_FEXTNVM3, reg);
	}

	if (phy_reset != 0)
		wm_get_cfg_done(sc);

	/* Reload EEPROM */
	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
	case WM_T_82544:
		delay(10);
		reg = CSR_READ(sc, WMREG_CTRL_EXT) | CTRL_EXT_EE_RST;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2000);
		break;
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82545_3:
	case WM_T_82546:
	case WM_T_82546_3:
		delay(5*1000);
		/* XXX Disable HW ARPs on ASF enabled adapters */
		break;
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
		delay(20000);
		/* XXX Disable HW ARPs on ASF enabled adapters */
		break;
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		if (sc->sc_flags & WM_F_EEPROM_FLASH) {
			delay(10);
			reg = CSR_READ(sc, WMREG_CTRL_EXT) | CTRL_EXT_EE_RST;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
			CSR_WRITE_FLUSH(sc);
		}
		/* check EECD_EE_AUTORD */
		wm_get_auto_rd_done(sc);
		/*
		 * Phy configuration from NVM just starts after EECD_AUTO_RD
		 * is set.
		 */
		if ((sc->sc_type == WM_T_82573) || (sc->sc_type == WM_T_82574)
		    || (sc->sc_type == WM_T_82583))
			delay(25*1000);
		break;
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
	case WM_T_80003:
		/* check EECD_EE_AUTORD */
		wm_get_auto_rd_done(sc);
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		break;
	default:
		panic("%s: unknown type\n", __func__);
	}

	/* Check whether EEPROM is present or not */
	switch (sc->sc_type) {
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_ICH8:
	case WM_T_ICH9:
		if ((CSR_READ(sc, WMREG_EECD) & EECD_EE_PRES) == 0) {
			/* Not found */
			sc->sc_flags |= WM_F_EEPROM_INVALID;
			if (sc->sc_type == WM_T_82575)
				wm_reset_init_script_82575(sc);
		}
		break;
	default:
		break;
	}

	if (phy_reset != 0)
		wm_phy_post_reset(sc);

	if ((sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354)) {
		/* Clear global device reset status bit */
		CSR_WRITE(sc, WMREG_STATUS, STATUS_DEV_RST_SET);
	}

	/* Clear any pending interrupt events. */
	CSR_WRITE(sc, WMREG_IMC, 0xffffffffU);
	reg = CSR_READ(sc, WMREG_ICR);
	if (wm_is_using_msix(sc)) {
		if (sc->sc_type != WM_T_82574) {
			CSR_WRITE(sc, WMREG_EIMC, 0xffffffffU);
			CSR_WRITE(sc, WMREG_EIAC, 0);
		} else
			CSR_WRITE(sc, WMREG_EIAC_82574, 0);
	}

	if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
	    || (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
	    || (sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT)
	    || (sc->sc_type == WM_T_PCH_SPT) || (sc->sc_type == WM_T_PCH_CNP)
	    || (sc->sc_type == WM_T_PCH_TGP)) {
		reg = CSR_READ(sc, WMREG_KABGTXD);
		reg |= KABGTXD_BGSQLBIAS;
		CSR_WRITE(sc, WMREG_KABGTXD, reg);
	}

	/* Reload sc_ctrl */
	sc->sc_ctrl = CSR_READ(sc, WMREG_CTRL);

	wm_set_eee(sc);

	/*
	 * For PCH, this write will make sure that any noise will be detected
	 * as a CRC error and be dropped rather than show up as a bad packet
	 * to the DMA engine
	 */
	if (sc->sc_type == WM_T_PCH)
		CSR_WRITE(sc, WMREG_CRC_OFFSET, 0x65656565);

	if (sc->sc_type >= WM_T_82544)
		CSR_WRITE(sc, WMREG_WUC, 0);

	if (sc->sc_type < WM_T_82575)
		wm_disable_aspm(sc); /* Workaround for some chips */

	wm_reset_mdicnfg_82580(sc);

	if ((sc->sc_flags & WM_F_PLL_WA_I210) != 0)
		wm_pll_workaround_i210(sc);

	if (sc->sc_type == WM_T_80003) {
		/* Default to TRUE to enable the MDIC W/A */
		sc->sc_flags |= WM_F_80003_MDIC_WA;

		rv = wm_kmrn_readreg(sc,
		    KUMCTRLSTA_OFFSET >> KUMCTRLSTA_OFFSET_SHIFT, &kmreg);
		if (rv == 0) {
			if ((kmreg & KUMCTRLSTA_OPMODE_MASK)
			    == KUMCTRLSTA_OPMODE_INBAND_MDIO)
				sc->sc_flags &= ~WM_F_80003_MDIC_WA;
			else
				sc->sc_flags |= WM_F_80003_MDIC_WA;
		}
	}
}

/*
 * wm_add_rxbuf:
 *
 *	Add a receive buffer to the indiciated descriptor.
 */
static int
wm_add_rxbuf(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;
	struct wm_rxsoft *rxs = &rxq->rxq_soft[idx];
	struct mbuf *m;
	int error;

	KASSERT(mutex_owned(rxq->rxq_lock));

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return ENOBUFS;
	MCLAIM(m, &sc->sc_ethercom.ec_rx_mowner);

	MCLGET(m, M_DONTWAIT);
	if ((m->m_flags & M_EXT) == 0) {
		m_freem(m);
		return ENOBUFS;
	}

	if (rxs->rxs_mbuf != NULL)
		bus_dmamap_unload(sc->sc_dmat, rxs->rxs_dmamap);

	rxs->rxs_mbuf = m;

	m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;
	/*
	 * Cannot use bus_dmamap_load_mbuf() here because m_data may be
	 * sc_align_tweak'd between bus_dmamap_load() and bus_dmamap_sync().
	 */
	error = bus_dmamap_load(sc->sc_dmat, rxs->rxs_dmamap, m->m_ext.ext_buf,
	    m->m_ext.ext_size, NULL, BUS_DMA_READ | BUS_DMA_NOWAIT);
	if (error) {
		/* XXX XXX XXX */
		aprint_error_dev(sc->sc_dev,
		    "unable to load rx DMA map %d, error = %d\n", idx, error);
		panic("wm_add_rxbuf");
	}

	bus_dmamap_sync(sc->sc_dmat, rxs->rxs_dmamap, 0,
	    rxs->rxs_dmamap->dm_mapsize, BUS_DMASYNC_PREREAD);

	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		if ((sc->sc_rctl & RCTL_EN) != 0)
			wm_init_rxdesc(rxq, idx);
	} else
		wm_init_rxdesc(rxq, idx);

	return 0;
}

/*
 * wm_rxdrain:
 *
 *	Drain the receive queue.
 */
static void
wm_rxdrain(struct wm_rxqueue *rxq)
{
	struct wm_softc *sc = rxq->rxq_sc;
	struct wm_rxsoft *rxs;
	int i;

	KASSERT(mutex_owned(rxq->rxq_lock));

	for (i = 0; i < WM_NRXDESC; i++) {
		rxs = &rxq->rxq_soft[i];
		if (rxs->rxs_mbuf != NULL) {
			bus_dmamap_unload(sc->sc_dmat, rxs->rxs_dmamap);
			m_freem(rxs->rxs_mbuf);
			rxs->rxs_mbuf = NULL;
		}
	}
}

/*
 * Setup registers for RSS.
 *
 * XXX not yet VMDq support
 */
static void
wm_init_rss(struct wm_softc *sc)
{
	uint32_t mrqc, reta_reg, rss_key[RSSRK_NUM_REGS];
	int i;

	CTASSERT(sizeof(rss_key) == RSS_KEYSIZE);

	for (i = 0; i < RETA_NUM_ENTRIES; i++) {
		unsigned int qid, reta_ent;

		qid  = i % sc->sc_nqueues;
		switch (sc->sc_type) {
		case WM_T_82574:
			reta_ent = __SHIFTIN(qid,
			    RETA_ENT_QINDEX_MASK_82574);
			break;
		case WM_T_82575:
			reta_ent = __SHIFTIN(qid,
			    RETA_ENT_QINDEX1_MASK_82575);
			break;
		default:
			reta_ent = __SHIFTIN(qid, RETA_ENT_QINDEX_MASK);
			break;
		}

		reta_reg = CSR_READ(sc, WMREG_RETA_Q(i));
		reta_reg &= ~RETA_ENTRY_MASK_Q(i);
		reta_reg |= __SHIFTIN(reta_ent, RETA_ENTRY_MASK_Q(i));
		CSR_WRITE(sc, WMREG_RETA_Q(i), reta_reg);
	}

	rss_getkey((uint8_t *)rss_key);
	for (i = 0; i < RSSRK_NUM_REGS; i++)
		CSR_WRITE(sc, WMREG_RSSRK(i), rss_key[i]);

	if (sc->sc_type == WM_T_82574)
		mrqc = MRQC_ENABLE_RSS_MQ_82574;
	else
		mrqc = MRQC_ENABLE_RSS_MQ;

	/*
	 * MRQC_RSS_FIELD_IPV6_EX is not set because of an errata.
	 * See IPV6EXDIS bit in wm_initialize_hardware_bits().
	 */
	mrqc |= (MRQC_RSS_FIELD_IPV4 | MRQC_RSS_FIELD_IPV4_TCP);
	mrqc |= (MRQC_RSS_FIELD_IPV6 | MRQC_RSS_FIELD_IPV6_TCP);
#if 0
	mrqc |= (MRQC_RSS_FIELD_IPV4_UDP | MRQC_RSS_FIELD_IPV6_UDP);
	mrqc |= MRQC_RSS_FIELD_IPV6_UDP_EX;
#endif
	mrqc |= MRQC_RSS_FIELD_IPV6_TCP_EX;

	CSR_WRITE(sc, WMREG_MRQC, mrqc);
}

/*
 * Adjust TX and RX queue numbers which the system actulally uses.
 *
 * The numbers are affected by below parameters.
 *     - The nubmer of hardware queues
 *     - The number of MSI-X vectors (= "nvectors" argument)
 *     - ncpu
 */
static void
wm_adjust_qnum(struct wm_softc *sc, int nvectors)
{
	int hw_ntxqueues, hw_nrxqueues, hw_nqueues;

	if (nvectors < 2) {
		sc->sc_nqueues = 1;
		return;
	}

	switch (sc->sc_type) {
	case WM_T_82572:
		hw_ntxqueues = 2;
		hw_nrxqueues = 2;
		break;
	case WM_T_82574:
		hw_ntxqueues = 2;
		hw_nrxqueues = 2;
		break;
	case WM_T_82575:
		hw_ntxqueues = 4;
		hw_nrxqueues = 4;
		break;
	case WM_T_82576:
		hw_ntxqueues = 16;
		hw_nrxqueues = 16;
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
		hw_ntxqueues = 8;
		hw_nrxqueues = 8;
		break;
	case WM_T_I210:
		hw_ntxqueues = 4;
		hw_nrxqueues = 4;
		break;
	case WM_T_I211:
		hw_ntxqueues = 2;
		hw_nrxqueues = 2;
		break;
		/*
		 * The below Ethernet controllers do not support MSI-X;
		 * this driver doesn't let them use multiqueue.
		 *     - WM_T_80003
		 *     - WM_T_ICH8
		 *     - WM_T_ICH9
		 *     - WM_T_ICH10
		 *     - WM_T_PCH
		 *     - WM_T_PCH2
		 *     - WM_T_PCH_LPT
		 */
	default:
		hw_ntxqueues = 1;
		hw_nrxqueues = 1;
		break;
	}

	hw_nqueues = uimin(hw_ntxqueues, hw_nrxqueues);

	/*
	 * As queues more than MSI-X vectors cannot improve scaling, we limit
	 * the number of queues used actually.
	 */
	if (nvectors < hw_nqueues + 1)
		sc->sc_nqueues = nvectors - 1;
	else
		sc->sc_nqueues = hw_nqueues;

	/*
	 * As queues more than CPUs cannot improve scaling, we limit
	 * the number of queues used actually.
	 */
	if (ncpu < sc->sc_nqueues)
		sc->sc_nqueues = ncpu;
}

static inline bool
wm_is_using_msix(struct wm_softc *sc)
{

	return (sc->sc_nintrs > 1);
}

static inline bool
wm_is_using_multiqueue(struct wm_softc *sc)
{

	return (sc->sc_nqueues > 1);
}

static int
wm_softint_establish_queue(struct wm_softc *sc, int qidx, int intr_idx)
{
	struct wm_queue *wmq = &sc->sc_queue[qidx];

	wmq->wmq_id = qidx;
	wmq->wmq_intr_idx = intr_idx;
	wmq->wmq_si = softint_establish(SOFTINT_NET | SOFTINT_MPSAFE,
	    wm_handle_queue, wmq);
	if (wmq->wmq_si != NULL)
		return 0;

	aprint_error_dev(sc->sc_dev, "unable to establish queue[%d] handler\n",
	    wmq->wmq_id);
	pci_intr_disestablish(sc->sc_pc, sc->sc_ihs[wmq->wmq_intr_idx]);
	sc->sc_ihs[wmq->wmq_intr_idx] = NULL;
	return ENOMEM;
}

/*
 * Both single interrupt MSI and INTx can use this function.
 */
static int
wm_setup_legacy(struct wm_softc *sc)
{
	pci_chipset_tag_t pc = sc->sc_pc;
	const char *intrstr = NULL;
	char intrbuf[PCI_INTRSTR_LEN];
	int error;

	error = wm_alloc_txrx_queues(sc);
	if (error) {
		aprint_error_dev(sc->sc_dev, "cannot allocate queues %d\n",
		    error);
		return ENOMEM;
	}
	intrstr = pci_intr_string(pc, sc->sc_intrs[0], intrbuf,
	    sizeof(intrbuf));
	pci_intr_setattr(pc, &sc->sc_intrs[0], PCI_INTR_MPSAFE, true);
	sc->sc_ihs[0] = pci_intr_establish_xname(pc, sc->sc_intrs[0],
	    IPL_NET, wm_intr_legacy, sc, device_xname(sc->sc_dev));
	if (sc->sc_ihs[0] == NULL) {
		aprint_error_dev(sc->sc_dev,"unable to establish %s\n",
		    (pci_intr_type(pc, sc->sc_intrs[0])
			== PCI_INTR_TYPE_MSI) ? "MSI" : "INTx");
		return ENOMEM;
	}

	aprint_normal_dev(sc->sc_dev, "interrupting at %s\n", intrstr);
	sc->sc_nintrs = 1;

	return wm_softint_establish_queue(sc, 0, 0);
}

static int
wm_setup_msix(struct wm_softc *sc)
{
	void *vih;
	kcpuset_t *affinity;
	int qidx, error, intr_idx, txrx_established;
	pci_chipset_tag_t pc = sc->sc_pc;
	const char *intrstr = NULL;
	char intrbuf[PCI_INTRSTR_LEN];
	char intr_xname[INTRDEVNAMEBUF];

	if (sc->sc_nqueues < ncpu) {
		/*
		 * To avoid other devices' interrupts, the affinity of Tx/Rx
		 * interrupts start from CPU#1.
		 */
		sc->sc_affinity_offset = 1;
	} else {
		/*
		 * In this case, this device use all CPUs. So, we unify
		 * affinitied cpu_index to msix vector number for readability.
		 */
		sc->sc_affinity_offset = 0;
	}

	error = wm_alloc_txrx_queues(sc);
	if (error) {
		aprint_error_dev(sc->sc_dev, "cannot allocate queues %d\n",
		    error);
		return ENOMEM;
	}

	kcpuset_create(&affinity, false);
	intr_idx = 0;

	/*
	 * TX and RX
	 */
	txrx_established = 0;
	for (qidx = 0; qidx < sc->sc_nqueues; qidx++) {
		struct wm_queue *wmq = &sc->sc_queue[qidx];
		int affinity_to = (sc->sc_affinity_offset + intr_idx) % ncpu;

		intrstr = pci_intr_string(pc, sc->sc_intrs[intr_idx], intrbuf,
		    sizeof(intrbuf));
		pci_intr_setattr(pc, &sc->sc_intrs[intr_idx],
		    PCI_INTR_MPSAFE, true);
		memset(intr_xname, 0, sizeof(intr_xname));
		snprintf(intr_xname, sizeof(intr_xname), "%sTXRX%d",
		    device_xname(sc->sc_dev), qidx);
		vih = pci_intr_establish_xname(pc, sc->sc_intrs[intr_idx],
		    IPL_NET, wm_txrxintr_msix, wmq, intr_xname);
		if (vih == NULL) {
			aprint_error_dev(sc->sc_dev,
			    "unable to establish MSI-X(for TX and RX)%s%s\n",
			    intrstr ? " at " : "",
			    intrstr ? intrstr : "");

			goto fail;
		}
		kcpuset_zero(affinity);
		/* Round-robin affinity */
		kcpuset_set(affinity, affinity_to);
		error = interrupt_distribute(vih, affinity, NULL);
		if (error == 0) {
			aprint_normal_dev(sc->sc_dev,
			    "for TX and RX interrupting at %s affinity to %u\n",
			    intrstr, affinity_to);
		} else {
			aprint_normal_dev(sc->sc_dev,
			    "for TX and RX interrupting at %s\n", intrstr);
		}
		sc->sc_ihs[intr_idx] = vih;
		if (wm_softint_establish_queue(sc, qidx, intr_idx) != 0)
			goto fail;
		txrx_established++;
		intr_idx++;
	}

	/* LINK */
	intrstr = pci_intr_string(pc, sc->sc_intrs[intr_idx], intrbuf,
	    sizeof(intrbuf));
	pci_intr_setattr(pc, &sc->sc_intrs[intr_idx], PCI_INTR_MPSAFE, true);
	memset(intr_xname, 0, sizeof(intr_xname));
	snprintf(intr_xname, sizeof(intr_xname), "%sLINK",
	    device_xname(sc->sc_dev));
	vih = pci_intr_establish_xname(pc, sc->sc_intrs[intr_idx],
	    IPL_NET, wm_linkintr_msix, sc, intr_xname);
	if (vih == NULL) {
		aprint_error_dev(sc->sc_dev,
		    "unable to establish MSI-X(for LINK)%s%s\n",
		    intrstr ? " at " : "",
		    intrstr ? intrstr : "");

		goto fail;
	}
	/* Keep default affinity to LINK interrupt */
	aprint_normal_dev(sc->sc_dev,
	    "for LINK interrupting at %s\n", intrstr);
	sc->sc_ihs[intr_idx] = vih;
	sc->sc_link_intr_idx = intr_idx;

	sc->sc_nintrs = sc->sc_nqueues + 1;
	kcpuset_destroy(affinity);
	return 0;

fail:
	for (qidx = 0; qidx < txrx_established; qidx++) {
		struct wm_queue *wmq = &sc->sc_queue[qidx];
		pci_intr_disestablish(sc->sc_pc,sc->sc_ihs[wmq->wmq_intr_idx]);
		sc->sc_ihs[wmq->wmq_intr_idx] = NULL;
	}

	kcpuset_destroy(affinity);
	return ENOMEM;
}

static void
wm_unset_stopping_flags(struct wm_softc *sc)
{
	int i;

	KASSERT(mutex_owned(sc->sc_core_lock));

	/* Must unset stopping flags in ascending order. */
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;

		mutex_enter(txq->txq_lock);
		txq->txq_stopping = false;
		mutex_exit(txq->txq_lock);

		mutex_enter(rxq->rxq_lock);
		rxq->rxq_stopping = false;
		mutex_exit(rxq->rxq_lock);
	}

	sc->sc_core_stopping = false;
}

static void
wm_set_stopping_flags(struct wm_softc *sc)
{
	int i;

	KASSERT(mutex_owned(sc->sc_core_lock));

	sc->sc_core_stopping = true;

	/* Must set stopping flags in ascending order. */
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;

		mutex_enter(rxq->rxq_lock);
		rxq->rxq_stopping = true;
		mutex_exit(rxq->rxq_lock);

		mutex_enter(txq->txq_lock);
		txq->txq_stopping = true;
		mutex_exit(txq->txq_lock);
	}
}

/*
 * Write interrupt interval value to ITR or EITR
 */
static void
wm_itrs_writereg(struct wm_softc *sc, struct wm_queue *wmq)
{

	if (!wmq->wmq_set_itr)
		return;

	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		uint32_t eitr = __SHIFTIN(wmq->wmq_itr, EITR_ITR_INT_MASK);

		/*
		 * 82575 doesn't have CNT_INGR field.
		 * So, overwrite counter field by software.
		 */
		if (sc->sc_type == WM_T_82575)
			eitr |= __SHIFTIN(wmq->wmq_itr,
			    EITR_COUNTER_MASK_82575);
		else
			eitr |= EITR_CNT_INGR;

		CSR_WRITE(sc, WMREG_EITR(wmq->wmq_intr_idx), eitr);
	} else if (sc->sc_type == WM_T_82574 && wm_is_using_msix(sc)) {
		/*
		 * 82574 has both ITR and EITR. SET EITR when we use
		 * the multi queue function with MSI-X.
		 */
		CSR_WRITE(sc, WMREG_EITR_82574(wmq->wmq_intr_idx),
		    wmq->wmq_itr & EITR_ITR_INT_MASK_82574);
	} else {
		KASSERT(wmq->wmq_id == 0);
		CSR_WRITE(sc, WMREG_ITR, wmq->wmq_itr);
	}

	wmq->wmq_set_itr = false;
}

/*
 * TODO
 * Below dynamic calculation of itr is almost the same as Linux igb,
 * however it does not fit to wm(4). So, we will have been disable AIM
 * until we will find appropriate calculation of itr.
 */
/*
 * Calculate interrupt interval value to be going to write register in
 * wm_itrs_writereg(). This function does not write ITR/EITR register.
 */
static void
wm_itrs_calculate(struct wm_softc *sc, struct wm_queue *wmq)
{
#ifdef NOTYET
	struct wm_rxqueue *rxq = &wmq->wmq_rxq;
	struct wm_txqueue *txq = &wmq->wmq_txq;
	uint32_t avg_size = 0;
	uint32_t new_itr;

	if (rxq->rxq_packets)
		avg_size =  rxq->rxq_bytes / rxq->rxq_packets;
	if (txq->txq_packets)
		avg_size = uimax(avg_size, txq->txq_bytes / txq->txq_packets);

	if (avg_size == 0) {
		new_itr = 450; /* restore default value */
		goto out;
	}

	/* Add 24 bytes to size to account for CRC, preamble, and gap */
	avg_size += 24;

	/* Don't starve jumbo frames */
	avg_size = uimin(avg_size, 3000);

	/* Give a little boost to mid-size frames */
	if ((avg_size > 300) && (avg_size < 1200))
		new_itr = avg_size / 3;
	else
		new_itr = avg_size / 2;

out:
	/*
	 * The usage of 82574 and 82575 EITR is different from otther NEWQUEUE
	 * controllers. See sc->sc_itr_init setting in wm_init_locked().
	 */
	if ((sc->sc_flags & WM_F_NEWQUEUE) == 0 || sc->sc_type != WM_T_82575)
		new_itr *= 4;

	if (new_itr != wmq->wmq_itr) {
		wmq->wmq_itr = new_itr;
		wmq->wmq_set_itr = true;
	} else
		wmq->wmq_set_itr = false;

	rxq->rxq_packets = 0;
	rxq->rxq_bytes = 0;
	txq->txq_packets = 0;
	txq->txq_bytes = 0;
#endif
}

static void
wm_init_sysctls(struct wm_softc *sc)
{
	struct sysctllog **log;
	const struct sysctlnode *rnode, *qnode, *cnode;
	int i, rv;
	const char *dvname;

	log = &sc->sc_sysctllog;
	dvname = device_xname(sc->sc_dev);

	rv = sysctl_createv(log, 0, NULL, &rnode,
	    0, CTLTYPE_NODE, dvname,
	    SYSCTL_DESCR("wm information and settings"),
	    NULL, 0, NULL, 0, CTL_HW, CTL_CREATE, CTL_EOL);
	if (rv != 0)
		goto err;

	rv = sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_BOOL, "txrx_workqueue",
	    SYSCTL_DESCR("Use workqueue for packet processing"),
	    NULL, 0, &sc->sc_txrx_use_workqueue, 0, CTL_CREATE, CTL_EOL);
	if (rv != 0)
		goto teardown;

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_queue *wmq = &sc->sc_queue[i];
		struct wm_txqueue *txq = &wmq->wmq_txq;
		struct wm_rxqueue *rxq = &wmq->wmq_rxq;

		snprintf(sc->sc_queue[i].sysctlname,
		    sizeof(sc->sc_queue[i].sysctlname), "q%d", i);

		if (sysctl_createv(log, 0, &rnode, &qnode,
		    0, CTLTYPE_NODE,
		    sc->sc_queue[i].sysctlname, SYSCTL_DESCR("Queue Name"),
		    NULL, 0, NULL, 0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_free", SYSCTL_DESCR("TX queue free"),
		    NULL, 0, &txq->txq_free,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txd_head", SYSCTL_DESCR("TX descriptor head"),
		    wm_sysctl_tdh_handler, 0, (void *)txq,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txd_tail", SYSCTL_DESCR("TX descriptor tail"),
		    wm_sysctl_tdt_handler, 0, (void *)txq,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_next", SYSCTL_DESCR("TX queue next"),
		    NULL, 0, &txq->txq_next,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_sfree", SYSCTL_DESCR("TX queue sfree"),
		    NULL, 0, &txq->txq_sfree,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_snext", SYSCTL_DESCR("TX queue snext"),
		    NULL, 0, &txq->txq_snext,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_sdirty", SYSCTL_DESCR("TX queue sdirty"),
		    NULL, 0, &txq->txq_sdirty,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txq_flags", SYSCTL_DESCR("TX queue flags"),
		    NULL, 0, &txq->txq_flags,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_BOOL,
		    "txq_stopping", SYSCTL_DESCR("TX queue stopping"),
		    NULL, 0, &txq->txq_stopping,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_BOOL,
		    "txq_sending", SYSCTL_DESCR("TX queue sending"),
		    NULL, 0, &txq->txq_sending,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &qnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "rxq_ptr", SYSCTL_DESCR("RX queue pointer"),
		    NULL, 0, &rxq->rxq_ptr,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;
	}

#ifdef WM_DEBUG
	rv = sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_INT, "debug_flags",
	    SYSCTL_DESCR(
		    "Debug flags:\n"	\
		    "\t0x01 LINK\n"	\
		    "\t0x02 TX\n"	\
		    "\t0x04 RX\n"	\
		    "\t0x08 GMII\n"	\
		    "\t0x10 MANAGE\n"	\
		    "\t0x20 NVM\n"	\
		    "\t0x40 INIT\n"	\
		    "\t0x80 LOCK"),
	    wm_sysctl_debug, 0, (void *)sc, 0, CTL_CREATE, CTL_EOL);
	if (rv != 0)
		goto teardown;
	rv = sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_BOOL, "trigger_reset",
	    SYSCTL_DESCR("Trigger an interface reset"),
	    NULL, 0, &sc->sc_trigger_reset, 0, CTL_CREATE, CTL_EOL);
	if (rv != 0)
		goto teardown;
#endif

	return;

teardown:
	sysctl_teardown(log);
err:
	sc->sc_sysctllog = NULL;
	device_printf(sc->sc_dev, "%s: sysctl_createv failed, rv = %d\n",
	    __func__, rv);
}

static void
wm_update_stats(struct wm_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	uint64_t crcerrs, algnerrc, symerrc, mpc, colc,  sec, rlec, rxerrc,
	    cexterr;
	uint64_t total_qdrop = 0;

	crcerrs = CSR_READ(sc, WMREG_CRCERRS);
	symerrc = CSR_READ(sc, WMREG_SYMERRC);
	mpc = CSR_READ(sc, WMREG_MPC);
	colc = CSR_READ(sc, WMREG_COLC);
	sec = CSR_READ(sc, WMREG_SEC);
	rlec = CSR_READ(sc, WMREG_RLEC);

	WM_EVCNT_ADD(&sc->sc_ev_crcerrs, crcerrs);
	WM_EVCNT_ADD(&sc->sc_ev_symerrc, symerrc);
	WM_EVCNT_ADD(&sc->sc_ev_mpc, mpc);
	WM_EVCNT_ADD(&sc->sc_ev_colc, colc);
	WM_EVCNT_ADD(&sc->sc_ev_sec, sec);
	WM_EVCNT_ADD(&sc->sc_ev_rlec, rlec);

	if (sc->sc_type >= WM_T_82543) {
		algnerrc = CSR_READ(sc, WMREG_ALGNERRC);
		rxerrc = CSR_READ(sc, WMREG_RXERRC);
		WM_EVCNT_ADD(&sc->sc_ev_algnerrc, algnerrc);
		WM_EVCNT_ADD(&sc->sc_ev_rxerrc, rxerrc);
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc)) {
			cexterr = CSR_READ(sc, WMREG_CEXTERR);
			WM_EVCNT_ADD(&sc->sc_ev_cexterr, cexterr);
		} else {
			cexterr = 0;
			/* Excessive collision + Link down */
			WM_EVCNT_ADD(&sc->sc_ev_htdpmc,
			    CSR_READ(sc, WMREG_HTDPMC));
		}

		WM_EVCNT_ADD(&sc->sc_ev_tncrs, CSR_READ(sc, WMREG_TNCRS));
		WM_EVCNT_ADD(&sc->sc_ev_tsctc, CSR_READ(sc, WMREG_TSCTC));
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			WM_EVCNT_ADD(&sc->sc_ev_tsctfc,
			    CSR_READ(sc, WMREG_TSCTFC));
		else {
			WM_EVCNT_ADD(&sc->sc_ev_cbrdpc,
			    CSR_READ(sc, WMREG_CBRDPC));
			WM_EVCNT_ADD(&sc->sc_ev_cbrmpc,
			    CSR_READ(sc, WMREG_CBRMPC));
		}
	} else
		algnerrc = rxerrc = cexterr = 0;

	if (sc->sc_type >= WM_T_82542_2_1) {
		WM_EVCNT_ADD(&sc->sc_ev_rx_xon, CSR_READ(sc, WMREG_XONRXC));
		WM_EVCNT_ADD(&sc->sc_ev_tx_xon, CSR_READ(sc, WMREG_XONTXC));
		WM_EVCNT_ADD(&sc->sc_ev_rx_xoff, CSR_READ(sc, WMREG_XOFFRXC));
		WM_EVCNT_ADD(&sc->sc_ev_tx_xoff, CSR_READ(sc, WMREG_XOFFTXC));
		WM_EVCNT_ADD(&sc->sc_ev_rx_macctl, CSR_READ(sc, WMREG_FCRUC));
	}

	WM_EVCNT_ADD(&sc->sc_ev_scc, CSR_READ(sc, WMREG_SCC));
	WM_EVCNT_ADD(&sc->sc_ev_ecol, CSR_READ(sc, WMREG_ECOL));
	WM_EVCNT_ADD(&sc->sc_ev_mcc, CSR_READ(sc, WMREG_MCC));
	WM_EVCNT_ADD(&sc->sc_ev_latecol, CSR_READ(sc, WMREG_LATECOL));

	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc)) {
		WM_EVCNT_ADD(&sc->sc_ev_cbtmpc, CSR_READ(sc, WMREG_CBTMPC));
	}

	WM_EVCNT_ADD(&sc->sc_ev_dc, CSR_READ(sc, WMREG_DC));
	WM_EVCNT_ADD(&sc->sc_ev_prc64, CSR_READ(sc, WMREG_PRC64));
	WM_EVCNT_ADD(&sc->sc_ev_prc127, CSR_READ(sc, WMREG_PRC127));
	WM_EVCNT_ADD(&sc->sc_ev_prc255, CSR_READ(sc, WMREG_PRC255));
	WM_EVCNT_ADD(&sc->sc_ev_prc511, CSR_READ(sc, WMREG_PRC511));
	WM_EVCNT_ADD(&sc->sc_ev_prc1023, CSR_READ(sc, WMREG_PRC1023));
	WM_EVCNT_ADD(&sc->sc_ev_prc1522, CSR_READ(sc, WMREG_PRC1522));
	WM_EVCNT_ADD(&sc->sc_ev_gprc, CSR_READ(sc, WMREG_GPRC));
	WM_EVCNT_ADD(&sc->sc_ev_bprc, CSR_READ(sc, WMREG_BPRC));
	WM_EVCNT_ADD(&sc->sc_ev_mprc, CSR_READ(sc, WMREG_MPRC));
	WM_EVCNT_ADD(&sc->sc_ev_gptc, CSR_READ(sc, WMREG_GPTC));

	WM_EVCNT_ADD(&sc->sc_ev_gorc,
	    CSR_READ(sc, WMREG_GORCL) +
	    ((uint64_t)CSR_READ(sc, WMREG_GORCH) << 32));
	WM_EVCNT_ADD(&sc->sc_ev_gotc,
	    CSR_READ(sc, WMREG_GOTCL) +
	    ((uint64_t)CSR_READ(sc, WMREG_GOTCH) << 32));

	WM_EVCNT_ADD(&sc->sc_ev_rnbc, CSR_READ(sc, WMREG_RNBC));
	WM_EVCNT_ADD(&sc->sc_ev_ruc, CSR_READ(sc, WMREG_RUC));
	WM_EVCNT_ADD(&sc->sc_ev_rfc, CSR_READ(sc, WMREG_RFC));
	WM_EVCNT_ADD(&sc->sc_ev_roc, CSR_READ(sc, WMREG_ROC));
	WM_EVCNT_ADD(&sc->sc_ev_rjc, CSR_READ(sc, WMREG_RJC));

	if (sc->sc_type >= WM_T_82540) {
		WM_EVCNT_ADD(&sc->sc_ev_mgtprc, CSR_READ(sc, WMREG_MGTPRC));
		WM_EVCNT_ADD(&sc->sc_ev_mgtpdc, CSR_READ(sc, WMREG_MGTPDC));
		WM_EVCNT_ADD(&sc->sc_ev_mgtptc, CSR_READ(sc, WMREG_MGTPTC));
	}

	/*
	 * The TOR(L) register includes:
	 *  - Error
	 *  - Flow control
	 *  - Broadcast rejected (This note is described in 82574 and newer
	 *    datasheets. What does "broadcast rejected" mean?)
	 */
	WM_EVCNT_ADD(&sc->sc_ev_tor,
	    CSR_READ(sc, WMREG_TORL) +
	    ((uint64_t)CSR_READ(sc, WMREG_TORH) << 32));
	WM_EVCNT_ADD(&sc->sc_ev_tot,
	    CSR_READ(sc, WMREG_TOTL) +
	    ((uint64_t)CSR_READ(sc, WMREG_TOTH) << 32));

	WM_EVCNT_ADD(&sc->sc_ev_tpr, CSR_READ(sc, WMREG_TPR));
	WM_EVCNT_ADD(&sc->sc_ev_tpt, CSR_READ(sc, WMREG_TPT));
	WM_EVCNT_ADD(&sc->sc_ev_ptc64, CSR_READ(sc, WMREG_PTC64));
	WM_EVCNT_ADD(&sc->sc_ev_ptc127, CSR_READ(sc, WMREG_PTC127));
	WM_EVCNT_ADD(&sc->sc_ev_ptc255, CSR_READ(sc, WMREG_PTC255));
	WM_EVCNT_ADD(&sc->sc_ev_ptc511, CSR_READ(sc, WMREG_PTC511));
	WM_EVCNT_ADD(&sc->sc_ev_ptc1023, CSR_READ(sc, WMREG_PTC1023));
	WM_EVCNT_ADD(&sc->sc_ev_ptc1522, CSR_READ(sc, WMREG_PTC1522));
	WM_EVCNT_ADD(&sc->sc_ev_mptc, CSR_READ(sc, WMREG_MPTC));
	WM_EVCNT_ADD(&sc->sc_ev_bptc, CSR_READ(sc, WMREG_BPTC));
	if (sc->sc_type >= WM_T_82571)
		WM_EVCNT_ADD(&sc->sc_ev_iac, CSR_READ(sc, WMREG_IAC));
	if (sc->sc_type < WM_T_82575) {
		WM_EVCNT_ADD(&sc->sc_ev_icrxptc, CSR_READ(sc, WMREG_ICRXPTC));
		WM_EVCNT_ADD(&sc->sc_ev_icrxatc, CSR_READ(sc, WMREG_ICRXATC));
		WM_EVCNT_ADD(&sc->sc_ev_ictxptc, CSR_READ(sc, WMREG_ICTXPTC));
		WM_EVCNT_ADD(&sc->sc_ev_ictxatc, CSR_READ(sc, WMREG_ICTXATC));
		WM_EVCNT_ADD(&sc->sc_ev_ictxqec, CSR_READ(sc, WMREG_ICTXQEC));
		WM_EVCNT_ADD(&sc->sc_ev_ictxqmtc,
		    CSR_READ(sc, WMREG_ICTXQMTC));
		WM_EVCNT_ADD(&sc->sc_ev_rxdmtc,
		    CSR_READ(sc, WMREG_ICRXDMTC));
		WM_EVCNT_ADD(&sc->sc_ev_icrxoc, CSR_READ(sc, WMREG_ICRXOC));
	} else if (!WM_IS_ICHPCH(sc)) {
		WM_EVCNT_ADD(&sc->sc_ev_rpthc, CSR_READ(sc, WMREG_RPTHC));
		WM_EVCNT_ADD(&sc->sc_ev_debug1, CSR_READ(sc, WMREG_DEBUG1));
		WM_EVCNT_ADD(&sc->sc_ev_debug2, CSR_READ(sc, WMREG_DEBUG2));
		WM_EVCNT_ADD(&sc->sc_ev_debug3, CSR_READ(sc, WMREG_DEBUG3));
		WM_EVCNT_ADD(&sc->sc_ev_hgptc,  CSR_READ(sc, WMREG_HGPTC));
		WM_EVCNT_ADD(&sc->sc_ev_debug4, CSR_READ(sc, WMREG_DEBUG4));
		WM_EVCNT_ADD(&sc->sc_ev_rxdmtc, CSR_READ(sc, WMREG_RXDMTC));
		WM_EVCNT_ADD(&sc->sc_ev_htcbdpc, CSR_READ(sc, WMREG_HTCBDPC));

		WM_EVCNT_ADD(&sc->sc_ev_hgorc,
		    CSR_READ(sc, WMREG_HGORCL) +
		    ((uint64_t)CSR_READ(sc, WMREG_HGORCH) << 32));
		WM_EVCNT_ADD(&sc->sc_ev_hgotc,
		    CSR_READ(sc, WMREG_HGOTCL) +
		    ((uint64_t)CSR_READ(sc, WMREG_HGOTCH) << 32));
		WM_EVCNT_ADD(&sc->sc_ev_lenerrs, CSR_READ(sc, WMREG_LENERRS));
		WM_EVCNT_ADD(&sc->sc_ev_scvpc, CSR_READ(sc, WMREG_SCVPC));
		WM_EVCNT_ADD(&sc->sc_ev_hrmpc, CSR_READ(sc, WMREG_HRMPC));
#ifdef WM_EVENT_COUNTERS
		for (int i = 0; i < sc->sc_nqueues; i++) {
			struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
			uint32_t rqdpc;

			rqdpc = CSR_READ(sc, WMREG_RQDPC(i));
			/*
			 * On I210 and newer device, the RQDPC register is not
			 * cleard on read.
			 */
			if ((rqdpc != 0) && (sc->sc_type >= WM_T_I210))
				CSR_WRITE(sc, WMREG_RQDPC(i), 0);
			WM_Q_EVCNT_ADD(rxq, qdrop, rqdpc);
			total_qdrop += rqdpc;
		}
#endif
	}
	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc)) {
		WM_EVCNT_ADD(&sc->sc_ev_tlpic, CSR_READ(sc, WMREG_TLPIC));
		WM_EVCNT_ADD(&sc->sc_ev_rlpic, CSR_READ(sc, WMREG_RLPIC));
		if ((CSR_READ(sc, WMREG_MANC) & MANC_EN_BMC2OS) != 0) {
			WM_EVCNT_ADD(&sc->sc_ev_b2ogprc,
			    CSR_READ(sc, WMREG_B2OGPRC));
			WM_EVCNT_ADD(&sc->sc_ev_o2bspc,
			    CSR_READ(sc, WMREG_O2BSPC));
			WM_EVCNT_ADD(&sc->sc_ev_b2ospc,
			    CSR_READ(sc, WMREG_B2OSPC));
			WM_EVCNT_ADD(&sc->sc_ev_o2bgptc,
			    CSR_READ(sc, WMREG_O2BGPTC));
		}
	}
	net_stat_ref_t nsr = IF_STAT_GETREF(ifp);
	if_statadd_ref(ifp, nsr, if_collisions, colc);
	if_statadd_ref(ifp, nsr, if_ierrors,
	    crcerrs + algnerrc + symerrc + rxerrc + sec + cexterr + rlec);
	/*
	 * WMREG_RNBC is incremented when there are no available buffers in
	 * host memory. It does not mean the number of dropped packets, because
	 * an Ethernet controller can receive packets in such case if there is
	 * space in the phy's FIFO.
	 *
	 * If you want to know the nubmer of WMREG_RMBC, you should use such as
	 * own EVCNT instead of if_iqdrops.
	 */
	if_statadd_ref(ifp, nsr, if_iqdrops, mpc + total_qdrop);
	IF_STAT_PUTREF(ifp);
}

void
wm_clear_evcnt(struct wm_softc *sc)
{
#ifdef WM_EVENT_COUNTERS
	int i;

	/* RX queues */
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;

		WM_Q_EVCNT_STORE(rxq, intr, 0);
		WM_Q_EVCNT_STORE(rxq, defer, 0);
		WM_Q_EVCNT_STORE(rxq, ipsum, 0);
		WM_Q_EVCNT_STORE(rxq, tusum, 0);
		if ((sc->sc_type >= WM_T_82575) && !WM_IS_ICHPCH(sc))
			WM_Q_EVCNT_STORE(rxq, qdrop, 0);
	}

	/* TX queues */
	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
		int j;

		WM_Q_EVCNT_STORE(txq, txsstall, 0);
		WM_Q_EVCNT_STORE(txq, txdstall, 0);
		WM_Q_EVCNT_STORE(txq, fifo_stall, 0);
		WM_Q_EVCNT_STORE(txq, txdw, 0);
		WM_Q_EVCNT_STORE(txq, txqe, 0);
		WM_Q_EVCNT_STORE(txq, ipsum, 0);
		WM_Q_EVCNT_STORE(txq, tusum, 0);
		WM_Q_EVCNT_STORE(txq, tusum6, 0);
		WM_Q_EVCNT_STORE(txq, tso, 0);
		WM_Q_EVCNT_STORE(txq, tso6, 0);
		WM_Q_EVCNT_STORE(txq, tsopain, 0);

		for (j = 0; j < WM_NTXSEGS; j++)
			WM_EVCNT_STORE(&txq->txq_ev_txseg[j], 0);

		WM_Q_EVCNT_STORE(txq, pcqdrop, 0);
		WM_Q_EVCNT_STORE(txq, descdrop, 0);
		WM_Q_EVCNT_STORE(txq, toomanyseg, 0);
		WM_Q_EVCNT_STORE(txq, defrag, 0);
		if (sc->sc_type <= WM_T_82544)
			WM_Q_EVCNT_STORE(txq, underrun, 0);
		WM_Q_EVCNT_STORE(txq, skipcontext, 0);
	}

	/* Miscs */
	WM_EVCNT_STORE(&sc->sc_ev_linkintr, 0);

	WM_EVCNT_STORE(&sc->sc_ev_crcerrs, 0);
	WM_EVCNT_STORE(&sc->sc_ev_symerrc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_mpc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_colc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_sec, 0);
	WM_EVCNT_STORE(&sc->sc_ev_rlec, 0);

	if (sc->sc_type >= WM_T_82543) {
		WM_EVCNT_STORE(&sc->sc_ev_algnerrc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rxerrc, 0);
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			WM_EVCNT_STORE(&sc->sc_ev_cexterr, 0);
		else
			WM_EVCNT_STORE(&sc->sc_ev_htdpmc, 0);

		WM_EVCNT_STORE(&sc->sc_ev_tncrs, 0);
		WM_EVCNT_STORE(&sc->sc_ev_tsctc, 0);
		if ((sc->sc_type < WM_T_82575) || WM_IS_ICHPCH(sc))
			WM_EVCNT_STORE(&sc->sc_ev_tsctfc, 0);
		else {
			WM_EVCNT_STORE(&sc->sc_ev_cbrdpc, 0);
			WM_EVCNT_STORE(&sc->sc_ev_cbrmpc, 0);
		}
	}

	if (sc->sc_type >= WM_T_82542_2_1) {
		WM_EVCNT_STORE(&sc->sc_ev_tx_xoff, 0);
		WM_EVCNT_STORE(&sc->sc_ev_tx_xon, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rx_xoff, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rx_xon, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rx_macctl, 0);
	}

	WM_EVCNT_STORE(&sc->sc_ev_scc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ecol, 0);
	WM_EVCNT_STORE(&sc->sc_ev_mcc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_latecol, 0);

	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc))
		WM_EVCNT_STORE(&sc->sc_ev_cbtmpc, 0);

	WM_EVCNT_STORE(&sc->sc_ev_dc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc64, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc127, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc255, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc511, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc1023, 0);
	WM_EVCNT_STORE(&sc->sc_ev_prc1522, 0);
	WM_EVCNT_STORE(&sc->sc_ev_gprc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_bprc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_mprc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_gptc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_gorc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_gotc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_rnbc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ruc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_rfc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_roc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_rjc, 0);
	if (sc->sc_type >= WM_T_82540) {
		WM_EVCNT_STORE(&sc->sc_ev_mgtprc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_mgtpdc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_mgtptc, 0);
	}
	WM_EVCNT_STORE(&sc->sc_ev_tor, 0);
	WM_EVCNT_STORE(&sc->sc_ev_tot, 0);
	WM_EVCNT_STORE(&sc->sc_ev_tpr, 0);
	WM_EVCNT_STORE(&sc->sc_ev_tpt, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc64, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc127, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc255, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc511, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc1023, 0);
	WM_EVCNT_STORE(&sc->sc_ev_ptc1522, 0);
	WM_EVCNT_STORE(&sc->sc_ev_mptc, 0);
	WM_EVCNT_STORE(&sc->sc_ev_bptc, 0);
	if (sc->sc_type >= WM_T_82571)
		WM_EVCNT_STORE(&sc->sc_ev_iac, 0);
	if (sc->sc_type < WM_T_82575) {
		WM_EVCNT_STORE(&sc->sc_ev_icrxptc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_icrxatc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_ictxptc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_ictxatc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_ictxqec, 0);
		WM_EVCNT_STORE(&sc->sc_ev_ictxqmtc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rxdmtc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_icrxoc, 0);
	} else if (!WM_IS_ICHPCH(sc)) {
		WM_EVCNT_STORE(&sc->sc_ev_rpthc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_debug1, 0);
		WM_EVCNT_STORE(&sc->sc_ev_debug2, 0);
		WM_EVCNT_STORE(&sc->sc_ev_debug3, 0);
		WM_EVCNT_STORE(&sc->sc_ev_hgptc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_debug4, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rxdmtc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_htcbdpc, 0);

		WM_EVCNT_STORE(&sc->sc_ev_hgorc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_hgotc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_lenerrs, 0);
		WM_EVCNT_STORE(&sc->sc_ev_scvpc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_hrmpc, 0);
	}
	if ((sc->sc_type >= WM_T_I350) && !WM_IS_ICHPCH(sc)) {
		WM_EVCNT_STORE(&sc->sc_ev_tlpic, 0);
		WM_EVCNT_STORE(&sc->sc_ev_rlpic, 0);
		WM_EVCNT_STORE(&sc->sc_ev_b2ogprc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_o2bspc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_b2ospc, 0);
		WM_EVCNT_STORE(&sc->sc_ev_o2bgptc, 0);
	}
#endif
}

/*
 * wm_init:		[ifnet interface function]
 *
 *	Initialize the interface.
 */
static int
wm_init(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	int ret;

	KASSERT(IFNET_LOCKED(ifp));

	if (sc->sc_dying)
		return ENXIO;

	mutex_enter(sc->sc_core_lock);
	ret = wm_init_locked(ifp);
	mutex_exit(sc->sc_core_lock);

	return ret;
}

static int
wm_init_locked(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct ethercom *ec = &sc->sc_ethercom;
	int i, j, trynum, error = 0;
	uint32_t reg, sfp_mask = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(IFNET_LOCKED(ifp));
	KASSERT(mutex_owned(sc->sc_core_lock));

	/*
	 * *_HDR_ALIGNED_P is constant 1 if __NO_STRICT_ALIGMENT is set.
	 * There is a small but measurable benefit to avoiding the adjusment
	 * of the descriptor so that the headers are aligned, for normal mtu,
	 * on such platforms.  One possibility is that the DMA itself is
	 * slightly more efficient if the front of the entire packet (instead
	 * of the front of the headers) is aligned.
	 *
	 * Note we must always set align_tweak to 0 if we are using
	 * jumbo frames.
	 */
#ifdef __NO_STRICT_ALIGNMENT
	sc->sc_align_tweak = 0;
#else
	if ((ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN) > (MCLBYTES - 2))
		sc->sc_align_tweak = 0;
	else
		sc->sc_align_tweak = 2;
#endif /* __NO_STRICT_ALIGNMENT */

	/* Cancel any pending I/O. */
	wm_stop_locked(ifp, false, false);

	/* Update statistics before reset */
	if_statadd2(ifp, if_collisions, CSR_READ(sc, WMREG_COLC),
	    if_ierrors, CSR_READ(sc, WMREG_RXERRC));

	/* >= PCH_SPT hardware workaround before reset. */
	if (sc->sc_type >= WM_T_PCH_SPT)
		wm_flush_desc_rings(sc);

	/* Reset the chip to a known state. */
	wm_reset(sc);

	/*
	 * AMT based hardware can now take control from firmware
	 * Do this after reset.
	 */
	if ((sc->sc_flags & WM_F_HAS_AMT) != 0)
		wm_get_hw_control(sc);

	if ((sc->sc_type >= WM_T_PCH_SPT) &&
	    pci_intr_type(sc->sc_pc, sc->sc_intrs[0]) == PCI_INTR_TYPE_INTX)
		wm_legacy_irq_quirk_spt(sc);

	/* Init hardware bits */
	wm_initialize_hardware_bits(sc);

	/* Reset the PHY. */
	if (sc->sc_flags & WM_F_HAS_MII)
		wm_gmii_reset(sc);

	if (sc->sc_type >= WM_T_ICH8) {
		reg = CSR_READ(sc, WMREG_GCR);
		/*
		 * ICH8 No-snoop bits are opposite polarity. Set to snoop by
		 * default after reset.
		 */
		if (sc->sc_type == WM_T_ICH8)
			reg |= GCR_NO_SNOOP_ALL;
		else
			reg &= ~GCR_NO_SNOOP_ALL;
		CSR_WRITE(sc, WMREG_GCR, reg);
	}

	/* Ungate DMA clock to avoid packet loss */
	if (sc->sc_type >= WM_T_PCH_TGP) {
		reg = CSR_READ(sc, WMREG_FFLT_DBG);
		reg |= (1 << 12);
		CSR_WRITE(sc, WMREG_FFLT_DBG, reg);
	}

	if ((sc->sc_type >= WM_T_ICH8)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_82546GB_QUAD_COPPER)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_82546GB_QUAD_COPPER_KSP3)) {

		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		reg |= CTRL_EXT_RO_DIS;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
	}

	/* Calculate (E)ITR value */
	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0 && sc->sc_type != WM_T_82575) {
		/*
		 * For NEWQUEUE's EITR (except for 82575).
		 * 82575's EITR should be set same throttling value as other
		 * old controllers' ITR because the interrupt/sec calculation
		 * is the same, that is, 1,000,000,000 / (N * 256).
		 *
		 * 82574's EITR should be set same throttling value as ITR.
		 *
		 * For N interrupts/sec, set this value to:
		 * 1,000,000 / N in contrast to ITR throttling value.
		 */
		sc->sc_itr_init = 450;
	} else if (sc->sc_type >= WM_T_82543) {
		/*
		 * Set up the interrupt throttling register (units of 256ns)
		 * Note that a footnote in Intel's documentation says this
		 * ticker runs at 1/4 the rate when the chip is in 100Mbit
		 * or 10Mbit mode.  Empirically, it appears to be the case
		 * that that is also true for the 1024ns units of the other
		 * interrupt-related timer registers -- so, really, we ought
		 * to divide this value by 4 when the link speed is low.
		 *
		 * XXX implement this division at link speed change!
		 */

		/*
		 * For N interrupts/sec, set this value to:
		 * 1,000,000,000 / (N * 256).  Note that we set the
		 * absolute and packet timer values to this value
		 * divided by 4 to get "simple timer" behavior.
		 */
		sc->sc_itr_init = 1500;		/* 2604 ints/sec */
	}

	error = wm_init_txrx_queues(sc);
	if (error)
		goto out;

	if (((sc->sc_flags & WM_F_SGMII) == 0) &&
	    (sc->sc_mediatype == WM_MEDIATYPE_SERDES) &&
	    (sc->sc_type >= WM_T_82575))
		wm_serdes_power_up_link_82575(sc);

	/* Clear out the VLAN table -- we don't use it (yet). */
	CSR_WRITE(sc, WMREG_VET, 0);
	if ((sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354))
		trynum = 10; /* Due to hw errata */
	else
		trynum = 1;
	for (i = 0; i < WM_VLAN_TABSIZE; i++)
		for (j = 0; j < trynum; j++)
			CSR_WRITE(sc, WMREG_VFTA + (i << 2), 0);

	/*
	 * Set up flow-control parameters.
	 *
	 * XXX Values could probably stand some tuning.
	 */
	if ((sc->sc_type != WM_T_ICH8) && (sc->sc_type != WM_T_ICH9)
	    && (sc->sc_type != WM_T_ICH10) && (sc->sc_type != WM_T_PCH)
	    && (sc->sc_type != WM_T_PCH2) && (sc->sc_type != WM_T_PCH_LPT)
	    && (sc->sc_type != WM_T_PCH_SPT) && (sc->sc_type != WM_T_PCH_CNP)
	    && (sc->sc_type != WM_T_PCH_TGP)) {
		CSR_WRITE(sc, WMREG_FCAL, FCAL_CONST);
		CSR_WRITE(sc, WMREG_FCAH, FCAH_CONST);
		CSR_WRITE(sc, WMREG_FCT, ETHERTYPE_FLOWCONTROL);
	}

	sc->sc_fcrtl = FCRTL_DFLT;
	if (sc->sc_type < WM_T_82543) {
		CSR_WRITE(sc, WMREG_OLD_FCRTH, FCRTH_DFLT);
		CSR_WRITE(sc, WMREG_OLD_FCRTL, sc->sc_fcrtl);
	} else {
		CSR_WRITE(sc, WMREG_FCRTH, FCRTH_DFLT);
		CSR_WRITE(sc, WMREG_FCRTL, sc->sc_fcrtl);
	}

	if (sc->sc_type == WM_T_80003)
		CSR_WRITE(sc, WMREG_FCTTV, 0xffff);
	else
		CSR_WRITE(sc, WMREG_FCTTV, FCTTV_DFLT);

	/* Writes the control register. */
	wm_set_vlan(sc);

	if (sc->sc_flags & WM_F_HAS_MII) {
		uint16_t kmreg;

		switch (sc->sc_type) {
		case WM_T_80003:
		case WM_T_ICH8:
		case WM_T_ICH9:
		case WM_T_ICH10:
		case WM_T_PCH:
		case WM_T_PCH2:
		case WM_T_PCH_LPT:
		case WM_T_PCH_SPT:
		case WM_T_PCH_CNP:
		case WM_T_PCH_TGP:
			/*
			 * Set the mac to wait the maximum time between each
			 * iteration and increase the max iterations when
			 * polling the phy; this fixes erroneous timeouts at
			 * 10Mbps.
			 */
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_TIMEOUTS,
			    0xFFFF);
			wm_kmrn_readreg(sc, KUMCTRLSTA_OFFSET_INB_PARAM,
			    &kmreg);
			kmreg |= 0x3F;
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_INB_PARAM,
			    kmreg);
			break;
		default:
			break;
		}

		if (sc->sc_type == WM_T_80003) {
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg &= ~CTRL_EXT_LINK_MODE_MASK;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			/* Bypass RX and TX FIFOs */
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_FIFO_CTRL,
			    KUMCTRLSTA_FIFO_CTRL_RX_BYPASS
			    | KUMCTRLSTA_FIFO_CTRL_TX_BYPASS);
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_INB_CTRL,
			    KUMCTRLSTA_INB_CTRL_DIS_PADDING |
			    KUMCTRLSTA_INB_CTRL_LINK_TMOUT_DFLT);
		}
	}
#if 0
	CSR_WRITE(sc, WMREG_CTRL_EXT, sc->sc_ctrl_ext);
#endif

	/* Set up checksum offload parameters. */
	reg = CSR_READ(sc, WMREG_RXCSUM);
	reg &= ~(RXCSUM_IPOFL | RXCSUM_IPV6OFL | RXCSUM_TUOFL);
	if (ifp->if_capenable & IFCAP_CSUM_IPv4_Rx)
		reg |= RXCSUM_IPOFL;
	if (ifp->if_capenable & (IFCAP_CSUM_TCPv4_Rx | IFCAP_CSUM_UDPv4_Rx))
		reg |= RXCSUM_IPOFL | RXCSUM_TUOFL;
	if (ifp->if_capenable & (IFCAP_CSUM_TCPv6_Rx | IFCAP_CSUM_UDPv6_Rx))
		reg |= RXCSUM_IPV6OFL | RXCSUM_TUOFL;
	CSR_WRITE(sc, WMREG_RXCSUM, reg);

	/* Set registers about MSI-X */
	if (wm_is_using_msix(sc)) {
		uint32_t ivar, qintr_idx;
		struct wm_queue *wmq;
		unsigned int qid;

		if (sc->sc_type == WM_T_82575) {
			/* Interrupt control */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg |= CTRL_EXT_PBA | CTRL_EXT_EIAME | CTRL_EXT_NSICR;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			/* TX and RX */
			for (i = 0; i < sc->sc_nqueues; i++) {
				wmq = &sc->sc_queue[i];
				CSR_WRITE(sc, WMREG_MSIXBM(wmq->wmq_intr_idx),
				    EITR_TX_QUEUE(wmq->wmq_id)
				    | EITR_RX_QUEUE(wmq->wmq_id));
			}
			/* Link status */
			CSR_WRITE(sc, WMREG_MSIXBM(sc->sc_link_intr_idx),
			    EITR_OTHER);
		} else if (sc->sc_type == WM_T_82574) {
			/* Interrupt control */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg |= CTRL_EXT_PBA | CTRL_EXT_EIAME;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			/*
			 * Work around issue with spurious interrupts
			 * in MSI-X mode.
			 * At wm_initialize_hardware_bits(), sc_nintrs has not
			 * initialized yet. So re-initialize WMREG_RFCTL here.
			 */
			reg = CSR_READ(sc, WMREG_RFCTL);
			reg |= WMREG_RFCTL_ACKDIS;
			CSR_WRITE(sc, WMREG_RFCTL, reg);

			ivar = 0;
			/* TX and RX */
			for (i = 0; i < sc->sc_nqueues; i++) {
				wmq = &sc->sc_queue[i];
				qid = wmq->wmq_id;
				qintr_idx = wmq->wmq_intr_idx;

				ivar |= __SHIFTIN((IVAR_VALID_82574|qintr_idx),
				    IVAR_TX_MASK_Q_82574(qid));
				ivar |= __SHIFTIN((IVAR_VALID_82574|qintr_idx),
				    IVAR_RX_MASK_Q_82574(qid));
			}
			/* Link status */
			ivar |= __SHIFTIN((IVAR_VALID_82574
				| sc->sc_link_intr_idx), IVAR_OTHER_MASK);
			CSR_WRITE(sc, WMREG_IVAR, ivar | IVAR_INT_ON_ALL_WB);
		} else {
			/* Interrupt control */
			CSR_WRITE(sc, WMREG_GPIE, GPIE_NSICR | GPIE_MULTI_MSIX
			    | GPIE_EIAME | GPIE_PBA);

			switch (sc->sc_type) {
			case WM_T_82580:
			case WM_T_I350:
			case WM_T_I354:
			case WM_T_I210:
			case WM_T_I211:
				/* TX and RX */
				for (i = 0; i < sc->sc_nqueues; i++) {
					wmq = &sc->sc_queue[i];
					qid = wmq->wmq_id;
					qintr_idx = wmq->wmq_intr_idx;

					ivar = CSR_READ(sc, WMREG_IVAR_Q(qid));
					ivar &= ~IVAR_TX_MASK_Q(qid);
					ivar |= __SHIFTIN((qintr_idx
						| IVAR_VALID),
					    IVAR_TX_MASK_Q(qid));
					ivar &= ~IVAR_RX_MASK_Q(qid);
					ivar |= __SHIFTIN((qintr_idx
						| IVAR_VALID),
					    IVAR_RX_MASK_Q(qid));
					CSR_WRITE(sc, WMREG_IVAR_Q(qid), ivar);
				}
				break;
			case WM_T_82576:
				/* TX and RX */
				for (i = 0; i < sc->sc_nqueues; i++) {
					wmq = &sc->sc_queue[i];
					qid = wmq->wmq_id;
					qintr_idx = wmq->wmq_intr_idx;

					ivar = CSR_READ(sc,
					    WMREG_IVAR_Q_82576(qid));
					ivar &= ~IVAR_TX_MASK_Q_82576(qid);
					ivar |= __SHIFTIN((qintr_idx
						| IVAR_VALID),
					    IVAR_TX_MASK_Q_82576(qid));
					ivar &= ~IVAR_RX_MASK_Q_82576(qid);
					ivar |= __SHIFTIN((qintr_idx
						| IVAR_VALID),
					    IVAR_RX_MASK_Q_82576(qid));
					CSR_WRITE(sc, WMREG_IVAR_Q_82576(qid),
					    ivar);
				}
				break;
			default:
				break;
			}

			/* Link status */
			ivar = __SHIFTIN((sc->sc_link_intr_idx | IVAR_VALID),
			    IVAR_MISC_OTHER);
			CSR_WRITE(sc, WMREG_IVAR_MISC, ivar);
		}

		if (wm_is_using_multiqueue(sc)) {
			wm_init_rss(sc);

			/*
			** NOTE: Receive Full-Packet Checksum Offload
			** is mutually exclusive with Multiqueue. However
			** this is not the same as TCP/IP checksums which
			** still work.
			*/
			reg = CSR_READ(sc, WMREG_RXCSUM);
			reg |= RXCSUM_PCSD;
			CSR_WRITE(sc, WMREG_RXCSUM, reg);
		}
	}

	/* Set up the interrupt registers. */
	CSR_WRITE(sc, WMREG_IMC, 0xffffffffU);

	/* Enable SFP module insertion interrupt if it's required */
	if ((sc->sc_flags & WM_F_SFP) != 0) {
		sc->sc_ctrl |= CTRL_EXTLINK_EN;
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
		sfp_mask = ICR_GPI(0);
	}

	if (wm_is_using_msix(sc)) {
		uint32_t mask;
		struct wm_queue *wmq;

		switch (sc->sc_type) {
		case WM_T_82574:
			mask = 0;
			for (i = 0; i < sc->sc_nqueues; i++) {
				wmq = &sc->sc_queue[i];
				mask |= ICR_TXQ(wmq->wmq_id);
				mask |= ICR_RXQ(wmq->wmq_id);
			}
			mask |= ICR_OTHER;
			CSR_WRITE(sc, WMREG_EIAC_82574, mask);
			CSR_WRITE(sc, WMREG_IMS, mask | ICR_LSC);
			break;
		default:
			if (sc->sc_type == WM_T_82575) {
				mask = 0;
				for (i = 0; i < sc->sc_nqueues; i++) {
					wmq = &sc->sc_queue[i];
					mask |= EITR_TX_QUEUE(wmq->wmq_id);
					mask |= EITR_RX_QUEUE(wmq->wmq_id);
				}
				mask |= EITR_OTHER;
			} else {
				mask = 0;
				for (i = 0; i < sc->sc_nqueues; i++) {
					wmq = &sc->sc_queue[i];
					mask |= 1 << wmq->wmq_intr_idx;
				}
				mask |= 1 << sc->sc_link_intr_idx;
			}
			CSR_WRITE(sc, WMREG_EIAC, mask);
			CSR_WRITE(sc, WMREG_EIAM, mask);
			CSR_WRITE(sc, WMREG_EIMS, mask);

			/* For other interrupts */
			CSR_WRITE(sc, WMREG_IMS, ICR_LSC | sfp_mask);
			break;
		}
	} else {
		sc->sc_icr = ICR_TXDW | ICR_LSC | ICR_RXSEQ | ICR_RXDMT0 |
		    ICR_RXO | ICR_RXT0 | sfp_mask;
		CSR_WRITE(sc, WMREG_IMS, sc->sc_icr);
	}

	/* Set up the inter-packet gap. */
	CSR_WRITE(sc, WMREG_TIPG, sc->sc_tipg);

	if (sc->sc_type >= WM_T_82543) {
		for (int qidx = 0; qidx < sc->sc_nqueues; qidx++) {
			struct wm_queue *wmq = &sc->sc_queue[qidx];
			wm_itrs_writereg(sc, wmq);
		}
		/*
		 * Link interrupts occur much less than TX
		 * interrupts and RX interrupts. So, we don't
		 * tune EINTR(WM_MSIX_LINKINTR_IDX) value like
		 * FreeBSD's if_igb.
		 */
	}

	/* Set the VLAN EtherType. */
	CSR_WRITE(sc, WMREG_VET, ETHERTYPE_VLAN);

	/*
	 * Set up the transmit control register; we start out with
	 * a collision distance suitable for FDX, but update it when
	 * we resolve the media type.
	 */
	sc->sc_tctl = TCTL_EN | TCTL_PSP | TCTL_RTLC
	    | TCTL_CT(TX_COLLISION_THRESHOLD)
	    | TCTL_COLD(TX_COLLISION_DISTANCE_FDX);
	if (sc->sc_type >= WM_T_82571)
		sc->sc_tctl |= TCTL_MULR;
	CSR_WRITE(sc, WMREG_TCTL, sc->sc_tctl);

	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		/* Write TDT after TCTL.EN is set. See the document. */
		CSR_WRITE(sc, WMREG_TDT(0), 0);
	}

	if (sc->sc_type == WM_T_80003) {
		reg = CSR_READ(sc, WMREG_TCTL_EXT);
		reg &= ~TCTL_EXT_GCEX_MASK;
		reg |= DEFAULT_80003ES2LAN_TCTL_EXT_GCEX;
		CSR_WRITE(sc, WMREG_TCTL_EXT, reg);
	}

	/* Set the media. */
	if ((error = mii_ifmedia_change(&sc->sc_mii)) != 0)
		goto out;

	/* Configure for OS presence */
	wm_init_manageability(sc);

	/*
	 * Set up the receive control register; we actually program the
	 * register when we set the receive filter. Use multicast address
	 * offset type 0.
	 *
	 * Only the i82544 has the ability to strip the incoming CRC, so we
	 * don't enable that feature.
	 */
	sc->sc_mchash_type = 0;
	sc->sc_rctl = RCTL_EN | RCTL_LBM_NONE | RCTL_RDMTS_1_2 | RCTL_DPF
	    | __SHIFTIN(sc->sc_mchash_type, RCTL_MO);

	/* 82574 use one buffer extended Rx descriptor. */
	if (sc->sc_type == WM_T_82574)
		sc->sc_rctl |= RCTL_DTYP_ONEBUF;

	if ((sc->sc_flags & WM_F_CRC_STRIP) != 0)
		sc->sc_rctl |= RCTL_SECRC;

	if (((ec->ec_capabilities & ETHERCAP_JUMBO_MTU) != 0)
	    && (ifp->if_mtu > ETHERMTU)) {
		sc->sc_rctl |= RCTL_LPE;
		if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
			CSR_WRITE(sc, WMREG_RLPML, ETHER_MAX_LEN_JUMBO);
	}

	if (MCLBYTES == 2048)
		sc->sc_rctl |= RCTL_2k;
	else {
		if (sc->sc_type >= WM_T_82543) {
			switch (MCLBYTES) {
			case 4096:
				sc->sc_rctl |= RCTL_BSEX | RCTL_BSEX_4k;
				break;
			case 8192:
				sc->sc_rctl |= RCTL_BSEX | RCTL_BSEX_8k;
				break;
			case 16384:
				sc->sc_rctl |= RCTL_BSEX | RCTL_BSEX_16k;
				break;
			default:
				panic("wm_init: MCLBYTES %d unsupported",
				    MCLBYTES);
				break;
			}
		} else
			panic("wm_init: i82542 requires MCLBYTES = 2048");
	}

	/* Enable ECC */
	switch (sc->sc_type) {
	case WM_T_82571:
		reg = CSR_READ(sc, WMREG_PBA_ECC);
		reg |= PBA_ECC_CORR_EN;
		CSR_WRITE(sc, WMREG_PBA_ECC, reg);
		break;
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		reg = CSR_READ(sc, WMREG_PBECCSTS);
		reg |= PBECCSTS_UNCORR_ECC_ENABLE;
		CSR_WRITE(sc, WMREG_PBECCSTS, reg);

		sc->sc_ctrl |= CTRL_MEHE;
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
		break;
	default:
		break;
	}

	/*
	 * Set the receive filter.
	 *
	 * For 82575 and 82576, the RX descriptors must be initialized after
	 * the setting of RCTL.EN in wm_set_filter()
	 */
	wm_set_filter(sc);

	/* On 575 and later set RDT only if RX enabled */
	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		int qidx;
		for (qidx = 0; qidx < sc->sc_nqueues; qidx++) {
			struct wm_rxqueue *rxq = &sc->sc_queue[qidx].wmq_rxq;
			for (i = 0; i < WM_NRXDESC; i++) {
				mutex_enter(rxq->rxq_lock);
				wm_init_rxdesc(rxq, i);
				mutex_exit(rxq->rxq_lock);

			}
		}
	}

	wm_unset_stopping_flags(sc);

	/* Start the one second link check clock. */
	callout_schedule(&sc->sc_tick_ch, hz);

	/*
	 * ...all done! (IFNET_LOCKED asserted above.)
	 */
	ifp->if_flags |= IFF_RUNNING;

out:
	/* Save last flags for the callback */
	sc->sc_if_flags = ifp->if_flags;
	sc->sc_ec_capenable = ec->ec_capenable;
	if (error)
		log(LOG_ERR, "%s: interface not running\n",
		    device_xname(sc->sc_dev));
	return error;
}

/*
 * wm_stop:		[ifnet interface function]
 *
 *	Stop transmission on the interface.
 */
static void
wm_stop(struct ifnet *ifp, int disable)
{
	struct wm_softc *sc = ifp->if_softc;

	ASSERT_SLEEPABLE();
	KASSERT(IFNET_LOCKED(ifp));

	mutex_enter(sc->sc_core_lock);
	wm_stop_locked(ifp, disable ? true : false, true);
	mutex_exit(sc->sc_core_lock);

	/*
	 * After wm_set_stopping_flags(), it is guaranteed that
	 * wm_handle_queue_work() does not call workqueue_enqueue().
	 * However, workqueue_wait() cannot call in wm_stop_locked()
	 * because it can sleep...
	 * so, call workqueue_wait() here.
	 */
	for (int i = 0; i < sc->sc_nqueues; i++)
		workqueue_wait(sc->sc_queue_wq, &sc->sc_queue[i].wmq_cookie);
	workqueue_wait(sc->sc_reset_wq, &sc->sc_reset_work);
}

static void
wm_stop_locked(struct ifnet *ifp, bool disable, bool wait)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txsoft *txs;
	int i, qidx;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(IFNET_LOCKED(ifp));
	KASSERT(mutex_owned(sc->sc_core_lock));

	wm_set_stopping_flags(sc);

	if (sc->sc_flags & WM_F_HAS_MII) {
		/* Down the MII. */
		mii_down(&sc->sc_mii);
	} else {
#if 0
		/* Should we clear PHY's status properly? */
		wm_reset(sc);
#endif
	}

	/* Stop the transmit and receive processes. */
	CSR_WRITE(sc, WMREG_TCTL, 0);
	CSR_WRITE(sc, WMREG_RCTL, 0);
	sc->sc_rctl &= ~RCTL_EN;

	/*
	 * Clear the interrupt mask to ensure the device cannot assert its
	 * interrupt line.
	 * Clear sc->sc_icr to ensure wm_intr_legacy() makes no attempt to
	 * service any currently pending or shared interrupt.
	 */
	CSR_WRITE(sc, WMREG_IMC, 0xffffffffU);
	sc->sc_icr = 0;
	if (wm_is_using_msix(sc)) {
		if (sc->sc_type != WM_T_82574) {
			CSR_WRITE(sc, WMREG_EIMC, 0xffffffffU);
			CSR_WRITE(sc, WMREG_EIAC, 0);
		} else
			CSR_WRITE(sc, WMREG_EIAC_82574, 0);
	}

	/*
	 * Stop callouts after interrupts are disabled; if we have
	 * to wait for them, we will be releasing the CORE_LOCK
	 * briefly, which will unblock interrupts on the current CPU.
	 */

	/* Stop the one second clock. */
	if (wait)
		callout_halt(&sc->sc_tick_ch, sc->sc_core_lock);
	else
		callout_stop(&sc->sc_tick_ch);

	/* Stop the 82547 Tx FIFO stall check timer. */
	if (sc->sc_type == WM_T_82547) {
		if (wait)
			callout_halt(&sc->sc_txfifo_ch, sc->sc_core_lock);
		else
			callout_stop(&sc->sc_txfifo_ch);
	}

	/* Release any queued transmit buffers. */
	for (qidx = 0; qidx < sc->sc_nqueues; qidx++) {
		struct wm_queue *wmq = &sc->sc_queue[qidx];
		struct wm_txqueue *txq = &wmq->wmq_txq;
		struct mbuf *m;

		mutex_enter(txq->txq_lock);
		txq->txq_sending = false; /* Ensure watchdog disabled */
		for (i = 0; i < WM_TXQUEUELEN(txq); i++) {
			txs = &txq->txq_soft[i];
			if (txs->txs_mbuf != NULL) {
				bus_dmamap_unload(sc->sc_dmat,txs->txs_dmamap);
				m_freem(txs->txs_mbuf);
				txs->txs_mbuf = NULL;
			}
		}
		/* Drain txq_interq */
		while ((m = pcq_get(txq->txq_interq)) != NULL)
			m_freem(m);
		mutex_exit(txq->txq_lock);
	}

	/* Mark the interface as down and cancel the watchdog timer. */
	ifp->if_flags &= ~IFF_RUNNING;
	sc->sc_if_flags = ifp->if_flags;

	if (disable) {
		for (i = 0; i < sc->sc_nqueues; i++) {
			struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
			mutex_enter(rxq->rxq_lock);
			wm_rxdrain(rxq);
			mutex_exit(rxq->rxq_lock);
		}
	}

#if 0 /* notyet */
	if (sc->sc_type >= WM_T_82544)
		CSR_WRITE(sc, WMREG_WUC, 0);
#endif
}

static void
wm_dump_mbuf_chain(struct wm_softc *sc, struct mbuf *m0)
{
	struct mbuf *m;
	int i;

	log(LOG_DEBUG, "%s: mbuf chain:\n", device_xname(sc->sc_dev));
	for (m = m0, i = 0; m != NULL; m = m->m_next, i++)
		log(LOG_DEBUG, "%s:\tm_data = %p, m_len = %d, "
		    "m_flags = 0x%08x\n", device_xname(sc->sc_dev),
		    m->m_data, m->m_len, m->m_flags);
	log(LOG_DEBUG, "%s:\t%d mbuf%s in chain\n", device_xname(sc->sc_dev),
	    i, i == 1 ? "" : "s");
}

/*
 * wm_82547_txfifo_stall:
 *
 *	Callout used to wait for the 82547 Tx FIFO to drain,
 *	reset the FIFO pointers, and restart packet transmission.
 */
static void
wm_82547_txfifo_stall(void *arg)
{
	struct wm_softc *sc = arg;
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;

	mutex_enter(txq->txq_lock);

	if (txq->txq_stopping)
		goto out;

	if (txq->txq_fifo_stall) {
		if (CSR_READ(sc, WMREG_TDT(0)) == CSR_READ(sc, WMREG_TDH(0)) &&
		    CSR_READ(sc, WMREG_TDFT) == CSR_READ(sc, WMREG_TDFH) &&
		    CSR_READ(sc, WMREG_TDFTS) == CSR_READ(sc, WMREG_TDFHS)) {
			/*
			 * Packets have drained.  Stop transmitter, reset
			 * FIFO pointers, restart transmitter, and kick
			 * the packet queue.
			 */
			uint32_t tctl = CSR_READ(sc, WMREG_TCTL);
			CSR_WRITE(sc, WMREG_TCTL, tctl & ~TCTL_EN);
			CSR_WRITE(sc, WMREG_TDFT, txq->txq_fifo_addr);
			CSR_WRITE(sc, WMREG_TDFH, txq->txq_fifo_addr);
			CSR_WRITE(sc, WMREG_TDFTS, txq->txq_fifo_addr);
			CSR_WRITE(sc, WMREG_TDFHS, txq->txq_fifo_addr);
			CSR_WRITE(sc, WMREG_TCTL, tctl);
			CSR_WRITE_FLUSH(sc);

			txq->txq_fifo_head = 0;
			txq->txq_fifo_stall = 0;
			wm_start_locked(&sc->sc_ethercom.ec_if);
		} else {
			/*
			 * Still waiting for packets to drain; try again in
			 * another tick.
			 */
			callout_schedule(&sc->sc_txfifo_ch, 1);
		}
	}

out:
	mutex_exit(txq->txq_lock);
}

/*
 * wm_82547_txfifo_bugchk:
 *
 *	Check for bug condition in the 82547 Tx FIFO.  We need to
 *	prevent enqueueing a packet that would wrap around the end
 *	if the Tx FIFO ring buffer, otherwise the chip will croak.
 *
 *	We do this by checking the amount of space before the end
 *	of the Tx FIFO buffer. If the packet will not fit, we "stall"
 *	the Tx FIFO, wait for all remaining packets to drain, reset
 *	the internal FIFO pointers to the beginning, and restart
 *	transmission on the interface.
 */
#define	WM_FIFO_HDR		0x10
#define	WM_82547_PAD_LEN	0x3e0
static int
wm_82547_txfifo_bugchk(struct wm_softc *sc, struct mbuf *m0)
{
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;
	int space = txq->txq_fifo_size - txq->txq_fifo_head;
	int len = roundup(m0->m_pkthdr.len + WM_FIFO_HDR, WM_FIFO_HDR);

	/* Just return if already stalled. */
	if (txq->txq_fifo_stall)
		return 1;

	if (sc->sc_mii.mii_media_active & IFM_FDX) {
		/* Stall only occurs in half-duplex mode. */
		goto send_packet;
	}

	if (len >= WM_82547_PAD_LEN + space) {
		txq->txq_fifo_stall = 1;
		callout_schedule(&sc->sc_txfifo_ch, 1);
		return 1;
	}

send_packet:
	txq->txq_fifo_head += len;
	if (txq->txq_fifo_head >= txq->txq_fifo_size)
		txq->txq_fifo_head -= txq->txq_fifo_size;

	return 0;
}

static int
wm_alloc_tx_descs(struct wm_softc *sc, struct wm_txqueue *txq)
{
	int error;

	/*
	 * Allocate the control data structures, and create and load the
	 * DMA map for it.
	 *
	 * NOTE: All Tx descriptors must be in the same 4G segment of
	 * memory.  So must Rx descriptors.  We simplify by allocating
	 * both sets within the same 4G segment.
	 */
	if (sc->sc_type < WM_T_82544)
		WM_NTXDESC(txq) = WM_NTXDESC_82542;
	else
		WM_NTXDESC(txq) = WM_NTXDESC_82544;
	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		txq->txq_descsize = sizeof(nq_txdesc_t);
	else
		txq->txq_descsize = sizeof(wiseman_txdesc_t);

	if ((error = bus_dmamem_alloc(sc->sc_dmat, WM_TXDESCS_SIZE(txq),
		    PAGE_SIZE, (bus_size_t) 0x100000000ULL, &txq->txq_desc_seg,
		    1, &txq->txq_desc_rseg, 0)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to allocate TX control data, error = %d\n",
		    error);
		goto fail_0;
	}

	if ((error = bus_dmamem_map(sc->sc_dmat, &txq->txq_desc_seg,
		    txq->txq_desc_rseg, WM_TXDESCS_SIZE(txq),
		    (void **)&txq->txq_descs_u, BUS_DMA_COHERENT)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to map TX control data, error = %d\n", error);
		goto fail_1;
	}

	if ((error = bus_dmamap_create(sc->sc_dmat, WM_TXDESCS_SIZE(txq), 1,
		    WM_TXDESCS_SIZE(txq), 0, 0, &txq->txq_desc_dmamap)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to create TX control data DMA map, error = %d\n",
		    error);
		goto fail_2;
	}

	if ((error = bus_dmamap_load(sc->sc_dmat, txq->txq_desc_dmamap,
		    txq->txq_descs_u, WM_TXDESCS_SIZE(txq), NULL, 0)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to load TX control data DMA map, error = %d\n",
		    error);
		goto fail_3;
	}

	return 0;

fail_3:
	bus_dmamap_destroy(sc->sc_dmat, txq->txq_desc_dmamap);
fail_2:
	bus_dmamem_unmap(sc->sc_dmat, (void *)txq->txq_descs_u,
	    WM_TXDESCS_SIZE(txq));
fail_1:
	bus_dmamem_free(sc->sc_dmat, &txq->txq_desc_seg, txq->txq_desc_rseg);
fail_0:
	return error;
}

static void
wm_free_tx_descs(struct wm_softc *sc, struct wm_txqueue *txq)
{

	bus_dmamap_unload(sc->sc_dmat, txq->txq_desc_dmamap);
	bus_dmamap_destroy(sc->sc_dmat, txq->txq_desc_dmamap);
	bus_dmamem_unmap(sc->sc_dmat, (void *)txq->txq_descs_u,
	    WM_TXDESCS_SIZE(txq));
	bus_dmamem_free(sc->sc_dmat, &txq->txq_desc_seg, txq->txq_desc_rseg);
}

static int
wm_alloc_rx_descs(struct wm_softc *sc, struct wm_rxqueue *rxq)
{
	int error;
	size_t rxq_descs_size;

	/*
	 * Allocate the control data structures, and create and load the
	 * DMA map for it.
	 *
	 * NOTE: All Tx descriptors must be in the same 4G segment of
	 * memory.  So must Rx descriptors.  We simplify by allocating
	 * both sets within the same 4G segment.
	 */
	rxq->rxq_ndesc = WM_NRXDESC;
	if (sc->sc_type == WM_T_82574)
		rxq->rxq_descsize = sizeof(ext_rxdesc_t);
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		rxq->rxq_descsize = sizeof(nq_rxdesc_t);
	else
		rxq->rxq_descsize = sizeof(wiseman_rxdesc_t);
	rxq_descs_size = rxq->rxq_descsize * rxq->rxq_ndesc;

	if ((error = bus_dmamem_alloc(sc->sc_dmat, rxq_descs_size,
		    PAGE_SIZE, (bus_size_t) 0x100000000ULL, &rxq->rxq_desc_seg,
		    1, &rxq->rxq_desc_rseg, 0)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to allocate RX control data, error = %d\n",
		    error);
		goto fail_0;
	}

	if ((error = bus_dmamem_map(sc->sc_dmat, &rxq->rxq_desc_seg,
		    rxq->rxq_desc_rseg, rxq_descs_size,
		    (void **)&rxq->rxq_descs_u, BUS_DMA_COHERENT)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to map RX control data, error = %d\n", error);
		goto fail_1;
	}

	if ((error = bus_dmamap_create(sc->sc_dmat, rxq_descs_size, 1,
		    rxq_descs_size, 0, 0, &rxq->rxq_desc_dmamap)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to create RX control data DMA map, error = %d\n",
		    error);
		goto fail_2;
	}

	if ((error = bus_dmamap_load(sc->sc_dmat, rxq->rxq_desc_dmamap,
		    rxq->rxq_descs_u, rxq_descs_size, NULL, 0)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "unable to load RX control data DMA map, error = %d\n",
		    error);
		goto fail_3;
	}

	return 0;

 fail_3:
	bus_dmamap_destroy(sc->sc_dmat, rxq->rxq_desc_dmamap);
 fail_2:
	bus_dmamem_unmap(sc->sc_dmat, (void *)rxq->rxq_descs_u,
	    rxq_descs_size);
 fail_1:
	bus_dmamem_free(sc->sc_dmat, &rxq->rxq_desc_seg, rxq->rxq_desc_rseg);
 fail_0:
	return error;
}

static void
wm_free_rx_descs(struct wm_softc *sc, struct wm_rxqueue *rxq)
{

	bus_dmamap_unload(sc->sc_dmat, rxq->rxq_desc_dmamap);
	bus_dmamap_destroy(sc->sc_dmat, rxq->rxq_desc_dmamap);
	bus_dmamem_unmap(sc->sc_dmat, (void *)rxq->rxq_descs_u,
	    rxq->rxq_descsize * rxq->rxq_ndesc);
	bus_dmamem_free(sc->sc_dmat, &rxq->rxq_desc_seg, rxq->rxq_desc_rseg);
}


static int
wm_alloc_tx_buffer(struct wm_softc *sc, struct wm_txqueue *txq)
{
	int i, error;

	/* Create the transmit buffer DMA maps. */
	WM_TXQUEUELEN(txq) =
	    (sc->sc_type == WM_T_82547 || sc->sc_type == WM_T_82547_2) ?
	    WM_TXQUEUELEN_MAX_82547 : WM_TXQUEUELEN_MAX;
	for (i = 0; i < WM_TXQUEUELEN(txq); i++) {
		if ((error = bus_dmamap_create(sc->sc_dmat, WM_MAXTXDMA,
			    WM_NTXSEGS, WTX_MAX_LEN, 0, 0,
			    &txq->txq_soft[i].txs_dmamap)) != 0) {
			aprint_error_dev(sc->sc_dev,
			    "unable to create Tx DMA map %d, error = %d\n",
			    i, error);
			goto fail;
		}
	}

	return 0;

fail:
	for (i = 0; i < WM_TXQUEUELEN(txq); i++) {
		if (txq->txq_soft[i].txs_dmamap != NULL)
			bus_dmamap_destroy(sc->sc_dmat,
			    txq->txq_soft[i].txs_dmamap);
	}
	return error;
}

static void
wm_free_tx_buffer(struct wm_softc *sc, struct wm_txqueue *txq)
{
	int i;

	for (i = 0; i < WM_TXQUEUELEN(txq); i++) {
		if (txq->txq_soft[i].txs_dmamap != NULL)
			bus_dmamap_destroy(sc->sc_dmat,
			    txq->txq_soft[i].txs_dmamap);
	}
}

static int
wm_alloc_rx_buffer(struct wm_softc *sc, struct wm_rxqueue *rxq)
{
	int i, error;

	/* Create the receive buffer DMA maps. */
	for (i = 0; i < rxq->rxq_ndesc; i++) {
		if ((error = bus_dmamap_create(sc->sc_dmat, MCLBYTES, 1,
			    MCLBYTES, 0, 0,
			    &rxq->rxq_soft[i].rxs_dmamap)) != 0) {
			aprint_error_dev(sc->sc_dev,
			    "unable to create Rx DMA map %d error = %d\n",
			    i, error);
			goto fail;
		}
		rxq->rxq_soft[i].rxs_mbuf = NULL;
	}

	return 0;

 fail:
	for (i = 0; i < rxq->rxq_ndesc; i++) {
		if (rxq->rxq_soft[i].rxs_dmamap != NULL)
			bus_dmamap_destroy(sc->sc_dmat,
			    rxq->rxq_soft[i].rxs_dmamap);
	}
	return error;
}

static void
wm_free_rx_buffer(struct wm_softc *sc, struct wm_rxqueue *rxq)
{
	int i;

	for (i = 0; i < rxq->rxq_ndesc; i++) {
		if (rxq->rxq_soft[i].rxs_dmamap != NULL)
			bus_dmamap_destroy(sc->sc_dmat,
			    rxq->rxq_soft[i].rxs_dmamap);
	}
}

/*
 * wm_alloc_quques:
 *	Allocate {tx,rx}descs and {tx,rx} buffers
 */
static int
wm_alloc_txrx_queues(struct wm_softc *sc)
{
	int i, error, tx_done, rx_done;

	sc->sc_queue = kmem_zalloc(sizeof(struct wm_queue) * sc->sc_nqueues,
	    KM_SLEEP);
	if (sc->sc_queue == NULL) {
		aprint_error_dev(sc->sc_dev,"unable to allocate wm_queue\n");
		error = ENOMEM;
		goto fail_0;
	}

	/* For transmission */
	error = 0;
	tx_done = 0;
	for (i = 0; i < sc->sc_nqueues; i++) {
#ifdef WM_EVENT_COUNTERS
		int j;
		const char *xname;
#endif
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
		txq->txq_sc = sc;
		txq->txq_lock = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);

		error = wm_alloc_tx_descs(sc, txq);
		if (error)
			break;
		error = wm_alloc_tx_buffer(sc, txq);
		if (error) {
			wm_free_tx_descs(sc, txq);
			break;
		}
		txq->txq_interq = pcq_create(WM_TXINTERQSIZE, KM_SLEEP);
		if (txq->txq_interq == NULL) {
			wm_free_tx_descs(sc, txq);
			wm_free_tx_buffer(sc, txq);
			error = ENOMEM;
			break;
		}

#ifdef WM_EVENT_COUNTERS
		xname = device_xname(sc->sc_dev);

		WM_Q_MISC_EVCNT_ATTACH(txq, txsstall, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, txdstall, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, fifo_stall, txq, i, xname);
		WM_Q_INTR_EVCNT_ATTACH(txq, txdw, txq, i, xname);
		WM_Q_INTR_EVCNT_ATTACH(txq, txqe, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, ipsum, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, tusum, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, tusum6, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, tso, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, tso6, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, tsopain, txq, i, xname);

		for (j = 0; j < WM_NTXSEGS; j++) {
			snprintf(txq->txq_txseg_evcnt_names[j],
			    sizeof(txq->txq_txseg_evcnt_names[j]),
			    "txq%02dtxseg%d", i, j);
			evcnt_attach_dynamic(&txq->txq_ev_txseg[j],
			    EVCNT_TYPE_MISC,
			    NULL, xname, txq->txq_txseg_evcnt_names[j]);
		}

		WM_Q_MISC_EVCNT_ATTACH(txq, pcqdrop, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, descdrop, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, toomanyseg, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, defrag, txq, i, xname);
		/* Only for 82544 (and earlier?) */
		if (sc->sc_type <= WM_T_82544)
			WM_Q_MISC_EVCNT_ATTACH(txq, underrun, txq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(txq, skipcontext, txq, i, xname);
#endif /* WM_EVENT_COUNTERS */

		tx_done++;
	}
	if (error)
		goto fail_1;

	/* For receive */
	error = 0;
	rx_done = 0;
	for (i = 0; i < sc->sc_nqueues; i++) {
#ifdef WM_EVENT_COUNTERS
		const char *xname;
#endif
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
		rxq->rxq_sc = sc;
		rxq->rxq_lock = mutex_obj_alloc(MUTEX_DEFAULT, IPL_NET);

		error = wm_alloc_rx_descs(sc, rxq);
		if (error)
			break;

		error = wm_alloc_rx_buffer(sc, rxq);
		if (error) {
			wm_free_rx_descs(sc, rxq);
			break;
		}

#ifdef WM_EVENT_COUNTERS
		xname = device_xname(sc->sc_dev);

		WM_Q_INTR_EVCNT_ATTACH(rxq, intr, rxq, i, xname);
		WM_Q_INTR_EVCNT_ATTACH(rxq, defer, rxq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(rxq, ipsum, rxq, i, xname);
		WM_Q_MISC_EVCNT_ATTACH(rxq, tusum, rxq, i, xname);
		if ((sc->sc_type >= WM_T_82575) && !WM_IS_ICHPCH(sc))
			WM_Q_MISC_EVCNT_ATTACH(rxq, qdrop, rxq, i, xname);
#endif /* WM_EVENT_COUNTERS */

		rx_done++;
	}
	if (error)
		goto fail_2;

	return 0;

fail_2:
	for (i = 0; i < rx_done; i++) {
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;
		wm_free_rx_buffer(sc, rxq);
		wm_free_rx_descs(sc, rxq);
		if (rxq->rxq_lock)
			mutex_obj_free(rxq->rxq_lock);
	}
fail_1:
	for (i = 0; i < tx_done; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
		pcq_destroy(txq->txq_interq);
		wm_free_tx_buffer(sc, txq);
		wm_free_tx_descs(sc, txq);
		if (txq->txq_lock)
			mutex_obj_free(txq->txq_lock);
	}

	kmem_free(sc->sc_queue,
	    sizeof(struct wm_queue) * sc->sc_nqueues);
fail_0:
	return error;
}

/*
 * wm_free_quques:
 *	Free {tx,rx}descs and {tx,rx} buffers
 */
static void
wm_free_txrx_queues(struct wm_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_rxqueue *rxq = &sc->sc_queue[i].wmq_rxq;

#ifdef WM_EVENT_COUNTERS
		WM_Q_EVCNT_DETACH(rxq, intr, rxq, i);
		WM_Q_EVCNT_DETACH(rxq, defer, rxq, i);
		WM_Q_EVCNT_DETACH(rxq, ipsum, rxq, i);
		WM_Q_EVCNT_DETACH(rxq, tusum, rxq, i);
		if ((sc->sc_type >= WM_T_82575) && !WM_IS_ICHPCH(sc))
			WM_Q_EVCNT_DETACH(rxq, qdrop, rxq, i);
#endif /* WM_EVENT_COUNTERS */

		wm_free_rx_buffer(sc, rxq);
		wm_free_rx_descs(sc, rxq);
		if (rxq->rxq_lock)
			mutex_obj_free(rxq->rxq_lock);
	}

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_txqueue *txq = &sc->sc_queue[i].wmq_txq;
		struct mbuf *m;
#ifdef WM_EVENT_COUNTERS
		int j;

		WM_Q_EVCNT_DETACH(txq, txsstall, txq, i);
		WM_Q_EVCNT_DETACH(txq, txdstall, txq, i);
		WM_Q_EVCNT_DETACH(txq, fifo_stall, txq, i);
		WM_Q_EVCNT_DETACH(txq, txdw, txq, i);
		WM_Q_EVCNT_DETACH(txq, txqe, txq, i);
		WM_Q_EVCNT_DETACH(txq, ipsum, txq, i);
		WM_Q_EVCNT_DETACH(txq, tusum, txq, i);
		WM_Q_EVCNT_DETACH(txq, tusum6, txq, i);
		WM_Q_EVCNT_DETACH(txq, tso, txq, i);
		WM_Q_EVCNT_DETACH(txq, tso6, txq, i);
		WM_Q_EVCNT_DETACH(txq, tsopain, txq, i);

		for (j = 0; j < WM_NTXSEGS; j++)
			evcnt_detach(&txq->txq_ev_txseg[j]);

		WM_Q_EVCNT_DETACH(txq, pcqdrop, txq, i);
		WM_Q_EVCNT_DETACH(txq, descdrop, txq, i);
		WM_Q_EVCNT_DETACH(txq, toomanyseg, txq, i);
		WM_Q_EVCNT_DETACH(txq, defrag, txq, i);
		if (sc->sc_type <= WM_T_82544)
			WM_Q_EVCNT_DETACH(txq, underrun, txq, i);
		WM_Q_EVCNT_DETACH(txq, skipcontext, txq, i);
#endif /* WM_EVENT_COUNTERS */

		/* Drain txq_interq */
		while ((m = pcq_get(txq->txq_interq)) != NULL)
			m_freem(m);
		pcq_destroy(txq->txq_interq);

		wm_free_tx_buffer(sc, txq);
		wm_free_tx_descs(sc, txq);
		if (txq->txq_lock)
			mutex_obj_free(txq->txq_lock);
	}

	kmem_free(sc->sc_queue, sizeof(struct wm_queue) * sc->sc_nqueues);
}

static void
wm_init_tx_descs(struct wm_softc *sc __unused, struct wm_txqueue *txq)
{

	KASSERT(mutex_owned(txq->txq_lock));

	/* Initialize the transmit descriptor ring. */
	memset(txq->txq_descs, 0, WM_TXDESCS_SIZE(txq));
	wm_cdtxsync(txq, 0, WM_NTXDESC(txq),
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	txq->txq_free = WM_NTXDESC(txq);
	txq->txq_next = 0;
}

static void
wm_init_tx_regs(struct wm_softc *sc, struct wm_queue *wmq,
    struct wm_txqueue *txq)
{

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(mutex_owned(txq->txq_lock));

	if (sc->sc_type < WM_T_82543) {
		CSR_WRITE(sc, WMREG_OLD_TDBAH, WM_CDTXADDR_HI(txq, 0));
		CSR_WRITE(sc, WMREG_OLD_TDBAL, WM_CDTXADDR_LO(txq, 0));
		CSR_WRITE(sc, WMREG_OLD_TDLEN, WM_TXDESCS_SIZE(txq));
		CSR_WRITE(sc, WMREG_OLD_TDH, 0);
		CSR_WRITE(sc, WMREG_OLD_TDT, 0);
		CSR_WRITE(sc, WMREG_OLD_TIDV, 128);
	} else {
		int qid = wmq->wmq_id;

		CSR_WRITE(sc, WMREG_TDBAH(qid), WM_CDTXADDR_HI(txq, 0));
		CSR_WRITE(sc, WMREG_TDBAL(qid), WM_CDTXADDR_LO(txq, 0));
		CSR_WRITE(sc, WMREG_TDLEN(qid), WM_TXDESCS_SIZE(txq));
		CSR_WRITE(sc, WMREG_TDH(qid), 0);

		if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
			/*
			 * Don't write TDT before TCTL.EN is set.
			 * See the document.
			 */
			CSR_WRITE(sc, WMREG_TXDCTL(qid), TXDCTL_QUEUE_ENABLE
			    | TXDCTL_PTHRESH(0) | TXDCTL_HTHRESH(0)
			    | TXDCTL_WTHRESH(0));
		else {
			/* XXX should update with AIM? */
			CSR_WRITE(sc, WMREG_TIDV, wmq->wmq_itr / 4);
			if (sc->sc_type >= WM_T_82540) {
				/* Should be the same */
				CSR_WRITE(sc, WMREG_TADV, wmq->wmq_itr / 4);
			}

			CSR_WRITE(sc, WMREG_TDT(qid), 0);
			CSR_WRITE(sc, WMREG_TXDCTL(qid), TXDCTL_PTHRESH(0) |
			    TXDCTL_HTHRESH(0) | TXDCTL_WTHRESH(0));
		}
	}
}

static void
wm_init_tx_buffer(struct wm_softc *sc __unused, struct wm_txqueue *txq)
{
	int i;

	KASSERT(mutex_owned(txq->txq_lock));

	/* Initialize the transmit job descriptors. */
	for (i = 0; i < WM_TXQUEUELEN(txq); i++)
		txq->txq_soft[i].txs_mbuf = NULL;
	txq->txq_sfree = WM_TXQUEUELEN(txq);
	txq->txq_snext = 0;
	txq->txq_sdirty = 0;
}

static void
wm_init_tx_queue(struct wm_softc *sc, struct wm_queue *wmq,
    struct wm_txqueue *txq)
{

	KASSERT(mutex_owned(txq->txq_lock));

	/*
	 * Set up some register offsets that are different between
	 * the i82542 and the i82543 and later chips.
	 */
	if (sc->sc_type < WM_T_82543)
		txq->txq_tdt_reg = WMREG_OLD_TDT;
	else
		txq->txq_tdt_reg = WMREG_TDT(wmq->wmq_id);

	wm_init_tx_descs(sc, txq);
	wm_init_tx_regs(sc, wmq, txq);
	wm_init_tx_buffer(sc, txq);

	/* Clear other than WM_TXQ_LINKDOWN_DISCARD */
	txq->txq_flags &= WM_TXQ_LINKDOWN_DISCARD;

	txq->txq_sending = false;
}

static void
wm_init_rx_regs(struct wm_softc *sc, struct wm_queue *wmq,
    struct wm_rxqueue *rxq)
{

	KASSERT(mutex_owned(rxq->rxq_lock));

	/*
	 * Initialize the receive descriptor and receive job
	 * descriptor rings.
	 */
	if (sc->sc_type < WM_T_82543) {
		CSR_WRITE(sc, WMREG_OLD_RDBAH0, WM_CDRXADDR_HI(rxq, 0));
		CSR_WRITE(sc, WMREG_OLD_RDBAL0, WM_CDRXADDR_LO(rxq, 0));
		CSR_WRITE(sc, WMREG_OLD_RDLEN0,
		    rxq->rxq_descsize * rxq->rxq_ndesc);
		CSR_WRITE(sc, WMREG_OLD_RDH0, 0);
		CSR_WRITE(sc, WMREG_OLD_RDT0, 0);
		CSR_WRITE(sc, WMREG_OLD_RDTR0, 28 | RDTR_FPD);

		CSR_WRITE(sc, WMREG_OLD_RDBA1_HI, 0);
		CSR_WRITE(sc, WMREG_OLD_RDBA1_LO, 0);
		CSR_WRITE(sc, WMREG_OLD_RDLEN1, 0);
		CSR_WRITE(sc, WMREG_OLD_RDH1, 0);
		CSR_WRITE(sc, WMREG_OLD_RDT1, 0);
		CSR_WRITE(sc, WMREG_OLD_RDTR1, 0);
	} else {
		int qid = wmq->wmq_id;

		CSR_WRITE(sc, WMREG_RDBAH(qid), WM_CDRXADDR_HI(rxq, 0));
		CSR_WRITE(sc, WMREG_RDBAL(qid), WM_CDRXADDR_LO(rxq, 0));
		CSR_WRITE(sc, WMREG_RDLEN(qid),
		    rxq->rxq_descsize * rxq->rxq_ndesc);

		if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
			uint32_t srrctl;

			if (MCLBYTES & ((1 << SRRCTL_BSIZEPKT_SHIFT) - 1))
				panic("%s: MCLBYTES %d unsupported for 82575 "
				    "or higher\n", __func__, MCLBYTES);

			/*
			 * Currently, support SRRCTL_DESCTYPE_ADV_ONEBUF
			 * only.
			 */
			srrctl = SRRCTL_DESCTYPE_ADV_ONEBUF
			    | (MCLBYTES >> SRRCTL_BSIZEPKT_SHIFT);
			/*
			 * Drop frames if the RX descriptor ring has no room.
			 * This is enabled only on multiqueue system to avoid
			 * bad influence to other queues.
			 */
			if (sc->sc_nqueues > 1)
				srrctl |= SRRCTL_DROP_EN;
			CSR_WRITE(sc, WMREG_SRRCTL(qid), srrctl);

			CSR_WRITE(sc, WMREG_RXDCTL(qid), RXDCTL_QUEUE_ENABLE
			    | RXDCTL_PTHRESH(16) | RXDCTL_HTHRESH(8)
			    | RXDCTL_WTHRESH(1));
			CSR_WRITE(sc, WMREG_RDH(qid), 0);
			CSR_WRITE(sc, WMREG_RDT(qid), 0);
		} else {
			CSR_WRITE(sc, WMREG_RDH(qid), 0);
			CSR_WRITE(sc, WMREG_RDT(qid), 0);
			/* XXX should update with AIM? */
			CSR_WRITE(sc, WMREG_RDTR,
			    (wmq->wmq_itr / 4) | RDTR_FPD);
			/* MUST be same */
			CSR_WRITE(sc, WMREG_RADV, wmq->wmq_itr / 4);
			CSR_WRITE(sc, WMREG_RXDCTL(qid), RXDCTL_PTHRESH(0) |
			    RXDCTL_HTHRESH(0) | RXDCTL_WTHRESH(1));
		}
	}
}

static int
wm_init_rx_buffer(struct wm_softc *sc, struct wm_rxqueue *rxq)
{
	struct wm_rxsoft *rxs;
	int error, i;

	KASSERT(mutex_owned(rxq->rxq_lock));

	for (i = 0; i < rxq->rxq_ndesc; i++) {
		rxs = &rxq->rxq_soft[i];
		if (rxs->rxs_mbuf == NULL) {
			if ((error = wm_add_rxbuf(rxq, i)) != 0) {
				log(LOG_ERR, "%s: unable to allocate or map "
				    "rx buffer %d, error = %d\n",
				    device_xname(sc->sc_dev), i, error);
				/*
				 * XXX Should attempt to run with fewer receive
				 * XXX buffers instead of just failing.
				 */
				wm_rxdrain(rxq);
				return ENOMEM;
			}
		} else {
			/*
			 * For 82575 and 82576, the RX descriptors must be
			 * initialized after the setting of RCTL.EN in
			 * wm_set_filter()
			 */
			if ((sc->sc_flags & WM_F_NEWQUEUE) == 0)
				wm_init_rxdesc(rxq, i);
		}
	}
	rxq->rxq_ptr = 0;
	rxq->rxq_discard = 0;
	WM_RXCHAIN_RESET(rxq);

	return 0;
}

static int
wm_init_rx_queue(struct wm_softc *sc, struct wm_queue *wmq,
    struct wm_rxqueue *rxq)
{

	KASSERT(mutex_owned(rxq->rxq_lock));

	/*
	 * Set up some register offsets that are different between
	 * the i82542 and the i82543 and later chips.
	 */
	if (sc->sc_type < WM_T_82543)
		rxq->rxq_rdt_reg = WMREG_OLD_RDT0;
	else
		rxq->rxq_rdt_reg = WMREG_RDT(wmq->wmq_id);

	wm_init_rx_regs(sc, wmq, rxq);
	return wm_init_rx_buffer(sc, rxq);
}

/*
 * wm_init_quques:
 *	Initialize {tx,rx}descs and {tx,rx} buffers
 */
static int
wm_init_txrx_queues(struct wm_softc *sc)
{
	int i, error = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	for (i = 0; i < sc->sc_nqueues; i++) {
		struct wm_queue *wmq = &sc->sc_queue[i];
		struct wm_txqueue *txq = &wmq->wmq_txq;
		struct wm_rxqueue *rxq = &wmq->wmq_rxq;

		/*
		 * TODO
		 * Currently, use constant variable instead of AIM.
		 * Furthermore, the interrupt interval of multiqueue which use
		 * polling mode is less than default value.
		 * More tuning and AIM are required.
		 */
		if (wm_is_using_multiqueue(sc))
			wmq->wmq_itr = 50;
		else
			wmq->wmq_itr = sc->sc_itr_init;
		wmq->wmq_set_itr = true;

		mutex_enter(txq->txq_lock);
		wm_init_tx_queue(sc, wmq, txq);
		mutex_exit(txq->txq_lock);

		mutex_enter(rxq->rxq_lock);
		error = wm_init_rx_queue(sc, wmq, rxq);
		mutex_exit(rxq->rxq_lock);
		if (error)
			break;
	}

	return error;
}

/*
 * wm_tx_offload:
 *
 *	Set up TCP/IP checksumming parameters for the
 *	specified packet.
 */
static void
wm_tx_offload(struct wm_softc *sc, struct wm_txqueue *txq,
    struct wm_txsoft *txs, uint32_t *cmdp, uint8_t *fieldsp)
{
	struct mbuf *m0 = txs->txs_mbuf;
	struct livengood_tcpip_ctxdesc *t;
	uint32_t ipcs, tucs, cmd, cmdlen, seg;
	uint32_t ipcse;
	struct ether_header *eh;
	int offset, iphl;
	uint8_t fields;

	/*
	 * XXX It would be nice if the mbuf pkthdr had offset
	 * fields for the protocol headers.
	 */

	eh = mtod(m0, struct ether_header *);
	switch (htons(eh->ether_type)) {
	case ETHERTYPE_IP:
	case ETHERTYPE_IPV6:
		offset = ETHER_HDR_LEN;
		break;

	case ETHERTYPE_VLAN:
		offset = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		break;

	default:
		/* Don't support this protocol or encapsulation. */
		txq->txq_last_hw_cmd = txq->txq_last_hw_fields = 0;
		txq->txq_last_hw_ipcs = 0;
		txq->txq_last_hw_tucs = 0;
		*fieldsp = 0;
		*cmdp = 0;
		return;
	}

	if ((m0->m_pkthdr.csum_flags &
	    (M_CSUM_TSOv4 | M_CSUM_UDPv4 | M_CSUM_TCPv4 | M_CSUM_IPv4)) != 0) {
		iphl = M_CSUM_DATA_IPv4_IPHL(m0->m_pkthdr.csum_data);
	} else
		iphl = M_CSUM_DATA_IPv6_IPHL(m0->m_pkthdr.csum_data);

	ipcse = offset + iphl - 1;

	cmd = WTX_CMD_DEXT | WTX_DTYP_D;
	cmdlen = WTX_CMD_DEXT | WTX_DTYP_C | WTX_CMD_IDE;
	seg = 0;
	fields = 0;

	if ((m0->m_pkthdr.csum_flags & (M_CSUM_TSOv4 | M_CSUM_TSOv6)) != 0) {
		int hlen = offset + iphl;
		bool v4 = (m0->m_pkthdr.csum_flags & M_CSUM_TSOv4) != 0;

		if (__predict_false(m0->m_len <
				    (hlen + sizeof(struct tcphdr)))) {
			/*
			 * TCP/IP headers are not in the first mbuf; we need
			 * to do this the slow and painful way. Let's just
			 * hope this doesn't happen very often.
			 */
			struct tcphdr th;

			WM_Q_EVCNT_INCR(txq, tsopain);

			m_copydata(m0, hlen, sizeof(th), &th);
			if (v4) {
				struct ip ip;

				m_copydata(m0, offset, sizeof(ip), &ip);
				ip.ip_len = 0;
				m_copyback(m0,
				    offset + offsetof(struct ip, ip_len),
				    sizeof(ip.ip_len), &ip.ip_len);
				th.th_sum = in_cksum_phdr(ip.ip_src.s_addr,
				    ip.ip_dst.s_addr, htons(IPPROTO_TCP));
			} else {
				struct ip6_hdr ip6;

				m_copydata(m0, offset, sizeof(ip6), &ip6);
				ip6.ip6_plen = 0;
				m_copyback(m0,
				    offset + offsetof(struct ip6_hdr, ip6_plen),
				    sizeof(ip6.ip6_plen), &ip6.ip6_plen);
				th.th_sum = in6_cksum_phdr(&ip6.ip6_src,
				    &ip6.ip6_dst, 0, htonl(IPPROTO_TCP));
			}
			m_copyback(m0, hlen + offsetof(struct tcphdr, th_sum),
			    sizeof(th.th_sum), &th.th_sum);

			hlen += th.th_off << 2;
		} else {
			/*
			 * TCP/IP headers are in the first mbuf; we can do
			 * this the easy way.
			 */
			struct tcphdr *th;

			if (v4) {
				struct ip *ip =
				    (void *)(mtod(m0, char *) + offset);
				th = (void *)(mtod(m0, char *) + hlen);

				ip->ip_len = 0;
				th->th_sum = in_cksum_phdr(ip->ip_src.s_addr,
				    ip->ip_dst.s_addr, htons(IPPROTO_TCP));
			} else {
				struct ip6_hdr *ip6 =
				    (void *)(mtod(m0, char *) + offset);
				th = (void *)(mtod(m0, char *) + hlen);

				ip6->ip6_plen = 0;
				th->th_sum = in6_cksum_phdr(&ip6->ip6_src,
				    &ip6->ip6_dst, 0, htonl(IPPROTO_TCP));
			}
			hlen += th->th_off << 2;
		}

		if (v4) {
			WM_Q_EVCNT_INCR(txq, tso);
			cmdlen |= WTX_TCPIP_CMD_IP;
		} else {
			WM_Q_EVCNT_INCR(txq, tso6);
			ipcse = 0;
		}
		cmd |= WTX_TCPIP_CMD_TSE;
		cmdlen |= WTX_TCPIP_CMD_TSE |
		    WTX_TCPIP_CMD_TCP | (m0->m_pkthdr.len - hlen);
		seg = WTX_TCPIP_SEG_HDRLEN(hlen) |
		    WTX_TCPIP_SEG_MSS(m0->m_pkthdr.segsz);
	}

	/*
	 * NOTE: Even if we're not using the IP or TCP/UDP checksum
	 * offload feature, if we load the context descriptor, we
	 * MUST provide valid values for IPCSS and TUCSS fields.
	 */

	ipcs = WTX_TCPIP_IPCSS(offset) |
	    WTX_TCPIP_IPCSO(offset + offsetof(struct ip, ip_sum)) |
	    WTX_TCPIP_IPCSE(ipcse);
	if (m0->m_pkthdr.csum_flags & (M_CSUM_IPv4 | M_CSUM_TSOv4)) {
		WM_Q_EVCNT_INCR(txq, ipsum);
		fields |= WTX_IXSM;
	}

	offset += iphl;

	if (m0->m_pkthdr.csum_flags &
	    (M_CSUM_TCPv4 | M_CSUM_UDPv4 | M_CSUM_TSOv4)) {
		WM_Q_EVCNT_INCR(txq, tusum);
		fields |= WTX_TXSM;
		tucs = WTX_TCPIP_TUCSS(offset) |
		    WTX_TCPIP_TUCSO(offset +
			M_CSUM_DATA_IPv4_OFFSET(m0->m_pkthdr.csum_data)) |
		    WTX_TCPIP_TUCSE(0) /* Rest of packet */;
	} else if ((m0->m_pkthdr.csum_flags &
	    (M_CSUM_TCPv6 | M_CSUM_UDPv6 | M_CSUM_TSOv6)) != 0) {
		WM_Q_EVCNT_INCR(txq, tusum6);
		fields |= WTX_TXSM;
		tucs = WTX_TCPIP_TUCSS(offset) |
		    WTX_TCPIP_TUCSO(offset +
			M_CSUM_DATA_IPv6_OFFSET(m0->m_pkthdr.csum_data)) |
		    WTX_TCPIP_TUCSE(0) /* Rest of packet */;
	} else {
		/* Just initialize it to a valid TCP context. */
		tucs = WTX_TCPIP_TUCSS(offset) |
		    WTX_TCPIP_TUCSO(offset + offsetof(struct tcphdr, th_sum)) |
		    WTX_TCPIP_TUCSE(0) /* Rest of packet */;
	}

	*cmdp = cmd;
	*fieldsp = fields;

	/*
	 * We don't have to write context descriptor for every packet
	 * except for 82574. For 82574, we must write context descriptor
	 * for every packet when we use two descriptor queues.
	 *
	 * The 82574L can only remember the *last* context used
	 * regardless of queue that it was use for.  We cannot reuse
	 * contexts on this hardware platform and must generate a new
	 * context every time.  82574L hardware spec, section 7.2.6,
	 * second note.
	 */
	if (sc->sc_nqueues < 2) {
		/*
		 * Setting up new checksum offload context for every
		 * frames takes a lot of processing time for hardware.
		 * This also reduces performance a lot for small sized
		 * frames so avoid it if driver can use previously
		 * configured checksum offload context.
		 * For TSO, in theory we can use the same TSO context only if
		 * frame is the same type(IP/TCP) and the same MSS. However
		 * checking whether a frame has the same IP/TCP structure is a
		 * hard thing so just ignore that and always restablish a
		 * new TSO context.
		 */
		if ((m0->m_pkthdr.csum_flags & (M_CSUM_TSOv4 | M_CSUM_TSOv6))
		    == 0) {
			if (txq->txq_last_hw_cmd == cmd &&
			    txq->txq_last_hw_fields == fields &&
			    txq->txq_last_hw_ipcs == (ipcs & 0xffff) &&
			    txq->txq_last_hw_tucs == (tucs & 0xffff)) {
				WM_Q_EVCNT_INCR(txq, skipcontext);
				return;
			}
		}

		txq->txq_last_hw_cmd = cmd;
		txq->txq_last_hw_fields = fields;
		txq->txq_last_hw_ipcs = (ipcs & 0xffff);
		txq->txq_last_hw_tucs = (tucs & 0xffff);
	}

	/* Fill in the context descriptor. */
	t = (struct livengood_tcpip_ctxdesc *)
	    &txq->txq_descs[txq->txq_next];
	t->tcpip_ipcs = htole32(ipcs);
	t->tcpip_tucs = htole32(tucs);
	t->tcpip_cmdlen = htole32(cmdlen);
	t->tcpip_seg = htole32(seg);
	wm_cdtxsync(txq, txq->txq_next, 1, BUS_DMASYNC_PREWRITE);

	txq->txq_next = WM_NEXTTX(txq, txq->txq_next);
	txs->txs_ndesc++;
}

static inline int
wm_select_txqueue(struct ifnet *ifp, struct mbuf *m)
{
	struct wm_softc *sc = ifp->if_softc;
	u_int cpuid = cpu_index(curcpu());

	/*
	 * Currently, simple distribute strategy.
	 * TODO:
	 * distribute by flowid(RSS has value).
	 */
	return ((cpuid + ncpu - sc->sc_affinity_offset) % ncpu) % sc->sc_nqueues;
}

static inline bool
wm_linkdown_discard(struct wm_txqueue *txq)
{

	if ((txq->txq_flags & WM_TXQ_LINKDOWN_DISCARD) != 0)
		return true;

	return false;
}

/*
 * wm_start:		[ifnet interface function]
 *
 *	Start packet transmission on the interface.
 */
static void
wm_start(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;

	KASSERT(if_is_mpsafe(ifp));
	/*
	 * if_obytes and if_omcasts are added in if_transmit()@if.c.
	 */

	mutex_enter(txq->txq_lock);
	if (!txq->txq_stopping)
		wm_start_locked(ifp);
	mutex_exit(txq->txq_lock);
}

static void
wm_start_locked(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;

	wm_send_common_locked(ifp, txq, false);
}

static int
wm_transmit(struct ifnet *ifp, struct mbuf *m)
{
	int qid;
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq;

	qid = wm_select_txqueue(ifp, m);
	txq = &sc->sc_queue[qid].wmq_txq;

	if (__predict_false(!pcq_put(txq->txq_interq, m))) {
		m_freem(m);
		WM_Q_EVCNT_INCR(txq, pcqdrop);
		return ENOBUFS;
	}

	net_stat_ref_t nsr = IF_STAT_GETREF(ifp);
	if_statadd_ref(ifp, nsr, if_obytes, m->m_pkthdr.len);
	if (m->m_flags & M_MCAST)
		if_statinc_ref(ifp, nsr, if_omcasts);
	IF_STAT_PUTREF(ifp);

	if (mutex_tryenter(txq->txq_lock)) {
		if (!txq->txq_stopping)
			wm_transmit_locked(ifp, txq);
		mutex_exit(txq->txq_lock);
	}

	return 0;
}

static void
wm_transmit_locked(struct ifnet *ifp, struct wm_txqueue *txq)
{

	wm_send_common_locked(ifp, txq, true);
}

static void
wm_send_common_locked(struct ifnet *ifp, struct wm_txqueue *txq,
    bool is_transmit)
{
	struct wm_softc *sc = ifp->if_softc;
	struct mbuf *m0;
	struct wm_txsoft *txs;
	bus_dmamap_t dmamap;
	int error, nexttx, lasttx = -1, ofree, seg, segs_needed, use_tso;
	bus_addr_t curaddr;
	bus_size_t seglen, curlen;
	uint32_t cksumcmd;
	uint8_t cksumfields;
	bool remap = true;

	KASSERT(mutex_owned(txq->txq_lock));
	KASSERT(!txq->txq_stopping);

	if ((txq->txq_flags & WM_TXQ_NO_SPACE) != 0)
		return;

	if (__predict_false(wm_linkdown_discard(txq))) {
		do {
			if (is_transmit)
				m0 = pcq_get(txq->txq_interq);
			else
				IFQ_DEQUEUE(&ifp->if_snd, m0);
			/*
			 * increment successed packet counter as in the case
			 * which the packet is discarded by link down PHY.
			 */
			if (m0 != NULL) {
				if_statinc(ifp, if_opackets);
				m_freem(m0);
			}
		} while (m0 != NULL);
		return;
	}

	/* Remember the previous number of free descriptors. */
	ofree = txq->txq_free;

	/*
	 * Loop through the send queue, setting up transmit descriptors
	 * until we drain the queue, or use up all available transmit
	 * descriptors.
	 */
	for (;;) {
		m0 = NULL;

		/* Get a work queue entry. */
		if (txq->txq_sfree < WM_TXQUEUE_GC(txq)) {
			wm_txeof(txq, UINT_MAX);
			if (txq->txq_sfree == 0) {
				DPRINTF(sc, WM_DEBUG_TX,
				    ("%s: TX: no free job descriptors\n",
					device_xname(sc->sc_dev)));
				WM_Q_EVCNT_INCR(txq, txsstall);
				break;
			}
		}

		/* Grab a packet off the queue. */
		if (is_transmit)
			m0 = pcq_get(txq->txq_interq);
		else
			IFQ_DEQUEUE(&ifp->if_snd, m0);
		if (m0 == NULL)
			break;

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: have packet to transmit: %p\n",
			device_xname(sc->sc_dev), m0));

		txs = &txq->txq_soft[txq->txq_snext];
		dmamap = txs->txs_dmamap;

		use_tso = (m0->m_pkthdr.csum_flags &
		    (M_CSUM_TSOv4 | M_CSUM_TSOv6)) != 0;

		/*
		 * So says the Linux driver:
		 * The controller does a simple calculation to make sure
		 * there is enough room in the FIFO before initiating the
		 * DMA for each buffer. The calc is:
		 *	4 = ceil(buffer len / MSS)
		 * To make sure we don't overrun the FIFO, adjust the max
		 * buffer len if the MSS drops.
		 */
		dmamap->dm_maxsegsz =
		    (use_tso && (m0->m_pkthdr.segsz << 2) < WTX_MAX_LEN)
		    ? m0->m_pkthdr.segsz << 2
		    : WTX_MAX_LEN;

		/*
		 * Load the DMA map.  If this fails, the packet either
		 * didn't fit in the allotted number of segments, or we
		 * were short on resources.  For the too-many-segments
		 * case, we simply report an error and drop the packet,
		 * since we can't sanely copy a jumbo packet to a single
		 * buffer.
		 */
retry:
		error = bus_dmamap_load_mbuf(sc->sc_dmat, dmamap, m0,
		    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
		if (__predict_false(error)) {
			if (error == EFBIG) {
				if (remap == true) {
					struct mbuf *m;

					remap = false;
					m = m_defrag(m0, M_NOWAIT);
					if (m != NULL) {
						WM_Q_EVCNT_INCR(txq, defrag);
						m0 = m;
						goto retry;
					}
				}
				WM_Q_EVCNT_INCR(txq, toomanyseg);
				log(LOG_ERR, "%s: Tx packet consumes too many "
				    "DMA segments, dropping...\n",
				    device_xname(sc->sc_dev));
				wm_dump_mbuf_chain(sc, m0);
				m_freem(m0);
				continue;
			}
			/* Short on resources, just stop for now. */
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: dmamap load failed: %d\n",
				device_xname(sc->sc_dev), error));
			break;
		}

		segs_needed = dmamap->dm_nsegs;
		if (use_tso) {
			/* For sentinel descriptor; see below. */
			segs_needed++;
		}

		/*
		 * Ensure we have enough descriptors free to describe
		 * the packet. Note, we always reserve one descriptor
		 * at the end of the ring due to the semantics of the
		 * TDT register, plus one more in the event we need
		 * to load offload context.
		 */
		if (segs_needed > txq->txq_free - 2) {
			/*
			 * Not enough free descriptors to transmit this
			 * packet.  We haven't committed anything yet,
			 * so just unload the DMA map, put the packet
			 * pack on the queue, and punt. Notify the upper
			 * layer that there are no more slots left.
			 */
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: need %d (%d) descriptors, have %d\n",
				device_xname(sc->sc_dev), dmamap->dm_nsegs,
				segs_needed, txq->txq_free - 1));
			txq->txq_flags |= WM_TXQ_NO_SPACE;
			bus_dmamap_unload(sc->sc_dmat, dmamap);
			WM_Q_EVCNT_INCR(txq, txdstall);
			break;
		}

		/*
		 * Check for 82547 Tx FIFO bug. We need to do this
		 * once we know we can transmit the packet, since we
		 * do some internal FIFO space accounting here.
		 */
		if (sc->sc_type == WM_T_82547 &&
		    wm_82547_txfifo_bugchk(sc, m0)) {
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: 82547 Tx FIFO bug detected\n",
				device_xname(sc->sc_dev)));
			txq->txq_flags |= WM_TXQ_NO_SPACE;
			bus_dmamap_unload(sc->sc_dmat, dmamap);
			WM_Q_EVCNT_INCR(txq, fifo_stall);
			break;
		}

		/* WE ARE NOW COMMITTED TO TRANSMITTING THE PACKET. */

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: packet has %d (%d) DMA segments\n",
		    device_xname(sc->sc_dev), dmamap->dm_nsegs, segs_needed));

		WM_EVCNT_INCR(&txq->txq_ev_txseg[dmamap->dm_nsegs - 1]);

		/*
		 * Store a pointer to the packet so that we can free it
		 * later.
		 *
		 * Initially, we consider the number of descriptors the
		 * packet uses the number of DMA segments.  This may be
		 * incremented by 1 if we do checksum offload (a descriptor
		 * is used to set the checksum context).
		 */
		txs->txs_mbuf = m0;
		txs->txs_firstdesc = txq->txq_next;
		txs->txs_ndesc = segs_needed;

		/* Set up offload parameters for this packet. */
		if (m0->m_pkthdr.csum_flags &
		    (M_CSUM_TSOv4 | M_CSUM_TSOv6 |
		    M_CSUM_IPv4 | M_CSUM_TCPv4 | M_CSUM_UDPv4 |
		    M_CSUM_TCPv6 | M_CSUM_UDPv6)) {
			wm_tx_offload(sc, txq, txs, &cksumcmd, &cksumfields);
		} else {
			txq->txq_last_hw_cmd = txq->txq_last_hw_fields = 0;
			txq->txq_last_hw_ipcs = txq->txq_last_hw_tucs = 0;
			cksumcmd = 0;
			cksumfields = 0;
		}

		cksumcmd |= WTX_CMD_IDE | WTX_CMD_IFCS;

		/* Sync the DMA map. */
		bus_dmamap_sync(sc->sc_dmat, dmamap, 0, dmamap->dm_mapsize,
		    BUS_DMASYNC_PREWRITE);

		/* Initialize the transmit descriptor. */
		for (nexttx = txq->txq_next, seg = 0;
		     seg < dmamap->dm_nsegs; seg++) {
			for (seglen = dmamap->dm_segs[seg].ds_len,
			     curaddr = dmamap->dm_segs[seg].ds_addr;
			     seglen != 0;
			     curaddr += curlen, seglen -= curlen,
			     nexttx = WM_NEXTTX(txq, nexttx)) {
				curlen = seglen;

				/*
				 * So says the Linux driver:
				 * Work around for premature descriptor
				 * write-backs in TSO mode.  Append a
				 * 4-byte sentinel descriptor.
				 */
				if (use_tso && seg == dmamap->dm_nsegs - 1 &&
				    curlen > 8)
					curlen -= 4;

				wm_set_dma_addr(
				    &txq->txq_descs[nexttx].wtx_addr, curaddr);
				txq->txq_descs[nexttx].wtx_cmdlen
				    = htole32(cksumcmd | curlen);
				txq->txq_descs[nexttx].wtx_fields.wtxu_status
				    = 0;
				txq->txq_descs[nexttx].wtx_fields.wtxu_options
				    = cksumfields;
				txq->txq_descs[nexttx].wtx_fields.wtxu_vlan =0;
				lasttx = nexttx;

				DPRINTF(sc, WM_DEBUG_TX,
				    ("%s: TX: desc %d: low %#" PRIx64 ", "
					"len %#04zx\n",
					device_xname(sc->sc_dev), nexttx,
					(uint64_t)curaddr, curlen));
			}
		}

		KASSERT(lasttx != -1);

		/*
		 * Set up the command byte on the last descriptor of
		 * the packet. If we're in the interrupt delay window,
		 * delay the interrupt.
		 */
		txq->txq_descs[lasttx].wtx_cmdlen |=
		    htole32(WTX_CMD_EOP | WTX_CMD_RS);

		/*
		 * If VLANs are enabled and the packet has a VLAN tag, set
		 * up the descriptor to encapsulate the packet for us.
		 *
		 * This is only valid on the last descriptor of the packet.
		 */
		if (vlan_has_tag(m0)) {
			txq->txq_descs[lasttx].wtx_cmdlen |=
			    htole32(WTX_CMD_VLE);
			txq->txq_descs[lasttx].wtx_fields.wtxu_vlan
			    = htole16(vlan_get_tag(m0));
		}

		txs->txs_lastdesc = lasttx;

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: desc %d: cmdlen 0x%08x\n",
			device_xname(sc->sc_dev),
			lasttx, le32toh(txq->txq_descs[lasttx].wtx_cmdlen)));

		/* Sync the descriptors we're using. */
		wm_cdtxsync(txq, txq->txq_next, txs->txs_ndesc,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		/* Give the packet to the chip. */
		CSR_WRITE(sc, txq->txq_tdt_reg, nexttx);

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: TDT -> %d\n", device_xname(sc->sc_dev), nexttx));

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: finished transmitting packet, job %d\n",
			device_xname(sc->sc_dev), txq->txq_snext));

		/* Advance the tx pointer. */
		txq->txq_free -= txs->txs_ndesc;
		txq->txq_next = nexttx;

		txq->txq_sfree--;
		txq->txq_snext = WM_NEXTTXS(txq, txq->txq_snext);

		/* Pass the packet to any BPF listeners. */
		bpf_mtap(ifp, m0, BPF_D_OUT);
	}

	if (m0 != NULL) {
		txq->txq_flags |= WM_TXQ_NO_SPACE;
		WM_Q_EVCNT_INCR(txq, descdrop);
		DPRINTF(sc, WM_DEBUG_TX, ("%s: TX: error after IFQ_DEQUEUE\n",
			__func__));
		m_freem(m0);
	}

	if (txq->txq_sfree == 0 || txq->txq_free <= 2) {
		/* No more slots; notify upper layer. */
		txq->txq_flags |= WM_TXQ_NO_SPACE;
	}

	if (txq->txq_free != ofree) {
		/* Set a watchdog timer in case the chip flakes out. */
		txq->txq_lastsent = time_uptime;
		txq->txq_sending = true;
	}
}

/*
 * wm_nq_tx_offload:
 *
 *	Set up TCP/IP checksumming parameters for the
 *	specified packet, for NEWQUEUE devices
 */
static void
wm_nq_tx_offload(struct wm_softc *sc, struct wm_txqueue *txq,
    struct wm_txsoft *txs, uint32_t *cmdlenp, uint32_t *fieldsp, bool *do_csum)
{
	struct mbuf *m0 = txs->txs_mbuf;
	uint32_t vl_len, mssidx, cmdc;
	struct ether_header *eh;
	int offset, iphl;

	/*
	 * XXX It would be nice if the mbuf pkthdr had offset
	 * fields for the protocol headers.
	 */
	*cmdlenp = 0;
	*fieldsp = 0;

	eh = mtod(m0, struct ether_header *);
	switch (htons(eh->ether_type)) {
	case ETHERTYPE_IP:
	case ETHERTYPE_IPV6:
		offset = ETHER_HDR_LEN;
		break;

	case ETHERTYPE_VLAN:
		offset = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
		break;

	default:
		/* Don't support this protocol or encapsulation. */
		*do_csum = false;
		return;
	}
	*do_csum = true;
	*cmdlenp = NQTX_DTYP_D | NQTX_CMD_DEXT | NQTX_CMD_IFCS;
	cmdc = NQTX_DTYP_C | NQTX_CMD_DEXT;

	vl_len = (offset << NQTXC_VLLEN_MACLEN_SHIFT);
	KASSERT((offset & ~NQTXC_VLLEN_MACLEN_MASK) == 0);

	if ((m0->m_pkthdr.csum_flags &
	    (M_CSUM_TSOv4 | M_CSUM_UDPv4 | M_CSUM_TCPv4 | M_CSUM_IPv4)) != 0) {
		iphl = M_CSUM_DATA_IPv4_IPHL(m0->m_pkthdr.csum_data);
	} else {
		iphl = M_CSUM_DATA_IPv6_IPHL(m0->m_pkthdr.csum_data);
	}
	vl_len |= (iphl << NQTXC_VLLEN_IPLEN_SHIFT);
	KASSERT((iphl & ~NQTXC_VLLEN_IPLEN_MASK) == 0);

	if (vlan_has_tag(m0)) {
		vl_len |= ((vlan_get_tag(m0) & NQTXC_VLLEN_VLAN_MASK)
		    << NQTXC_VLLEN_VLAN_SHIFT);
		*cmdlenp |= NQTX_CMD_VLE;
	}

	mssidx = 0;

	if ((m0->m_pkthdr.csum_flags & (M_CSUM_TSOv4 | M_CSUM_TSOv6)) != 0) {
		int hlen = offset + iphl;
		int tcp_hlen;
		bool v4 = (m0->m_pkthdr.csum_flags & M_CSUM_TSOv4) != 0;

		if (__predict_false(m0->m_len <
				    (hlen + sizeof(struct tcphdr)))) {
			/*
			 * TCP/IP headers are not in the first mbuf; we need
			 * to do this the slow and painful way. Let's just
			 * hope this doesn't happen very often.
			 */
			struct tcphdr th;

			WM_Q_EVCNT_INCR(txq, tsopain);

			m_copydata(m0, hlen, sizeof(th), &th);
			if (v4) {
				struct ip ip;

				m_copydata(m0, offset, sizeof(ip), &ip);
				ip.ip_len = 0;
				m_copyback(m0,
				    offset + offsetof(struct ip, ip_len),
				    sizeof(ip.ip_len), &ip.ip_len);
				th.th_sum = in_cksum_phdr(ip.ip_src.s_addr,
				    ip.ip_dst.s_addr, htons(IPPROTO_TCP));
			} else {
				struct ip6_hdr ip6;

				m_copydata(m0, offset, sizeof(ip6), &ip6);
				ip6.ip6_plen = 0;
				m_copyback(m0,
				    offset + offsetof(struct ip6_hdr, ip6_plen),
				    sizeof(ip6.ip6_plen), &ip6.ip6_plen);
				th.th_sum = in6_cksum_phdr(&ip6.ip6_src,
				    &ip6.ip6_dst, 0, htonl(IPPROTO_TCP));
			}
			m_copyback(m0, hlen + offsetof(struct tcphdr, th_sum),
			    sizeof(th.th_sum), &th.th_sum);

			tcp_hlen = th.th_off << 2;
		} else {
			/*
			 * TCP/IP headers are in the first mbuf; we can do
			 * this the easy way.
			 */
			struct tcphdr *th;

			if (v4) {
				struct ip *ip =
				    (void *)(mtod(m0, char *) + offset);
				th = (void *)(mtod(m0, char *) + hlen);

				ip->ip_len = 0;
				th->th_sum = in_cksum_phdr(ip->ip_src.s_addr,
				    ip->ip_dst.s_addr, htons(IPPROTO_TCP));
			} else {
				struct ip6_hdr *ip6 =
				    (void *)(mtod(m0, char *) + offset);
				th = (void *)(mtod(m0, char *) + hlen);

				ip6->ip6_plen = 0;
				th->th_sum = in6_cksum_phdr(&ip6->ip6_src,
				    &ip6->ip6_dst, 0, htonl(IPPROTO_TCP));
			}
			tcp_hlen = th->th_off << 2;
		}
		hlen += tcp_hlen;
		*cmdlenp |= NQTX_CMD_TSE;

		if (v4) {
			WM_Q_EVCNT_INCR(txq, tso);
			*fieldsp |= NQTXD_FIELDS_IXSM | NQTXD_FIELDS_TUXSM;
		} else {
			WM_Q_EVCNT_INCR(txq, tso6);
			*fieldsp |= NQTXD_FIELDS_TUXSM;
		}
		*fieldsp |= ((m0->m_pkthdr.len - hlen) << NQTXD_FIELDS_PAYLEN_SHIFT);
		KASSERT(((m0->m_pkthdr.len - hlen) & ~NQTXD_FIELDS_PAYLEN_MASK) == 0);
		mssidx |= (m0->m_pkthdr.segsz << NQTXC_MSSIDX_MSS_SHIFT);
		KASSERT((m0->m_pkthdr.segsz & ~NQTXC_MSSIDX_MSS_MASK) == 0);
		mssidx |= (tcp_hlen << NQTXC_MSSIDX_L4LEN_SHIFT);
		KASSERT((tcp_hlen & ~NQTXC_MSSIDX_L4LEN_MASK) == 0);
	} else {
		*fieldsp |= (m0->m_pkthdr.len << NQTXD_FIELDS_PAYLEN_SHIFT);
		KASSERT((m0->m_pkthdr.len & ~NQTXD_FIELDS_PAYLEN_MASK) == 0);
	}

	if (m0->m_pkthdr.csum_flags & M_CSUM_IPv4) {
		*fieldsp |= NQTXD_FIELDS_IXSM;
		cmdc |= NQTXC_CMD_IP4;
	}

	if (m0->m_pkthdr.csum_flags &
	    (M_CSUM_UDPv4 | M_CSUM_TCPv4 | M_CSUM_TSOv4)) {
		WM_Q_EVCNT_INCR(txq, tusum);
		if (m0->m_pkthdr.csum_flags & (M_CSUM_TCPv4 | M_CSUM_TSOv4))
			cmdc |= NQTXC_CMD_TCP;
		else
			cmdc |= NQTXC_CMD_UDP;

		cmdc |= NQTXC_CMD_IP4;
		*fieldsp |= NQTXD_FIELDS_TUXSM;
	}
	if (m0->m_pkthdr.csum_flags &
	    (M_CSUM_UDPv6 | M_CSUM_TCPv6 | M_CSUM_TSOv6)) {
		WM_Q_EVCNT_INCR(txq, tusum6);
		if (m0->m_pkthdr.csum_flags & (M_CSUM_TCPv6 | M_CSUM_TSOv6))
			cmdc |= NQTXC_CMD_TCP;
		else
			cmdc |= NQTXC_CMD_UDP;

		cmdc |= NQTXC_CMD_IP6;
		*fieldsp |= NQTXD_FIELDS_TUXSM;
	}

	/*
	 * We don't have to write context descriptor for every packet to
	 * NEWQUEUE controllers, that is 82575, 82576, 82580, I350, I354,
	 * I210 and I211. It is enough to write once per a Tx queue for these
	 * controllers.
	 * It would be overhead to write context descriptor for every packet,
	 * however it does not cause problems.
	 */
	/* Fill in the context descriptor. */
	txq->txq_nq_descs[txq->txq_next].nqtx_ctx.nqtxc_vl_len =
	    htole32(vl_len);
	txq->txq_nq_descs[txq->txq_next].nqtx_ctx.nqtxc_sn = 0;
	txq->txq_nq_descs[txq->txq_next].nqtx_ctx.nqtxc_cmd =
	    htole32(cmdc);
	txq->txq_nq_descs[txq->txq_next].nqtx_ctx.nqtxc_mssidx =
	    htole32(mssidx);
	wm_cdtxsync(txq, txq->txq_next, 1, BUS_DMASYNC_PREWRITE);
	DPRINTF(sc, WM_DEBUG_TX,
	    ("%s: TX: context desc %d 0x%08x%08x\n", device_xname(sc->sc_dev),
		txq->txq_next, 0, vl_len));
	DPRINTF(sc, WM_DEBUG_TX, ("\t0x%08x%08x\n", mssidx, cmdc));
	txq->txq_next = WM_NEXTTX(txq, txq->txq_next);
	txs->txs_ndesc++;
}

/*
 * wm_nq_start:		[ifnet interface function]
 *
 *	Start packet transmission on the interface for NEWQUEUE devices
 */
static void
wm_nq_start(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;

	KASSERT(if_is_mpsafe(ifp));
	/*
	 * if_obytes and if_omcasts are added in if_transmit()@if.c.
	 */

	mutex_enter(txq->txq_lock);
	if (!txq->txq_stopping)
		wm_nq_start_locked(ifp);
	mutex_exit(txq->txq_lock);
}

static void
wm_nq_start_locked(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq = &sc->sc_queue[0].wmq_txq;

	wm_nq_send_common_locked(ifp, txq, false);
}

static int
wm_nq_transmit(struct ifnet *ifp, struct mbuf *m)
{
	int qid;
	struct wm_softc *sc = ifp->if_softc;
	struct wm_txqueue *txq;

	qid = wm_select_txqueue(ifp, m);
	txq = &sc->sc_queue[qid].wmq_txq;

	if (__predict_false(!pcq_put(txq->txq_interq, m))) {
		m_freem(m);
		WM_Q_EVCNT_INCR(txq, pcqdrop);
		return ENOBUFS;
	}

	net_stat_ref_t nsr = IF_STAT_GETREF(ifp);
	if_statadd_ref(ifp, nsr, if_obytes, m->m_pkthdr.len);
	if (m->m_flags & M_MCAST)
		if_statinc_ref(ifp, nsr, if_omcasts);
	IF_STAT_PUTREF(ifp);

	/*
	 * The situations which this mutex_tryenter() fails at running time
	 * are below two patterns.
	 *     (1) contention with interrupt handler(wm_txrxintr_msix())
	 *     (2) contention with deferred if_start softint(wm_handle_queue())
	 * In the case of (1), the last packet enqueued to txq->txq_interq is
	 * dequeued by wm_deferred_start_locked(). So, it does not get stuck.
	 * In the case of (2), the last packet enqueued to txq->txq_interq is
	 * also dequeued by wm_deferred_start_locked(). So, it does not get
	 * stuck, either.
	 */
	if (mutex_tryenter(txq->txq_lock)) {
		if (!txq->txq_stopping)
			wm_nq_transmit_locked(ifp, txq);
		mutex_exit(txq->txq_lock);
	}

	return 0;
}

static void
wm_nq_transmit_locked(struct ifnet *ifp, struct wm_txqueue *txq)
{

	wm_nq_send_common_locked(ifp, txq, true);
}

static void
wm_nq_send_common_locked(struct ifnet *ifp, struct wm_txqueue *txq,
    bool is_transmit)
{
	struct wm_softc *sc = ifp->if_softc;
	struct mbuf *m0;
	struct wm_txsoft *txs;
	bus_dmamap_t dmamap;
	int error, nexttx, lasttx = -1, seg, segs_needed;
	bool do_csum, sent;
	bool remap = true;

	KASSERT(mutex_owned(txq->txq_lock));
	KASSERT(!txq->txq_stopping);

	if ((txq->txq_flags & WM_TXQ_NO_SPACE) != 0)
		return;

	if (__predict_false(wm_linkdown_discard(txq))) {
		do {
			if (is_transmit)
				m0 = pcq_get(txq->txq_interq);
			else
				IFQ_DEQUEUE(&ifp->if_snd, m0);
			/*
			 * increment successed packet counter as in the case
			 * which the packet is discarded by link down PHY.
			 */
			if (m0 != NULL) {
				if_statinc(ifp, if_opackets);
				m_freem(m0);
			}
		} while (m0 != NULL);
		return;
	}

	sent = false;

	/*
	 * Loop through the send queue, setting up transmit descriptors
	 * until we drain the queue, or use up all available transmit
	 * descriptors.
	 */
	for (;;) {
		m0 = NULL;

		/* Get a work queue entry. */
		if (txq->txq_sfree < WM_TXQUEUE_GC(txq)) {
			wm_txeof(txq, UINT_MAX);
			if (txq->txq_sfree == 0) {
				DPRINTF(sc, WM_DEBUG_TX,
				    ("%s: TX: no free job descriptors\n",
					device_xname(sc->sc_dev)));
				WM_Q_EVCNT_INCR(txq, txsstall);
				break;
			}
		}

		/* Grab a packet off the queue. */
		if (is_transmit)
			m0 = pcq_get(txq->txq_interq);
		else
			IFQ_DEQUEUE(&ifp->if_snd, m0);
		if (m0 == NULL)
			break;

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: have packet to transmit: %p\n",
			device_xname(sc->sc_dev), m0));

		txs = &txq->txq_soft[txq->txq_snext];
		dmamap = txs->txs_dmamap;

		/*
		 * Load the DMA map.  If this fails, the packet either
		 * didn't fit in the allotted number of segments, or we
		 * were short on resources.  For the too-many-segments
		 * case, we simply report an error and drop the packet,
		 * since we can't sanely copy a jumbo packet to a single
		 * buffer.
		 */
retry:
		error = bus_dmamap_load_mbuf(sc->sc_dmat, dmamap, m0,
		    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
		if (__predict_false(error)) {
			if (error == EFBIG) {
				if (remap == true) {
					struct mbuf *m;

					remap = false;
					m = m_defrag(m0, M_NOWAIT);
					if (m != NULL) {
						WM_Q_EVCNT_INCR(txq, defrag);
						m0 = m;
						goto retry;
					}
				}
				WM_Q_EVCNT_INCR(txq, toomanyseg);
				log(LOG_ERR, "%s: Tx packet consumes too many "
				    "DMA segments, dropping...\n",
				    device_xname(sc->sc_dev));
				wm_dump_mbuf_chain(sc, m0);
				m_freem(m0);
				continue;
			}
			/* Short on resources, just stop for now. */
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: dmamap load failed: %d\n",
				device_xname(sc->sc_dev), error));
			break;
		}

		segs_needed = dmamap->dm_nsegs;

		/*
		 * Ensure we have enough descriptors free to describe
		 * the packet. Note, we always reserve one descriptor
		 * at the end of the ring due to the semantics of the
		 * TDT register, plus one more in the event we need
		 * to load offload context.
		 */
		if (segs_needed > txq->txq_free - 2) {
			/*
			 * Not enough free descriptors to transmit this
			 * packet.  We haven't committed anything yet,
			 * so just unload the DMA map, put the packet
			 * pack on the queue, and punt. Notify the upper
			 * layer that there are no more slots left.
			 */
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: need %d (%d) descriptors, have %d\n",
				device_xname(sc->sc_dev), dmamap->dm_nsegs,
				segs_needed, txq->txq_free - 1));
			txq->txq_flags |= WM_TXQ_NO_SPACE;
			bus_dmamap_unload(sc->sc_dmat, dmamap);
			WM_Q_EVCNT_INCR(txq, txdstall);
			break;
		}

		/* WE ARE NOW COMMITTED TO TRANSMITTING THE PACKET. */

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: packet has %d (%d) DMA segments\n",
		    device_xname(sc->sc_dev), dmamap->dm_nsegs, segs_needed));

		WM_EVCNT_INCR(&txq->txq_ev_txseg[dmamap->dm_nsegs - 1]);

		/*
		 * Store a pointer to the packet so that we can free it
		 * later.
		 *
		 * Initially, we consider the number of descriptors the
		 * packet uses the number of DMA segments.  This may be
		 * incremented by 1 if we do checksum offload (a descriptor
		 * is used to set the checksum context).
		 */
		txs->txs_mbuf = m0;
		txs->txs_firstdesc = txq->txq_next;
		txs->txs_ndesc = segs_needed;

		/* Set up offload parameters for this packet. */
		uint32_t cmdlen, fields, dcmdlen;
		if (m0->m_pkthdr.csum_flags &
		    (M_CSUM_TSOv4 | M_CSUM_TSOv6 |
			M_CSUM_IPv4 | M_CSUM_TCPv4 | M_CSUM_UDPv4 |
			M_CSUM_TCPv6 | M_CSUM_UDPv6)) {
			wm_nq_tx_offload(sc, txq, txs, &cmdlen, &fields,
			    &do_csum);
		} else {
			do_csum = false;
			cmdlen = 0;
			fields = 0;
		}

		/* Sync the DMA map. */
		bus_dmamap_sync(sc->sc_dmat, dmamap, 0, dmamap->dm_mapsize,
		    BUS_DMASYNC_PREWRITE);

		/* Initialize the first transmit descriptor. */
		nexttx = txq->txq_next;
		if (!do_csum) {
			/* Set up a legacy descriptor */
			wm_set_dma_addr(&txq->txq_descs[nexttx].wtx_addr,
			    dmamap->dm_segs[0].ds_addr);
			txq->txq_descs[nexttx].wtx_cmdlen =
			    htole32(WTX_CMD_IFCS | dmamap->dm_segs[0].ds_len);
			txq->txq_descs[nexttx].wtx_fields.wtxu_status = 0;
			txq->txq_descs[nexttx].wtx_fields.wtxu_options = 0;
			if (vlan_has_tag(m0)) {
				txq->txq_descs[nexttx].wtx_cmdlen |=
				    htole32(WTX_CMD_VLE);
				txq->txq_descs[nexttx].wtx_fields.wtxu_vlan =
				    htole16(vlan_get_tag(m0));
			} else
				txq->txq_descs[nexttx].wtx_fields.wtxu_vlan =0;

			dcmdlen = 0;
		} else {
			/* Set up an advanced data descriptor */
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_addr =
			    htole64(dmamap->dm_segs[0].ds_addr);
			KASSERT((dmamap->dm_segs[0].ds_len & cmdlen) == 0);
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_cmdlen =
			    htole32(dmamap->dm_segs[0].ds_len | cmdlen);
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_fields =
			    htole32(fields);
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: adv data desc %d 0x%" PRIx64 "\n",
				device_xname(sc->sc_dev), nexttx,
				(uint64_t)dmamap->dm_segs[0].ds_addr));
			DPRINTF(sc, WM_DEBUG_TX,
			    ("\t 0x%08x%08x\n", fields,
				(uint32_t)dmamap->dm_segs[0].ds_len | cmdlen));
			dcmdlen = NQTX_DTYP_D | NQTX_CMD_DEXT;
		}

		lasttx = nexttx;
		nexttx = WM_NEXTTX(txq, nexttx);
		/*
		 * Fill in the next descriptors. Legacy or advanced format
		 * is the same here.
		 */
		for (seg = 1; seg < dmamap->dm_nsegs;
		     seg++, nexttx = WM_NEXTTX(txq, nexttx)) {
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_addr =
			    htole64(dmamap->dm_segs[seg].ds_addr);
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_cmdlen =
			    htole32(dcmdlen | dmamap->dm_segs[seg].ds_len);
			KASSERT((dcmdlen & dmamap->dm_segs[seg].ds_len) == 0);
			txq->txq_nq_descs[nexttx].nqtx_data.nqtxd_fields = 0;
			lasttx = nexttx;

			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: desc %d: %#" PRIx64 ", len %#04zx\n",
				device_xname(sc->sc_dev), nexttx,
				(uint64_t)dmamap->dm_segs[seg].ds_addr,
				dmamap->dm_segs[seg].ds_len));
		}

		KASSERT(lasttx != -1);

		/*
		 * Set up the command byte on the last descriptor of
		 * the packet. If we're in the interrupt delay window,
		 * delay the interrupt.
		 */
		KASSERT((WTX_CMD_EOP | WTX_CMD_RS) ==
		    (NQTX_CMD_EOP | NQTX_CMD_RS));
		txq->txq_descs[lasttx].wtx_cmdlen |=
		    htole32(WTX_CMD_EOP | WTX_CMD_RS);

		txs->txs_lastdesc = lasttx;

		DPRINTF(sc, WM_DEBUG_TX, ("%s: TX: desc %d: cmdlen 0x%08x\n",
		    device_xname(sc->sc_dev),
		    lasttx, le32toh(txq->txq_descs[lasttx].wtx_cmdlen)));

		/* Sync the descriptors we're using. */
		wm_cdtxsync(txq, txq->txq_next, txs->txs_ndesc,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

		/* Give the packet to the chip. */
		CSR_WRITE(sc, txq->txq_tdt_reg, nexttx);
		sent = true;

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: TDT -> %d\n", device_xname(sc->sc_dev), nexttx));

		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: finished transmitting packet, job %d\n",
			device_xname(sc->sc_dev), txq->txq_snext));

		/* Advance the tx pointer. */
		txq->txq_free -= txs->txs_ndesc;
		txq->txq_next = nexttx;

		txq->txq_sfree--;
		txq->txq_snext = WM_NEXTTXS(txq, txq->txq_snext);

		/* Pass the packet to any BPF listeners. */
		bpf_mtap(ifp, m0, BPF_D_OUT);
	}

	if (m0 != NULL) {
		txq->txq_flags |= WM_TXQ_NO_SPACE;
		WM_Q_EVCNT_INCR(txq, descdrop);
		DPRINTF(sc, WM_DEBUG_TX, ("%s: TX: error after IFQ_DEQUEUE\n",
			__func__));
		m_freem(m0);
	}

	if (txq->txq_sfree == 0 || txq->txq_free <= 2) {
		/* No more slots; notify upper layer. */
		txq->txq_flags |= WM_TXQ_NO_SPACE;
	}

	if (sent) {
		/* Set a watchdog timer in case the chip flakes out. */
		txq->txq_lastsent = time_uptime;
		txq->txq_sending = true;
	}
}

static void
wm_deferred_start_locked(struct wm_txqueue *txq)
{
	struct wm_softc *sc = txq->txq_sc;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct wm_queue *wmq = container_of(txq, struct wm_queue, wmq_txq);
	int qid = wmq->wmq_id;

	KASSERT(mutex_owned(txq->txq_lock));
	KASSERT(!txq->txq_stopping);

	if ((sc->sc_flags & WM_F_NEWQUEUE) != 0) {
		/* XXX need for ALTQ or one CPU system */
		if (qid == 0)
			wm_nq_start_locked(ifp);
		wm_nq_transmit_locked(ifp, txq);
	} else {
		/* XXX need for ALTQ or one CPU system */
		if (qid == 0)
			wm_start_locked(ifp);
		wm_transmit_locked(ifp, txq);
	}
}

/* Interrupt */

/*
 * wm_txeof:
 *
 *	Helper; handle transmit interrupts.
 */
static bool
wm_txeof(struct wm_txqueue *txq, u_int limit)
{
	struct wm_softc *sc = txq->txq_sc;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct wm_txsoft *txs;
	int count = 0;
	int i;
	uint8_t status;
	bool more = false;

	KASSERT(mutex_owned(txq->txq_lock));

	if (txq->txq_stopping)
		return false;

	txq->txq_flags &= ~WM_TXQ_NO_SPACE;

	/*
	 * Go through the Tx list and free mbufs for those
	 * frames which have been transmitted.
	 */
	for (i = txq->txq_sdirty; txq->txq_sfree != WM_TXQUEUELEN(txq);
	     i = WM_NEXTTXS(txq, i), txq->txq_sfree++) {
		txs = &txq->txq_soft[i];

		DPRINTF(sc, WM_DEBUG_TX, ("%s: TX: checking job %d\n",
			device_xname(sc->sc_dev), i));

		wm_cdtxsync(txq, txs->txs_firstdesc, txs->txs_ndesc,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

		status =
		    txq->txq_descs[txs->txs_lastdesc].wtx_fields.wtxu_status;
		if ((status & WTX_ST_DD) == 0) {
			wm_cdtxsync(txq, txs->txs_lastdesc, 1,
			    BUS_DMASYNC_PREREAD);
			break;
		}

		if (limit-- == 0) {
			more = true;
			DPRINTF(sc, WM_DEBUG_TX,
			    ("%s: TX: loop limited, job %d is not processed\n",
				device_xname(sc->sc_dev), i));
			break;
		}

		count++;
		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: job %d done: descs %d..%d\n",
		    device_xname(sc->sc_dev), i, txs->txs_firstdesc,
		    txs->txs_lastdesc));

#ifdef WM_EVENT_COUNTERS
		if ((status & WTX_ST_TU) && (sc->sc_type <= WM_T_82544))
			WM_Q_EVCNT_INCR(txq, underrun);
#endif /* WM_EVENT_COUNTERS */

		/*
		 * 82574 and newer's document says the status field has neither
		 * EC (Excessive Collision) bit nor LC (Late Collision) bit
		 * (reserved). Refer "PCIe GbE Controller Open Source Software
		 * Developer's Manual", 82574 datasheet and newer.
		 *
		 * XXX I saw the LC bit was set on I218 even though the media
		 * was full duplex, so the bit might be used for other
		 * meaning ...(I have no document).
		 */

		if (((status & (WTX_ST_EC | WTX_ST_LC)) != 0)
		    && ((sc->sc_type < WM_T_82574)
			|| (sc->sc_type == WM_T_80003))) {
			if_statinc(ifp, if_oerrors);
			if (status & WTX_ST_LC)
				log(LOG_WARNING, "%s: late collision\n",
				    device_xname(sc->sc_dev));
			else if (status & WTX_ST_EC) {
				if_statadd(ifp, if_collisions,
				    TX_COLLISION_THRESHOLD + 1);
				log(LOG_WARNING, "%s: excessive collisions\n",
				    device_xname(sc->sc_dev));
			}
		} else
			if_statinc(ifp, if_opackets);

		txq->txq_packets++;
		txq->txq_bytes += txs->txs_mbuf->m_pkthdr.len;

		txq->txq_free += txs->txs_ndesc;
		bus_dmamap_sync(sc->sc_dmat, txs->txs_dmamap,
		    0, txs->txs_dmamap->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, txs->txs_dmamap);
		m_freem(txs->txs_mbuf);
		txs->txs_mbuf = NULL;
	}

	/* Update the dirty transmit buffer pointer. */
	txq->txq_sdirty = i;
	DPRINTF(sc, WM_DEBUG_TX,
	    ("%s: TX: txsdirty -> %d\n", device_xname(sc->sc_dev), i));

	if (count != 0)
		rnd_add_uint32(&sc->rnd_source, count);

	/*
	 * If there are no more pending transmissions, cancel the watchdog
	 * timer.
	 */
	if (txq->txq_sfree == WM_TXQUEUELEN(txq))
		txq->txq_sending = false;

	return more;
}

static inline uint32_t
wm_rxdesc_get_status(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return EXTRXC_STATUS(
		    le32toh(rxq->rxq_ext_descs[idx].erx_ctx.erxc_err_stat));
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return NQRXC_STATUS(
		    le32toh(rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_err_stat));
	else
		return rxq->rxq_descs[idx].wrx_status;
}

static inline uint32_t
wm_rxdesc_get_errors(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return EXTRXC_ERROR(
		    le32toh(rxq->rxq_ext_descs[idx].erx_ctx.erxc_err_stat));
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return NQRXC_ERROR(
		    le32toh(rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_err_stat));
	else
		return rxq->rxq_descs[idx].wrx_errors;
}

static inline uint16_t
wm_rxdesc_get_vlantag(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return rxq->rxq_ext_descs[idx].erx_ctx.erxc_vlan;
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_vlan;
	else
		return rxq->rxq_descs[idx].wrx_special;
}

static inline int
wm_rxdesc_get_pktlen(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return rxq->rxq_ext_descs[idx].erx_ctx.erxc_pktlen;
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_pktlen;
	else
		return rxq->rxq_descs[idx].wrx_len;
}

#ifdef WM_DEBUG
static inline uint32_t
wm_rxdesc_get_rsshash(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return rxq->rxq_ext_descs[idx].erx_ctx.erxc_rsshash;
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_rsshash;
	else
		return 0;
}

static inline uint8_t
wm_rxdesc_get_rsstype(struct wm_rxqueue *rxq, int idx)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (sc->sc_type == WM_T_82574)
		return EXTRXC_RSS_TYPE(rxq->rxq_ext_descs[idx].erx_ctx.erxc_mrq);
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return NQRXC_RSS_TYPE(rxq->rxq_nq_descs[idx].nqrx_ctx.nrxc_misc);
	else
		return 0;
}
#endif /* WM_DEBUG */

static inline bool
wm_rxdesc_is_set_status(struct wm_softc *sc, uint32_t status,
    uint32_t legacy_bit, uint32_t ext_bit, uint32_t nq_bit)
{

	if (sc->sc_type == WM_T_82574)
		return (status & ext_bit) != 0;
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return (status & nq_bit) != 0;
	else
		return (status & legacy_bit) != 0;
}

static inline bool
wm_rxdesc_is_set_error(struct wm_softc *sc, uint32_t error,
    uint32_t legacy_bit, uint32_t ext_bit, uint32_t nq_bit)
{

	if (sc->sc_type == WM_T_82574)
		return (error & ext_bit) != 0;
	else if ((sc->sc_flags & WM_F_NEWQUEUE) != 0)
		return (error & nq_bit) != 0;
	else
		return (error & legacy_bit) != 0;
}

static inline bool
wm_rxdesc_is_eop(struct wm_rxqueue *rxq, uint32_t status)
{

	if (wm_rxdesc_is_set_status(rxq->rxq_sc, status,
		WRX_ST_EOP, EXTRXC_STATUS_EOP, NQRXC_STATUS_EOP))
		return true;
	else
		return false;
}

static inline bool
wm_rxdesc_has_errors(struct wm_rxqueue *rxq, uint32_t errors)
{
	struct wm_softc *sc = rxq->rxq_sc;

	/* XXX missing error bit for newqueue? */
	if (wm_rxdesc_is_set_error(sc, errors,
		WRX_ER_CE | WRX_ER_SE | WRX_ER_SEQ | WRX_ER_CXE | WRX_ER_RXE,
		EXTRXC_ERROR_CE | EXTRXC_ERROR_SE | EXTRXC_ERROR_SEQ
		| EXTRXC_ERROR_CXE | EXTRXC_ERROR_RXE,
		NQRXC_ERROR_RXE)) {
		if (wm_rxdesc_is_set_error(sc, errors, WRX_ER_SE,
		    EXTRXC_ERROR_SE, 0))
			log(LOG_WARNING, "%s: symbol error\n",
			    device_xname(sc->sc_dev));
		else if (wm_rxdesc_is_set_error(sc, errors, WRX_ER_SEQ,
		    EXTRXC_ERROR_SEQ, 0))
			log(LOG_WARNING, "%s: receive sequence error\n",
			    device_xname(sc->sc_dev));
		else if (wm_rxdesc_is_set_error(sc, errors, WRX_ER_CE,
		    EXTRXC_ERROR_CE, 0))
			log(LOG_WARNING, "%s: CRC error\n",
			    device_xname(sc->sc_dev));
		return true;
	}

	return false;
}

static inline bool
wm_rxdesc_dd(struct wm_rxqueue *rxq, int idx, uint32_t status)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (!wm_rxdesc_is_set_status(sc, status, WRX_ST_DD, EXTRXC_STATUS_DD,
		NQRXC_STATUS_DD)) {
		/* We have processed all of the receive descriptors. */
		wm_cdrxsync(rxq, idx, BUS_DMASYNC_PREREAD);
		return false;
	}

	return true;
}

static inline bool
wm_rxdesc_input_vlantag(struct wm_rxqueue *rxq, uint32_t status,
    uint16_t vlantag, struct mbuf *m)
{

	if (wm_rxdesc_is_set_status(rxq->rxq_sc, status,
		WRX_ST_VP, EXTRXC_STATUS_VP, NQRXC_STATUS_VP)) {
		vlan_set_tag(m, le16toh(vlantag));
	}

	return true;
}

static inline void
wm_rxdesc_ensure_checksum(struct wm_rxqueue *rxq, uint32_t status,
    uint32_t errors, struct mbuf *m)
{
	struct wm_softc *sc = rxq->rxq_sc;

	if (!wm_rxdesc_is_set_status(sc, status, WRX_ST_IXSM, 0, 0)) {
		if (wm_rxdesc_is_set_status(sc, status,
		    WRX_ST_IPCS, EXTRXC_STATUS_IPCS, NQRXC_STATUS_IPCS)) {
			WM_Q_EVCNT_INCR(rxq, ipsum);
			m->m_pkthdr.csum_flags |= M_CSUM_IPv4;
			if (wm_rxdesc_is_set_error(sc, errors,
			    WRX_ER_IPE, EXTRXC_ERROR_IPE, NQRXC_ERROR_IPE))
				m->m_pkthdr.csum_flags |= M_CSUM_IPv4_BAD;
		}
		if (wm_rxdesc_is_set_status(sc, status,
		    WRX_ST_TCPCS, EXTRXC_STATUS_TCPCS, NQRXC_STATUS_L4I)) {
			/*
			 * Note: we don't know if this was TCP or UDP,
			 * so we just set both bits, and expect the
			 * upper layers to deal.
			 */
			WM_Q_EVCNT_INCR(rxq, tusum);
			m->m_pkthdr.csum_flags |=
			    M_CSUM_TCPv4 | M_CSUM_UDPv4 |
			    M_CSUM_TCPv6 | M_CSUM_UDPv6;
			if (wm_rxdesc_is_set_error(sc, errors, WRX_ER_TCPE,
			    EXTRXC_ERROR_TCPE, NQRXC_ERROR_L4E))
				m->m_pkthdr.csum_flags |= M_CSUM_TCP_UDP_BAD;
		}
	}
}

/*
 * wm_rxeof:
 *
 *	Helper; handle receive interrupts.
 */
static bool
wm_rxeof(struct wm_rxqueue *rxq, u_int limit)
{
	struct wm_softc *sc = rxq->rxq_sc;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct wm_rxsoft *rxs;
	struct mbuf *m;
	int i, len;
	int count = 0;
	uint32_t status, errors;
	uint16_t vlantag;
	bool more = false;

	KASSERT(mutex_owned(rxq->rxq_lock));

	for (i = rxq->rxq_ptr;; i = WM_NEXTRX(i)) {
		rxs = &rxq->rxq_soft[i];

		DPRINTF(sc, WM_DEBUG_RX,
		    ("%s: RX: checking descriptor %d\n",
			device_xname(sc->sc_dev), i));
		wm_cdrxsync(rxq, i,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

		status = wm_rxdesc_get_status(rxq, i);
		errors = wm_rxdesc_get_errors(rxq, i);
		len = le16toh(wm_rxdesc_get_pktlen(rxq, i));
		vlantag = wm_rxdesc_get_vlantag(rxq, i);
#ifdef WM_DEBUG
		uint32_t rsshash = le32toh(wm_rxdesc_get_rsshash(rxq, i));
		uint8_t rsstype = wm_rxdesc_get_rsstype(rxq, i);
#endif

		if (!wm_rxdesc_dd(rxq, i, status))
			break;

		if (limit-- == 0) {
			more = true;
			DPRINTF(sc, WM_DEBUG_RX,
			    ("%s: RX: loop limited, descriptor %d is not processed\n",
				device_xname(sc->sc_dev), i));
			break;
		}

		count++;
		if (__predict_false(rxq->rxq_discard)) {
			DPRINTF(sc, WM_DEBUG_RX,
			    ("%s: RX: discarding contents of descriptor %d\n",
				device_xname(sc->sc_dev), i));
			wm_init_rxdesc(rxq, i);
			if (wm_rxdesc_is_eop(rxq, status)) {
				/* Reset our state. */
				DPRINTF(sc, WM_DEBUG_RX,
				    ("%s: RX: resetting rxdiscard -> 0\n",
					device_xname(sc->sc_dev)));
				rxq->rxq_discard = 0;
			}
			continue;
		}

		bus_dmamap_sync(sc->sc_dmat, rxs->rxs_dmamap, 0,
		    rxs->rxs_dmamap->dm_mapsize, BUS_DMASYNC_POSTREAD);

		m = rxs->rxs_mbuf;

		/*
		 * Add a new receive buffer to the ring, unless of
		 * course the length is zero. Treat the latter as a
		 * failed mapping.
		 */
		if ((len == 0) || (wm_add_rxbuf(rxq, i) != 0)) {
			/*
			 * Failed, throw away what we've done so
			 * far, and discard the rest of the packet.
			 */
			if_statinc(ifp, if_ierrors);
			bus_dmamap_sync(sc->sc_dmat, rxs->rxs_dmamap, 0,
			    rxs->rxs_dmamap->dm_mapsize, BUS_DMASYNC_PREREAD);
			wm_init_rxdesc(rxq, i);
			if (!wm_rxdesc_is_eop(rxq, status))
				rxq->rxq_discard = 1;
			m_freem(rxq->rxq_head);
			WM_RXCHAIN_RESET(rxq);
			DPRINTF(sc, WM_DEBUG_RX,
			    ("%s: RX: Rx buffer allocation failed, "
			    "dropping packet%s\n", device_xname(sc->sc_dev),
				rxq->rxq_discard ? " (discard)" : ""));
			continue;
		}

		m->m_len = len;
		rxq->rxq_len += len;
		DPRINTF(sc, WM_DEBUG_RX,
		    ("%s: RX: buffer at %p len %d\n",
			device_xname(sc->sc_dev), m->m_data, len));

		/* If this is not the end of the packet, keep looking. */
		if (!wm_rxdesc_is_eop(rxq, status)) {
			WM_RXCHAIN_LINK(rxq, m);
			DPRINTF(sc, WM_DEBUG_RX,
			    ("%s: RX: not yet EOP, rxlen -> %d\n",
				device_xname(sc->sc_dev), rxq->rxq_len));
			continue;
		}

		/*
		 * Okay, we have the entire packet now. The chip is
		 * configured to include the FCS except I35[04], I21[01].
		 * (not all chips can be configured to strip it), so we need
		 * to trim it. Those chips have an eratta, the RCTL_SECRC bit
		 * in RCTL register is always set, so we don't trim it.
		 * PCH2 and newer chip also not include FCS when jumbo
		 * frame is used to do workaround an errata.
		 * May need to adjust length of previous mbuf in the
		 * chain if the current mbuf is too short.
		 */
		if ((sc->sc_flags & WM_F_CRC_STRIP) == 0) {
			if (m->m_len < ETHER_CRC_LEN) {
				rxq->rxq_tail->m_len
				    -= (ETHER_CRC_LEN - m->m_len);
				m->m_len = 0;
			} else
				m->m_len -= ETHER_CRC_LEN;
			len = rxq->rxq_len - ETHER_CRC_LEN;
		} else
			len = rxq->rxq_len;

		WM_RXCHAIN_LINK(rxq, m);

		*rxq->rxq_tailp = NULL;
		m = rxq->rxq_head;

		WM_RXCHAIN_RESET(rxq);

		DPRINTF(sc, WM_DEBUG_RX,
		    ("%s: RX: have entire packet, len -> %d\n",
			device_xname(sc->sc_dev), len));

		/* If an error occurred, update stats and drop the packet. */
		if (wm_rxdesc_has_errors(rxq, errors)) {
			m_freem(m);
			continue;
		}

		/* No errors.  Receive the packet. */
		m_set_rcvif(m, ifp);
		m->m_pkthdr.len = len;
		/*
		 * TODO
		 * should be save rsshash and rsstype to this mbuf.
		 */
		DPRINTF(sc, WM_DEBUG_RX,
		    ("%s: RX: RSS type=%" PRIu8 ", RSS hash=%" PRIu32 "\n",
			device_xname(sc->sc_dev), rsstype, rsshash));

		/*
		 * If VLANs are enabled, VLAN packets have been unwrapped
		 * for us.  Associate the tag with the packet.
		 */
		if (!wm_rxdesc_input_vlantag(rxq, status, vlantag, m))
			continue;

		/* Set up checksum info for this packet. */
		wm_rxdesc_ensure_checksum(rxq, status, errors, m);

		rxq->rxq_packets++;
		rxq->rxq_bytes += len;
		/* Pass it on. */
		if_percpuq_enqueue(sc->sc_ipq, m);

		if (rxq->rxq_stopping)
			break;
	}
	rxq->rxq_ptr = i;

	if (count != 0)
		rnd_add_uint32(&sc->rnd_source, count);

	DPRINTF(sc, WM_DEBUG_RX,
	    ("%s: RX: rxptr -> %d\n", device_xname(sc->sc_dev), i));

	return more;
}

/*
 * wm_linkintr_gmii:
 *
 *	Helper; handle link interrupts for GMII.
 */
static void
wm_linkintr_gmii(struct wm_softc *sc, uint32_t icr)
{
	device_t dev = sc->sc_dev;
	uint32_t status, reg;
	bool link;
	bool dopoll = true;
	int rv;

	KASSERT(mutex_owned(sc->sc_core_lock));

	DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s:\n", device_xname(dev),
		__func__));

	if ((icr & ICR_LSC) == 0) {
		if (icr & ICR_RXSEQ)
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("%s: LINK Receive sequence error\n",
				device_xname(dev)));
		return;
	}

	/* Link status changed */
	status = CSR_READ(sc, WMREG_STATUS);
	link = status & STATUS_LU;
	if (link) {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> up %s\n",
			device_xname(dev),
			(status & STATUS_FD) ? "FDX" : "HDX"));
		if (wm_phy_need_linkdown_discard(sc)) {
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("%s: linkintr: Clear linkdown discard flag\n",
				device_xname(dev)));
			wm_clear_linkdown_discard(sc);
		}
	} else {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> down\n",
			device_xname(dev)));
		if (wm_phy_need_linkdown_discard(sc)) {
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("%s: linkintr: Set linkdown discard flag\n",
				device_xname(dev)));
			wm_set_linkdown_discard(sc);
		}
	}
	if ((sc->sc_type == WM_T_ICH8) && (link == false))
		wm_gig_downshift_workaround_ich8lan(sc);

	if ((sc->sc_type == WM_T_ICH8) && (sc->sc_phytype == WMPHY_IGP_3))
		wm_kmrn_lock_loss_workaround_ich8lan(sc);

	DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> mii_pollstat\n",
		device_xname(dev)));
	if ((sc->sc_flags & WM_F_DELAY_LINKUP) != 0) {
		if (link) {
			/*
			 * To workaround the problem, it's required to wait
			 * several hundred miliseconds. The time depend
			 * on the environment. Wait 1 second for the safety.
			 */
			dopoll = false;
			getmicrotime(&sc->sc_linkup_delay_time);
			sc->sc_linkup_delay_time.tv_sec += 1;
		} else if (sc->sc_linkup_delay_time.tv_sec != 0) {
			/*
			 * Simplify by checking tv_sec only. It's enough.
			 *
			 * Currently, it's not required to clear the time.
			 * It's just to know the timer is stopped
			 * (for debugging).
			 */

			sc->sc_linkup_delay_time.tv_sec = 0;
			sc->sc_linkup_delay_time.tv_usec = 0;
		}
	}

	/*
	 * Call mii_pollstat().
	 *
	 * Some (not all) systems use I35[04] or I21[01] don't send packet soon
	 * after linkup. The MAC send a packet to the PHY and any error is not
	 * observed. This behavior causes a problem that gratuitous ARP and/or
	 * IPv6 DAD packet are silently dropped. To avoid this problem, don't
	 * call mii_pollstat() here which will send LINK_STATE_UP notification
	 * to the upper layer. Instead, mii_pollstat() will be called in
	 * wm_gmii_mediastatus() or mii_tick() will be called in wm_tick().
	 */
	if (dopoll)
		mii_pollstat(&sc->sc_mii);

	/* Do some workarounds soon after link status is changed. */

	if (sc->sc_type == WM_T_82543) {
		int miistatus, active;

		/*
		 * With 82543, we need to force speed and
		 * duplex on the MAC equal to what the PHY
		 * speed and duplex configuration is.
		 */
		miistatus = sc->sc_mii.mii_media_status;

		if (miistatus & IFM_ACTIVE) {
			active = sc->sc_mii.mii_media_active;
			sc->sc_ctrl &= ~(CTRL_SPEED_MASK | CTRL_FD);
			switch (IFM_SUBTYPE(active)) {
			case IFM_10_T:
				sc->sc_ctrl |= CTRL_SPEED_10;
				break;
			case IFM_100_TX:
				sc->sc_ctrl |= CTRL_SPEED_100;
				break;
			case IFM_1000_T:
				sc->sc_ctrl |= CTRL_SPEED_1000;
				break;
			default:
				/*
				 * Fiber?
				 * Shoud not enter here.
				 */
				device_printf(dev, "unknown media (%x)\n",
				    active);
				break;
			}
			if (active & IFM_FDX)
				sc->sc_ctrl |= CTRL_FD;
			CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
		}
	} else if (sc->sc_type == WM_T_PCH) {
		wm_k1_gig_workaround_hv(sc,
		    ((sc->sc_mii.mii_media_status & IFM_ACTIVE) != 0));
	}

	/*
	 * When connected at 10Mbps half-duplex, some parts are excessively
	 * aggressive resulting in many collisions. To avoid this, increase
	 * the IPG and reduce Rx latency in the PHY.
	 */
	if ((sc->sc_type >= WM_T_PCH2) && (sc->sc_type <= WM_T_PCH_TGP)
	    && link) {
		uint32_t tipg_reg;
		uint32_t speed = __SHIFTOUT(status, STATUS_SPEED);
		bool fdx;
		uint16_t emi_addr, emi_val;

		tipg_reg = CSR_READ(sc, WMREG_TIPG);
		tipg_reg &= ~TIPG_IPGT_MASK;
		fdx = status & STATUS_FD;

		if (!fdx && (speed == STATUS_SPEED_10)) {
			tipg_reg |= 0xff;
			/* Reduce Rx latency in analog PHY */
			emi_val = 0;
		} else if ((sc->sc_type >= WM_T_PCH_SPT) &&
		    fdx && speed != STATUS_SPEED_1000) {
			tipg_reg |= 0xc;
			emi_val = 1;
		} else {
			/* Roll back the default values */
			tipg_reg |= 0x08;
			emi_val = 1;
		}

		CSR_WRITE(sc, WMREG_TIPG, tipg_reg);

		rv = sc->phy.acquire(sc);
		if (rv)
			return;

		if (sc->sc_type == WM_T_PCH2)
			emi_addr = I82579_RX_CONFIG;
		else
			emi_addr = I217_RX_CONFIG;
		rv = wm_write_emi_reg_locked(dev, emi_addr, emi_val);

		if (sc->sc_type >= WM_T_PCH_LPT) {
			uint16_t phy_reg;

			sc->phy.readreg_locked(dev, 2,
			    I217_PLL_CLOCK_GATE_REG, &phy_reg);
			phy_reg &= ~I217_PLL_CLOCK_GATE_MASK;
			if (speed == STATUS_SPEED_100
			    || speed == STATUS_SPEED_10)
				phy_reg |= 0x3e8;
			else
				phy_reg |= 0xfa;
			sc->phy.writereg_locked(dev, 2,
			    I217_PLL_CLOCK_GATE_REG, phy_reg);

			if (speed == STATUS_SPEED_1000) {
				sc->phy.readreg_locked(dev, 2,
				    HV_PM_CTRL, &phy_reg);

				phy_reg |= HV_PM_CTRL_K1_CLK_REQ;

				sc->phy.writereg_locked(dev, 2,
				    HV_PM_CTRL, phy_reg);
			}
		}
		sc->phy.release(sc);

		if (rv)
			return;

		if (sc->sc_type >= WM_T_PCH_SPT) {
			uint16_t data, ptr_gap;

			if (speed == STATUS_SPEED_1000) {
				rv = sc->phy.acquire(sc);
				if (rv)
					return;

				rv = sc->phy.readreg_locked(dev, 2,
				    I82579_UNKNOWN1, &data);
				if (rv) {
					sc->phy.release(sc);
					return;
				}

				ptr_gap = (data & (0x3ff << 2)) >> 2;
				if (ptr_gap < 0x18) {
					data &= ~(0x3ff << 2);
					data |= (0x18 << 2);
					rv = sc->phy.writereg_locked(dev,
					    2, I82579_UNKNOWN1, data);
				}
				sc->phy.release(sc);
				if (rv)
					return;
			} else {
				rv = sc->phy.acquire(sc);
				if (rv)
					return;

				rv = sc->phy.writereg_locked(dev, 2,
				    I82579_UNKNOWN1, 0xc023);
				sc->phy.release(sc);
				if (rv)
					return;

			}
		}
	}

	/*
	 * I217 Packet Loss issue:
	 * ensure that FEXTNVM4 Beacon Duration is set correctly
	 * on power up.
	 * Set the Beacon Duration for I217 to 8 usec
	 */
	if (sc->sc_type >= WM_T_PCH_LPT) {
		reg = CSR_READ(sc, WMREG_FEXTNVM4);
		reg &= ~FEXTNVM4_BEACON_DURATION;
		reg |= FEXTNVM4_BEACON_DURATION_8US;
		CSR_WRITE(sc, WMREG_FEXTNVM4, reg);
	}

	/* Work-around I218 hang issue */
	if ((sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_LM) ||
	    (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_V) ||
	    (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_LM3) ||
	    (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_V3))
		wm_k1_workaround_lpt_lp(sc, link);

	if (sc->sc_type >= WM_T_PCH_LPT) {
		/*
		 * Set platform power management values for Latency
		 * Tolerance Reporting (LTR)
		 */
		wm_platform_pm_pch_lpt(sc,
		    ((sc->sc_mii.mii_media_status & IFM_ACTIVE) != 0));
	}

	/* Clear link partner's EEE ability */
	sc->eee_lp_ability = 0;

	/* FEXTNVM6 K1-off workaround */
	if (sc->sc_type == WM_T_PCH_SPT) {
		reg = CSR_READ(sc, WMREG_FEXTNVM6);
		if (CSR_READ(sc, WMREG_PCIEANACFG) & FEXTNVM6_K1_OFF_ENABLE)
			reg |= FEXTNVM6_K1_OFF_ENABLE;
		else
			reg &= ~FEXTNVM6_K1_OFF_ENABLE;
		CSR_WRITE(sc, WMREG_FEXTNVM6, reg);
	}

	if (!link)
		return;

	switch (sc->sc_type) {
	case WM_T_PCH2:
		wm_k1_workaround_lv(sc);
		/* FALLTHROUGH */
	case WM_T_PCH:
		if (sc->sc_phytype == WMPHY_82578)
			wm_link_stall_workaround_hv(sc);
		break;
	default:
		break;
	}

	/* Enable/Disable EEE after link up */
	if (sc->sc_phytype > WMPHY_82579)
		wm_set_eee_pchlan(sc);
}

/*
 * wm_linkintr_tbi:
 *
 *	Helper; handle link interrupts for TBI mode.
 */
static void
wm_linkintr_tbi(struct wm_softc *sc, uint32_t icr)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	uint32_t status;

	DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s:\n", device_xname(sc->sc_dev),
		__func__));

	status = CSR_READ(sc, WMREG_STATUS);
	if (icr & ICR_LSC) {
		wm_check_for_link(sc);
		if (status & STATUS_LU) {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> up %s\n",
				device_xname(sc->sc_dev),
				(status & STATUS_FD) ? "FDX" : "HDX"));
			/*
			 * NOTE: CTRL will update TFCE and RFCE automatically,
			 * so we should update sc->sc_ctrl
			 */

			sc->sc_ctrl = CSR_READ(sc, WMREG_CTRL);
			sc->sc_tctl &= ~TCTL_COLD(0x3ff);
			sc->sc_fcrtl &= ~FCRTL_XONE;
			if (status & STATUS_FD)
				sc->sc_tctl |=
				    TCTL_COLD(TX_COLLISION_DISTANCE_FDX);
			else
				sc->sc_tctl |=
				    TCTL_COLD(TX_COLLISION_DISTANCE_HDX);
			if (sc->sc_ctrl & CTRL_TFCE)
				sc->sc_fcrtl |= FCRTL_XONE;
			CSR_WRITE(sc, WMREG_TCTL, sc->sc_tctl);
			CSR_WRITE(sc, (sc->sc_type < WM_T_82543) ?
			    WMREG_OLD_FCRTL : WMREG_FCRTL, sc->sc_fcrtl);
			sc->sc_tbi_linkup = 1;
			if_link_state_change(ifp, LINK_STATE_UP);
		} else {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> down\n",
				device_xname(sc->sc_dev)));
			sc->sc_tbi_linkup = 0;
			if_link_state_change(ifp, LINK_STATE_DOWN);
		}
		/* Update LED */
		wm_tbi_serdes_set_linkled(sc);
	} else if (icr & ICR_RXSEQ)
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: LINK: Receive sequence error\n",
			device_xname(sc->sc_dev)));
}

/*
 * wm_linkintr_serdes:
 *
 *	Helper; handle link interrupts for TBI mode.
 */
static void
wm_linkintr_serdes(struct wm_softc *sc, uint32_t icr)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct mii_data *mii = &sc->sc_mii;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint32_t pcs_adv, pcs_lpab, reg;

	DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s:\n", device_xname(sc->sc_dev),
		__func__));

	if (icr & ICR_LSC) {
		/* Check PCS */
		reg = CSR_READ(sc, WMREG_PCS_LSTS);
		if ((reg & PCS_LSTS_LINKOK) != 0) {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> up\n",
				device_xname(sc->sc_dev)));
			mii->mii_media_status |= IFM_ACTIVE;
			sc->sc_tbi_linkup = 1;
			if_link_state_change(ifp, LINK_STATE_UP);
		} else {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: LSC -> down\n",
				device_xname(sc->sc_dev)));
			mii->mii_media_status |= IFM_NONE;
			sc->sc_tbi_linkup = 0;
			if_link_state_change(ifp, LINK_STATE_DOWN);
			wm_tbi_serdes_set_linkled(sc);
			return;
		}
		mii->mii_media_active |= IFM_1000_SX;
		if ((reg & PCS_LSTS_FDX) != 0)
			mii->mii_media_active |= IFM_FDX;
		else
			mii->mii_media_active |= IFM_HDX;
		if (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO) {
			/* Check flow */
			reg = CSR_READ(sc, WMREG_PCS_LSTS);
			if ((reg & PCS_LSTS_AN_COMP) == 0) {
				DPRINTF(sc, WM_DEBUG_LINK,
				    ("XXX LINKOK but not ACOMP\n"));
				return;
			}
			pcs_adv = CSR_READ(sc, WMREG_PCS_ANADV);
			pcs_lpab = CSR_READ(sc, WMREG_PCS_LPAB);
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("XXX AN result %08x, %08x\n", pcs_adv, pcs_lpab));
			if ((pcs_adv & TXCW_SYM_PAUSE)
			    && (pcs_lpab & TXCW_SYM_PAUSE)) {
				mii->mii_media_active |= IFM_FLOW
				    | IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE;
			} else if (((pcs_adv & TXCW_SYM_PAUSE) == 0)
			    && (pcs_adv & TXCW_ASYM_PAUSE)
			    && (pcs_lpab & TXCW_SYM_PAUSE)
			    && (pcs_lpab & TXCW_ASYM_PAUSE))
				mii->mii_media_active |= IFM_FLOW
				    | IFM_ETH_TXPAUSE;
			else if ((pcs_adv & TXCW_SYM_PAUSE)
			    && (pcs_adv & TXCW_ASYM_PAUSE)
			    && ((pcs_lpab & TXCW_SYM_PAUSE) == 0)
			    && (pcs_lpab & TXCW_ASYM_PAUSE))
				mii->mii_media_active |= IFM_FLOW
				    | IFM_ETH_RXPAUSE;
		}
		/* Update LED */
		wm_tbi_serdes_set_linkled(sc);
	} else
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: LINK: Receive sequence error\n",
		    device_xname(sc->sc_dev)));
}

/*
 * wm_linkintr:
 *
 *	Helper; handle link interrupts.
 */
static void
wm_linkintr(struct wm_softc *sc, uint32_t icr)
{

	KASSERT(mutex_owned(sc->sc_core_lock));

	if (sc->sc_flags & WM_F_HAS_MII)
		wm_linkintr_gmii(sc, icr);
	else if ((sc->sc_mediatype == WM_MEDIATYPE_SERDES)
	    && ((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211)))
		wm_linkintr_serdes(sc, icr);
	else
		wm_linkintr_tbi(sc, icr);
}


static inline void
wm_sched_handle_queue(struct wm_softc *sc, struct wm_queue *wmq)
{

	if (wmq->wmq_txrx_use_workqueue) {
		if (!wmq->wmq_wq_enqueued) {
			wmq->wmq_wq_enqueued = true;
			workqueue_enqueue(sc->sc_queue_wq, &wmq->wmq_cookie,
			    curcpu());
		}
	} else
		softint_schedule(wmq->wmq_si);
}

static inline void
wm_legacy_intr_disable(struct wm_softc *sc)
{

	CSR_WRITE(sc, WMREG_IMC, 0xffffffffU);
}

static inline void
wm_legacy_intr_enable(struct wm_softc *sc)
{

	CSR_WRITE(sc, WMREG_IMS, sc->sc_icr);
}

/*
 * wm_intr_legacy:
 *
 *	Interrupt service routine for INTx and MSI.
 */
static int
wm_intr_legacy(void *arg)
{
	struct wm_softc *sc = arg;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct wm_queue *wmq = &sc->sc_queue[0];
	struct wm_txqueue *txq = &wmq->wmq_txq;
	struct wm_rxqueue *rxq = &wmq->wmq_rxq;
	u_int txlimit = sc->sc_tx_intr_process_limit;
	u_int rxlimit = sc->sc_rx_intr_process_limit;
	uint32_t icr, rndval = 0;
	bool more = false;

	icr = CSR_READ(sc, WMREG_ICR);
	if ((icr & sc->sc_icr) == 0)
		return 0;

	DPRINTF(sc, WM_DEBUG_TX,
	    ("%s: INTx: got intr\n",device_xname(sc->sc_dev)));
	if (rndval == 0)
		rndval = icr;

	mutex_enter(txq->txq_lock);

	if (txq->txq_stopping) {
		mutex_exit(txq->txq_lock);
		return 1;
	}

#if defined(WM_DEBUG) || defined(WM_EVENT_COUNTERS)
	if (icr & ICR_TXDW) {
		DPRINTF(sc, WM_DEBUG_TX,
		    ("%s: TX: got TXDW interrupt\n",
			device_xname(sc->sc_dev)));
		WM_Q_EVCNT_INCR(txq, txdw);
	}
#endif
	if (txlimit > 0) {
		more |= wm_txeof(txq, txlimit);
		if (!IF_IS_EMPTY(&ifp->if_snd))
			more = true;
	} else
		more = true;
	mutex_exit(txq->txq_lock);

	mutex_enter(rxq->rxq_lock);

	if (rxq->rxq_stopping) {
		mutex_exit(rxq->rxq_lock);
		return 1;
	}

#if defined(WM_DEBUG) || defined(WM_EVENT_COUNTERS)
	if (icr & (ICR_RXDMT0 | ICR_RXT0)) {
		DPRINTF(sc, WM_DEBUG_RX,
		    ("%s: RX: got Rx intr %#" __PRIxBIT "\n",
			device_xname(sc->sc_dev),
			icr & (ICR_RXDMT0 | ICR_RXT0)));
		WM_Q_EVCNT_INCR(rxq, intr);
	}
#endif
	if (rxlimit > 0) {
		/*
		 * wm_rxeof() does *not* call upper layer functions directly,
		 * as if_percpuq_enqueue() just call softint_schedule().
		 * So, we can call wm_rxeof() in interrupt context.
		 */
		more = wm_rxeof(rxq, rxlimit);
	} else
		more = true;

	mutex_exit(rxq->rxq_lock);

	mutex_enter(sc->sc_core_lock);

	if (sc->sc_core_stopping) {
		mutex_exit(sc->sc_core_lock);
		return 1;
	}

	if (icr & (ICR_LSC | ICR_RXSEQ)) {
		WM_EVCNT_INCR(&sc->sc_ev_linkintr);
		wm_linkintr(sc, icr);
	}
	if ((icr & ICR_GPI(0)) != 0)
		device_printf(sc->sc_dev, "got module interrupt\n");

	mutex_exit(sc->sc_core_lock);

	if (icr & ICR_RXO) {
#if defined(WM_DEBUG)
		log(LOG_WARNING, "%s: Receive overrun\n",
		    device_xname(sc->sc_dev));
#endif /* defined(WM_DEBUG) */
	}

	rnd_add_uint32(&sc->rnd_source, rndval);

	if (more) {
		/* Try to get more packets going. */
		wm_legacy_intr_disable(sc);
		wmq->wmq_txrx_use_workqueue = sc->sc_txrx_use_workqueue;
		wm_sched_handle_queue(sc, wmq);
	}

	return 1;
}

static inline void
wm_txrxintr_disable(struct wm_queue *wmq)
{
	struct wm_softc *sc = wmq->wmq_txq.txq_sc;

	if (__predict_false(!wm_is_using_msix(sc))) {
		wm_legacy_intr_disable(sc);
		return;
	}

	if (sc->sc_type == WM_T_82574)
		CSR_WRITE(sc, WMREG_IMC,
		    ICR_TXQ(wmq->wmq_id) | ICR_RXQ(wmq->wmq_id));
	else if (sc->sc_type == WM_T_82575)
		CSR_WRITE(sc, WMREG_EIMC,
		    EITR_TX_QUEUE(wmq->wmq_id) | EITR_RX_QUEUE(wmq->wmq_id));
	else
		CSR_WRITE(sc, WMREG_EIMC, 1 << wmq->wmq_intr_idx);
}

static inline void
wm_txrxintr_enable(struct wm_queue *wmq)
{
	struct wm_softc *sc = wmq->wmq_txq.txq_sc;

	wm_itrs_calculate(sc, wmq);

	if (__predict_false(!wm_is_using_msix(sc))) {
		wm_legacy_intr_enable(sc);
		return;
	}

	/*
	 * ICR_OTHER which is disabled in wm_linkintr_msix() is enabled here.
	 * There is no need to care about which of RXQ(0) and RXQ(1) enable
	 * ICR_OTHER in first, because each RXQ/TXQ interrupt is disabled
	 * while each wm_handle_queue(wmq) is runnig.
	 */
	if (sc->sc_type == WM_T_82574)
		CSR_WRITE(sc, WMREG_IMS,
		    ICR_TXQ(wmq->wmq_id) | ICR_RXQ(wmq->wmq_id) | ICR_OTHER);
	else if (sc->sc_type == WM_T_82575)
		CSR_WRITE(sc, WMREG_EIMS,
		    EITR_TX_QUEUE(wmq->wmq_id) | EITR_RX_QUEUE(wmq->wmq_id));
	else
		CSR_WRITE(sc, WMREG_EIMS, 1 << wmq->wmq_intr_idx);
}

static int
wm_txrxintr_msix(void *arg)
{
	struct wm_queue *wmq = arg;
	struct wm_txqueue *txq = &wmq->wmq_txq;
	struct wm_rxqueue *rxq = &wmq->wmq_rxq;
	struct wm_softc *sc = txq->txq_sc;
	u_int txlimit = sc->sc_tx_intr_process_limit;
	u_int rxlimit = sc->sc_rx_intr_process_limit;
	bool txmore;
	bool rxmore;

	KASSERT(wmq->wmq_intr_idx == wmq->wmq_id);

	DPRINTF(sc, WM_DEBUG_TX,
	    ("%s: TX: got Tx intr\n", device_xname(sc->sc_dev)));

	wm_txrxintr_disable(wmq);

	mutex_enter(txq->txq_lock);

	if (txq->txq_stopping) {
		mutex_exit(txq->txq_lock);
		return 1;
	}

	WM_Q_EVCNT_INCR(txq, txdw);
	if (txlimit > 0) {
		txmore = wm_txeof(txq, txlimit);
		/* wm_deferred start() is done in wm_handle_queue(). */
	} else
		txmore = true;
	mutex_exit(txq->txq_lock);

	DPRINTF(sc, WM_DEBUG_RX,
	    ("%s: RX: got Rx intr\n", device_xname(sc->sc_dev)));
	mutex_enter(rxq->rxq_lock);

	if (rxq->rxq_stopping) {
		mutex_exit(rxq->rxq_lock);
		return 1;
	}

	WM_Q_EVCNT_INCR(rxq, intr);
	if (rxlimit > 0) {
		rxmore = wm_rxeof(rxq, rxlimit);
	} else
		rxmore = true;
	mutex_exit(rxq->rxq_lock);

	wm_itrs_writereg(sc, wmq);

	if (txmore || rxmore) {
		wmq->wmq_txrx_use_workqueue = sc->sc_txrx_use_workqueue;
		wm_sched_handle_queue(sc, wmq);
	} else
		wm_txrxintr_enable(wmq);

	return 1;
}

static void
wm_handle_queue(void *arg)
{
	struct wm_queue *wmq = arg;
	struct wm_txqueue *txq = &wmq->wmq_txq;
	struct wm_rxqueue *rxq = &wmq->wmq_rxq;
	struct wm_softc *sc = txq->txq_sc;
	u_int txlimit = sc->sc_tx_process_limit;
	u_int rxlimit = sc->sc_rx_process_limit;
	bool txmore;
	bool rxmore;

	mutex_enter(txq->txq_lock);
	if (txq->txq_stopping) {
		mutex_exit(txq->txq_lock);
		return;
	}
	txmore = wm_txeof(txq, txlimit);
	wm_deferred_start_locked(txq);
	mutex_exit(txq->txq_lock);

	mutex_enter(rxq->rxq_lock);
	if (rxq->rxq_stopping) {
		mutex_exit(rxq->rxq_lock);
		return;
	}
	WM_Q_EVCNT_INCR(rxq, defer);
	rxmore = wm_rxeof(rxq, rxlimit);
	mutex_exit(rxq->rxq_lock);

	if (txmore || rxmore) {
		wmq->wmq_txrx_use_workqueue = sc->sc_txrx_use_workqueue;
		wm_sched_handle_queue(sc, wmq);
	} else
		wm_txrxintr_enable(wmq);
}

static void
wm_handle_queue_work(struct work *wk, void *context)
{
	struct wm_queue *wmq = container_of(wk, struct wm_queue, wmq_cookie);

	/*
	 * Some qemu environment workaround.  They don't stop interrupt
	 * immediately.
	 */
	wmq->wmq_wq_enqueued = false;
	wm_handle_queue(wmq);
}

/*
 * wm_linkintr_msix:
 *
 *	Interrupt service routine for link status change for MSI-X.
 */
static int
wm_linkintr_msix(void *arg)
{
	struct wm_softc *sc = arg;
	uint32_t reg;
	bool has_rxo;

	reg = CSR_READ(sc, WMREG_ICR);
	mutex_enter(sc->sc_core_lock);
	DPRINTF(sc, WM_DEBUG_LINK,
	    ("%s: LINK: got link intr. ICR = %08x\n",
		device_xname(sc->sc_dev), reg));

	if (sc->sc_core_stopping)
		goto out;

	if ((reg & ICR_LSC) != 0) {
		WM_EVCNT_INCR(&sc->sc_ev_linkintr);
		wm_linkintr(sc, ICR_LSC);
	}
	if ((reg & ICR_GPI(0)) != 0)
		device_printf(sc->sc_dev, "got module interrupt\n");

	/*
	 * XXX 82574 MSI-X mode workaround
	 *
	 * 82574 MSI-X mode causes a receive overrun(RXO) interrupt as an
	 * ICR_OTHER MSI-X vector; furthermore it causes neither ICR_RXQ(0)
	 * nor ICR_RXQ(1) vectors. So, we generate ICR_RXQ(0) and ICR_RXQ(1)
	 * interrupts by writing WMREG_ICS to process receive packets.
	 */
	if (sc->sc_type == WM_T_82574 && ((reg & ICR_RXO) != 0)) {
#if defined(WM_DEBUG)
		log(LOG_WARNING, "%s: Receive overrun\n",
		    device_xname(sc->sc_dev));
#endif /* defined(WM_DEBUG) */

		has_rxo = true;
		/*
		 * The RXO interrupt is very high rate when receive traffic is
		 * high rate. We use polling mode for ICR_OTHER like Tx/Rx
		 * interrupts. ICR_OTHER will be enabled at the end of
		 * wm_txrxintr_msix() which is kicked by both ICR_RXQ(0) and
		 * ICR_RXQ(1) interrupts.
		 */
		CSR_WRITE(sc, WMREG_IMC, ICR_OTHER);

		CSR_WRITE(sc, WMREG_ICS, ICR_RXQ(0) | ICR_RXQ(1));
	}



out:
	mutex_exit(sc->sc_core_lock);

	if (sc->sc_type == WM_T_82574) {
		if (!has_rxo)
			CSR_WRITE(sc, WMREG_IMS, ICR_OTHER | ICR_LSC);
		else
			CSR_WRITE(sc, WMREG_IMS, ICR_LSC);
	} else if (sc->sc_type == WM_T_82575)
		CSR_WRITE(sc, WMREG_EIMS, EITR_OTHER);
	else
		CSR_WRITE(sc, WMREG_EIMS, 1 << sc->sc_link_intr_idx);

	return 1;
}

/*
 * Media related.
 * GMII, SGMII, TBI (and SERDES)
 */

/* Common */

/*
 * wm_tbi_serdes_set_linkled:
 *
 *	Update the link LED on TBI and SERDES devices.
 */
static void
wm_tbi_serdes_set_linkled(struct wm_softc *sc)
{

	if (sc->sc_tbi_linkup)
		sc->sc_ctrl |= CTRL_SWDPIN(0);
	else
		sc->sc_ctrl &= ~CTRL_SWDPIN(0);

	/* 82540 or newer devices are active low */
	sc->sc_ctrl ^= (sc->sc_type >= WM_T_82540) ? CTRL_SWDPIN(0) : 0;

	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
}

/* GMII related */

/*
 * wm_gmii_reset:
 *
 *	Reset the PHY.
 */
static void
wm_gmii_reset(struct wm_softc *sc)
{
	uint32_t reg;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		aprint_error_dev(sc->sc_dev, "%s: failed to get semaphore\n",
		    __func__);
		return;
	}

	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
		/* null */
		break;
	case WM_T_82543:
		/*
		 * With 82543, we need to force speed and duplex on the MAC
		 * equal to what the PHY speed and duplex configuration is.
		 * In addition, we need to perform a hardware reset on the PHY
		 * to take it out of reset.
		 */
		sc->sc_ctrl |= CTRL_FRCSPD | CTRL_FRCFDX;
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

		/* The PHY reset pin is active-low. */
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		reg &= ~((CTRL_EXT_SWDPIO_MASK << CTRL_EXT_SWDPIO_SHIFT) |
		    CTRL_EXT_SWDPIN(4));
		reg |= CTRL_EXT_SWDPIO(4);

		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
		CSR_WRITE_FLUSH(sc);
		delay(10*1000);

		CSR_WRITE(sc, WMREG_CTRL_EXT, reg | CTRL_EXT_SWDPIN(4));
		CSR_WRITE_FLUSH(sc);
		delay(150);
#if 0
		sc->sc_ctrl_ext = reg | CTRL_EXT_SWDPIN(4);
#endif
		delay(20*1000);	/* XXX extra delay to get PHY ID? */
		break;
	case WM_T_82544:	/* Reset 10000us */
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82545_3:
	case WM_T_82546:
	case WM_T_82546_3:
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
	case WM_T_82571:	/* Reset 100us */
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
	case WM_T_82583:
	case WM_T_80003:
		/* Generic reset */
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl | CTRL_PHY_RESET);
		CSR_WRITE_FLUSH(sc);
		delay(20000);
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
		CSR_WRITE_FLUSH(sc);
		delay(20000);

		if ((sc->sc_type == WM_T_82541)
		    || (sc->sc_type == WM_T_82541_2)
		    || (sc->sc_type == WM_T_82547)
		    || (sc->sc_type == WM_T_82547_2)) {
			/* Workaround for igp are done in igp_reset() */
			/* XXX add code to set LED after phy reset */
		}
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		/* Generic reset */
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl | CTRL_PHY_RESET);
		CSR_WRITE_FLUSH(sc);
		delay(100);
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
		CSR_WRITE_FLUSH(sc);
		delay(150);
		break;
	default:
		panic("%s: %s: unknown type\n", device_xname(sc->sc_dev),
		    __func__);
		break;
	}

	sc->phy.release(sc);

	/* get_cfg_done */
	wm_get_cfg_done(sc);

	/* Extra setup */
	switch (sc->sc_type) {
	case WM_T_82542_2_0:
	case WM_T_82542_2_1:
	case WM_T_82543:
	case WM_T_82544:
	case WM_T_82540:
	case WM_T_82545:
	case WM_T_82545_3:
	case WM_T_82546:
	case WM_T_82546_3:
	case WM_T_82541_2:
	case WM_T_82547_2:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
	case WM_T_80003:
		/* Null */
		break;
	case WM_T_82541:
	case WM_T_82547:
		/* XXX Configure actively LED after PHY reset */
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		wm_phy_post_reset(sc);
		break;
	default:
		panic("%s: unknown type\n", __func__);
		break;
	}
}

/*
 * Set up sc_phytype and mii_{read|write}reg.
 *
 *  To identify PHY type, correct read/write function should be selected.
 * To select correct read/write function, PCI ID or MAC type are required
 * without accessing PHY registers.
 *
 *  On the first call of this function, PHY ID is not known yet. Check
 * PCI ID or MAC type. The list of the PCI ID may not be perfect, so the
 * result might be incorrect.
 *
 *  In the second call, PHY OUI and model is used to identify PHY type.
 * It might not be perfect because of the lack of compared entry, but it
 * would be better than the first call.
 *
 *  If the detected new result and previous assumption is different,
 * a diagnostic message will be printed.
 */
static void
wm_gmii_setup_phytype(struct wm_softc *sc, uint32_t phy_oui,
    uint16_t phy_model)
{
	device_t dev = sc->sc_dev;
	struct mii_data *mii = &sc->sc_mii;
	uint16_t new_phytype = WMPHY_UNKNOWN;
	uint16_t doubt_phytype = WMPHY_UNKNOWN;
	mii_readreg_t new_readreg;
	mii_writereg_t new_writereg;
	bool dodiag = true;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/*
	 * 1000BASE-T SFP uses SGMII and the first asumed PHY type is always
	 * incorrect. So don't print diag output when it's 2nd call.
	 */
	if ((sc->sc_sfptype != 0) && (phy_oui == 0) && (phy_model == 0))
		dodiag = false;

	if (mii->mii_readreg == NULL) {
		/*
		 *  This is the first call of this function. For ICH and PCH
		 * variants, it's difficult to determine the PHY access method
		 * by sc_type, so use the PCI product ID for some devices.
		 */

		switch (sc->sc_pcidevid) {
		case PCI_PRODUCT_INTEL_PCH_M_LM:
		case PCI_PRODUCT_INTEL_PCH_M_LC:
			/* 82577 */
			new_phytype = WMPHY_82577;
			break;
		case PCI_PRODUCT_INTEL_PCH_D_DM:
		case PCI_PRODUCT_INTEL_PCH_D_DC:
			/* 82578 */
			new_phytype = WMPHY_82578;
			break;
		case PCI_PRODUCT_INTEL_PCH2_LV_LM:
		case PCI_PRODUCT_INTEL_PCH2_LV_V:
			/* 82579 */
			new_phytype = WMPHY_82579;
			break;
		case PCI_PRODUCT_INTEL_82801H_82567V_3:
		case PCI_PRODUCT_INTEL_82801I_BM:
		case PCI_PRODUCT_INTEL_82801I_IGP_M_AMT: /* Not IGP but BM */
		case PCI_PRODUCT_INTEL_82801J_R_BM_LM:
		case PCI_PRODUCT_INTEL_82801J_R_BM_LF:
		case PCI_PRODUCT_INTEL_82801J_D_BM_LM:
		case PCI_PRODUCT_INTEL_82801J_D_BM_LF:
		case PCI_PRODUCT_INTEL_82801J_R_BM_V:
			/* ICH8, 9, 10 with 82567 */
			new_phytype = WMPHY_BM;
			break;
		default:
			break;
		}
	} else {
		/* It's not the first call. Use PHY OUI and model */
		switch (phy_oui) {
		case MII_OUI_ATTANSIC: /* atphy(4) */
			switch (phy_model) {
			case MII_MODEL_ATTANSIC_AR8021:
				new_phytype = WMPHY_82578;
				break;
			default:
				break;
			}
			break;
		case MII_OUI_xxMARVELL:
			switch (phy_model) {
			case MII_MODEL_xxMARVELL_I210:
				new_phytype = WMPHY_I210;
				break;
			case MII_MODEL_xxMARVELL_E1011:
			case MII_MODEL_xxMARVELL_E1000_3:
			case MII_MODEL_xxMARVELL_E1000_5:
			case MII_MODEL_xxMARVELL_E1112:
				new_phytype = WMPHY_M88;
				break;
			case MII_MODEL_xxMARVELL_E1149:
				new_phytype = WMPHY_BM;
				break;
			case MII_MODEL_xxMARVELL_E1111:
			case MII_MODEL_xxMARVELL_I347:
			case MII_MODEL_xxMARVELL_E1512:
			case MII_MODEL_xxMARVELL_E1340M:
			case MII_MODEL_xxMARVELL_E1543:
				new_phytype = WMPHY_M88;
				break;
			case MII_MODEL_xxMARVELL_I82563:
				new_phytype = WMPHY_GG82563;
				break;
			default:
				break;
			}
			break;
		case MII_OUI_INTEL:
			switch (phy_model) {
			case MII_MODEL_INTEL_I82577:
				new_phytype = WMPHY_82577;
				break;
			case MII_MODEL_INTEL_I82579:
				new_phytype = WMPHY_82579;
				break;
			case MII_MODEL_INTEL_I217:
				new_phytype = WMPHY_I217;
				break;
			case MII_MODEL_INTEL_I82580:
				new_phytype = WMPHY_82580;
				break;
			case MII_MODEL_INTEL_I350:
				new_phytype = WMPHY_I350;
				break;
			default:
				break;
			}
			break;
		case MII_OUI_yyINTEL:
			switch (phy_model) {
			case MII_MODEL_yyINTEL_I82562G:
			case MII_MODEL_yyINTEL_I82562EM:
			case MII_MODEL_yyINTEL_I82562ET:
				new_phytype = WMPHY_IFE;
				break;
			case MII_MODEL_yyINTEL_IGP01E1000:
				new_phytype = WMPHY_IGP;
				break;
			case MII_MODEL_yyINTEL_I82566:
				new_phytype = WMPHY_IGP_3;
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}

		if (dodiag) {
			if (new_phytype == WMPHY_UNKNOWN)
				aprint_verbose_dev(dev,
				    "%s: Unknown PHY model. OUI=%06x, "
				    "model=%04x\n", __func__, phy_oui,
				    phy_model);

			if ((sc->sc_phytype != WMPHY_UNKNOWN)
			    && (sc->sc_phytype != new_phytype)) {
				aprint_error_dev(dev, "Previously assumed PHY "
				    "type(%u) was incorrect. PHY type from PHY"
				    "ID = %u\n", sc->sc_phytype, new_phytype);
			}
		}
	}

	/* Next, use sc->sc_flags and sc->sc_type to set read/write funcs. */
	if (((sc->sc_flags & WM_F_SGMII) != 0) && !wm_sgmii_uses_mdio(sc)) {
		/* SGMII */
		new_readreg = wm_sgmii_readreg;
		new_writereg = wm_sgmii_writereg;
	} else if ((sc->sc_type == WM_T_82574) || (sc->sc_type == WM_T_82583)){
		/* BM2 (phyaddr == 1) */
		if ((sc->sc_phytype != WMPHY_UNKNOWN)
		    && (new_phytype != WMPHY_BM)
		    && (new_phytype != WMPHY_UNKNOWN))
			doubt_phytype = new_phytype;
		new_phytype = WMPHY_BM;
		new_readreg = wm_gmii_bm_readreg;
		new_writereg = wm_gmii_bm_writereg;
	} else if (sc->sc_type >= WM_T_PCH) {
		/* All PCH* use _hv_ */
		new_readreg = wm_gmii_hv_readreg;
		new_writereg = wm_gmii_hv_writereg;
	} else if (sc->sc_type >= WM_T_ICH8) {
		/* non-82567 ICH8, 9 and 10 */
		new_readreg = wm_gmii_i82544_readreg;
		new_writereg = wm_gmii_i82544_writereg;
	} else if (sc->sc_type >= WM_T_80003) {
		/* 80003 */
		if ((sc->sc_phytype != WMPHY_UNKNOWN)
		    && (new_phytype != WMPHY_GG82563)
		    && (new_phytype != WMPHY_UNKNOWN))
			doubt_phytype = new_phytype;
		new_phytype = WMPHY_GG82563;
		new_readreg = wm_gmii_i80003_readreg;
		new_writereg = wm_gmii_i80003_writereg;
	} else if (sc->sc_type >= WM_T_I210) {
		/* I210 and I211 */
		if ((sc->sc_phytype != WMPHY_UNKNOWN)
		    && (new_phytype != WMPHY_I210)
		    && (new_phytype != WMPHY_UNKNOWN))
			doubt_phytype = new_phytype;
		new_phytype = WMPHY_I210;
		new_readreg = wm_gmii_gs40g_readreg;
		new_writereg = wm_gmii_gs40g_writereg;
	} else if (sc->sc_type >= WM_T_82580) {
		/* 82580, I350 and I354 */
		new_readreg = wm_gmii_82580_readreg;
		new_writereg = wm_gmii_82580_writereg;
	} else if (sc->sc_type >= WM_T_82544) {
		/* 82544, 0, [56], [17], 8257[1234] and 82583 */
		new_readreg = wm_gmii_i82544_readreg;
		new_writereg = wm_gmii_i82544_writereg;
	} else {
		new_readreg = wm_gmii_i82543_readreg;
		new_writereg = wm_gmii_i82543_writereg;
	}

	if (new_phytype == WMPHY_BM) {
		/* All BM use _bm_ */
		new_readreg = wm_gmii_bm_readreg;
		new_writereg = wm_gmii_bm_writereg;
	}
	if ((sc->sc_type >= WM_T_PCH) && (sc->sc_type <= WM_T_PCH_TGP)) {
		/* All PCH* use _hv_ */
		new_readreg = wm_gmii_hv_readreg;
		new_writereg = wm_gmii_hv_writereg;
	}

	/* Diag output */
	if (dodiag) {
		if (doubt_phytype != WMPHY_UNKNOWN)
			aprint_error_dev(dev, "Assumed new PHY type was "
			    "incorrect. old = %u, new = %u\n", sc->sc_phytype,
			    new_phytype);
		else if ((sc->sc_phytype != WMPHY_UNKNOWN)
		    && (sc->sc_phytype != new_phytype))
			aprint_error_dev(dev, "Previously assumed PHY type(%u)"
			    "was incorrect. New PHY type = %u\n",
			    sc->sc_phytype, new_phytype);

		if ((mii->mii_readreg != NULL) &&
		    (new_phytype == WMPHY_UNKNOWN))
			aprint_error_dev(dev, "PHY type is still unknown.\n");

		if ((mii->mii_readreg != NULL) &&
		    (mii->mii_readreg != new_readreg))
			aprint_error_dev(dev, "Previously assumed PHY "
			    "read/write function was incorrect.\n");
	}

	/* Update now */
	sc->sc_phytype = new_phytype;
	mii->mii_readreg = new_readreg;
	mii->mii_writereg = new_writereg;
	if (new_readreg == wm_gmii_hv_readreg) {
		sc->phy.readreg_locked = wm_gmii_hv_readreg_locked;
		sc->phy.writereg_locked = wm_gmii_hv_writereg_locked;
	} else if (new_readreg == wm_sgmii_readreg) {
		sc->phy.readreg_locked = wm_sgmii_readreg_locked;
		sc->phy.writereg_locked = wm_sgmii_writereg_locked;
	} else if (new_readreg == wm_gmii_i82544_readreg) {
		sc->phy.readreg_locked = wm_gmii_i82544_readreg_locked;
		sc->phy.writereg_locked = wm_gmii_i82544_writereg_locked;
	}
}

/*
 * wm_get_phy_id_82575:
 *
 * Return PHY ID. Return -1 if it failed.
 */
static int
wm_get_phy_id_82575(struct wm_softc *sc)
{
	uint32_t reg;
	int phyid = -1;

	/* XXX */
	if ((sc->sc_flags & WM_F_SGMII) == 0)
		return -1;

	if (wm_sgmii_uses_mdio(sc)) {
		switch (sc->sc_type) {
		case WM_T_82575:
		case WM_T_82576:
			reg = CSR_READ(sc, WMREG_MDIC);
			phyid = (reg & MDIC_PHY_MASK) >> MDIC_PHY_SHIFT;
			break;
		case WM_T_82580:
		case WM_T_I350:
		case WM_T_I354:
		case WM_T_I210:
		case WM_T_I211:
			reg = CSR_READ(sc, WMREG_MDICNFG);
			phyid = (reg & MDICNFG_PHY_MASK) >> MDICNFG_PHY_SHIFT;
			break;
		default:
			return -1;
		}
	}

	return phyid;
}

/*
 * wm_gmii_mediainit:
 *
 *	Initialize media for use on 1000BASE-T devices.
 */
static void
wm_gmii_mediainit(struct wm_softc *sc, pci_product_id_t prodid)
{
	device_t dev = sc->sc_dev;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct mii_data *mii = &sc->sc_mii;

	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* We have GMII. */
	sc->sc_flags |= WM_F_HAS_MII;

	if (sc->sc_type == WM_T_80003)
		sc->sc_tipg =  TIPG_1000T_80003_DFLT;
	else
		sc->sc_tipg = TIPG_1000T_DFLT;

	/*
	 * Let the chip set speed/duplex on its own based on
	 * signals from the PHY.
	 * XXXbouyer - I'm not sure this is right for the 80003,
	 * the em driver only sets CTRL_SLU here - but it seems to work.
	 */
	sc->sc_ctrl |= CTRL_SLU;
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

	/* Initialize our media structures and probe the GMII. */
	mii->mii_ifp = ifp;

	mii->mii_statchg = wm_gmii_statchg;

	/* get PHY control from SMBus to PCIe */
	if ((sc->sc_type == WM_T_PCH) || (sc->sc_type == WM_T_PCH2)
	    || (sc->sc_type == WM_T_PCH_LPT) || (sc->sc_type == WM_T_PCH_SPT)
	    || (sc->sc_type == WM_T_PCH_CNP) || (sc->sc_type == WM_T_PCH_TGP))
		wm_init_phy_workarounds_pchlan(sc);

	wm_gmii_reset(sc);

	sc->sc_ethercom.ec_mii = &sc->sc_mii;
	ifmedia_init_with_lock(&mii->mii_media, IFM_IMASK, wm_gmii_mediachange,
	    wm_gmii_mediastatus, sc->sc_core_lock);

	/* Setup internal SGMII PHY for SFP */
	wm_sgmii_sfp_preconfig(sc);

	if ((sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)
	    || (sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I354)
	    || (sc->sc_type == WM_T_I210) || (sc->sc_type == WM_T_I211)) {
		if ((sc->sc_flags & WM_F_SGMII) == 0) {
			/* Attach only one port */
			mii_attach(sc->sc_dev, &sc->sc_mii, 0xffffffff, 1,
			    MII_OFFSET_ANY, MIIF_DOPAUSE);
		} else {
			int i, id;
			uint32_t ctrl_ext;

			id = wm_get_phy_id_82575(sc);
			if (id != -1) {
				mii_attach(sc->sc_dev, &sc->sc_mii, 0xffffffff,
				    id, MII_OFFSET_ANY, MIIF_DOPAUSE);
			}
			if ((id == -1)
			    || (LIST_FIRST(&mii->mii_phys) == NULL)) {
				/* Power on sgmii phy if it is disabled */
				ctrl_ext = CSR_READ(sc, WMREG_CTRL_EXT);
				CSR_WRITE(sc, WMREG_CTRL_EXT,
				    ctrl_ext &~ CTRL_EXT_SWDPIN(3));
				CSR_WRITE_FLUSH(sc);
				delay(300*1000); /* XXX too long */

				/*
				 * From 1 to 8.
				 *
				 * I2C access fails with I2C register's ERROR
				 * bit set, so prevent error message while
				 * scanning.
				 */
				sc->phy.no_errprint = true;
				for (i = 1; i < 8; i++)
					mii_attach(sc->sc_dev, &sc->sc_mii,
					    0xffffffff, i, MII_OFFSET_ANY,
					    MIIF_DOPAUSE);
				sc->phy.no_errprint = false;

				/* Restore previous sfp cage power state */
				CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext);
			}
		}
	} else
		mii_attach(sc->sc_dev, &sc->sc_mii, 0xffffffff, MII_PHY_ANY,
		    MII_OFFSET_ANY, MIIF_DOPAUSE);

	/*
	 * If the MAC is PCH2 or PCH_LPT and failed to detect MII PHY, call
	 * wm_set_mdio_slow_mode_hv() for a workaround and retry.
	 */
	if (((sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT) ||
		(sc->sc_type == WM_T_PCH_SPT) || (sc->sc_type == WM_T_PCH_CNP)
		|| (sc->sc_type == WM_T_PCH_TGP))
	    && (LIST_FIRST(&mii->mii_phys) == NULL)) {
		wm_set_mdio_slow_mode_hv(sc);
		mii_attach(sc->sc_dev, &sc->sc_mii, 0xffffffff, MII_PHY_ANY,
		    MII_OFFSET_ANY, MIIF_DOPAUSE);
	}

	/*
	 * (For ICH8 variants)
	 * If PHY detection failed, use BM's r/w function and retry.
	 */
	if (LIST_FIRST(&mii->mii_phys) == NULL) {
		/* if failed, retry with *_bm_* */
		aprint_verbose_dev(dev, "Assumed PHY access function "
		    "(type = %d) might be incorrect. Use BM and retry.\n",
		    sc->sc_phytype);
		sc->sc_phytype = WMPHY_BM;
		mii->mii_readreg = wm_gmii_bm_readreg;
		mii->mii_writereg = wm_gmii_bm_writereg;

		mii_attach(sc->sc_dev, &sc->sc_mii, 0xffffffff, MII_PHY_ANY,
		    MII_OFFSET_ANY, MIIF_DOPAUSE);
	}

	if (LIST_FIRST(&mii->mii_phys) == NULL) {
		/* Any PHY wasn't found */
		ifmedia_add(&mii->mii_media, IFM_ETHER | IFM_NONE, 0, NULL);
		ifmedia_set(&mii->mii_media, IFM_ETHER | IFM_NONE);
		sc->sc_phytype = WMPHY_NONE;
	} else {
		struct mii_softc *child = LIST_FIRST(&mii->mii_phys);

		/*
		 * PHY found! Check PHY type again by the second call of
		 * wm_gmii_setup_phytype.
		 */
		wm_gmii_setup_phytype(sc, child->mii_mpd_oui,
		    child->mii_mpd_model);

		ifmedia_set(&mii->mii_media, IFM_ETHER | IFM_AUTO);
	}
}

/*
 * wm_gmii_mediachange:	[ifmedia interface function]
 *
 *	Set hardware to newly-selected media on a 1000BASE-T device.
 */
static int
wm_gmii_mediachange(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct ifmedia_entry *ife = sc->sc_mii.mii_media.ifm_cur;
	uint32_t reg;
	int rc;

	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	KASSERT(mutex_owned(sc->sc_core_lock));

	if ((sc->sc_if_flags & IFF_UP) == 0)
		return 0;

	/* XXX Not for I354? FreeBSD's e1000_82575.c doesn't include it */
	if ((sc->sc_type == WM_T_82580)
	    || (sc->sc_type == WM_T_I350) || (sc->sc_type == WM_T_I210)
	    || (sc->sc_type == WM_T_I211)) {
		reg = CSR_READ(sc, WMREG_PHPM);
		reg &= ~PHPM_GO_LINK_D;
		CSR_WRITE(sc, WMREG_PHPM, reg);
	}

	/* Disable D0 LPLU. */
	wm_lplu_d0_disable(sc);

	sc->sc_ctrl &= ~(CTRL_SPEED_MASK | CTRL_FD);
	sc->sc_ctrl |= CTRL_SLU;
	if ((IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO)
	    || (sc->sc_type > WM_T_82543)) {
		sc->sc_ctrl &= ~(CTRL_FRCSPD | CTRL_FRCFDX);
	} else {
		sc->sc_ctrl &= ~CTRL_ASDE;
		sc->sc_ctrl |= CTRL_FRCSPD | CTRL_FRCFDX;
		if (ife->ifm_media & IFM_FDX)
			sc->sc_ctrl |= CTRL_FD;
		switch (IFM_SUBTYPE(ife->ifm_media)) {
		case IFM_10_T:
			sc->sc_ctrl |= CTRL_SPEED_10;
			break;
		case IFM_100_TX:
			sc->sc_ctrl |= CTRL_SPEED_100;
			break;
		case IFM_1000_T:
			sc->sc_ctrl |= CTRL_SPEED_1000;
			break;
		case IFM_NONE:
			/* There is no specific setting for IFM_NONE */
			break;
		default:
			panic("wm_gmii_mediachange: bad media 0x%x",
			    ife->ifm_media);
		}
	}
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
	CSR_WRITE_FLUSH(sc);

	if ((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211))
		wm_serdes_mediachange(ifp);

	if (sc->sc_type <= WM_T_82543)
		wm_gmii_reset(sc);
	else if ((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211)
	    && ((sc->sc_flags & WM_F_SGMII) != 0)) {
		/* allow time for SFP cage time to power up phy */
		delay(300 * 1000);
		wm_gmii_reset(sc);
	}

	if ((rc = mii_mediachg(&sc->sc_mii)) == ENXIO)
		return 0;
	return rc;
}

/*
 * wm_gmii_mediastatus:	[ifmedia interface function]
 *
 *	Get the current interface media status on a 1000BASE-T device.
 */
static void
wm_gmii_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct wm_softc *sc = ifp->if_softc;
	struct ethercom *ec = &sc->sc_ethercom;
	struct mii_data *mii;
	bool dopoll = true;

	/*
	 * In normal drivers, ether_mediastatus() is called here.
	 * To avoid calling mii_pollstat(), ether_mediastatus() is open coded.
	 */
	KASSERT(mutex_owned(sc->sc_core_lock));
	KASSERT(ec->ec_mii != NULL);
	KASSERT(mii_locked(ec->ec_mii));

	mii = ec->ec_mii;
	if ((sc->sc_flags & WM_F_DELAY_LINKUP) != 0) {
		struct timeval now;

		getmicrotime(&now);
		if (timercmp(&now, &sc->sc_linkup_delay_time, <))
			dopoll = false;
		else if (sc->sc_linkup_delay_time.tv_sec != 0) {
			/* Simplify by checking tv_sec only. It's enough. */

			sc->sc_linkup_delay_time.tv_sec = 0;
			sc->sc_linkup_delay_time.tv_usec = 0;
		}
	}

	/*
	 * Don't call mii_pollstat() while doing workaround.
	 * See also wm_linkintr_gmii() and wm_tick().
	 */
	if (dopoll)
		mii_pollstat(mii);
	ifmr->ifm_active = mii->mii_media_active;
	ifmr->ifm_status = mii->mii_media_status;

	ifmr->ifm_active = (ifmr->ifm_active & ~IFM_ETH_FMASK)
	    | sc->sc_flowflags;
}

#define	MDI_IO		CTRL_SWDPIN(2)
#define	MDI_DIR		CTRL_SWDPIO(2)	/* host -> PHY */
#define	MDI_CLK		CTRL_SWDPIN(3)

static void
wm_i82543_mii_sendbits(struct wm_softc *sc, uint32_t data, int nbits)
{
	uint32_t i, v;

	v = CSR_READ(sc, WMREG_CTRL);
	v &= ~(MDI_IO | MDI_CLK | (CTRL_SWDPIO_MASK << CTRL_SWDPIO_SHIFT));
	v |= MDI_DIR | CTRL_SWDPIO(3);

	for (i = __BIT(nbits - 1); i != 0; i >>= 1) {
		if (data & i)
			v |= MDI_IO;
		else
			v &= ~MDI_IO;
		CSR_WRITE(sc, WMREG_CTRL, v);
		CSR_WRITE_FLUSH(sc);
		delay(10);
		CSR_WRITE(sc, WMREG_CTRL, v | MDI_CLK);
		CSR_WRITE_FLUSH(sc);
		delay(10);
		CSR_WRITE(sc, WMREG_CTRL, v);
		CSR_WRITE_FLUSH(sc);
		delay(10);
	}
}

static uint16_t
wm_i82543_mii_recvbits(struct wm_softc *sc)
{
	uint32_t v, i;
	uint16_t data = 0;

	v = CSR_READ(sc, WMREG_CTRL);
	v &= ~(MDI_IO | MDI_CLK | (CTRL_SWDPIO_MASK << CTRL_SWDPIO_SHIFT));
	v |= CTRL_SWDPIO(3);

	CSR_WRITE(sc, WMREG_CTRL, v);
	CSR_WRITE_FLUSH(sc);
	delay(10);
	CSR_WRITE(sc, WMREG_CTRL, v | MDI_CLK);
	CSR_WRITE_FLUSH(sc);
	delay(10);
	CSR_WRITE(sc, WMREG_CTRL, v);
	CSR_WRITE_FLUSH(sc);
	delay(10);

	for (i = 0; i < 16; i++) {
		data <<= 1;
		CSR_WRITE(sc, WMREG_CTRL, v | MDI_CLK);
		CSR_WRITE_FLUSH(sc);
		delay(10);
		if (CSR_READ(sc, WMREG_CTRL) & MDI_IO)
			data |= 1;
		CSR_WRITE(sc, WMREG_CTRL, v);
		CSR_WRITE_FLUSH(sc);
		delay(10);
	}

	CSR_WRITE(sc, WMREG_CTRL, v | MDI_CLK);
	CSR_WRITE_FLUSH(sc);
	delay(10);
	CSR_WRITE(sc, WMREG_CTRL, v);
	CSR_WRITE_FLUSH(sc);
	delay(10);

	return data;
}

#undef MDI_IO
#undef MDI_DIR
#undef MDI_CLK

/*
 * wm_gmii_i82543_readreg:	[mii interface function]
 *
 *	Read a PHY register on the GMII (i82543 version).
 */
static int
wm_gmii_i82543_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);

	wm_i82543_mii_sendbits(sc, 0xffffffffU, 32);
	wm_i82543_mii_sendbits(sc, reg | (phy << 5) |
	    (MII_COMMAND_READ << 10) | (MII_COMMAND_START << 12), 14);
	*val = wm_i82543_mii_recvbits(sc) & 0xffff;

	DPRINTF(sc, WM_DEBUG_GMII,
	    ("%s: GMII: read phy %d reg %d -> 0x%04hx\n",
		device_xname(dev), phy, reg, *val));

	return 0;
}

/*
 * wm_gmii_i82543_writereg:	[mii interface function]
 *
 *	Write a PHY register on the GMII (i82543 version).
 */
static int
wm_gmii_i82543_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);

	wm_i82543_mii_sendbits(sc, 0xffffffffU, 32);
	wm_i82543_mii_sendbits(sc, val | (MII_COMMAND_ACK << 16) |
	    (reg << 18) | (phy << 23) | (MII_COMMAND_WRITE << 28) |
	    (MII_COMMAND_START << 30), 32);

	return 0;
}

/*
 * wm_gmii_mdic_readreg:	[mii interface function]
 *
 *	Read a PHY register on the GMII.
 */
static int
wm_gmii_mdic_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	uint32_t mdic = 0;
	int i;

	if ((sc->sc_phytype != WMPHY_82579) && (sc->sc_phytype != WMPHY_I217)
	    && (reg > MII_ADDRMASK)) {
		device_printf(dev, "%s: PHYTYPE = %d, addr 0x%x > 0x1f\n",
		    __func__, sc->sc_phytype, reg);
		reg &= MII_ADDRMASK;
	}

	CSR_WRITE(sc, WMREG_MDIC, MDIC_OP_READ | MDIC_PHYADD(phy) |
	    MDIC_REGADD(reg));

	for (i = 0; i < WM_GEN_POLL_TIMEOUT * 3; i++) {
		delay(50);
		mdic = CSR_READ(sc, WMREG_MDIC);
		if (mdic & MDIC_READY)
			break;
	}

	if ((mdic & MDIC_READY) == 0) {
		DPRINTF(sc, WM_DEBUG_GMII,
		    ("%s: MDIC read timed out: phy %d reg %d\n",
			device_xname(dev), phy, reg));
		return ETIMEDOUT;
	} else if (mdic & MDIC_E) {
		/* This is normal if no PHY is present. */
		DPRINTF(sc, WM_DEBUG_GMII,
		    ("%s: MDIC read error: phy %d reg %d\n",
			device_xname(sc->sc_dev), phy, reg));
		return -1;
	} else
		*val = MDIC_DATA(mdic);

	/*
	 * Allow some time after each MDIC transaction to avoid
	 * reading duplicate data in the next MDIC transaction.
	 */
	if (sc->sc_type == WM_T_PCH2)
		delay(100);

	return 0;
}

/*
 * wm_gmii_mdic_writereg:	[mii interface function]
 *
 *	Write a PHY register on the GMII.
 */
static int
wm_gmii_mdic_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	uint32_t mdic = 0;
	int i;

	if ((sc->sc_phytype != WMPHY_82579) && (sc->sc_phytype != WMPHY_I217)
	    && (reg > MII_ADDRMASK)) {
		device_printf(dev, "%s: PHYTYPE = %d, addr 0x%x > 0x1f\n",
		    __func__, sc->sc_phytype, reg);
		reg &= MII_ADDRMASK;
	}

	CSR_WRITE(sc, WMREG_MDIC, MDIC_OP_WRITE | MDIC_PHYADD(phy) |
	    MDIC_REGADD(reg) | MDIC_DATA(val));

	for (i = 0; i < WM_GEN_POLL_TIMEOUT * 3; i++) {
		delay(50);
		mdic = CSR_READ(sc, WMREG_MDIC);
		if (mdic & MDIC_READY)
			break;
	}

	if ((mdic & MDIC_READY) == 0) {
		DPRINTF(sc, WM_DEBUG_GMII,
		    ("%s: MDIC write timed out: phy %d reg %d\n",
			device_xname(dev), phy, reg));
		return ETIMEDOUT;
	} else if (mdic & MDIC_E) {
		DPRINTF(sc, WM_DEBUG_GMII,
		    ("%s: MDIC write error: phy %d reg %d\n",
			device_xname(dev), phy, reg));
		return -1;
	}

	/*
	 * Allow some time after each MDIC transaction to avoid
	 * reading duplicate data in the next MDIC transaction.
	 */
	if (sc->sc_type == WM_T_PCH2)
		delay(100);

	return 0;
}

/*
 * wm_gmii_i82544_readreg:	[mii interface function]
 *
 *	Read a PHY register on the GMII.
 */
static int
wm_gmii_i82544_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_gmii_i82544_readreg_locked(dev, phy, reg, val);

	sc->phy.release(sc);

	return rv;
}

static int
wm_gmii_i82544_readreg_locked(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	switch (sc->sc_phytype) {
	case WMPHY_IGP:
	case WMPHY_IGP_2:
	case WMPHY_IGP_3:
		if (reg > BME1000_MAX_MULTI_PAGE_REG) {
			rv = wm_gmii_mdic_writereg(dev, phy,
			    IGPHY_PAGE_SELECT, reg);
			if (rv != 0)
				return rv;
		}
		break;
	default:
#ifdef WM_DEBUG
		if ((reg >> MII_ADDRBITS) != 0)
			device_printf(dev,
			    "%s: PHYTYPE = 0x%x, addr = 0x%02x\n",
			    __func__, sc->sc_phytype, reg);
#endif
		break;
	}

	return wm_gmii_mdic_readreg(dev, phy, reg & MII_ADDRMASK, val);
}

/*
 * wm_gmii_i82544_writereg:	[mii interface function]
 *
 *	Write a PHY register on the GMII.
 */
static int
wm_gmii_i82544_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_gmii_i82544_writereg_locked(dev, phy, reg & MII_ADDRMASK, val);
	sc->phy.release(sc);

	return rv;
}

static int
wm_gmii_i82544_writereg_locked(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	switch (sc->sc_phytype) {
	case WMPHY_IGP:
	case WMPHY_IGP_2:
	case WMPHY_IGP_3:
		if (reg > BME1000_MAX_MULTI_PAGE_REG) {
			rv = wm_gmii_mdic_writereg(dev, phy,
			    IGPHY_PAGE_SELECT, reg);
			if (rv != 0)
				return rv;
		}
		break;
	default:
#ifdef WM_DEBUG
		if ((reg >> MII_ADDRBITS) != 0)
			device_printf(dev,
			    "%s: PHYTYPE == 0x%x, addr = 0x%02x",
			    __func__, sc->sc_phytype, reg);
#endif
		break;
	}

	return wm_gmii_mdic_writereg(dev, phy, reg & MII_ADDRMASK, val);
}

/*
 * wm_gmii_i80003_readreg:	[mii interface function]
 *
 *	Read a PHY register on the kumeran
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_i80003_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int page_select;
	uint16_t temp, temp2;
	int rv;

	if (phy != 1) /* Only one PHY on kumeran bus */
		return -1;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	if ((reg & MII_ADDRMASK) < GG82563_MIN_ALT_REG)
		page_select = GG82563_PHY_PAGE_SELECT;
	else {
		/*
		 * Use Alternative Page Select register to access registers
		 * 30 and 31.
		 */
		page_select = GG82563_PHY_PAGE_SELECT_ALT;
	}
	temp = reg >> GG82563_PAGE_SHIFT;
	if ((rv = wm_gmii_mdic_writereg(dev, phy, page_select, temp)) != 0)
		goto out;

	if ((sc->sc_flags & WM_F_80003_MDIC_WA) != 0) {
		/*
		 * Wait more 200us for a bug of the ready bit in the MDIC
		 * register.
		 */
		delay(200);
		rv = wm_gmii_mdic_readreg(dev, phy, page_select, &temp2);
		if ((rv != 0) || (temp2 != temp)) {
			device_printf(dev, "%s failed\n", __func__);
			rv = -1;
			goto out;
		}
		delay(200);
		rv = wm_gmii_mdic_readreg(dev, phy, reg & MII_ADDRMASK, val);
		delay(200);
	} else
		rv = wm_gmii_mdic_readreg(dev, phy, reg & MII_ADDRMASK, val);

out:
	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_i80003_writereg:	[mii interface function]
 *
 *	Write a PHY register on the kumeran.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_i80003_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int page_select, rv;
	uint16_t temp, temp2;

	if (phy != 1) /* Only one PHY on kumeran bus */
		return -1;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	if ((reg & MII_ADDRMASK) < GG82563_MIN_ALT_REG)
		page_select = GG82563_PHY_PAGE_SELECT;
	else {
		/*
		 * Use Alternative Page Select register to access registers
		 * 30 and 31.
		 */
		page_select = GG82563_PHY_PAGE_SELECT_ALT;
	}
	temp = (uint16_t)reg >> GG82563_PAGE_SHIFT;
	if ((rv = wm_gmii_mdic_writereg(dev, phy, page_select, temp)) != 0)
		goto out;

	if ((sc->sc_flags & WM_F_80003_MDIC_WA) != 0) {
		/*
		 * Wait more 200us for a bug of the ready bit in the MDIC
		 * register.
		 */
		delay(200);
		rv = wm_gmii_mdic_readreg(dev, phy, page_select, &temp2);
		if ((rv != 0) || (temp2 != temp)) {
			device_printf(dev, "%s failed\n", __func__);
			rv = -1;
			goto out;
		}
		delay(200);
		rv = wm_gmii_mdic_writereg(dev, phy, reg & MII_ADDRMASK, val);
		delay(200);
	} else
		rv = wm_gmii_mdic_writereg(dev, phy, reg & MII_ADDRMASK, val);

out:
	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_bm_readreg:	[mii interface function]
 *
 *	Read a PHY register on the kumeran
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_bm_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	uint16_t page = reg >> BME1000_PAGE_SHIFT;
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	if ((sc->sc_type != WM_T_82574) && (sc->sc_type != WM_T_82583))
		phy = ((page >= 768) || ((page == 0) && (reg == 25))
		    || (reg == 31)) ? 1 : phy;
	/* Page 800 works differently than the rest so it has its own func */
	if (page == BM_WUC_PAGE) {
		rv = wm_access_phy_wakeup_reg_bm(dev, reg, val, true, false);
		goto release;
	}

	if (reg > BME1000_MAX_MULTI_PAGE_REG) {
		if ((phy == 1) && (sc->sc_type != WM_T_82574)
		    && (sc->sc_type != WM_T_82583))
			rv = wm_gmii_mdic_writereg(dev, phy,
			    IGPHY_PAGE_SELECT, page << BME1000_PAGE_SHIFT);
		else
			rv = wm_gmii_mdic_writereg(dev, phy,
			    BME1000_PHY_PAGE_SELECT, page);
		if (rv != 0)
			goto release;
	}

	rv = wm_gmii_mdic_readreg(dev, phy, reg & MII_ADDRMASK, val);

release:
	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_bm_writereg:	[mii interface function]
 *
 *	Write a PHY register on the kumeran.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_bm_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	uint16_t page = reg >> BME1000_PAGE_SHIFT;
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	if ((sc->sc_type != WM_T_82574) && (sc->sc_type != WM_T_82583))
		phy = ((page >= 768) || ((page == 0) && (reg == 25))
		    || (reg == 31)) ? 1 : phy;
	/* Page 800 works differently than the rest so it has its own func */
	if (page == BM_WUC_PAGE) {
		rv = wm_access_phy_wakeup_reg_bm(dev, reg, &val, false, false);
		goto release;
	}

	if (reg > BME1000_MAX_MULTI_PAGE_REG) {
		if ((phy == 1) && (sc->sc_type != WM_T_82574)
		    && (sc->sc_type != WM_T_82583))
			rv = wm_gmii_mdic_writereg(dev, phy,
			    IGPHY_PAGE_SELECT, page << BME1000_PAGE_SHIFT);
		else
			rv = wm_gmii_mdic_writereg(dev, phy,
			    BME1000_PHY_PAGE_SELECT, page);
		if (rv != 0)
			goto release;
	}

	rv = wm_gmii_mdic_writereg(dev, phy, reg & MII_ADDRMASK, val);

release:
	sc->phy.release(sc);
	return rv;
}

/*
 *  wm_enable_phy_wakeup_reg_access_bm - enable access to BM wakeup registers
 *  @dev: pointer to the HW structure
 *  @phy_reg: pointer to store original contents of BM_WUC_ENABLE_REG
 *
 *  Assumes semaphore already acquired and phy_reg points to a valid memory
 *  address to store contents of the BM_WUC_ENABLE_REG register.
 */
static int
wm_enable_phy_wakeup_reg_access_bm(device_t dev, uint16_t *phy_regp)
{
#ifdef WM_DEBUG
	struct wm_softc *sc = device_private(dev);
#endif
	uint16_t temp;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));

	if (!phy_regp)
		return -1;

	/* All page select, port ctrl and wakeup registers use phy address 1 */

	/* Select Port Control Registers page */
	rv = wm_gmii_mdic_writereg(dev, 1, IGPHY_PAGE_SELECT,
	    BM_PORT_CTRL_PAGE << IGP3_PAGE_SHIFT);
	if (rv != 0)
		return rv;

	/* Read WUCE and save it */
	rv = wm_gmii_mdic_readreg(dev, 1, BM_WUC_ENABLE_REG, phy_regp);
	if (rv != 0)
		return rv;

	/* Enable both PHY wakeup mode and Wakeup register page writes.
	 * Prevent a power state change by disabling ME and Host PHY wakeup.
	 */
	temp = *phy_regp;
	temp |= BM_WUC_ENABLE_BIT;
	temp &= ~(BM_WUC_ME_WU_BIT | BM_WUC_HOST_WU_BIT);

	if ((rv = wm_gmii_mdic_writereg(dev, 1, BM_WUC_ENABLE_REG, temp)) != 0)
		return rv;

	/* Select Host Wakeup Registers page - caller now able to write
	 * registers on the Wakeup registers page
	 */
	return wm_gmii_mdic_writereg(dev, 1, IGPHY_PAGE_SELECT,
	    BM_WUC_PAGE << IGP3_PAGE_SHIFT);
}

/*
 *  wm_disable_phy_wakeup_reg_access_bm - disable access to BM wakeup regs
 *  @dev: pointer to the HW structure
 *  @phy_reg: pointer to original contents of BM_WUC_ENABLE_REG
 *
 *  Restore BM_WUC_ENABLE_REG to its original value.
 *
 *  Assumes semaphore already acquired and *phy_reg is the contents of the
 *  BM_WUC_ENABLE_REG before register(s) on BM_WUC_PAGE were accessed by
 *  caller.
 */
static int
wm_disable_phy_wakeup_reg_access_bm(device_t dev, uint16_t *phy_regp)
{
#ifdef WM_DEBUG
	struct wm_softc *sc = device_private(dev);
#endif

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));

	if (!phy_regp)
		return -1;

	/* Select Port Control Registers page */
	wm_gmii_mdic_writereg(dev, 1, IGPHY_PAGE_SELECT,
	    BM_PORT_CTRL_PAGE << IGP3_PAGE_SHIFT);

	/* Restore 769.17 to its original value */
	wm_gmii_mdic_writereg(dev, 1, BM_WUC_ENABLE_REG, *phy_regp);

	return 0;
}

/*
 *  wm_access_phy_wakeup_reg_bm - Read/write BM PHY wakeup register
 *  @sc: pointer to the HW structure
 *  @offset: register offset to be read or written
 *  @val: pointer to the data to read or write
 *  @rd: determines if operation is read or write
 *  @page_set: BM_WUC_PAGE already set and access enabled
 *
 *  Read the PHY register at offset and store the retrieved information in
 *  data, or write data to PHY register at offset.  Note the procedure to
 *  access the PHY wakeup registers is different than reading the other PHY
 *  registers. It works as such:
 *  1) Set 769.17.2 (page 769, register 17, bit 2) = 1
 *  2) Set page to 800 for host (801 if we were manageability)
 *  3) Write the address using the address opcode (0x11)
 *  4) Read or write the data using the data opcode (0x12)
 *  5) Restore 769.17.2 to its original value
 *
 *  Steps 1 and 2 are done by wm_enable_phy_wakeup_reg_access_bm() and
 *  step 5 is done by wm_disable_phy_wakeup_reg_access_bm().
 *
 *  Assumes semaphore is already acquired.  When page_set==TRUE, assumes
 *  the PHY page is set to BM_WUC_PAGE (i.e. a function in the call stack
 *  is responsible for calls to wm_[enable|disable]_phy_wakeup_reg_bm()).
 */
static int
wm_access_phy_wakeup_reg_bm(device_t dev, int offset, int16_t *val, int rd,
    bool page_set)
{
	struct wm_softc *sc = device_private(dev);
	uint16_t regnum = BM_PHY_REG_NUM(offset);
	uint16_t page = BM_PHY_REG_PAGE(offset);
	uint16_t wuce;
	int rv = 0;

	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s called\n",
		device_xname(dev), __func__));
	/* XXX Gig must be disabled for MDIO accesses to page 800 */
	if ((sc->sc_type == WM_T_PCH)
	    && ((CSR_READ(sc, WMREG_PHY_CTRL) & PHY_CTRL_GBE_DIS) == 0)) {
		device_printf(dev,
		    "Attempting to access page %d while gig enabled.\n", page);
	}

	if (!page_set) {
		/* Enable access to PHY wakeup registers */
		rv = wm_enable_phy_wakeup_reg_access_bm(dev, &wuce);
		if (rv != 0) {
			device_printf(dev,
			    "%s: Could not enable PHY wakeup reg access\n",
			    __func__);
			return rv;
		}
	}
	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s: Accessing PHY page %d reg 0x%x\n",
		device_xname(sc->sc_dev), __func__, page, regnum));

	/*
	 * 2) Access PHY wakeup register.
	 * See wm_access_phy_wakeup_reg_bm.
	 */

	/* Write the Wakeup register page offset value using opcode 0x11 */
	rv = wm_gmii_mdic_writereg(dev, 1, BM_WUC_ADDRESS_OPCODE, regnum);
	if (rv != 0)
		return rv;

	if (rd) {
		/* Read the Wakeup register page value using opcode 0x12 */
		rv = wm_gmii_mdic_readreg(dev, 1, BM_WUC_DATA_OPCODE, val);
	} else {
		/* Write the Wakeup register page value using opcode 0x12 */
		rv = wm_gmii_mdic_writereg(dev, 1, BM_WUC_DATA_OPCODE, *val);
	}
	if (rv != 0)
		return rv;

	if (!page_set)
		rv = wm_disable_phy_wakeup_reg_access_bm(dev, &wuce);

	return rv;
}

/*
 * wm_gmii_hv_readreg:	[mii interface function]
 *
 *	Read a PHY register on the kumeran
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_hv_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s called\n",
		device_xname(dev), __func__));

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_gmii_hv_readreg_locked(dev, phy, reg, val);
	sc->phy.release(sc);
	return rv;
}

static int
wm_gmii_hv_readreg_locked(device_t dev, int phy, int reg, uint16_t *val)
{
	uint16_t page = BM_PHY_REG_PAGE(reg);
	uint16_t regnum = BM_PHY_REG_NUM(reg);
	int rv;

	phy = (page >= HV_INTC_FC_PAGE_START) ? 1 : phy;

	/* Page 800 works differently than the rest so it has its own func */
	if (page == BM_WUC_PAGE)
		return wm_access_phy_wakeup_reg_bm(dev, reg, val, true, false);

	/*
	 * Lower than page 768 works differently than the rest so it has its
	 * own func
	 */
	if ((page > 0) && (page < HV_INTC_FC_PAGE_START)) {
		device_printf(dev, "gmii_hv_readreg!!!\n");
		return -1;
	}

	/*
	 * XXX I21[789] documents say that the SMBus Address register is at
	 * PHY address 01, Page 0 (not 768), Register 26.
	 */
	if (page == HV_INTC_FC_PAGE_START)
		page = 0;

	if (regnum > BME1000_MAX_MULTI_PAGE_REG) {
		rv = wm_gmii_mdic_writereg(dev, 1, IGPHY_PAGE_SELECT,
		    page << BME1000_PAGE_SHIFT);
		if (rv != 0)
			return rv;
	}

	return wm_gmii_mdic_readreg(dev, phy, regnum & MII_ADDRMASK, val);
}

/*
 * wm_gmii_hv_writereg:	[mii interface function]
 *
 *	Write a PHY register on the kumeran.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_hv_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	DPRINTF(sc, WM_DEBUG_GMII, ("%s: %s called\n",
		device_xname(dev), __func__));

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_gmii_hv_writereg_locked(dev, phy, reg, val);
	sc->phy.release(sc);

	return rv;
}

static int
wm_gmii_hv_writereg_locked(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	uint16_t page = BM_PHY_REG_PAGE(reg);
	uint16_t regnum = BM_PHY_REG_NUM(reg);
	int rv;

	phy = (page >= HV_INTC_FC_PAGE_START) ? 1 : phy;

	/* Page 800 works differently than the rest so it has its own func */
	if (page == BM_WUC_PAGE)
		return wm_access_phy_wakeup_reg_bm(dev, reg, &val, false,
		    false);

	/*
	 * Lower than page 768 works differently than the rest so it has its
	 * own func
	 */
	if ((page > 0) && (page < HV_INTC_FC_PAGE_START)) {
		device_printf(dev, "gmii_hv_writereg!!!\n");
		return -1;
	}

	{
		/*
		 * XXX I21[789] documents say that the SMBus Address register
		 * is at PHY address 01, Page 0 (not 768), Register 26.
		 */
		if (page == HV_INTC_FC_PAGE_START)
			page = 0;

		/*
		 * XXX Workaround MDIO accesses being disabled after entering
		 * IEEE Power Down (whenever bit 11 of the PHY control
		 * register is set)
		 */
		if (sc->sc_phytype == WMPHY_82578) {
			struct mii_softc *child;

			child = LIST_FIRST(&sc->sc_mii.mii_phys);
			if ((child != NULL) && (child->mii_mpd_rev >= 1)
			    && (phy == 2) && ((regnum & MII_ADDRMASK) == 0)
			    && ((val & (1 << 11)) != 0)) {
				device_printf(dev, "XXX need workaround\n");
			}
		}

		if (regnum > BME1000_MAX_MULTI_PAGE_REG) {
			rv = wm_gmii_mdic_writereg(dev, 1,
			    IGPHY_PAGE_SELECT, page << BME1000_PAGE_SHIFT);
			if (rv != 0)
				return rv;
		}
	}

	return wm_gmii_mdic_writereg(dev, phy, regnum & MII_ADDRMASK, val);
}

/*
 * wm_gmii_82580_readreg:	[mii interface function]
 *
 *	Read a PHY register on the 82580 and I350.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_82580_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

#ifdef DIAGNOSTIC
	if (reg > MII_ADDRMASK) {
		device_printf(dev, "%s: PHYTYPE = %d, addr 0x%x > 0x1f\n",
		    __func__, sc->sc_phytype, reg);
		reg &= MII_ADDRMASK;
	}
#endif
	rv = wm_gmii_mdic_readreg(dev, phy, reg, val);

	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_82580_writereg:	[mii interface function]
 *
 *	Write a PHY register on the 82580 and I350.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_82580_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

#ifdef DIAGNOSTIC
	if (reg > MII_ADDRMASK) {
		device_printf(dev, "%s: PHYTYPE = %d, addr 0x%x > 0x1f\n",
		    __func__, sc->sc_phytype, reg);
		reg &= MII_ADDRMASK;
	}
#endif
	rv = wm_gmii_mdic_writereg(dev, phy, reg, val);

	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_gs40g_readreg:	[mii interface function]
 *
 *	Read a PHY register on the I2100 and I211.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_gs40g_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int page, offset;
	int rv;

	/* Acquire semaphore */
	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	/* Page select */
	page = reg >> GS40G_PAGE_SHIFT;
	rv = wm_gmii_mdic_writereg(dev, phy, GS40G_PAGE_SELECT, page);
	if (rv != 0)
		goto release;

	/* Read reg */
	offset = reg & GS40G_OFFSET_MASK;
	rv = wm_gmii_mdic_readreg(dev, phy, offset, val);

release:
	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_gs40g_writereg:	[mii interface function]
 *
 *	Write a PHY register on the I210 and I211.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_gmii_gs40g_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	uint16_t page;
	int offset, rv;

	/* Acquire semaphore */
	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	/* Page select */
	page = reg >> GS40G_PAGE_SHIFT;
	rv = wm_gmii_mdic_writereg(dev, phy, GS40G_PAGE_SELECT, page);
	if (rv != 0)
		goto release;

	/* Write reg */
	offset = reg & GS40G_OFFSET_MASK;
	rv = wm_gmii_mdic_writereg(dev, phy, offset, val);

release:
	/* Release semaphore */
	sc->phy.release(sc);
	return rv;
}

/*
 * wm_gmii_statchg:	[mii interface function]
 *
 *	Callback from MII layer when media changes.
 */
static void
wm_gmii_statchg(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct mii_data *mii = &sc->sc_mii;

	sc->sc_ctrl &= ~(CTRL_TFCE | CTRL_RFCE);
	sc->sc_tctl &= ~TCTL_COLD(0x3ff);
	sc->sc_fcrtl &= ~FCRTL_XONE;

	/* Get flow control negotiation result. */
	if (IFM_SUBTYPE(mii->mii_media.ifm_cur->ifm_media) == IFM_AUTO &&
	    (mii->mii_media_active & IFM_ETH_FMASK) != sc->sc_flowflags) {
		sc->sc_flowflags = mii->mii_media_active & IFM_ETH_FMASK;
		mii->mii_media_active &= ~IFM_ETH_FMASK;
	}

	if (sc->sc_flowflags & IFM_FLOW) {
		if (sc->sc_flowflags & IFM_ETH_TXPAUSE) {
			sc->sc_ctrl |= CTRL_TFCE;
			sc->sc_fcrtl |= FCRTL_XONE;
		}
		if (sc->sc_flowflags & IFM_ETH_RXPAUSE)
			sc->sc_ctrl |= CTRL_RFCE;
	}

	if (mii->mii_media_active & IFM_FDX) {
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: LINK: statchg: FDX\n", ifp->if_xname));
		sc->sc_tctl |= TCTL_COLD(TX_COLLISION_DISTANCE_FDX);
	} else {
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: LINK: statchg: HDX\n", ifp->if_xname));
		sc->sc_tctl |= TCTL_COLD(TX_COLLISION_DISTANCE_HDX);
	}

	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
	CSR_WRITE(sc, WMREG_TCTL, sc->sc_tctl);
	CSR_WRITE(sc, (sc->sc_type < WM_T_82543) ?
	    WMREG_OLD_FCRTL : WMREG_FCRTL, sc->sc_fcrtl);
	if (sc->sc_type == WM_T_80003) {
		switch (IFM_SUBTYPE(mii->mii_media_active)) {
		case IFM_1000_T:
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_HD_CTRL,
			    KUMCTRLSTA_HD_CTRL_1000_DEFAULT);
			sc->sc_tipg =  TIPG_1000T_80003_DFLT;
			break;
		default:
			wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_HD_CTRL,
			    KUMCTRLSTA_HD_CTRL_10_100_DEFAULT);
			sc->sc_tipg =  TIPG_10_100_80003_DFLT;
			break;
		}
		CSR_WRITE(sc, WMREG_TIPG, sc->sc_tipg);
	}
}

/* kumeran related (80003, ICH* and PCH*) */

/*
 * wm_kmrn_readreg:
 *
 *	Read a kumeran register
 */
static int
wm_kmrn_readreg(struct wm_softc *sc, int reg, uint16_t *val)
{
	int rv;

	if (sc->sc_type == WM_T_80003)
		rv = wm_get_swfw_semaphore(sc, SWFW_MAC_CSR_SM);
	else
		rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(sc->sc_dev, "%s: failed to get semaphore\n",
		    __func__);
		return rv;
	}

	rv = wm_kmrn_readreg_locked(sc, reg, val);

	if (sc->sc_type == WM_T_80003)
		wm_put_swfw_semaphore(sc, SWFW_MAC_CSR_SM);
	else
		sc->phy.release(sc);

	return rv;
}

static int
wm_kmrn_readreg_locked(struct wm_softc *sc, int reg, uint16_t *val)
{

	CSR_WRITE(sc, WMREG_KUMCTRLSTA,
	    ((reg << KUMCTRLSTA_OFFSET_SHIFT) & KUMCTRLSTA_OFFSET) |
	    KUMCTRLSTA_REN);
	CSR_WRITE_FLUSH(sc);
	delay(2);

	*val = CSR_READ(sc, WMREG_KUMCTRLSTA) & KUMCTRLSTA_MASK;

	return 0;
}

/*
 * wm_kmrn_writereg:
 *
 *	Write a kumeran register
 */
static int
wm_kmrn_writereg(struct wm_softc *sc, int reg, uint16_t val)
{
	int rv;

	if (sc->sc_type == WM_T_80003)
		rv = wm_get_swfw_semaphore(sc, SWFW_MAC_CSR_SM);
	else
		rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(sc->sc_dev, "%s: failed to get semaphore\n",
		    __func__);
		return rv;
	}

	rv = wm_kmrn_writereg_locked(sc, reg, val);

	if (sc->sc_type == WM_T_80003)
		wm_put_swfw_semaphore(sc, SWFW_MAC_CSR_SM);
	else
		sc->phy.release(sc);

	return rv;
}

static int
wm_kmrn_writereg_locked(struct wm_softc *sc, int reg, uint16_t val)
{

	CSR_WRITE(sc, WMREG_KUMCTRLSTA,
	    ((reg << KUMCTRLSTA_OFFSET_SHIFT) & KUMCTRLSTA_OFFSET) | val);

	return 0;
}

/*
 * EMI register related (82579, WMPHY_I217(PCH2 and newer))
 * This access method is different from IEEE MMD.
 */
static int
wm_access_emi_reg_locked(device_t dev, int reg, uint16_t *val, bool rd)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.writereg_locked(dev, 2, I82579_EMI_ADDR, reg);
	if (rv != 0)
		return rv;

	if (rd)
		rv = sc->phy.readreg_locked(dev, 2, I82579_EMI_DATA, val);
	else
		rv = sc->phy.writereg_locked(dev, 2, I82579_EMI_DATA, *val);
	return rv;
}

static int
wm_read_emi_reg_locked(device_t dev, int reg, uint16_t *val)
{

	return wm_access_emi_reg_locked(dev, reg, val, true);
}

static int
wm_write_emi_reg_locked(device_t dev, int reg, uint16_t val)
{

	return wm_access_emi_reg_locked(dev, reg, &val, false);
}

/* SGMII related */

/*
 * wm_sgmii_uses_mdio
 *
 * Check whether the transaction is to the internal PHY or the external
 * MDIO interface. Return true if it's MDIO.
 */
static bool
wm_sgmii_uses_mdio(struct wm_softc *sc)
{
	uint32_t reg;
	bool ismdio = false;

	switch (sc->sc_type) {
	case WM_T_82575:
	case WM_T_82576:
		reg = CSR_READ(sc, WMREG_MDIC);
		ismdio = ((reg & MDIC_DEST) != 0);
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		reg = CSR_READ(sc, WMREG_MDICNFG);
		ismdio = ((reg & MDICNFG_DEST) != 0);
		break;
	default:
		break;
	}

	return ismdio;
}

/* Setup internal SGMII PHY for SFP */
static void
wm_sgmii_sfp_preconfig(struct wm_softc *sc)
{
	uint16_t id1, id2, phyreg;
	int i, rv;

	if (((sc->sc_flags & WM_F_SGMII) == 0)
	    || ((sc->sc_flags & WM_F_SFP) == 0))
		return;

	for (i = 0; i < MII_NPHY; i++) {
		sc->phy.no_errprint = true;
		rv = sc->phy.readreg_locked(sc->sc_dev, i, MII_PHYIDR1, &id1);
		if (rv != 0)
			continue;
		rv = sc->phy.readreg_locked(sc->sc_dev, i, MII_PHYIDR2, &id2);
		if (rv != 0)
			continue;
		if (MII_OUI(id1, id2) != MII_OUI_xxMARVELL)
			continue;
		sc->phy.no_errprint = false;

		sc->phy.readreg_locked(sc->sc_dev, i, MAKPHY_ESSR, &phyreg);
		phyreg &= ~(ESSR_SER_ANEG_BYPASS | ESSR_HWCFG_MODE);
		phyreg |= ESSR_SGMII_WOC_COPPER;
		sc->phy.writereg_locked(sc->sc_dev, i, MAKPHY_ESSR, phyreg);
		break;
	}

}

/*
 * wm_sgmii_readreg:	[mii interface function]
 *
 *	Read a PHY register on the SGMII
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_sgmii_readreg(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_sgmii_readreg_locked(dev, phy, reg, val);

	sc->phy.release(sc);
	return rv;
}

static int
wm_sgmii_readreg_locked(device_t dev, int phy, int reg, uint16_t *val)
{
	struct wm_softc *sc = device_private(dev);
	uint32_t i2ccmd;
	int i, rv = 0;

	i2ccmd = (reg << I2CCMD_REG_ADDR_SHIFT)
	    | (phy << I2CCMD_PHY_ADDR_SHIFT) | I2CCMD_OPCODE_READ;
	CSR_WRITE(sc, WMREG_I2CCMD, i2ccmd);

	/* Poll the ready bit */
	for (i = 0; i < I2CCMD_PHY_TIMEOUT; i++) {
		delay(50);
		i2ccmd = CSR_READ(sc, WMREG_I2CCMD);
		if (i2ccmd & I2CCMD_READY)
			break;
	}
	if ((i2ccmd & I2CCMD_READY) == 0) {
		device_printf(dev, "I2CCMD Read did not complete\n");
		rv = ETIMEDOUT;
	}
	if ((i2ccmd & I2CCMD_ERROR) != 0) {
		if (!sc->phy.no_errprint)
			device_printf(dev, "I2CCMD Error bit set\n");
		rv = EIO;
	}

	*val = (uint16_t)((i2ccmd >> 8) & 0x00ff) | ((i2ccmd << 8) & 0xff00);

	return rv;
}

/*
 * wm_sgmii_writereg:	[mii interface function]
 *
 *	Write a PHY register on the SGMII.
 * This could be handled by the PHY layer if we didn't have to lock the
 * resource ...
 */
static int
wm_sgmii_writereg(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = wm_sgmii_writereg_locked(dev, phy, reg, val);

	sc->phy.release(sc);

	return rv;
}

static int
wm_sgmii_writereg_locked(device_t dev, int phy, int reg, uint16_t val)
{
	struct wm_softc *sc = device_private(dev);
	uint32_t i2ccmd;
	uint16_t swapdata;
	int rv = 0;
	int i;

	/* Swap the data bytes for the I2C interface */
	swapdata = ((val >> 8) & 0x00FF) | ((val << 8) & 0xFF00);
	i2ccmd = (reg << I2CCMD_REG_ADDR_SHIFT)
	    | (phy << I2CCMD_PHY_ADDR_SHIFT) | I2CCMD_OPCODE_WRITE | swapdata;
	CSR_WRITE(sc, WMREG_I2CCMD, i2ccmd);

	/* Poll the ready bit */
	for (i = 0; i < I2CCMD_PHY_TIMEOUT; i++) {
		delay(50);
		i2ccmd = CSR_READ(sc, WMREG_I2CCMD);
		if (i2ccmd & I2CCMD_READY)
			break;
	}
	if ((i2ccmd & I2CCMD_READY) == 0) {
		device_printf(dev, "I2CCMD Write did not complete\n");
		rv = ETIMEDOUT;
	}
	if ((i2ccmd & I2CCMD_ERROR) != 0) {
		device_printf(dev, "I2CCMD Error bit set\n");
		rv = EIO;
	}

	return rv;
}

/* TBI related */

static bool
wm_tbi_havesignal(struct wm_softc *sc, uint32_t ctrl)
{
	bool sig;

	sig = ctrl & CTRL_SWDPIN(1);

	/*
	 * On 82543 and 82544, the CTRL_SWDPIN(1) bit will be 0 if the optics
	 * detect a signal, 1 if they don't.
	 */
	if ((sc->sc_type == WM_T_82543) || (sc->sc_type == WM_T_82544))
		sig = !sig;

	return sig;
}

/*
 * wm_tbi_mediainit:
 *
 *	Initialize media for use on 1000BASE-X devices.
 */
static void
wm_tbi_mediainit(struct wm_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	const char *sep = "";

	if (sc->sc_type < WM_T_82543)
		sc->sc_tipg = TIPG_WM_DFLT;
	else
		sc->sc_tipg = TIPG_LG_DFLT;

	sc->sc_tbi_serdes_anegticks = 5;

	/* Initialize our media structures */
	sc->sc_mii.mii_ifp = ifp;
	sc->sc_ethercom.ec_mii = &sc->sc_mii;

	ifp->if_baudrate = IF_Gbps(1);
	if (((sc->sc_type >= WM_T_82575) && (sc->sc_type <= WM_T_I211))
	    && (sc->sc_mediatype == WM_MEDIATYPE_SERDES)) {
		ifmedia_init_with_lock(&sc->sc_mii.mii_media, IFM_IMASK,
		    wm_serdes_mediachange, wm_serdes_mediastatus,
		    sc->sc_core_lock);
	} else {
		ifmedia_init_with_lock(&sc->sc_mii.mii_media, IFM_IMASK,
		    wm_tbi_mediachange, wm_tbi_mediastatus, sc->sc_core_lock);
	}

	/*
	 * SWD Pins:
	 *
	 *	0 = Link LED (output)
	 *	1 = Loss Of Signal (input)
	 */
	sc->sc_ctrl |= CTRL_SWDPIO(0);

	/* XXX Perhaps this is only for TBI */
	if (sc->sc_mediatype != WM_MEDIATYPE_SERDES)
		sc->sc_ctrl &= ~CTRL_SWDPIO(1);

	if (sc->sc_mediatype == WM_MEDIATYPE_SERDES)
		sc->sc_ctrl &= ~CTRL_LRST;

	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

#define	ADD(ss, mm, dd)							  \
do {									  \
	aprint_normal("%s%s", sep, ss);					  \
	ifmedia_add(&sc->sc_mii.mii_media, IFM_ETHER | (mm), (dd), NULL); \
	sep = ", ";							  \
} while (/*CONSTCOND*/0)

	aprint_normal_dev(sc->sc_dev, "");

	if (sc->sc_type == WM_T_I354) {
		uint32_t status;

		status = CSR_READ(sc, WMREG_STATUS);
		if (((status & STATUS_2P5_SKU) != 0)
		    && ((status & STATUS_2P5_SKU_OVER) == 0)) {
			ADD("2500baseKX-FDX", IFM_2500_KX | IFM_FDX,ANAR_X_FD);
		} else
			ADD("1000baseKX-FDX", IFM_1000_KX | IFM_FDX,ANAR_X_FD);
	} else if (sc->sc_type == WM_T_82545) {
		/* Only 82545 is LX (XXX except SFP) */
		ADD("1000baseLX", IFM_1000_LX, ANAR_X_HD);
		ADD("1000baseLX-FDX", IFM_1000_LX | IFM_FDX, ANAR_X_FD);
	} else if (sc->sc_sfptype != 0) {
		/* XXX wm(4) fiber/serdes don't use ifm_data */
		switch (sc->sc_sfptype) {
		default:
		case SFF_SFP_ETH_FLAGS_1000SX:
			ADD("1000baseSX", IFM_1000_SX, ANAR_X_HD);
			ADD("1000baseSX-FDX", IFM_1000_SX | IFM_FDX, ANAR_X_FD);
			break;
		case SFF_SFP_ETH_FLAGS_1000LX:
			ADD("1000baseLX", IFM_1000_LX, ANAR_X_HD);
			ADD("1000baseLX-FDX", IFM_1000_LX | IFM_FDX, ANAR_X_FD);
			break;
		case SFF_SFP_ETH_FLAGS_1000CX:
			ADD("1000baseCX", IFM_1000_CX, ANAR_X_HD);
			ADD("1000baseCX-FDX", IFM_1000_CX | IFM_FDX, ANAR_X_FD);
			break;
		case SFF_SFP_ETH_FLAGS_1000T:
			ADD("1000baseT", IFM_1000_T, 0);
			ADD("1000baseT-FDX", IFM_1000_T | IFM_FDX, 0);
			break;
		case SFF_SFP_ETH_FLAGS_100FX:
			ADD("100baseFX", IFM_100_FX, ANAR_TX);
			ADD("100baseFX-FDX", IFM_100_FX | IFM_FDX, ANAR_TX_FD);
			break;
		}
	} else {
		ADD("1000baseSX", IFM_1000_SX, ANAR_X_HD);
		ADD("1000baseSX-FDX", IFM_1000_SX | IFM_FDX, ANAR_X_FD);
	}
	ADD("auto", IFM_AUTO, ANAR_X_FD | ANAR_X_HD);
	aprint_normal("\n");

#undef ADD

	ifmedia_set(&sc->sc_mii.mii_media, IFM_ETHER | IFM_AUTO);
}

/*
 * wm_tbi_mediachange:	[ifmedia interface function]
 *
 *	Set hardware to newly-selected media on a 1000BASE-X device.
 */
static int
wm_tbi_mediachange(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	struct ifmedia_entry *ife = sc->sc_mii.mii_media.ifm_cur;
	uint32_t status, ctrl;
	bool signal;
	int i;

	KASSERT(sc->sc_mediatype != WM_MEDIATYPE_COPPER);
	if (sc->sc_mediatype == WM_MEDIATYPE_SERDES) {
		/* XXX need some work for >= 82571 and < 82575 */
		if (sc->sc_type < WM_T_82575)
			return 0;
	}

	if ((sc->sc_type == WM_T_82571) || (sc->sc_type == WM_T_82572)
	    || (sc->sc_type >= WM_T_82575))
		CSR_WRITE(sc, WMREG_SCTL, SCTL_DISABLE_SERDES_LOOPBACK);

	sc->sc_ctrl &= ~CTRL_LRST;
	sc->sc_txcw = TXCW_ANE;
	if (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO)
		sc->sc_txcw |= TXCW_FD | TXCW_HD;
	else if (ife->ifm_media & IFM_FDX)
		sc->sc_txcw |= TXCW_FD;
	else
		sc->sc_txcw |= TXCW_HD;

	if ((sc->sc_mii.mii_media.ifm_media & IFM_FLOW) != 0)
		sc->sc_txcw |= TXCW_SYM_PAUSE | TXCW_ASYM_PAUSE;

	DPRINTF(sc, WM_DEBUG_LINK,("%s: sc_txcw = 0x%x after autoneg check\n",
		device_xname(sc->sc_dev), sc->sc_txcw));
	CSR_WRITE(sc, WMREG_TXCW, sc->sc_txcw);
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
	CSR_WRITE_FLUSH(sc);
	delay(1000);

	ctrl = CSR_READ(sc, WMREG_CTRL);
	signal = wm_tbi_havesignal(sc, ctrl);

	DPRINTF(sc, WM_DEBUG_LINK,
	    ("%s: signal = %d\n", device_xname(sc->sc_dev), signal));

	if (signal) {
		/* Have signal; wait for the link to come up. */
		for (i = 0; i < WM_LINKUP_TIMEOUT; i++) {
			delay(10000);
			if (CSR_READ(sc, WMREG_STATUS) & STATUS_LU)
				break;
		}

		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: i = %d after waiting for link\n",
			device_xname(sc->sc_dev), i));

		status = CSR_READ(sc, WMREG_STATUS);
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: status after final read = 0x%x, STATUS_LU = %#"
			__PRIxBIT "\n",
			device_xname(sc->sc_dev), status, STATUS_LU));
		if (status & STATUS_LU) {
			/* Link is up. */
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("%s: LINK: set media -> link up %s\n",
				device_xname(sc->sc_dev),
				(status & STATUS_FD) ? "FDX" : "HDX"));

			/*
			 * NOTE: CTRL will update TFCE and RFCE automatically,
			 * so we should update sc->sc_ctrl
			 */
			sc->sc_ctrl = CSR_READ(sc, WMREG_CTRL);
			sc->sc_tctl &= ~TCTL_COLD(0x3ff);
			sc->sc_fcrtl &= ~FCRTL_XONE;
			if (status & STATUS_FD)
				sc->sc_tctl |=
				    TCTL_COLD(TX_COLLISION_DISTANCE_FDX);
			else
				sc->sc_tctl |=
				    TCTL_COLD(TX_COLLISION_DISTANCE_HDX);
			if (CSR_READ(sc, WMREG_CTRL) & CTRL_TFCE)
				sc->sc_fcrtl |= FCRTL_XONE;
			CSR_WRITE(sc, WMREG_TCTL, sc->sc_tctl);
			CSR_WRITE(sc, (sc->sc_type < WM_T_82543) ?
			    WMREG_OLD_FCRTL : WMREG_FCRTL, sc->sc_fcrtl);
			sc->sc_tbi_linkup = 1;
		} else {
			if (i == WM_LINKUP_TIMEOUT)
				wm_check_for_link(sc);
			/* Link is down. */
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("%s: LINK: set media -> link down\n",
				device_xname(sc->sc_dev)));
			sc->sc_tbi_linkup = 0;
		}
	} else {
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: LINK: set media -> no signal\n",
			device_xname(sc->sc_dev)));
		sc->sc_tbi_linkup = 0;
	}

	wm_tbi_serdes_set_linkled(sc);

	return 0;
}

/*
 * wm_tbi_mediastatus:	[ifmedia interface function]
 *
 *	Get the current interface media status on a 1000BASE-X device.
 */
static void
wm_tbi_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct wm_softc *sc = ifp->if_softc;
	uint32_t ctrl, status;

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	status = CSR_READ(sc, WMREG_STATUS);
	if ((status & STATUS_LU) == 0) {
		ifmr->ifm_active |= IFM_NONE;
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;
	/* Only 82545 is LX */
	if (sc->sc_type == WM_T_82545)
		ifmr->ifm_active |= IFM_1000_LX;
	else
		ifmr->ifm_active |= IFM_1000_SX;
	if (CSR_READ(sc, WMREG_STATUS) & STATUS_FD)
		ifmr->ifm_active |= IFM_FDX;
	else
		ifmr->ifm_active |= IFM_HDX;
	ctrl = CSR_READ(sc, WMREG_CTRL);
	if (ctrl & CTRL_RFCE)
		ifmr->ifm_active |= IFM_FLOW | IFM_ETH_RXPAUSE;
	if (ctrl & CTRL_TFCE)
		ifmr->ifm_active |= IFM_FLOW | IFM_ETH_TXPAUSE;
}

/* XXX TBI only */
static int
wm_check_for_link(struct wm_softc *sc)
{
	struct ifmedia_entry *ife = sc->sc_mii.mii_media.ifm_cur;
	uint32_t rxcw;
	uint32_t ctrl;
	uint32_t status;
	bool signal;

	DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_mediatype == WM_MEDIATYPE_SERDES) {
		/* XXX need some work for >= 82571 */
		if (sc->sc_type >= WM_T_82571) {
			sc->sc_tbi_linkup = 1;
			return 0;
		}
	}

	rxcw = CSR_READ(sc, WMREG_RXCW);
	ctrl = CSR_READ(sc, WMREG_CTRL);
	status = CSR_READ(sc, WMREG_STATUS);
	signal = wm_tbi_havesignal(sc, ctrl);

	DPRINTF(sc, WM_DEBUG_LINK,
	    ("%s: %s: signal = %d, status_lu = %d, rxcw_c = %d\n",
		device_xname(sc->sc_dev), __func__, signal,
		((status & STATUS_LU) != 0), ((rxcw & RXCW_C) != 0)));

	/*
	 * SWDPIN   LU RXCW
	 *	0    0	  0
	 *	0    0	  1	(should not happen)
	 *	0    1	  0	(should not happen)
	 *	0    1	  1	(should not happen)
	 *	1    0	  0	Disable autonego and force linkup
	 *	1    0	  1	got /C/ but not linkup yet
	 *	1    1	  0	(linkup)
	 *	1    1	  1	If IFM_AUTO, back to autonego
	 *
	 */
	if (signal && ((status & STATUS_LU) == 0) && ((rxcw & RXCW_C) == 0)) {
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("%s: %s: force linkup and fullduplex\n",
			device_xname(sc->sc_dev), __func__));
		sc->sc_tbi_linkup = 0;
		/* Disable auto-negotiation in the TXCW register */
		CSR_WRITE(sc, WMREG_TXCW, (sc->sc_txcw & ~TXCW_ANE));

		/*
		 * Force link-up and also force full-duplex.
		 *
		 * NOTE: CTRL was updated TFCE and RFCE automatically,
		 * so we should update sc->sc_ctrl
		 */
		sc->sc_ctrl = ctrl | CTRL_SLU | CTRL_FD;
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
	} else if (((status & STATUS_LU) != 0)
	    && ((rxcw & RXCW_C) != 0)
	    && (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO)) {
		sc->sc_tbi_linkup = 1;
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s: go back to autonego\n",
			device_xname(sc->sc_dev), __func__));
		CSR_WRITE(sc, WMREG_TXCW, sc->sc_txcw);
		CSR_WRITE(sc, WMREG_CTRL, (ctrl & ~CTRL_SLU));
	} else if (signal && ((rxcw & RXCW_C) != 0)) {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s: /C/",
			device_xname(sc->sc_dev), __func__));
	} else {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s: linkup %08x,%08x,%08x\n",
			device_xname(sc->sc_dev), __func__, rxcw, ctrl,
			status));
	}

	return 0;
}

/*
 * wm_tbi_tick:
 *
 *	Check the link on TBI devices.
 *	This function acts as mii_tick().
 */
static void
wm_tbi_tick(struct wm_softc *sc)
{
	struct mii_data *mii = &sc->sc_mii;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint32_t status;

	KASSERT(mutex_owned(sc->sc_core_lock));

	status = CSR_READ(sc, WMREG_STATUS);

	/* XXX is this needed? */
	(void)CSR_READ(sc, WMREG_RXCW);
	(void)CSR_READ(sc, WMREG_CTRL);

	/* set link status */
	if ((status & STATUS_LU) == 0) {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: checklink -> down\n",
			device_xname(sc->sc_dev)));
		sc->sc_tbi_linkup = 0;
	} else if (sc->sc_tbi_linkup == 0) {
		DPRINTF(sc, WM_DEBUG_LINK, ("%s: LINK: checklink -> up %s\n",
			device_xname(sc->sc_dev),
			(status & STATUS_FD) ? "FDX" : "HDX"));
		sc->sc_tbi_linkup = 1;
		sc->sc_tbi_serdes_ticks = 0;
	}

	if ((sc->sc_if_flags & IFF_UP) == 0)
		goto setled;

	if ((status & STATUS_LU) == 0) {
		sc->sc_tbi_linkup = 0;
		/* If the timer expired, retry autonegotiation */
		if ((IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO)
		    && (++sc->sc_tbi_serdes_ticks
			>= sc->sc_tbi_serdes_anegticks)) {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s: EXPIRE\n",
				device_xname(sc->sc_dev), __func__));
			sc->sc_tbi_serdes_ticks = 0;
			/*
			 * Reset the link, and let autonegotiation do
			 * its thing
			 */
			sc->sc_ctrl |= CTRL_LRST;
			CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
			CSR_WRITE_FLUSH(sc);
			delay(1000);
			sc->sc_ctrl &= ~CTRL_LRST;
			CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);
			CSR_WRITE_FLUSH(sc);
			delay(1000);
			CSR_WRITE(sc, WMREG_TXCW,
			    sc->sc_txcw & ~TXCW_ANE);
			CSR_WRITE(sc, WMREG_TXCW, sc->sc_txcw);
		}
	}

setled:
	wm_tbi_serdes_set_linkled(sc);
}

/* SERDES related */
static void
wm_serdes_power_up_link_82575(struct wm_softc *sc)
{
	uint32_t reg;

	if ((sc->sc_mediatype != WM_MEDIATYPE_SERDES)
	    && ((sc->sc_flags & WM_F_SGMII) == 0))
		return;

	/* Enable PCS to turn on link */
	reg = CSR_READ(sc, WMREG_PCS_CFG);
	reg |= PCS_CFG_PCS_EN;
	CSR_WRITE(sc, WMREG_PCS_CFG, reg);

	/* Power up the laser */
	reg = CSR_READ(sc, WMREG_CTRL_EXT);
	reg &= ~CTRL_EXT_SWDPIN(3);
	CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

	/* Flush the write to verify completion */
	CSR_WRITE_FLUSH(sc);
	delay(1000);
}

static int
wm_serdes_mediachange(struct ifnet *ifp)
{
	struct wm_softc *sc = ifp->if_softc;
	bool pcs_autoneg = true; /* XXX */
	uint32_t ctrl_ext, pcs_lctl, reg;

	if ((sc->sc_mediatype != WM_MEDIATYPE_SERDES)
	    && ((sc->sc_flags & WM_F_SGMII) == 0))
		return 0;

	/* XXX Currently, this function is not called on 8257[12] */
	if ((sc->sc_type == WM_T_82571) || (sc->sc_type == WM_T_82572)
	    || (sc->sc_type >= WM_T_82575))
		CSR_WRITE(sc, WMREG_SCTL, SCTL_DISABLE_SERDES_LOOPBACK);

	/* Power on the sfp cage if present */
	ctrl_ext = CSR_READ(sc, WMREG_CTRL_EXT);
	ctrl_ext &= ~CTRL_EXT_SWDPIN(3);
	ctrl_ext |= CTRL_EXT_I2C_ENA;
	CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext);

	sc->sc_ctrl |= CTRL_SLU;

	if ((sc->sc_type == WM_T_82575) || (sc->sc_type == WM_T_82576)) {
		sc->sc_ctrl |= CTRL_SWDPIN(0) | CTRL_SWDPIN(1);

		reg = CSR_READ(sc, WMREG_CONNSW);
		reg |= CONNSW_ENRGSRC;
		CSR_WRITE(sc, WMREG_CONNSW, reg);
	}

	pcs_lctl = CSR_READ(sc, WMREG_PCS_LCTL);
	switch (ctrl_ext & CTRL_EXT_LINK_MODE_MASK) {
	case CTRL_EXT_LINK_MODE_SGMII:
		/* SGMII mode lets the phy handle forcing speed/duplex */
		pcs_autoneg = true;
		/* Autoneg time out should be disabled for SGMII mode */
		pcs_lctl &= ~PCS_LCTL_AN_TIMEOUT;
		break;
	case CTRL_EXT_LINK_MODE_1000KX:
		pcs_autoneg = false;
		/* FALLTHROUGH */
	default:
		if ((sc->sc_type == WM_T_82575)
		    || (sc->sc_type == WM_T_82576)) {
			if ((sc->sc_flags & WM_F_PCS_DIS_AUTONEGO) != 0)
				pcs_autoneg = false;
		}
		sc->sc_ctrl |= CTRL_SPEED_1000 | CTRL_FRCSPD | CTRL_FD
		    | CTRL_FRCFDX;

		/* Set speed of 1000/Full if speed/duplex is forced */
		pcs_lctl |= PCS_LCTL_FSV_1000 | PCS_LCTL_FDV_FULL;
	}
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl);

	pcs_lctl &= ~(PCS_LCTL_AN_ENABLE | PCS_LCTL_FLV_LINK_UP |
	    PCS_LCTL_FSD | PCS_LCTL_FORCE_LINK);

	if (pcs_autoneg) {
		/* Set PCS register for autoneg */
		pcs_lctl |= PCS_LCTL_AN_ENABLE | PCS_LCTL_AN_RESTART;

		/* Disable force flow control for autoneg */
		pcs_lctl &= ~PCS_LCTL_FORCE_FC;

		/* Configure flow control advertisement for autoneg */
		reg = CSR_READ(sc, WMREG_PCS_ANADV);
		reg &= ~(TXCW_ASYM_PAUSE | TXCW_SYM_PAUSE);
		reg |= TXCW_ASYM_PAUSE | TXCW_SYM_PAUSE;
		CSR_WRITE(sc, WMREG_PCS_ANADV, reg);
	} else
		pcs_lctl |= PCS_LCTL_FSD | PCS_LCTL_FORCE_FC;

	CSR_WRITE(sc, WMREG_PCS_LCTL, pcs_lctl);

	return 0;
}

static void
wm_serdes_mediastatus(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct wm_softc *sc = ifp->if_softc;
	struct mii_data *mii = &sc->sc_mii;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint32_t pcs_adv, pcs_lpab, reg;

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	/* Check PCS */
	reg = CSR_READ(sc, WMREG_PCS_LSTS);
	if ((reg & PCS_LSTS_LINKOK) == 0) {
		ifmr->ifm_active |= IFM_NONE;
		sc->sc_tbi_linkup = 0;
		goto setled;
	}

	sc->sc_tbi_linkup = 1;
	ifmr->ifm_status |= IFM_ACTIVE;
	if (sc->sc_type == WM_T_I354) {
		uint32_t status;

		status = CSR_READ(sc, WMREG_STATUS);
		if (((status & STATUS_2P5_SKU) != 0)
		    && ((status & STATUS_2P5_SKU_OVER) == 0)) {
			ifmr->ifm_active |= IFM_2500_KX;
		} else
			ifmr->ifm_active |= IFM_1000_KX;
	} else {
		switch (__SHIFTOUT(reg, PCS_LSTS_SPEED)) {
		case PCS_LSTS_SPEED_10:
			ifmr->ifm_active |= IFM_10_T; /* XXX */
			break;
		case PCS_LSTS_SPEED_100:
			ifmr->ifm_active |= IFM_100_FX; /* XXX */
			break;
		case PCS_LSTS_SPEED_1000:
			ifmr->ifm_active |= IFM_1000_SX; /* XXX */
			break;
		default:
			device_printf(sc->sc_dev, "Unknown speed\n");
			ifmr->ifm_active |= IFM_1000_SX; /* XXX */
			break;
		}
	}
	ifp->if_baudrate = ifmedia_baudrate(ifmr->ifm_active);
	if ((reg & PCS_LSTS_FDX) != 0)
		ifmr->ifm_active |= IFM_FDX;
	else
		ifmr->ifm_active |= IFM_HDX;
	mii->mii_media_active &= ~IFM_ETH_FMASK;
	if (IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO) {
		/* Check flow */
		reg = CSR_READ(sc, WMREG_PCS_LSTS);
		if ((reg & PCS_LSTS_AN_COMP) == 0) {
			DPRINTF(sc, WM_DEBUG_LINK,
			    ("XXX LINKOK but not ACOMP\n"));
			goto setled;
		}
		pcs_adv = CSR_READ(sc, WMREG_PCS_ANADV);
		pcs_lpab = CSR_READ(sc, WMREG_PCS_LPAB);
		DPRINTF(sc, WM_DEBUG_LINK,
		    ("XXX AN result(2) %08x, %08x\n", pcs_adv, pcs_lpab));
		if ((pcs_adv & TXCW_SYM_PAUSE)
		    && (pcs_lpab & TXCW_SYM_PAUSE)) {
			mii->mii_media_active |= IFM_FLOW
			    | IFM_ETH_TXPAUSE | IFM_ETH_RXPAUSE;
		} else if (((pcs_adv & TXCW_SYM_PAUSE) == 0)
		    && (pcs_adv & TXCW_ASYM_PAUSE)
		    && (pcs_lpab & TXCW_SYM_PAUSE)
		    && (pcs_lpab & TXCW_ASYM_PAUSE)) {
			mii->mii_media_active |= IFM_FLOW
			    | IFM_ETH_TXPAUSE;
		} else if ((pcs_adv & TXCW_SYM_PAUSE)
		    && (pcs_adv & TXCW_ASYM_PAUSE)
		    && ((pcs_lpab & TXCW_SYM_PAUSE) == 0)
		    && (pcs_lpab & TXCW_ASYM_PAUSE)) {
			mii->mii_media_active |= IFM_FLOW
			    | IFM_ETH_RXPAUSE;
		}
	}
	ifmr->ifm_active = (ifmr->ifm_active & ~IFM_ETH_FMASK)
	    | (mii->mii_media_active & IFM_ETH_FMASK);
setled:
	wm_tbi_serdes_set_linkled(sc);
}

/*
 * wm_serdes_tick:
 *
 *	Check the link on serdes devices.
 */
static void
wm_serdes_tick(struct wm_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	struct mii_data *mii = &sc->sc_mii;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	uint32_t reg;

	KASSERT(mutex_owned(sc->sc_core_lock));

	mii->mii_media_status = IFM_AVALID;
	mii->mii_media_active = IFM_ETHER;

	/* Check PCS */
	reg = CSR_READ(sc, WMREG_PCS_LSTS);
	if ((reg & PCS_LSTS_LINKOK) != 0) {
		mii->mii_media_status |= IFM_ACTIVE;
		sc->sc_tbi_linkup = 1;
		sc->sc_tbi_serdes_ticks = 0;
		mii->mii_media_active |= IFM_1000_SX; /* XXX */
		if ((reg & PCS_LSTS_FDX) != 0)
			mii->mii_media_active |= IFM_FDX;
		else
			mii->mii_media_active |= IFM_HDX;
	} else {
		mii->mii_media_status |= IFM_NONE;
		sc->sc_tbi_linkup = 0;
		/* If the timer expired, retry autonegotiation */
		if ((IFM_SUBTYPE(ife->ifm_media) == IFM_AUTO)
		    && (++sc->sc_tbi_serdes_ticks
			>= sc->sc_tbi_serdes_anegticks)) {
			DPRINTF(sc, WM_DEBUG_LINK, ("%s: %s: EXPIRE\n",
				device_xname(sc->sc_dev), __func__));
			sc->sc_tbi_serdes_ticks = 0;
			/* XXX */
			wm_serdes_mediachange(ifp);
		}
	}

	wm_tbi_serdes_set_linkled(sc);
}

/* SFP related */

static int
wm_sfp_read_data_byte(struct wm_softc *sc, uint16_t offset, uint8_t *data)
{
	uint32_t i2ccmd;
	int i;

	i2ccmd = (offset << I2CCMD_REG_ADDR_SHIFT) | I2CCMD_OPCODE_READ;
	CSR_WRITE(sc, WMREG_I2CCMD, i2ccmd);

	/* Poll the ready bit */
	for (i = 0; i < I2CCMD_PHY_TIMEOUT; i++) {
		delay(50);
		i2ccmd = CSR_READ(sc, WMREG_I2CCMD);
		if (i2ccmd & I2CCMD_READY)
			break;
	}
	if ((i2ccmd & I2CCMD_READY) == 0)
		return -1;
	if ((i2ccmd & I2CCMD_ERROR) != 0)
		return -1;

	*data = i2ccmd & 0x00ff;

	return 0;
}

static uint32_t
wm_sfp_get_media_type(struct wm_softc *sc)
{
	uint32_t ctrl_ext;
	uint8_t val = 0;
	int timeout = 3;
	uint32_t mediatype = WM_MEDIATYPE_UNKNOWN;
	int rv = -1;

	ctrl_ext = CSR_READ(sc, WMREG_CTRL_EXT);
	ctrl_ext &= ~CTRL_EXT_SWDPIN(3);
	CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext | CTRL_EXT_I2C_ENA);
	CSR_WRITE_FLUSH(sc);

	/* Read SFP module data */
	while (timeout) {
		rv = wm_sfp_read_data_byte(sc, SFF_SFP_ID_OFF, &val);
		if (rv == 0)
			break;
		delay(100*1000); /* XXX too big */
		timeout--;
	}
	if (rv != 0)
		goto out;

	switch (val) {
	case SFF_SFP_ID_SFF:
		aprint_normal_dev(sc->sc_dev,
		    "Module/Connector soldered to board\n");
		break;
	case SFF_SFP_ID_SFP:
		sc->sc_flags |= WM_F_SFP;
		break;
	case SFF_SFP_ID_UNKNOWN:
		goto out;
	default:
		break;
	}

	rv = wm_sfp_read_data_byte(sc, SFF_SFP_ETH_FLAGS_OFF, &val);
	if (rv != 0)
		goto out;

	sc->sc_sfptype = val;
	if ((val & (SFF_SFP_ETH_FLAGS_1000SX | SFF_SFP_ETH_FLAGS_1000LX)) != 0)
		mediatype = WM_MEDIATYPE_SERDES;
	else if ((val & SFF_SFP_ETH_FLAGS_1000T) != 0) {
		sc->sc_flags |= WM_F_SGMII;
		mediatype = WM_MEDIATYPE_COPPER;
	} else if ((val & SFF_SFP_ETH_FLAGS_100FX) != 0) {
		sc->sc_flags |= WM_F_SGMII;
		mediatype = WM_MEDIATYPE_SERDES;
	} else {
		device_printf(sc->sc_dev, "%s: unknown media type? (0x%hhx)\n",
		    __func__, sc->sc_sfptype);
		sc->sc_sfptype = 0; /* XXX unknown */
	}

out:
	/* Restore I2C interface setting */
	CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext);

	return mediatype;
}

/*
 * NVM related.
 * Microwire, SPI (w/wo EERD) and Flash.
 */

/* Both spi and uwire */

/*
 * wm_eeprom_sendbits:
 *
 *	Send a series of bits to the EEPROM.
 */
static void
wm_eeprom_sendbits(struct wm_softc *sc, uint32_t bits, int nbits)
{
	uint32_t reg;
	int x;

	reg = CSR_READ(sc, WMREG_EECD);

	for (x = nbits; x > 0; x--) {
		if (bits & (1U << (x - 1)))
			reg |= EECD_DI;
		else
			reg &= ~EECD_DI;
		CSR_WRITE(sc, WMREG_EECD, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2);
		CSR_WRITE(sc, WMREG_EECD, reg | EECD_SK);
		CSR_WRITE_FLUSH(sc);
		delay(2);
		CSR_WRITE(sc, WMREG_EECD, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2);
	}
}

/*
 * wm_eeprom_recvbits:
 *
 *	Receive a series of bits from the EEPROM.
 */
static void
wm_eeprom_recvbits(struct wm_softc *sc, uint32_t *valp, int nbits)
{
	uint32_t reg, val;
	int x;

	reg = CSR_READ(sc, WMREG_EECD) & ~EECD_DI;

	val = 0;
	for (x = nbits; x > 0; x--) {
		CSR_WRITE(sc, WMREG_EECD, reg | EECD_SK);
		CSR_WRITE_FLUSH(sc);
		delay(2);
		if (CSR_READ(sc, WMREG_EECD) & EECD_DO)
			val |= (1U << (x - 1));
		CSR_WRITE(sc, WMREG_EECD, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2);
	}
	*valp = val;
}

/* Microwire */

/*
 * wm_nvm_read_uwire:
 *
 *	Read a word from the EEPROM using the MicroWire protocol.
 */
static int
wm_nvm_read_uwire(struct wm_softc *sc, int word, int wordcnt, uint16_t *data)
{
	uint32_t reg, val;
	int i, rv;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	for (i = 0; i < wordcnt; i++) {
		/* Clear SK and DI. */
		reg = CSR_READ(sc, WMREG_EECD) & ~(EECD_SK | EECD_DI);
		CSR_WRITE(sc, WMREG_EECD, reg);

		/*
		 * XXX: workaround for a bug in qemu-0.12.x and prior
		 * and Xen.
		 *
		 * We use this workaround only for 82540 because qemu's
		 * e1000 act as 82540.
		 */
		if (sc->sc_type == WM_T_82540) {
			reg |= EECD_SK;
			CSR_WRITE(sc, WMREG_EECD, reg);
			reg &= ~EECD_SK;
			CSR_WRITE(sc, WMREG_EECD, reg);
			CSR_WRITE_FLUSH(sc);
			delay(2);
		}
		/* XXX: end of workaround */

		/* Set CHIP SELECT. */
		reg |= EECD_CS;
		CSR_WRITE(sc, WMREG_EECD, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2);

		/* Shift in the READ command. */
		wm_eeprom_sendbits(sc, UWIRE_OPC_READ, 3);

		/* Shift in address. */
		wm_eeprom_sendbits(sc, word + i, sc->sc_nvm_addrbits);

		/* Shift out the data. */
		wm_eeprom_recvbits(sc, &val, 16);
		data[i] = val & 0xffff;

		/* Clear CHIP SELECT. */
		reg = CSR_READ(sc, WMREG_EECD) & ~EECD_CS;
		CSR_WRITE(sc, WMREG_EECD, reg);
		CSR_WRITE_FLUSH(sc);
		delay(2);
	}

	sc->nvm.release(sc);
	return 0;
}

/* SPI */

/*
 * Set SPI and FLASH related information from the EECD register.
 * For 82541 and 82547, the word size is taken from EEPROM.
 */
static int
wm_nvm_set_addrbits_size_eecd(struct wm_softc *sc)
{
	int size;
	uint32_t reg;
	uint16_t data;

	reg = CSR_READ(sc, WMREG_EECD);
	sc->sc_nvm_addrbits = (reg & EECD_EE_ABITS) ? 16 : 8;

	/* Read the size of NVM from EECD by default */
	size = __SHIFTOUT(reg, EECD_EE_SIZE_EX_MASK);
	switch (sc->sc_type) {
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
		/* Set dummy value to access EEPROM */
		sc->sc_nvm_wordsize = 64;
		if (wm_nvm_read(sc, NVM_OFF_EEPROM_SIZE, 1, &data) != 0) {
			aprint_error_dev(sc->sc_dev,
			    "%s: failed to read EEPROM size\n", __func__);
		}
		reg = data;
		size = __SHIFTOUT(reg, EECD_EE_SIZE_EX_MASK);
		if (size == 0)
			size = 6; /* 64 word size */
		else
			size += NVM_WORD_SIZE_BASE_SHIFT + 1;
		break;
	case WM_T_80003:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573: /* SPI case */
	case WM_T_82574: /* SPI case */
	case WM_T_82583: /* SPI case */
		size += NVM_WORD_SIZE_BASE_SHIFT;
		if (size > 14)
			size = 14;
		break;
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
	case WM_T_I210:
	case WM_T_I211:
		size += NVM_WORD_SIZE_BASE_SHIFT;
		if (size > 15)
			size = 15;
		break;
	default:
		aprint_error_dev(sc->sc_dev,
		    "%s: unknown device(%d)?\n", __func__, sc->sc_type);
		return -1;
		break;
	}

	sc->sc_nvm_wordsize = 1 << size;

	return 0;
}

/*
 * wm_nvm_ready_spi:
 *
 *	Wait for a SPI EEPROM to be ready for commands.
 */
static int
wm_nvm_ready_spi(struct wm_softc *sc)
{
	uint32_t val;
	int usec;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	for (usec = 0; usec < SPI_MAX_RETRIES; delay(5), usec += 5) {
		wm_eeprom_sendbits(sc, SPI_OPC_RDSR, 8);
		wm_eeprom_recvbits(sc, &val, 8);
		if ((val & SPI_SR_RDY) == 0)
			break;
	}
	if (usec >= SPI_MAX_RETRIES) {
		aprint_error_dev(sc->sc_dev,"EEPROM failed to become ready\n");
		return -1;
	}
	return 0;
}

/*
 * wm_nvm_read_spi:
 *
 *	Read a work from the EEPROM using the SPI protocol.
 */
static int
wm_nvm_read_spi(struct wm_softc *sc, int word, int wordcnt, uint16_t *data)
{
	uint32_t reg, val;
	int i;
	uint8_t opc;
	int rv;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	/* Clear SK and CS. */
	reg = CSR_READ(sc, WMREG_EECD) & ~(EECD_SK | EECD_CS);
	CSR_WRITE(sc, WMREG_EECD, reg);
	CSR_WRITE_FLUSH(sc);
	delay(2);

	if ((rv = wm_nvm_ready_spi(sc)) != 0)
		goto out;

	/* Toggle CS to flush commands. */
	CSR_WRITE(sc, WMREG_EECD, reg | EECD_CS);
	CSR_WRITE_FLUSH(sc);
	delay(2);
	CSR_WRITE(sc, WMREG_EECD, reg);
	CSR_WRITE_FLUSH(sc);
	delay(2);

	opc = SPI_OPC_READ;
	if (sc->sc_nvm_addrbits == 8 && word >= 128)
		opc |= SPI_OPC_A8;

	wm_eeprom_sendbits(sc, opc, 8);
	wm_eeprom_sendbits(sc, word << 1, sc->sc_nvm_addrbits);

	for (i = 0; i < wordcnt; i++) {
		wm_eeprom_recvbits(sc, &val, 16);
		data[i] = ((val >> 8) & 0xff) | ((val & 0xff) << 8);
	}

	/* Raise CS and clear SK. */
	reg = (CSR_READ(sc, WMREG_EECD) & ~EECD_SK) | EECD_CS;
	CSR_WRITE(sc, WMREG_EECD, reg);
	CSR_WRITE_FLUSH(sc);
	delay(2);

out:
	sc->nvm.release(sc);
	return rv;
}

/* Using with EERD */

static int
wm_poll_eerd_eewr_done(struct wm_softc *sc, int rw)
{
	uint32_t attempts = 100000;
	uint32_t i, reg = 0;
	int32_t done = -1;

	for (i = 0; i < attempts; i++) {
		reg = CSR_READ(sc, rw);

		if (reg & EERD_DONE) {
			done = 0;
			break;
		}
		delay(5);
	}

	return done;
}

static int
wm_nvm_read_eerd(struct wm_softc *sc, int offset, int wordcnt, uint16_t *data)
{
	int i, eerd = 0;
	int rv;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	for (i = 0; i < wordcnt; i++) {
		eerd = ((offset + i) << EERD_ADDR_SHIFT) | EERD_START;
		CSR_WRITE(sc, WMREG_EERD, eerd);
		rv = wm_poll_eerd_eewr_done(sc, WMREG_EERD);
		if (rv != 0) {
			aprint_error_dev(sc->sc_dev, "EERD polling failed: "
			    "offset=%d. wordcnt=%d\n", offset, wordcnt);
			break;
		}
		data[i] = (CSR_READ(sc, WMREG_EERD) >> EERD_DATA_SHIFT);
	}

	sc->nvm.release(sc);
	return rv;
}

/* Flash */

static int
wm_nvm_valid_bank_detect_ich8lan(struct wm_softc *sc, unsigned int *bank)
{
	uint32_t eecd;
	uint32_t act_offset = ICH_NVM_SIG_WORD * 2 + 1;
	uint32_t bank1_offset = sc->sc_ich8_flash_bank_size * sizeof(uint16_t);
	uint32_t nvm_dword = 0;
	uint8_t sig_byte = 0;
	int rv;

	switch (sc->sc_type) {
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		bank1_offset = sc->sc_ich8_flash_bank_size * 2;
		act_offset = ICH_NVM_SIG_WORD * 2;

		/* Set bank to 0 in case flash read fails. */
		*bank = 0;

		/* Check bank 0 */
		rv = wm_read_ich8_dword(sc, act_offset, &nvm_dword);
		if (rv != 0)
			return rv;
		sig_byte = (uint8_t)((nvm_dword & 0xFF00) >> 8);
		if ((sig_byte & ICH_NVM_VALID_SIG_MASK) == ICH_NVM_SIG_VALUE) {
			*bank = 0;
			return 0;
		}

		/* Check bank 1 */
		rv = wm_read_ich8_dword(sc, act_offset + bank1_offset,
		    &nvm_dword);
		sig_byte = (uint8_t)((nvm_dword & 0xFF00) >> 8);
		if ((sig_byte & ICH_NVM_VALID_SIG_MASK) == ICH_NVM_SIG_VALUE) {
			*bank = 1;
			return 0;
		}
		aprint_error_dev(sc->sc_dev,
		    "%s: no valid NVM bank present (%u)\n", __func__, *bank);
		return -1;
	case WM_T_ICH8:
	case WM_T_ICH9:
		eecd = CSR_READ(sc, WMREG_EECD);
		if ((eecd & EECD_SEC1VAL_VALMASK) == EECD_SEC1VAL_VALMASK) {
			*bank = ((eecd & EECD_SEC1VAL) != 0) ? 1 : 0;
			return 0;
		}
		/* FALLTHROUGH */
	default:
		/* Default to 0 */
		*bank = 0;

		/* Check bank 0 */
		wm_read_ich8_byte(sc, act_offset, &sig_byte);
		if ((sig_byte & ICH_NVM_VALID_SIG_MASK) == ICH_NVM_SIG_VALUE) {
			*bank = 0;
			return 0;
		}

		/* Check bank 1 */
		wm_read_ich8_byte(sc, act_offset + bank1_offset,
		    &sig_byte);
		if ((sig_byte & ICH_NVM_VALID_SIG_MASK) == ICH_NVM_SIG_VALUE) {
			*bank = 1;
			return 0;
		}
	}

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: No valid NVM bank present\n",
		device_xname(sc->sc_dev)));
	return -1;
}

/******************************************************************************
 * This function does initial flash setup so that a new read/write/erase cycle
 * can be started.
 *
 * sc - The pointer to the hw structure
 ****************************************************************************/
static int32_t
wm_ich8_cycle_init(struct wm_softc *sc)
{
	uint16_t hsfsts;
	int32_t error = 1;
	int32_t i     = 0;

	if (sc->sc_type >= WM_T_PCH_SPT)
		hsfsts = ICH8_FLASH_READ32(sc, ICH_FLASH_HSFSTS) & 0xffffUL;
	else
		hsfsts = ICH8_FLASH_READ16(sc, ICH_FLASH_HSFSTS);

	/* May be check the Flash Des Valid bit in Hw status */
	if ((hsfsts & HSFSTS_FLDVAL) == 0)
		return error;

	/* Clear FCERR in Hw status by writing 1 */
	/* Clear DAEL in Hw status by writing a 1 */
	hsfsts |= HSFSTS_ERR | HSFSTS_DAEL;

	if (sc->sc_type >= WM_T_PCH_SPT)
		ICH8_FLASH_WRITE32(sc, ICH_FLASH_HSFSTS, hsfsts & 0xffffUL);
	else
		ICH8_FLASH_WRITE16(sc, ICH_FLASH_HSFSTS, hsfsts);

	/*
	 * Either we should have a hardware SPI cycle in progress bit to check
	 * against, in order to start a new cycle or FDONE bit should be
	 * changed in the hardware so that it is 1 after hardware reset, which
	 * can then be used as an indication whether a cycle is in progress or
	 * has been completed .. we should also have some software semaphore
	 * mechanism to guard FDONE or the cycle in progress bit so that two
	 * threads access to those bits can be sequentiallized or a way so that
	 * 2 threads don't start the cycle at the same time
	 */

	if ((hsfsts & HSFSTS_FLINPRO) == 0) {
		/*
		 * There is no cycle running at present, so we can start a
		 * cycle
		 */

		/* Begin by setting Flash Cycle Done. */
		hsfsts |= HSFSTS_DONE;
		if (sc->sc_type >= WM_T_PCH_SPT)
			ICH8_FLASH_WRITE32(sc, ICH_FLASH_HSFSTS,
			    hsfsts & 0xffffUL);
		else
			ICH8_FLASH_WRITE16(sc, ICH_FLASH_HSFSTS, hsfsts);
		error = 0;
	} else {
		/*
		 * Otherwise poll for sometime so the current cycle has a
		 * chance to end before giving up.
		 */
		for (i = 0; i < ICH_FLASH_COMMAND_TIMEOUT; i++) {
			if (sc->sc_type >= WM_T_PCH_SPT)
				hsfsts = ICH8_FLASH_READ32(sc,
				    ICH_FLASH_HSFSTS) & 0xffffUL;
			else
				hsfsts = ICH8_FLASH_READ16(sc,
				    ICH_FLASH_HSFSTS);
			if ((hsfsts & HSFSTS_FLINPRO) == 0) {
				error = 0;
				break;
			}
			delay(1);
		}
		if (error == 0) {
			/*
			 * Successful in waiting for previous cycle to timeout,
			 * now set the Flash Cycle Done.
			 */
			hsfsts |= HSFSTS_DONE;
			if (sc->sc_type >= WM_T_PCH_SPT)
				ICH8_FLASH_WRITE32(sc, ICH_FLASH_HSFSTS,
				    hsfsts & 0xffffUL);
			else
				ICH8_FLASH_WRITE16(sc, ICH_FLASH_HSFSTS,
				    hsfsts);
		}
	}
	return error;
}

/******************************************************************************
 * This function starts a flash cycle and waits for its completion
 *
 * sc - The pointer to the hw structure
 ****************************************************************************/
static int32_t
wm_ich8_flash_cycle(struct wm_softc *sc, uint32_t timeout)
{
	uint16_t hsflctl;
	uint16_t hsfsts;
	int32_t error = 1;
	uint32_t i = 0;

	/* Start a cycle by writing 1 in Flash Cycle Go in Hw Flash Control */
	if (sc->sc_type >= WM_T_PCH_SPT)
		hsflctl = ICH8_FLASH_READ32(sc, ICH_FLASH_HSFSTS) >> 16;
	else
		hsflctl = ICH8_FLASH_READ16(sc, ICH_FLASH_HSFCTL);
	hsflctl |= HSFCTL_GO;
	if (sc->sc_type >= WM_T_PCH_SPT)
		ICH8_FLASH_WRITE32(sc, ICH_FLASH_HSFSTS,
		    (uint32_t)hsflctl << 16);
	else
		ICH8_FLASH_WRITE16(sc, ICH_FLASH_HSFCTL, hsflctl);

	/* Wait till FDONE bit is set to 1 */
	do {
		if (sc->sc_type >= WM_T_PCH_SPT)
			hsfsts = ICH8_FLASH_READ32(sc, ICH_FLASH_HSFSTS)
			    & 0xffffUL;
		else
			hsfsts = ICH8_FLASH_READ16(sc, ICH_FLASH_HSFSTS);
		if (hsfsts & HSFSTS_DONE)
			break;
		delay(1);
		i++;
	} while (i < timeout);
	if ((hsfsts & HSFSTS_DONE) == 1 && (hsfsts & HSFSTS_ERR) == 0)
		error = 0;

	return error;
}

/******************************************************************************
 * Reads a byte or (d)word from the NVM using the ICH8 flash access registers.
 *
 * sc - The pointer to the hw structure
 * index - The index of the byte or word to read.
 * size - Size of data to read, 1=byte 2=word, 4=dword
 * data - Pointer to the word to store the value read.
 *****************************************************************************/
static int32_t
wm_read_ich8_data(struct wm_softc *sc, uint32_t index,
    uint32_t size, uint32_t *data)
{
	uint16_t hsfsts;
	uint16_t hsflctl;
	uint32_t flash_linear_address;
	uint32_t flash_data = 0;
	int32_t error = 1;
	int32_t count = 0;

	if (size < 1  || size > 4 || data == 0x0 ||
	    index > ICH_FLASH_LINEAR_ADDR_MASK)
		return error;

	flash_linear_address = (ICH_FLASH_LINEAR_ADDR_MASK & index) +
	    sc->sc_ich8_flash_base;

	do {
		delay(1);
		/* Steps */
		error = wm_ich8_cycle_init(sc);
		if (error)
			break;

		if (sc->sc_type >= WM_T_PCH_SPT)
			hsflctl = ICH8_FLASH_READ32(sc, ICH_FLASH_HSFSTS)
			    >> 16;
		else
			hsflctl = ICH8_FLASH_READ16(sc, ICH_FLASH_HSFCTL);
		/* 0b/1b corresponds to 1 or 2 byte size, respectively. */
		hsflctl |=  ((size - 1) << HSFCTL_BCOUNT_SHIFT)
		    & HSFCTL_BCOUNT_MASK;
		hsflctl |= ICH_CYCLE_READ << HSFCTL_CYCLE_SHIFT;
		if (sc->sc_type >= WM_T_PCH_SPT) {
			/*
			 * In SPT, This register is in Lan memory space, not
			 * flash. Therefore, only 32 bit access is supported.
			 */
			ICH8_FLASH_WRITE32(sc, ICH_FLASH_HSFSTS,
			    (uint32_t)hsflctl << 16);
		} else
			ICH8_FLASH_WRITE16(sc, ICH_FLASH_HSFCTL, hsflctl);

		/*
		 * Write the last 24 bits of index into Flash Linear address
		 * field in Flash Address
		 */
		/* TODO: TBD maybe check the index against the size of flash */

		ICH8_FLASH_WRITE32(sc, ICH_FLASH_FADDR, flash_linear_address);

		error = wm_ich8_flash_cycle(sc, ICH_FLASH_COMMAND_TIMEOUT);

		/*
		 * Check if FCERR is set to 1, if set to 1, clear it and try
		 * the whole sequence a few more times, else read in (shift in)
		 * the Flash Data0, the order is least significant byte first
		 * msb to lsb
		 */
		if (error == 0) {
			flash_data = ICH8_FLASH_READ32(sc, ICH_FLASH_FDATA0);
			if (size == 1)
				*data = (uint8_t)(flash_data & 0x000000FF);
			else if (size == 2)
				*data = (uint16_t)(flash_data & 0x0000FFFF);
			else if (size == 4)
				*data = (uint32_t)flash_data;
			break;
		} else {
			/*
			 * If we've gotten here, then things are probably
			 * completely hosed, but if the error condition is
			 * detected, it won't hurt to give it another try...
			 * ICH_FLASH_CYCLE_REPEAT_COUNT times.
			 */
			if (sc->sc_type >= WM_T_PCH_SPT)
				hsfsts = ICH8_FLASH_READ32(sc,
				    ICH_FLASH_HSFSTS) & 0xffffUL;
			else
				hsfsts = ICH8_FLASH_READ16(sc,
				    ICH_FLASH_HSFSTS);

			if (hsfsts & HSFSTS_ERR) {
				/* Repeat for some time before giving up. */
				continue;
			} else if ((hsfsts & HSFSTS_DONE) == 0)
				break;
		}
	} while (count++ < ICH_FLASH_CYCLE_REPEAT_COUNT);

	return error;
}

/******************************************************************************
 * Reads a single byte from the NVM using the ICH8 flash access registers.
 *
 * sc - pointer to wm_hw structure
 * index - The index of the byte to read.
 * data - Pointer to a byte to store the value read.
 *****************************************************************************/
static int32_t
wm_read_ich8_byte(struct wm_softc *sc, uint32_t index, uint8_t* data)
{
	int32_t status;
	uint32_t word = 0;

	status = wm_read_ich8_data(sc, index, 1, &word);
	if (status == 0)
		*data = (uint8_t)word;
	else
		*data = 0;

	return status;
}

/******************************************************************************
 * Reads a word from the NVM using the ICH8 flash access registers.
 *
 * sc - pointer to wm_hw structure
 * index - The starting byte index of the word to read.
 * data - Pointer to a word to store the value read.
 *****************************************************************************/
static int32_t
wm_read_ich8_word(struct wm_softc *sc, uint32_t index, uint16_t *data)
{
	int32_t status;
	uint32_t word = 0;

	status = wm_read_ich8_data(sc, index, 2, &word);
	if (status == 0)
		*data = (uint16_t)word;
	else
		*data = 0;

	return status;
}

/******************************************************************************
 * Reads a dword from the NVM using the ICH8 flash access registers.
 *
 * sc - pointer to wm_hw structure
 * index - The starting byte index of the word to read.
 * data - Pointer to a word to store the value read.
 *****************************************************************************/
static int32_t
wm_read_ich8_dword(struct wm_softc *sc, uint32_t index, uint32_t *data)
{
	int32_t status;

	status = wm_read_ich8_data(sc, index, 4, data);
	return status;
}

/******************************************************************************
 * Reads a 16 bit word or words from the EEPROM using the ICH8's flash access
 * register.
 *
 * sc - Struct containing variables accessed by shared code
 * offset - offset of word in the EEPROM to read
 * data - word read from the EEPROM
 * words - number of words to read
 *****************************************************************************/
static int
wm_nvm_read_ich8(struct wm_softc *sc, int offset, int words, uint16_t *data)
{
	int rv;
	uint32_t flash_bank = 0;
	uint32_t act_offset = 0;
	uint32_t bank_offset = 0;
	uint16_t word = 0;
	uint16_t i = 0;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	/*
	 * We need to know which is the valid flash bank.  In the event
	 * that we didn't allocate eeprom_shadow_ram, we may not be
	 * managing flash_bank. So it cannot be trusted and needs
	 * to be updated with each read.
	 */
	rv = wm_nvm_valid_bank_detect_ich8lan(sc, &flash_bank);
	if (rv) {
		DPRINTF(sc, WM_DEBUG_NVM, ("%s: failed to detect NVM bank\n",
			device_xname(sc->sc_dev)));
		flash_bank = 0;
	}

	/*
	 * Adjust offset appropriately if we're on bank 1 - adjust for word
	 * size
	 */
	bank_offset = flash_bank * (sc->sc_ich8_flash_bank_size * 2);

	for (i = 0; i < words; i++) {
		/* The NVM part needs a byte offset, hence * 2 */
		act_offset = bank_offset + ((offset + i) * 2);
		rv = wm_read_ich8_word(sc, act_offset, &word);
		if (rv) {
			aprint_error_dev(sc->sc_dev,
			    "%s: failed to read NVM\n", __func__);
			break;
		}
		data[i] = word;
	}

	sc->nvm.release(sc);
	return rv;
}

/******************************************************************************
 * Reads a 16 bit word or words from the EEPROM using the SPT's flash access
 * register.
 *
 * sc - Struct containing variables accessed by shared code
 * offset - offset of word in the EEPROM to read
 * data - word read from the EEPROM
 * words - number of words to read
 *****************************************************************************/
static int
wm_nvm_read_spt(struct wm_softc *sc, int offset, int words, uint16_t *data)
{
	int	 rv;
	uint32_t flash_bank = 0;
	uint32_t act_offset = 0;
	uint32_t bank_offset = 0;
	uint32_t dword = 0;
	uint16_t i = 0;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	/*
	 * We need to know which is the valid flash bank.  In the event
	 * that we didn't allocate eeprom_shadow_ram, we may not be
	 * managing flash_bank. So it cannot be trusted and needs
	 * to be updated with each read.
	 */
	rv = wm_nvm_valid_bank_detect_ich8lan(sc, &flash_bank);
	if (rv) {
		DPRINTF(sc, WM_DEBUG_NVM, ("%s: failed to detect NVM bank\n",
			device_xname(sc->sc_dev)));
		flash_bank = 0;
	}

	/*
	 * Adjust offset appropriately if we're on bank 1 - adjust for word
	 * size
	 */
	bank_offset = flash_bank * (sc->sc_ich8_flash_bank_size * 2);

	for (i = 0; i < words; i++) {
		/* The NVM part needs a byte offset, hence * 2 */
		act_offset = bank_offset + ((offset + i) * 2);
		/* but we must read dword aligned, so mask ... */
		rv = wm_read_ich8_dword(sc, act_offset & ~0x3, &dword);
		if (rv) {
			aprint_error_dev(sc->sc_dev,
			    "%s: failed to read NVM\n", __func__);
			break;
		}
		/* ... and pick out low or high word */
		if ((act_offset & 0x2) == 0)
			data[i] = (uint16_t)(dword & 0xFFFF);
		else
			data[i] = (uint16_t)((dword >> 16) & 0xFFFF);
	}

	sc->nvm.release(sc);
	return rv;
}

/* iNVM */

static int
wm_nvm_read_word_invm(struct wm_softc *sc, uint16_t address, uint16_t *data)
{
	int32_t	 rv = 0;
	uint32_t invm_dword;
	uint16_t i;
	uint8_t record_type, word_address;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	for (i = 0; i < INVM_SIZE; i++) {
		invm_dword = CSR_READ(sc, WM_INVM_DATA_REG(i));
		/* Get record type */
		record_type = INVM_DWORD_TO_RECORD_TYPE(invm_dword);
		if (record_type == INVM_UNINITIALIZED_STRUCTURE)
			break;
		if (record_type == INVM_CSR_AUTOLOAD_STRUCTURE)
			i += INVM_CSR_AUTOLOAD_DATA_SIZE_IN_DWORDS;
		if (record_type == INVM_RSA_KEY_SHA256_STRUCTURE)
			i += INVM_RSA_KEY_SHA256_DATA_SIZE_IN_DWORDS;
		if (record_type == INVM_WORD_AUTOLOAD_STRUCTURE) {
			word_address = INVM_DWORD_TO_WORD_ADDRESS(invm_dword);
			if (word_address == address) {
				*data = INVM_DWORD_TO_WORD_DATA(invm_dword);
				rv = 0;
				break;
			}
		}
	}

	return rv;
}

static int
wm_nvm_read_invm(struct wm_softc *sc, int offset, int words, uint16_t *data)
{
	int i, rv;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->nvm.acquire(sc);
	if (rv != 0)
		return rv;

	for (i = 0; i < words; i++) {
		switch (offset + i) {
		case NVM_OFF_MACADDR:
		case NVM_OFF_MACADDR1:
		case NVM_OFF_MACADDR2:
			rv = wm_nvm_read_word_invm(sc, offset + i, &data[i]);
			if (rv != 0) {
				data[i] = 0xffff;
				rv = -1;
			}
			break;
		case NVM_OFF_CFG1: /* == INVM_AUTOLOAD */
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = INVM_DEFAULT_AL;
				rv = 0;
			}
			break;
		case NVM_OFF_CFG2:
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = NVM_INIT_CTRL_2_DEFAULT_I211;
				rv = 0;
			}
			break;
		case NVM_OFF_CFG4:
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = NVM_INIT_CTRL_4_DEFAULT_I211;
				rv = 0;
			}
			break;
		case NVM_OFF_LED_1_CFG:
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = NVM_LED_1_CFG_DEFAULT_I211;
				rv = 0;
			}
			break;
		case NVM_OFF_LED_0_2_CFG:
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = NVM_LED_0_2_CFG_DEFAULT_I211;
				rv = 0;
			}
			break;
		case NVM_OFF_ID_LED_SETTINGS:
			rv = wm_nvm_read_word_invm(sc, offset, data);
			if (rv != 0) {
				*data = ID_LED_RESERVED_FFFF;
				rv = 0;
			}
			break;
		default:
			DPRINTF(sc, WM_DEBUG_NVM,
			    ("NVM word 0x%02x is not mapped.\n", offset));
			*data = NVM_RESERVED_WORD;
			break;
		}
	}

	sc->nvm.release(sc);
	return rv;
}

/* Lock, detecting NVM type, validate checksum, version and read */

static int
wm_nvm_is_onboard_eeprom(struct wm_softc *sc)
{
	uint32_t eecd = 0;

	if (sc->sc_type == WM_T_82573 || sc->sc_type == WM_T_82574
	    || sc->sc_type == WM_T_82583) {
		eecd = CSR_READ(sc, WMREG_EECD);

		/* Isolate bits 15 & 16 */
		eecd = ((eecd >> 15) & 0x03);

		/* If both bits are set, device is Flash type */
		if (eecd == 0x03)
			return 0;
	}
	return 1;
}

static int
wm_nvm_flash_presence_i210(struct wm_softc *sc)
{
	uint32_t eec;

	eec = CSR_READ(sc, WMREG_EEC);
	if ((eec & EEC_FLASH_DETECTED) != 0)
		return 1;

	return 0;
}

/*
 * wm_nvm_validate_checksum
 *
 * The checksum is defined as the sum of the first 64 (16 bit) words.
 */
static int
wm_nvm_validate_checksum(struct wm_softc *sc)
{
	uint16_t checksum;
	uint16_t eeprom_data;
#ifdef WM_DEBUG
	uint16_t csum_wordaddr, valid_checksum;
#endif
	int i;

	checksum = 0;

	/* Don't check for I211 */
	if (sc->sc_type == WM_T_I211)
		return 0;

#ifdef WM_DEBUG
	if ((sc->sc_type == WM_T_PCH_LPT) || (sc->sc_type == WM_T_PCH_SPT) ||
	    (sc->sc_type == WM_T_PCH_CNP) || (sc->sc_type == WM_T_PCH_TGP)) {
		csum_wordaddr = NVM_OFF_COMPAT;
		valid_checksum = NVM_COMPAT_VALID_CHECKSUM;
	} else {
		csum_wordaddr = NVM_OFF_FUTURE_INIT_WORD1;
		valid_checksum = NVM_FUTURE_INIT_WORD1_VALID_CHECKSUM;
	}

	/* Dump EEPROM image for debug */
	if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
	    || (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
	    || (sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT)) {
		/* XXX PCH_SPT? */
		wm_nvm_read(sc, csum_wordaddr, 1, &eeprom_data);
		if ((eeprom_data & valid_checksum) == 0)
			DPRINTF(sc, WM_DEBUG_NVM,
			    ("%s: NVM need to be updated (%04x != %04x)\n",
				device_xname(sc->sc_dev), eeprom_data,
				valid_checksum));
	}

	if ((sc->sc_debug & WM_DEBUG_NVM) != 0) {
		printf("%s: NVM dump:\n", device_xname(sc->sc_dev));
		for (i = 0; i < NVM_SIZE; i++) {
			if (wm_nvm_read(sc, i, 1, &eeprom_data))
				printf("XXXX ");
			else
				printf("%04hx ", eeprom_data);
			if (i % 8 == 7)
				printf("\n");
		}
	}

#endif /* WM_DEBUG */

	for (i = 0; i < NVM_SIZE; i++) {
		if (wm_nvm_read(sc, i, 1, &eeprom_data))
			return -1;
		checksum += eeprom_data;
	}

	if (checksum != (uint16_t) NVM_CHECKSUM) {
#ifdef WM_DEBUG
		printf("%s: NVM checksum mismatch (%04x != %04x)\n",
		    device_xname(sc->sc_dev), checksum, NVM_CHECKSUM);
#endif
	}

	return 0;
}

static void
wm_nvm_version_invm(struct wm_softc *sc)
{
	uint32_t dword;

	/*
	 * Linux's code to decode version is very strange, so we don't
	 * obey that algorithm and just use word 61 as the document.
	 * Perhaps it's not perfect though...
	 *
	 * Example:
	 *
	 *   Word61: 00800030 -> Version 0.6 (I211 spec update notes about 0.6)
	 */
	dword = CSR_READ(sc, WM_INVM_DATA_REG(61));
	dword = __SHIFTOUT(dword, INVM_VER_1);
	sc->sc_nvm_ver_major = __SHIFTOUT(dword, INVM_MAJOR);
	sc->sc_nvm_ver_minor = __SHIFTOUT(dword, INVM_MINOR);
}

static void
wm_nvm_version(struct wm_softc *sc)
{
	uint16_t major, minor, build, patch;
	uint16_t uid0, uid1;
	uint16_t nvm_data;
	uint16_t off;
	bool check_version = false;
	bool check_optionrom = false;
	bool have_build = false;
	bool have_uid = true;

	/*
	 * Version format:
	 *
	 * XYYZ
	 * X0YZ
	 * X0YY
	 *
	 * Example:
	 *
	 *	82571	0x50a2	5.10.2?	(the spec update notes about 5.6-5.10)
	 *	82571	0x50a6	5.10.6?
	 *	82572	0x506a	5.6.10?
	 *	82572EI	0x5069	5.6.9?
	 *	82574L	0x1080	1.8.0?	(the spec update notes about 2.1.4)
	 *		0x2013	2.1.3?
	 *	82583	0x10a0	1.10.0? (document says it's default value)
	 * ICH8+82567	0x0040	0.4.0?
	 * ICH9+82566	0x1040	1.4.0?
	 *ICH10+82567	0x0043	0.4.3?
	 *  PCH+82577	0x00c1	0.12.1?
	 * PCH2+82579	0x00d3	0.13.3?
	 *		0x00d4	0.13.4?
	 *  LPT+I218	0x0023	0.2.3?
	 *  SPT+I219	0x0084	0.8.4?
	 *  CNP+I219	0x0054	0.5.4?
	 */

	/*
	 * XXX
	 * Qemu's e1000e emulation (82574L)'s SPI has only 64 words.
	 * I've never seen real 82574 hardware with such small SPI ROM.
	 */
	if ((sc->sc_nvm_wordsize < NVM_OFF_IMAGE_UID1)
	    || (wm_nvm_read(sc, NVM_OFF_IMAGE_UID1, 1, &uid1) != 0))
		have_uid = false;

	switch (sc->sc_type) {
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82574:
	case WM_T_82583:
		check_version = true;
		check_optionrom = true;
		have_build = true;
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		check_version = true;
		have_build = true;
		have_uid = false;
		break;
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
		if (have_uid && (uid1 & NVM_MAJOR_MASK) != NVM_UID_VALID)
			check_version = true;
		break;
	case WM_T_I211:
		wm_nvm_version_invm(sc);
		have_uid = false;
		goto printver;
	case WM_T_I210:
		if (!wm_nvm_flash_presence_i210(sc)) {
			wm_nvm_version_invm(sc);
			have_uid = false;
			goto printver;
		}
		/* FALLTHROUGH */
	case WM_T_I350:
	case WM_T_I354:
		check_version = true;
		check_optionrom = true;
		break;
	default:
		return;
	}
	if (check_version
	    && (wm_nvm_read(sc, NVM_OFF_VERSION, 1, &nvm_data) == 0)) {
		major = (nvm_data & NVM_MAJOR_MASK) >> NVM_MAJOR_SHIFT;
		if (have_build || ((nvm_data & 0x0f00) != 0x0000)) {
			minor = (nvm_data & NVM_MINOR_MASK) >> NVM_MINOR_SHIFT;
			build = nvm_data & NVM_BUILD_MASK;
			have_build = true;
		} else
			minor = nvm_data & 0x00ff;

		/* Decimal */
		minor = (minor / 16) * 10 + (minor % 16);
		sc->sc_nvm_ver_major = major;
		sc->sc_nvm_ver_minor = minor;

printver:
		aprint_verbose(", version %d.%d", sc->sc_nvm_ver_major,
		    sc->sc_nvm_ver_minor);
		if (have_build) {
			sc->sc_nvm_ver_build = build;
			aprint_verbose(".%d", build);
		}
	}

	/* Assume the Option ROM area is at avove NVM_SIZE */
	if ((sc->sc_nvm_wordsize > NVM_SIZE) && check_optionrom
	    && (wm_nvm_read(sc, NVM_OFF_COMB_VER_PTR, 1, &off) == 0)) {
		/* Option ROM Version */
		if ((off != 0x0000) && (off != 0xffff)) {
			int rv;
			uint16_t oid0, oid1;

			off += NVM_COMBO_VER_OFF;
			rv = wm_nvm_read(sc, off + 1, 1, &oid1);
			rv |= wm_nvm_read(sc, off, 1, &oid0);
			if ((rv == 0) && (oid0 != 0) && (oid0 != 0xffff)
			    && (oid1 != 0) && (oid1 != 0xffff)) {
				/* 16bits */
				major = oid0 >> 8;
				build = (oid0 << 8) | (oid1 >> 8);
				patch = oid1 & 0x00ff;
				aprint_verbose(", option ROM Version %d.%d.%d",
				    major, build, patch);
			}
		}
	}

	if (have_uid && (wm_nvm_read(sc, NVM_OFF_IMAGE_UID0, 1, &uid0) == 0))
		aprint_verbose(", Image Unique ID %08x",
		    ((uint32_t)uid1 << 16) | uid0);
}

/*
 * wm_nvm_read:
 *
 *	Read data from the serial EEPROM.
 */
static int
wm_nvm_read(struct wm_softc *sc, int word, int wordcnt, uint16_t *data)
{
	int rv;

	DPRINTF(sc, WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_flags & WM_F_EEPROM_INVALID)
		return -1;

	rv = sc->nvm.read(sc, word, wordcnt, data);

	return rv;
}

/*
 * Hardware semaphores.
 * Very complexed...
 */

static int
wm_get_null(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	return 0;
}

static void
wm_put_null(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	return;
}

static int
wm_get_eecd(struct wm_softc *sc)
{
	uint32_t reg;
	int x;

	DPRINTF(sc, WM_DEBUG_LOCK | WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	reg = CSR_READ(sc, WMREG_EECD);

	/* Request EEPROM access. */
	reg |= EECD_EE_REQ;
	CSR_WRITE(sc, WMREG_EECD, reg);

	/* ..and wait for it to be granted. */
	for (x = 0; x < 1000; x++) {
		reg = CSR_READ(sc, WMREG_EECD);
		if (reg & EECD_EE_GNT)
			break;
		delay(5);
	}
	if ((reg & EECD_EE_GNT) == 0) {
		aprint_error_dev(sc->sc_dev,
		    "could not acquire EEPROM GNT\n");
		reg &= ~EECD_EE_REQ;
		CSR_WRITE(sc, WMREG_EECD, reg);
		return -1;
	}

	return 0;
}

static void
wm_nvm_eec_clock_raise(struct wm_softc *sc, uint32_t *eecd)
{

	*eecd |= EECD_SK;
	CSR_WRITE(sc, WMREG_EECD, *eecd);
	CSR_WRITE_FLUSH(sc);
	if ((sc->sc_flags & WM_F_EEPROM_SPI) != 0)
		delay(1);
	else
		delay(50);
}

static void
wm_nvm_eec_clock_lower(struct wm_softc *sc, uint32_t *eecd)
{

	*eecd &= ~EECD_SK;
	CSR_WRITE(sc, WMREG_EECD, *eecd);
	CSR_WRITE_FLUSH(sc);
	if ((sc->sc_flags & WM_F_EEPROM_SPI) != 0)
		delay(1);
	else
		delay(50);
}

static void
wm_put_eecd(struct wm_softc *sc)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* Stop nvm */
	reg = CSR_READ(sc, WMREG_EECD);
	if ((sc->sc_flags & WM_F_EEPROM_SPI) != 0) {
		/* Pull CS high */
		reg |= EECD_CS;
		wm_nvm_eec_clock_lower(sc, &reg);
	} else {
		/* CS on Microwire is active-high */
		reg &= ~(EECD_CS | EECD_DI);
		CSR_WRITE(sc, WMREG_EECD, reg);
		wm_nvm_eec_clock_raise(sc, &reg);
		wm_nvm_eec_clock_lower(sc, &reg);
	}

	reg = CSR_READ(sc, WMREG_EECD);
	reg &= ~EECD_EE_REQ;
	CSR_WRITE(sc, WMREG_EECD, reg);

	return;
}

/*
 * Get hardware semaphore.
 * Same as e1000_get_hw_semaphore_generic()
 */
static int
wm_get_swsm_semaphore(struct wm_softc *sc)
{
	int32_t timeout;
	uint32_t swsm;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(sc->sc_nvm_wordsize > 0);

retry:
	/* Get the SW semaphore. */
	timeout = sc->sc_nvm_wordsize + 1;
	while (timeout) {
		swsm = CSR_READ(sc, WMREG_SWSM);

		if ((swsm & SWSM_SMBI) == 0)
			break;

		delay(50);
		timeout--;
	}

	if (timeout == 0) {
		if ((sc->sc_flags & WM_F_WA_I210_CLSEM) != 0) {
			/*
			 * In rare circumstances, the SW semaphore may already
			 * be held unintentionally. Clear the semaphore once
			 * before giving up.
			 */
			sc->sc_flags &= ~WM_F_WA_I210_CLSEM;
			wm_put_swsm_semaphore(sc);
			goto retry;
		}
		aprint_error_dev(sc->sc_dev, "could not acquire SWSM SMBI\n");
		return -1;
	}

	/* Get the FW semaphore. */
	timeout = sc->sc_nvm_wordsize + 1;
	while (timeout) {
		swsm = CSR_READ(sc, WMREG_SWSM);
		swsm |= SWSM_SWESMBI;
		CSR_WRITE(sc, WMREG_SWSM, swsm);
		/* If we managed to set the bit we got the semaphore. */
		swsm = CSR_READ(sc, WMREG_SWSM);
		if (swsm & SWSM_SWESMBI)
			break;

		delay(50);
		timeout--;
	}

	if (timeout == 0) {
		aprint_error_dev(sc->sc_dev,
		    "could not acquire SWSM SWESMBI\n");
		/* Release semaphores */
		wm_put_swsm_semaphore(sc);
		return -1;
	}
	return 0;
}

/*
 * Put hardware semaphore.
 * Same as e1000_put_hw_semaphore_generic()
 */
static void
wm_put_swsm_semaphore(struct wm_softc *sc)
{
	uint32_t swsm;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	swsm = CSR_READ(sc, WMREG_SWSM);
	swsm &= ~(SWSM_SMBI | SWSM_SWESMBI);
	CSR_WRITE(sc, WMREG_SWSM, swsm);
}

/*
 * Get SW/FW semaphore.
 * Same as e1000_acquire_swfw_sync_{80003es2lan,82575}().
 */
static int
wm_get_swfw_semaphore(struct wm_softc *sc, uint16_t mask)
{
	uint32_t swfw_sync;
	uint32_t swmask = mask << SWFW_SOFT_SHIFT;
	uint32_t fwmask = mask << SWFW_FIRM_SHIFT;
	int timeout;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_type == WM_T_80003)
		timeout = 50;
	else
		timeout = 200;

	while (timeout) {
		if (wm_get_swsm_semaphore(sc)) {
			aprint_error_dev(sc->sc_dev,
			    "%s: failed to get semaphore\n",
			    __func__);
			return -1;
		}
		swfw_sync = CSR_READ(sc, WMREG_SW_FW_SYNC);
		if ((swfw_sync & (swmask | fwmask)) == 0) {
			swfw_sync |= swmask;
			CSR_WRITE(sc, WMREG_SW_FW_SYNC, swfw_sync);
			wm_put_swsm_semaphore(sc);
			return 0;
		}
		wm_put_swsm_semaphore(sc);
		delay(5000);
		timeout--;
	}
	device_printf(sc->sc_dev,
	    "failed to get swfw semaphore mask 0x%x swfw 0x%x\n",
	    mask, swfw_sync);
	return -1;
}

static void
wm_put_swfw_semaphore(struct wm_softc *sc, uint16_t mask)
{
	uint32_t swfw_sync;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	while (wm_get_swsm_semaphore(sc) != 0)
		continue;

	swfw_sync = CSR_READ(sc, WMREG_SW_FW_SYNC);
	swfw_sync &= ~(mask << SWFW_SOFT_SHIFT);
	CSR_WRITE(sc, WMREG_SW_FW_SYNC, swfw_sync);

	wm_put_swsm_semaphore(sc);
}

static int
wm_get_nvm_80003(struct wm_softc *sc)
{
	int rv;

	DPRINTF(sc, WM_DEBUG_LOCK | WM_DEBUG_NVM, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if ((rv = wm_get_swfw_semaphore(sc, SWFW_EEP_SM)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "%s: failed to get semaphore(SWFW)\n", __func__);
		return rv;
	}

	if (((sc->sc_flags & WM_F_LOCK_EECD) != 0)
	    && (rv = wm_get_eecd(sc)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "%s: failed to get semaphore(EECD)\n", __func__);
		wm_put_swfw_semaphore(sc, SWFW_EEP_SM);
		return rv;
	}

	return 0;
}

static void
wm_put_nvm_80003(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if ((sc->sc_flags & WM_F_LOCK_EECD) != 0)
		wm_put_eecd(sc);
	wm_put_swfw_semaphore(sc, SWFW_EEP_SM);
}

static int
wm_get_nvm_82571(struct wm_softc *sc)
{
	int rv;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if ((rv = wm_get_swsm_semaphore(sc)) != 0)
		return rv;

	switch (sc->sc_type) {
	case WM_T_82573:
		break;
	default:
		if ((sc->sc_flags & WM_F_LOCK_EECD) != 0)
			rv = wm_get_eecd(sc);
		break;
	}

	if (rv != 0) {
		aprint_error_dev(sc->sc_dev,
		    "%s: failed to get semaphore\n",
		    __func__);
		wm_put_swsm_semaphore(sc);
	}

	return rv;
}

static void
wm_put_nvm_82571(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	switch (sc->sc_type) {
	case WM_T_82573:
		break;
	default:
		if ((sc->sc_flags & WM_F_LOCK_EECD) != 0)
			wm_put_eecd(sc);
		break;
	}

	wm_put_swsm_semaphore(sc);
}

static int
wm_get_phy_82575(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	return wm_get_swfw_semaphore(sc, swfwphysem[sc->sc_funcid]);
}

static void
wm_put_phy_82575(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	wm_put_swfw_semaphore(sc, swfwphysem[sc->sc_funcid]);
}

static int
wm_get_swfwhw_semaphore(struct wm_softc *sc)
{
	uint32_t ext_ctrl;
	int timeout = 200;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	mutex_enter(sc->sc_ich_phymtx); /* Use PHY mtx for both PHY and NVM */
	for (timeout = 0; timeout < 200; timeout++) {
		ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
		ext_ctrl |= EXTCNFCTR_MDIO_SW_OWNERSHIP;
		CSR_WRITE(sc, WMREG_EXTCNFCTR, ext_ctrl);

		ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
		if (ext_ctrl & EXTCNFCTR_MDIO_SW_OWNERSHIP)
			return 0;
		delay(5000);
	}
	device_printf(sc->sc_dev,
	    "failed to get swfwhw semaphore ext_ctrl 0x%x\n", ext_ctrl);
	mutex_exit(sc->sc_ich_phymtx); /* Use PHY mtx for both PHY and NVM */
	return -1;
}

static void
wm_put_swfwhw_semaphore(struct wm_softc *sc)
{
	uint32_t ext_ctrl;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
	ext_ctrl &= ~EXTCNFCTR_MDIO_SW_OWNERSHIP;
	CSR_WRITE(sc, WMREG_EXTCNFCTR, ext_ctrl);

	mutex_exit(sc->sc_ich_phymtx); /* Use PHY mtx for both PHY and NVM */
}

static int
wm_get_swflag_ich8lan(struct wm_softc *sc)
{
	uint32_t ext_ctrl;
	int timeout;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	mutex_enter(sc->sc_ich_phymtx);
	for (timeout = 0; timeout < WM_PHY_CFG_TIMEOUT; timeout++) {
		ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
		if ((ext_ctrl & EXTCNFCTR_MDIO_SW_OWNERSHIP) == 0)
			break;
		delay(1000);
	}
	if (timeout >= WM_PHY_CFG_TIMEOUT) {
		device_printf(sc->sc_dev,
		    "SW has already locked the resource\n");
		goto out;
	}

	ext_ctrl |= EXTCNFCTR_MDIO_SW_OWNERSHIP;
	CSR_WRITE(sc, WMREG_EXTCNFCTR, ext_ctrl);
	for (timeout = 0; timeout < 1000; timeout++) {
		ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
		if (ext_ctrl & EXTCNFCTR_MDIO_SW_OWNERSHIP)
			break;
		delay(1000);
	}
	if (timeout >= 1000) {
		device_printf(sc->sc_dev, "failed to acquire semaphore\n");
		ext_ctrl &= ~EXTCNFCTR_MDIO_SW_OWNERSHIP;
		CSR_WRITE(sc, WMREG_EXTCNFCTR, ext_ctrl);
		goto out;
	}
	return 0;

out:
	mutex_exit(sc->sc_ich_phymtx);
	return -1;
}

static void
wm_put_swflag_ich8lan(struct wm_softc *sc)
{
	uint32_t ext_ctrl;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	ext_ctrl = CSR_READ(sc, WMREG_EXTCNFCTR);
	if (ext_ctrl & EXTCNFCTR_MDIO_SW_OWNERSHIP) {
		ext_ctrl &= ~EXTCNFCTR_MDIO_SW_OWNERSHIP;
		CSR_WRITE(sc, WMREG_EXTCNFCTR, ext_ctrl);
	} else
		device_printf(sc->sc_dev, "Semaphore unexpectedly released\n");

	mutex_exit(sc->sc_ich_phymtx);
}

static int
wm_get_nvm_ich8lan(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	mutex_enter(sc->sc_ich_nvmmtx);

	return 0;
}

static void
wm_put_nvm_ich8lan(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	mutex_exit(sc->sc_ich_nvmmtx);
}

static int
wm_get_hw_semaphore_82573(struct wm_softc *sc)
{
	int i = 0;
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	reg = CSR_READ(sc, WMREG_EXTCNFCTR);
	do {
		CSR_WRITE(sc, WMREG_EXTCNFCTR,
		    reg | EXTCNFCTR_MDIO_SW_OWNERSHIP);
		reg = CSR_READ(sc, WMREG_EXTCNFCTR);
		if ((reg & EXTCNFCTR_MDIO_SW_OWNERSHIP) != 0)
			break;
		delay(2*1000);
		i++;
	} while (i < WM_MDIO_OWNERSHIP_TIMEOUT);

	if (i == WM_MDIO_OWNERSHIP_TIMEOUT) {
		wm_put_hw_semaphore_82573(sc);
		log(LOG_ERR, "%s: Driver can't access the PHY\n",
		    device_xname(sc->sc_dev));
		return -1;
	}

	return 0;
}

static void
wm_put_hw_semaphore_82573(struct wm_softc *sc)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	reg = CSR_READ(sc, WMREG_EXTCNFCTR);
	reg &= ~EXTCNFCTR_MDIO_SW_OWNERSHIP;
	CSR_WRITE(sc, WMREG_EXTCNFCTR, reg);
}

/*
 * Management mode and power management related subroutines.
 * BMC, AMT, suspend/resume and EEE.
 */

#ifdef WM_WOL
static int
wm_check_mng_mode(struct wm_softc *sc)
{
	int rv;

	switch (sc->sc_type) {
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		rv = wm_check_mng_mode_ich8lan(sc);
		break;
	case WM_T_82574:
	case WM_T_82583:
		rv = wm_check_mng_mode_82574(sc);
		break;
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_80003:
		rv = wm_check_mng_mode_generic(sc);
		break;
	default:
		/* Noting to do */
		rv = 0;
		break;
	}

	return rv;
}

static int
wm_check_mng_mode_ich8lan(struct wm_softc *sc)
{
	uint32_t fwsm;

	fwsm = CSR_READ(sc, WMREG_FWSM);

	if (((fwsm & FWSM_FW_VALID) != 0)
	    && (__SHIFTOUT(fwsm, FWSM_MODE) == MNG_ICH_IAMT_MODE))
		return 1;

	return 0;
}

static int
wm_check_mng_mode_82574(struct wm_softc *sc)
{
	uint16_t data;

	wm_nvm_read(sc, NVM_OFF_CFG2, 1, &data);

	if ((data & NVM_CFG2_MNGM_MASK) != 0)
		return 1;

	return 0;
}

static int
wm_check_mng_mode_generic(struct wm_softc *sc)
{
	uint32_t fwsm;

	fwsm = CSR_READ(sc, WMREG_FWSM);

	if (__SHIFTOUT(fwsm, FWSM_MODE) == MNG_IAMT_MODE)
		return 1;

	return 0;
}
#endif /* WM_WOL */

static int
wm_enable_mng_pass_thru(struct wm_softc *sc)
{
	uint32_t manc, fwsm, factps;

	if ((sc->sc_flags & WM_F_ASF_FIRMWARE_PRES) == 0)
		return 0;

	manc = CSR_READ(sc, WMREG_MANC);

	DPRINTF(sc, WM_DEBUG_MANAGE, ("%s: MANC (%08x)\n",
		device_xname(sc->sc_dev), manc));
	if ((manc & MANC_RECV_TCO_EN) == 0)
		return 0;

	if ((sc->sc_flags & WM_F_ARC_SUBSYS_VALID) != 0) {
		fwsm = CSR_READ(sc, WMREG_FWSM);
		factps = CSR_READ(sc, WMREG_FACTPS);
		if (((factps & FACTPS_MNGCG) == 0)
		    && (__SHIFTOUT(fwsm, FWSM_MODE) == MNG_ICH_IAMT_MODE))
			return 1;
	} else if ((sc->sc_type == WM_T_82574) || (sc->sc_type == WM_T_82583)){
		uint16_t data;

		factps = CSR_READ(sc, WMREG_FACTPS);
		wm_nvm_read(sc, NVM_OFF_CFG2, 1, &data);
		DPRINTF(sc, WM_DEBUG_MANAGE, ("%s: FACTPS = %08x, CFG2=%04x\n",
			device_xname(sc->sc_dev), factps, data));
		if (((factps & FACTPS_MNGCG) == 0)
		    && ((data & NVM_CFG2_MNGM_MASK)
			== (NVM_CFG2_MNGM_PT << NVM_CFG2_MNGM_SHIFT)))
			return 1;
	} else if (((manc & MANC_SMBUS_EN) != 0)
	    && ((manc & MANC_ASF_EN) == 0))
		return 1;

	return 0;
}

static bool
wm_phy_resetisblocked(struct wm_softc *sc)
{
	bool blocked = false;
	uint32_t reg;
	int i = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	switch (sc->sc_type) {
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		do {
			reg = CSR_READ(sc, WMREG_FWSM);
			if ((reg & FWSM_RSPCIPHY) == 0) {
				blocked = true;
				delay(10*1000);
				continue;
			}
			blocked = false;
		} while (blocked && (i++ < 30));
		return blocked;
		break;
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_80003:
		reg = CSR_READ(sc, WMREG_MANC);
		if ((reg & MANC_BLK_PHY_RST_ON_IDE) != 0)
			return true;
		else
			return false;
		break;
	default:
		/* No problem */
		break;
	}

	return false;
}

static void
wm_get_hw_control(struct wm_softc *sc)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_type == WM_T_82573) {
		reg = CSR_READ(sc, WMREG_SWSM);
		CSR_WRITE(sc, WMREG_SWSM, reg | SWSM_DRV_LOAD);
	} else if (sc->sc_type >= WM_T_82571) {
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg | CTRL_EXT_DRV_LOAD);
	}
}

static void
wm_release_hw_control(struct wm_softc *sc)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_LOCK, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_type == WM_T_82573) {
		reg = CSR_READ(sc, WMREG_SWSM);
		CSR_WRITE(sc, WMREG_SWSM, reg & ~SWSM_DRV_LOAD);
	} else if (sc->sc_type >= WM_T_82571) {
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg & ~CTRL_EXT_DRV_LOAD);
	}
}

static void
wm_gate_hw_phy_config_ich8lan(struct wm_softc *sc, bool gate)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_type < WM_T_PCH2)
		return;

	reg = CSR_READ(sc, WMREG_EXTCNFCTR);

	if (gate)
		reg |= EXTCNFCTR_GATE_PHY_CFG;
	else
		reg &= ~EXTCNFCTR_GATE_PHY_CFG;

	CSR_WRITE(sc, WMREG_EXTCNFCTR, reg);
}

static int
wm_init_phy_workarounds_pchlan(struct wm_softc *sc)
{
	uint32_t fwsm, reg;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* Gate automatic PHY configuration by hardware on non-managed 82579 */
	wm_gate_hw_phy_config_ich8lan(sc, true);

	/* Disable ULP */
	wm_ulp_disable(sc);

	/* Acquire PHY semaphore */
	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		DPRINTF(sc, WM_DEBUG_INIT,
		    ("%s: %s: failed\n", device_xname(sc->sc_dev), __func__));
		return rv;
	}

	/* The MAC-PHY interconnect may be in SMBus mode.  If the PHY is
	 * inaccessible and resetting the PHY is not blocked, toggle the
	 * LANPHYPC Value bit to force the interconnect to PCIe mode.
	 */
	fwsm = CSR_READ(sc, WMREG_FWSM);
	switch (sc->sc_type) {
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		if (wm_phy_is_accessible_pchlan(sc))
			break;

		/* Before toggling LANPHYPC, see if PHY is accessible by
		 * forcing MAC to SMBus mode first.
		 */
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		reg |= CTRL_EXT_FORCE_SMBUS;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
#if 0
		/* XXX Isn't this required??? */
		CSR_WRITE_FLUSH(sc);
#endif
		/* Wait 50 milliseconds for MAC to finish any retries
		 * that it might be trying to perform from previous
		 * attempts to acknowledge any phy read requests.
		 */
		delay(50 * 1000);
		/* FALLTHROUGH */
	case WM_T_PCH2:
		if (wm_phy_is_accessible_pchlan(sc) == true)
			break;
		/* FALLTHROUGH */
	case WM_T_PCH:
		if (sc->sc_type == WM_T_PCH)
			if ((fwsm & FWSM_FW_VALID) != 0)
				break;

		if (wm_phy_resetisblocked(sc) == true) {
			device_printf(sc->sc_dev, "XXX reset is blocked(2)\n");
			break;
		}

		/* Toggle LANPHYPC Value bit */
		wm_toggle_lanphypc_pch_lpt(sc);

		if (sc->sc_type >= WM_T_PCH_LPT) {
			if (wm_phy_is_accessible_pchlan(sc) == true)
				break;

			/* Toggling LANPHYPC brings the PHY out of SMBus mode
			 * so ensure that the MAC is also out of SMBus mode
			 */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg &= ~CTRL_EXT_FORCE_SMBUS;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

			if (wm_phy_is_accessible_pchlan(sc) == true)
				break;
			rv = -1;
		}
		break;
	default:
		break;
	}

	/* Release semaphore */
	sc->phy.release(sc);

	if (rv == 0) {
		/* Check to see if able to reset PHY.  Print error if not */
		if (wm_phy_resetisblocked(sc)) {
			device_printf(sc->sc_dev, "XXX reset is blocked(3)\n");
			goto out;
		}

		/* Reset the PHY before any access to it.  Doing so, ensures
		 * that the PHY is in a known good state before we read/write
		 * PHY registers.  The generic reset is sufficient here,
		 * because we haven't determined the PHY type yet.
		 */
		if (wm_reset_phy(sc) != 0)
			goto out;

		/* On a successful reset, possibly need to wait for the PHY
		 * to quiesce to an accessible state before returning control
		 * to the calling function.  If the PHY does not quiesce, then
		 * return E1000E_BLK_PHY_RESET, as this is the condition that
		 *  the PHY is in.
		 */
		if (wm_phy_resetisblocked(sc))
			device_printf(sc->sc_dev, "XXX reset is blocked(4)\n");
	}

out:
	/* Ungate automatic PHY configuration on non-managed 82579 */
	if ((sc->sc_type == WM_T_PCH2) && ((fwsm & FWSM_FW_VALID) == 0)) {
		delay(10*1000);
		wm_gate_hw_phy_config_ich8lan(sc, false);
	}

	return 0;
}

static void
wm_init_manageability(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(IFNET_LOCKED(&sc->sc_ethercom.ec_if));

	if (sc->sc_flags & WM_F_HAS_MANAGE) {
		uint32_t manc2h = CSR_READ(sc, WMREG_MANC2H);
		uint32_t manc = CSR_READ(sc, WMREG_MANC);

		/* Disable hardware interception of ARP */
		manc &= ~MANC_ARP_EN;

		/* Enable receiving management packets to the host */
		if (sc->sc_type >= WM_T_82571) {
			manc |= MANC_EN_MNG2HOST;
			manc2h |= MANC2H_PORT_623 | MANC2H_PORT_624;
			CSR_WRITE(sc, WMREG_MANC2H, manc2h);
		}

		CSR_WRITE(sc, WMREG_MANC, manc);
	}
}

static void
wm_release_manageability(struct wm_softc *sc)
{

	if (sc->sc_flags & WM_F_HAS_MANAGE) {
		uint32_t manc = CSR_READ(sc, WMREG_MANC);

		manc |= MANC_ARP_EN;
		if (sc->sc_type >= WM_T_82571)
			manc &= ~MANC_EN_MNG2HOST;

		CSR_WRITE(sc, WMREG_MANC, manc);
	}
}

static void
wm_get_wakeup(struct wm_softc *sc)
{

	/* 0: HAS_AMT, ARC_SUBSYS_VALID, ASF_FIRMWARE_PRES */
	switch (sc->sc_type) {
	case WM_T_82573:
	case WM_T_82583:
		sc->sc_flags |= WM_F_HAS_AMT;
		/* FALLTHROUGH */
	case WM_T_80003:
	case WM_T_82575:
	case WM_T_82576:
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I354:
		if ((CSR_READ(sc, WMREG_FWSM) & FWSM_MODE) != 0)
			sc->sc_flags |= WM_F_ARC_SUBSYS_VALID;
		/* FALLTHROUGH */
	case WM_T_82541:
	case WM_T_82541_2:
	case WM_T_82547:
	case WM_T_82547_2:
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82574:
		sc->sc_flags |= WM_F_ASF_FIRMWARE_PRES;
		break;
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		sc->sc_flags |= WM_F_HAS_AMT;
		sc->sc_flags |= WM_F_ASF_FIRMWARE_PRES;
		break;
	default:
		break;
	}

	/* 1: HAS_MANAGE */
	if (wm_enable_mng_pass_thru(sc) != 0)
		sc->sc_flags |= WM_F_HAS_MANAGE;

	/*
	 * Note that the WOL flags is set after the resetting of the eeprom
	 * stuff
	 */
}

/*
 * Unconfigure Ultra Low Power mode.
 * Only for I217 and newer (see below).
 */
static int
wm_ulp_disable(struct wm_softc *sc)
{
	uint32_t reg;
	uint16_t phyreg;
	int i = 0, rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	/* Exclude old devices */
	if ((sc->sc_type < WM_T_PCH_LPT)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I217_LM)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I217_V)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_LM2)
	    || (sc->sc_pcidevid == PCI_PRODUCT_INTEL_I218_V2))
		return 0;

	if ((CSR_READ(sc, WMREG_FWSM) & FWSM_FW_VALID) != 0) {
		/* Request ME un-configure ULP mode in the PHY */
		reg = CSR_READ(sc, WMREG_H2ME);
		reg &= ~H2ME_ULP;
		reg |= H2ME_ENFORCE_SETTINGS;
		CSR_WRITE(sc, WMREG_H2ME, reg);

		/* Poll up to 300msec for ME to clear ULP_CFG_DONE. */
		while ((CSR_READ(sc, WMREG_FWSM) & FWSM_ULP_CFG_DONE) != 0) {
			if (i++ == 30) {
				device_printf(sc->sc_dev, "%s timed out\n",
				    __func__);
				return -1;
			}
			delay(10 * 1000);
		}
		reg = CSR_READ(sc, WMREG_H2ME);
		reg &= ~H2ME_ENFORCE_SETTINGS;
		CSR_WRITE(sc, WMREG_H2ME, reg);

		return 0;
	}

	/* Acquire semaphore */
	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		DPRINTF(sc, WM_DEBUG_INIT,
		    ("%s: %s: failed\n", device_xname(sc->sc_dev), __func__));
		return rv;
	}

	/* Toggle LANPHYPC */
	wm_toggle_lanphypc_pch_lpt(sc);

	/* Unforce SMBus mode in PHY */
	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, CV_SMB_CTRL, &phyreg);
	if (rv != 0) {
		uint32_t reg2;

		aprint_debug_dev(sc->sc_dev, "%s: Force SMBus first.\n",
		    __func__);
		reg2 = CSR_READ(sc, WMREG_CTRL_EXT);
		reg2 |= CTRL_EXT_FORCE_SMBUS;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg2);
		delay(50 * 1000);

		rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, CV_SMB_CTRL,
		    &phyreg);
		if (rv != 0)
			goto release;
	}
	phyreg &= ~CV_SMB_CTRL_FORCE_SMBUS;
	wm_gmii_hv_writereg_locked(sc->sc_dev, 2, CV_SMB_CTRL, phyreg);

	/* Unforce SMBus mode in MAC */
	reg = CSR_READ(sc, WMREG_CTRL_EXT);
	reg &= ~CTRL_EXT_FORCE_SMBUS;
	CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, HV_PM_CTRL, &phyreg);
	if (rv != 0)
		goto release;
	phyreg |= HV_PM_CTRL_K1_ENA;
	wm_gmii_hv_writereg_locked(sc->sc_dev, 2, HV_PM_CTRL, phyreg);

	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, I218_ULP_CONFIG1,
	    &phyreg);
	if (rv != 0)
		goto release;
	phyreg &= ~(I218_ULP_CONFIG1_IND
	    | I218_ULP_CONFIG1_STICKY_ULP
	    | I218_ULP_CONFIG1_RESET_TO_SMBUS
	    | I218_ULP_CONFIG1_WOL_HOST
	    | I218_ULP_CONFIG1_INBAND_EXIT
	    | I218_ULP_CONFIG1_EN_ULP_LANPHYPC
	    | I218_ULP_CONFIG1_DIS_CLR_STICKY_ON_PERST
	    | I218_ULP_CONFIG1_DIS_SMB_PERST);
	wm_gmii_hv_writereg_locked(sc->sc_dev, 2, I218_ULP_CONFIG1, phyreg);
	phyreg |= I218_ULP_CONFIG1_START;
	wm_gmii_hv_writereg_locked(sc->sc_dev, 2, I218_ULP_CONFIG1, phyreg);

	reg = CSR_READ(sc, WMREG_FEXTNVM7);
	reg &= ~FEXTNVM7_DIS_SMB_PERST;
	CSR_WRITE(sc, WMREG_FEXTNVM7, reg);

release:
	/* Release semaphore */
	sc->phy.release(sc);
	wm_gmii_reset(sc);
	delay(50 * 1000);

	return rv;
}

/* WOL in the newer chipset interfaces (pchlan) */
static int
wm_enable_phy_wakeup(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t mreg, moff;
	uint16_t wuce, wuc, wufc, preg;
	int i, rv;

	KASSERT(sc->sc_type >= WM_T_PCH);

	/* Copy MAC RARs to PHY RARs */
	wm_copy_rx_addrs_to_phy_ich8lan(sc);

	/* Activate PHY wakeup */
	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to acquire semaphore\n",
		    __func__);
		return rv;
	}

	/*
	 * Enable access to PHY wakeup registers.
	 * BM_MTA, BM_RCTL, BM_WUFC and BM_WUC are in BM_WUC_PAGE.
	 */
	rv = wm_enable_phy_wakeup_reg_access_bm(dev, &wuce);
	if (rv != 0) {
		device_printf(dev,
		    "%s: Could not enable PHY wakeup reg access\n", __func__);
		goto release;
	}

	/* Copy MAC MTA to PHY MTA */
	for (i = 0; i < WM_ICH8_MC_TABSIZE; i++) {
		uint16_t lo, hi;

		mreg = CSR_READ(sc, WMREG_CORDOVA_MTA + (i * 4));
		lo = (uint16_t)(mreg & 0xffff);
		hi = (uint16_t)((mreg >> 16) & 0xffff);
		wm_access_phy_wakeup_reg_bm(dev, BM_MTA(i), &lo, 0, true);
		wm_access_phy_wakeup_reg_bm(dev, BM_MTA(i) + 1, &hi, 0, true);
	}

	/* Configure PHY Rx Control register */
	wm_access_phy_wakeup_reg_bm(dev, BM_RCTL, &preg, 1, true);
	mreg = CSR_READ(sc, WMREG_RCTL);
	if (mreg & RCTL_UPE)
		preg |= BM_RCTL_UPE;
	if (mreg & RCTL_MPE)
		preg |= BM_RCTL_MPE;
	preg &= ~(BM_RCTL_MO_MASK);
	moff = __SHIFTOUT(mreg, RCTL_MO);
	if (moff != 0)
		preg |= moff << BM_RCTL_MO_SHIFT;
	if (mreg & RCTL_BAM)
		preg |= BM_RCTL_BAM;
	if (mreg & RCTL_PMCF)
		preg |= BM_RCTL_PMCF;
	mreg = CSR_READ(sc, WMREG_CTRL);
	if (mreg & CTRL_RFCE)
		preg |= BM_RCTL_RFCE;
	wm_access_phy_wakeup_reg_bm(dev, BM_RCTL, &preg, 0, true);

	wuc = WUC_APME | WUC_PME_EN;
	wufc = WUFC_MAG;
	/* Enable PHY wakeup in MAC register */
	CSR_WRITE(sc, WMREG_WUC,
	    WUC_PHY_WAKE | WUC_PME_STATUS | WUC_APMPME | wuc);
	CSR_WRITE(sc, WMREG_WUFC, wufc);

	/* Configure and enable PHY wakeup in PHY registers */
	wm_access_phy_wakeup_reg_bm(dev, BM_WUC, &wuc, 0, true);
	wm_access_phy_wakeup_reg_bm(dev, BM_WUFC, &wufc, 0, true);

	wuce |= BM_WUC_ENABLE_BIT | BM_WUC_HOST_WU_BIT;
	wm_disable_phy_wakeup_reg_access_bm(dev, &wuce);

release:
	sc->phy.release(sc);

	return 0;
}

/* Power down workaround on D3 */
static void
wm_igp3_phy_powerdown_workaround_ich8lan(struct wm_softc *sc)
{
	uint32_t reg;
	uint16_t phyreg;
	int i;

	for (i = 0; i < 2; i++) {
		/* Disable link */
		reg = CSR_READ(sc, WMREG_PHY_CTRL);
		reg |= PHY_CTRL_GBE_DIS | PHY_CTRL_NOND0A_GBE_DIS;
		CSR_WRITE(sc, WMREG_PHY_CTRL, reg);

		/*
		 * Call gig speed drop workaround on Gig disable before
		 * accessing any PHY registers
		 */
		if (sc->sc_type == WM_T_ICH8)
			wm_gig_downshift_workaround_ich8lan(sc);

		/* Write VR power-down enable */
		sc->sc_mii.mii_readreg(sc->sc_dev, 1, IGP3_VR_CTRL, &phyreg);
		phyreg &= ~IGP3_VR_CTRL_DEV_POWERDOWN_MODE_MASK;
		phyreg |= IGP3_VR_CTRL_MODE_SHUTDOWN;
		sc->sc_mii.mii_writereg(sc->sc_dev, 1, IGP3_VR_CTRL, phyreg);

		/* Read it back and test */
		sc->sc_mii.mii_readreg(sc->sc_dev, 1, IGP3_VR_CTRL, &phyreg);
		phyreg &= IGP3_VR_CTRL_DEV_POWERDOWN_MODE_MASK;
		if ((phyreg == IGP3_VR_CTRL_MODE_SHUTDOWN) || (i != 0))
			break;

		/* Issue PHY reset and repeat at most one more time */
		CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl | CTRL_PHY_RESET);
	}
}

/*
 *  wm_suspend_workarounds_ich8lan - workarounds needed during S0->Sx
 *  @sc: pointer to the HW structure
 *
 *  During S0 to Sx transition, it is possible the link remains at gig
 *  instead of negotiating to a lower speed.  Before going to Sx, set
 *  'Gig Disable' to force link speed negotiation to a lower speed based on
 *  the LPLU setting in the NVM or custom setting.  For PCH and newer parts,
 *  the OEM bits PHY register (LED, GbE disable and LPLU configurations) also
 *  needs to be written.
 *  Parts that support (and are linked to a partner which support) EEE in
 *  100Mbps should disable LPLU since 100Mbps w/ EEE requires less power
 *  than 10Mbps w/o EEE.
 */
static void
wm_suspend_workarounds_ich8lan(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	struct ethercom *ec = &sc->sc_ethercom;
	uint32_t phy_ctrl;
	int rv;

	phy_ctrl = CSR_READ(sc, WMREG_PHY_CTRL);
	phy_ctrl |= PHY_CTRL_GBE_DIS;

	KASSERT((sc->sc_type >= WM_T_ICH8) && (sc->sc_type <= WM_T_PCH_TGP));

	if (sc->sc_phytype == WMPHY_I217) {
		uint16_t devid = sc->sc_pcidevid;

		if ((devid == PCI_PRODUCT_INTEL_I218_LM) ||
		    (devid == PCI_PRODUCT_INTEL_I218_V) ||
		    (devid == PCI_PRODUCT_INTEL_I218_LM3) ||
		    (devid == PCI_PRODUCT_INTEL_I218_V3) ||
		    (sc->sc_type >= WM_T_PCH_SPT))
			CSR_WRITE(sc, WMREG_FEXTNVM6,
			    CSR_READ(sc, WMREG_FEXTNVM6)
			    & ~FEXTNVM6_REQ_PLL_CLK);

		if (sc->phy.acquire(sc) != 0)
			goto out;

		if ((ec->ec_capenable & ETHERCAP_EEE) != 0) {
			uint16_t eee_advert;

			rv = wm_read_emi_reg_locked(dev,
			    I217_EEE_ADVERTISEMENT, &eee_advert);
			if (rv)
				goto release;

			/*
			 * Disable LPLU if both link partners support 100BaseT
			 * EEE and 100Full is advertised on both ends of the
			 * link, and enable Auto Enable LPI since there will
			 * be no driver to enable LPI while in Sx.
			 */
			if ((eee_advert & AN_EEEADVERT_100_TX) &&
			    (sc->eee_lp_ability & AN_EEEADVERT_100_TX)) {
				uint16_t anar, phy_reg;

				sc->phy.readreg_locked(dev, 2, MII_ANAR,
				    &anar);
				if (anar & ANAR_TX_FD) {
					phy_ctrl &= ~(PHY_CTRL_D0A_LPLU |
					    PHY_CTRL_NOND0A_LPLU);

					/* Set Auto Enable LPI after link up */
					sc->phy.readreg_locked(dev, 2,
					    I217_LPI_GPIO_CTRL, &phy_reg);
					phy_reg |= I217_LPI_GPIO_CTRL_AUTO_EN_LPI;
					sc->phy.writereg_locked(dev, 2,
					    I217_LPI_GPIO_CTRL, phy_reg);
				}
			}
		}

		/*
		 * For i217 Intel Rapid Start Technology support,
		 * when the system is going into Sx and no manageability engine
		 * is present, the driver must configure proxy to reset only on
		 * power good.	LPI (Low Power Idle) state must also reset only
		 * on power good, as well as the MTA (Multicast table array).
		 * The SMBus release must also be disabled on LCD reset.
		 */

		/*
		 * Enable MTA to reset for Intel Rapid Start Technology
		 * Support
		 */

release:
		sc->phy.release(sc);
	}
out:
	CSR_WRITE(sc, WMREG_PHY_CTRL, phy_ctrl);

	if (sc->sc_type == WM_T_ICH8)
		wm_gig_downshift_workaround_ich8lan(sc);

	if (sc->sc_type >= WM_T_PCH) {
		wm_oem_bits_config_ich8lan(sc, false);

		/* Reset PHY to activate OEM bits on 82577/8 */
		if (sc->sc_type == WM_T_PCH)
			wm_reset_phy(sc);

		if (sc->phy.acquire(sc) != 0)
			return;
		wm_write_smbus_addr(sc);
		sc->phy.release(sc);
	}
}

/*
 *  wm_resume_workarounds_pchlan - workarounds needed during Sx->S0
 *  @sc: pointer to the HW structure
 *
 *  During Sx to S0 transitions on non-managed devices or managed devices
 *  on which PHY resets are not blocked, if the PHY registers cannot be
 *  accessed properly by the s/w toggle the LANPHYPC value to power cycle
 *  the PHY.
 *  On i217, setup Intel Rapid Start Technology.
 */
static int
wm_resume_workarounds_pchlan(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	int rv;

	if (sc->sc_type < WM_T_PCH2)
		return 0;

	rv = wm_init_phy_workarounds_pchlan(sc);
	if (rv != 0)
		return rv;

	/* For i217 Intel Rapid Start Technology support when the system
	 * is transitioning from Sx and no manageability engine is present
	 * configure SMBus to restore on reset, disable proxy, and enable
	 * the reset on MTA (Multicast table array).
	 */
	if (sc->sc_phytype == WMPHY_I217) {
		uint16_t phy_reg;

		rv = sc->phy.acquire(sc);
		if (rv != 0)
			return rv;

		/* Clear Auto Enable LPI after link up */
		sc->phy.readreg_locked(dev, 1, I217_LPI_GPIO_CTRL, &phy_reg);
		phy_reg &= ~I217_LPI_GPIO_CTRL_AUTO_EN_LPI;
		sc->phy.writereg_locked(dev, 1, I217_LPI_GPIO_CTRL, phy_reg);

		if ((CSR_READ(sc, WMREG_FWSM) & FWSM_FW_VALID) == 0) {
			/* Restore clear on SMB if no manageability engine
			 * is present
			 */
			rv = sc->phy.readreg_locked(dev, 1, I217_MEMPWR,
			    &phy_reg);
			if (rv != 0)
				goto release;
			phy_reg |= I217_MEMPWR_DISABLE_SMB_RELEASE;
			sc->phy.writereg_locked(dev, 1, I217_MEMPWR, phy_reg);

			/* Disable Proxy */
			sc->phy.writereg_locked(dev, 1, I217_PROXY_CTRL, 0);
		}
		/* Enable reset on MTA */
		sc->phy.readreg_locked(dev, 1, I217_CFGREG, &phy_reg);
		if (rv != 0)
			goto release;
		phy_reg &= ~I217_CGFREG_ENABLE_MTA_RESET;
		sc->phy.writereg_locked(dev, 1, I217_CFGREG, phy_reg);

release:
		sc->phy.release(sc);
		return rv;
	}

	return 0;
}

static void
wm_enable_wakeup(struct wm_softc *sc)
{
	uint32_t reg, pmreg;
	pcireg_t pmode;
	int rv = 0;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (pci_get_capability(sc->sc_pc, sc->sc_pcitag, PCI_CAP_PWRMGMT,
	    &pmreg, NULL) == 0)
		return;

	if ((sc->sc_flags & WM_F_WOL) == 0)
		goto pme;

	/* Advertise the wakeup capability */
	CSR_WRITE(sc, WMREG_CTRL, sc->sc_ctrl | CTRL_SWDPIN(2)
	    | CTRL_SWDPIN(3));

	/* Keep the laser running on fiber adapters */
	if ((sc->sc_mediatype == WM_MEDIATYPE_FIBER)
	    || (sc->sc_mediatype == WM_MEDIATYPE_SERDES)) {
		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		reg |= CTRL_EXT_SWDPIN(3);
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
	}

	if ((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9) ||
	    (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH) ||
	    (sc->sc_type == WM_T_PCH2) || (sc->sc_type == WM_T_PCH_LPT) ||
	    (sc->sc_type == WM_T_PCH_SPT) || (sc->sc_type == WM_T_PCH_CNP) ||
	    (sc->sc_type == WM_T_PCH_TGP))
		wm_suspend_workarounds_ich8lan(sc);

#if 0	/* For the multicast packet */
	reg = CSR_READ(sc, WMREG_WUFC) | WUFC_MAG;
	reg |= WUFC_MC;
	CSR_WRITE(sc, WMREG_RCTL, CSR_READ(sc, WMREG_RCTL) | RCTL_MPE);
#endif

	if (sc->sc_type >= WM_T_PCH) {
		rv = wm_enable_phy_wakeup(sc);
		if (rv != 0)
			goto pme;
	} else {
		/* Enable wakeup by the MAC */
		CSR_WRITE(sc, WMREG_WUC, WUC_APME | WUC_PME_EN);
		CSR_WRITE(sc, WMREG_WUFC, WUFC_MAG);
	}

	if (((sc->sc_type == WM_T_ICH8) || (sc->sc_type == WM_T_ICH9)
		|| (sc->sc_type == WM_T_ICH10) || (sc->sc_type == WM_T_PCH)
		|| (sc->sc_type == WM_T_PCH2))
	    && (sc->sc_phytype == WMPHY_IGP_3))
		wm_igp3_phy_powerdown_workaround_ich8lan(sc);

pme:
	/* Request PME */
	pmode = pci_conf_read(sc->sc_pc, sc->sc_pcitag, pmreg + PCI_PMCSR);
	pmode |= PCI_PMCSR_PME_STS; /* in case it's already set (W1C) */
	if ((rv == 0) && (sc->sc_flags & WM_F_WOL) != 0) {
		/* For WOL */
		pmode |= PCI_PMCSR_PME_EN;
	} else {
		/* Disable WOL */
		pmode &= ~PCI_PMCSR_PME_EN;
	}
	pci_conf_write(sc->sc_pc, sc->sc_pcitag, pmreg + PCI_PMCSR, pmode);
}

/* Disable ASPM L0s and/or L1 for workaround */
static void
wm_disable_aspm(struct wm_softc *sc)
{
	pcireg_t reg, mask = 0;
	unsigned const char *str = "";

	/*
	 *  Only for PCIe device which has PCIe capability in the PCI config
	 * space.
	 */
	if (((sc->sc_flags & WM_F_PCIE) == 0) || (sc->sc_pcixe_capoff == 0))
		return;

	switch (sc->sc_type) {
	case WM_T_82571:
	case WM_T_82572:
		/*
		 * 8257[12] Errata 13: Device Does Not Support PCIe Active
		 * State Power management L1 State (ASPM L1).
		 */
		mask = PCIE_LCSR_ASPM_L1;
		str = "L1 is";
		break;
	case WM_T_82573:
	case WM_T_82574:
	case WM_T_82583:
		/*
		 * The 82573 disappears when PCIe ASPM L0s is enabled.
		 *
		 * The 82574 and 82583 does not support PCIe ASPM L0s with
		 * some chipset.  The document of 82574 and 82583 says that
		 * disabling L0s with some specific chipset is sufficient,
		 * but we follow as of the Intel em driver does.
		 *
		 * References:
		 * Errata 8 of the Specification Update of i82573.
		 * Errata 20 of the Specification Update of i82574.
		 * Errata 9 of the Specification Update of i82583.
		 */
		mask = PCIE_LCSR_ASPM_L1 | PCIE_LCSR_ASPM_L0S;
		str = "L0s and L1 are";
		break;
	default:
		return;
	}

	reg = pci_conf_read(sc->sc_pc, sc->sc_pcitag,
	    sc->sc_pcixe_capoff + PCIE_LCSR);
	reg &= ~mask;
	pci_conf_write(sc->sc_pc, sc->sc_pcitag,
	    sc->sc_pcixe_capoff + PCIE_LCSR, reg);

	/* Print only in wm_attach() */
	if ((sc->sc_flags & WM_F_ATTACHED) == 0)
		aprint_verbose_dev(sc->sc_dev,
		    "ASPM %s disabled to workaround the errata.\n", str);
}

/* LPLU */

static void
wm_lplu_d0_disable(struct wm_softc *sc)
{
	struct mii_data *mii = &sc->sc_mii;
	uint32_t reg;
	uint16_t phyval;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->sc_phytype == WMPHY_IFE)
		return;

	switch (sc->sc_type) {
	case WM_T_82571:
	case WM_T_82572:
	case WM_T_82573:
	case WM_T_82575:
	case WM_T_82576:
		mii->mii_readreg(sc->sc_dev, 1, IGPHY_POWER_MGMT, &phyval);
		phyval &= ~PMR_D0_LPLU;
		mii->mii_writereg(sc->sc_dev, 1, IGPHY_POWER_MGMT, phyval);
		break;
	case WM_T_82580:
	case WM_T_I350:
	case WM_T_I210:
	case WM_T_I211:
		reg = CSR_READ(sc, WMREG_PHPM);
		reg &= ~PHPM_D0A_LPLU;
		CSR_WRITE(sc, WMREG_PHPM, reg);
		break;
	case WM_T_82574:
	case WM_T_82583:
	case WM_T_ICH8:
	case WM_T_ICH9:
	case WM_T_ICH10:
		reg = CSR_READ(sc, WMREG_PHY_CTRL);
		reg &= ~(PHY_CTRL_GBE_DIS | PHY_CTRL_D0A_LPLU);
		CSR_WRITE(sc, WMREG_PHY_CTRL, reg);
		CSR_WRITE_FLUSH(sc);
		break;
	case WM_T_PCH:
	case WM_T_PCH2:
	case WM_T_PCH_LPT:
	case WM_T_PCH_SPT:
	case WM_T_PCH_CNP:
	case WM_T_PCH_TGP:
		wm_gmii_hv_readreg(sc->sc_dev, 1, HV_OEM_BITS, &phyval);
		phyval &= ~(HV_OEM_BITS_A1KDIS | HV_OEM_BITS_LPLU);
		if (wm_phy_resetisblocked(sc) == false)
			phyval |= HV_OEM_BITS_ANEGNOW;
		wm_gmii_hv_writereg(sc->sc_dev, 1, HV_OEM_BITS, phyval);
		break;
	default:
		break;
	}
}

/* EEE */

static int
wm_set_eee_i350(struct wm_softc *sc)
{
	struct ethercom *ec = &sc->sc_ethercom;
	uint32_t ipcnfg, eeer;
	uint32_t ipcnfg_mask
	    = IPCNFG_EEE_1G_AN | IPCNFG_EEE_100M_AN | IPCNFG_10BASE_TE;
	uint32_t eeer_mask = EEER_TX_LPI_EN | EEER_RX_LPI_EN | EEER_LPI_FC;

	KASSERT(sc->sc_mediatype == WM_MEDIATYPE_COPPER);

	ipcnfg = CSR_READ(sc, WMREG_IPCNFG);
	eeer = CSR_READ(sc, WMREG_EEER);

	/* Enable or disable per user setting */
	if ((ec->ec_capenable & ETHERCAP_EEE) != 0) {
		ipcnfg |= ipcnfg_mask;
		eeer |= eeer_mask;
	} else {
		ipcnfg &= ~ipcnfg_mask;
		eeer &= ~eeer_mask;
	}

	CSR_WRITE(sc, WMREG_IPCNFG, ipcnfg);
	CSR_WRITE(sc, WMREG_EEER, eeer);
	CSR_READ(sc, WMREG_IPCNFG); /* XXX flush? */
	CSR_READ(sc, WMREG_EEER); /* XXX flush? */

	return 0;
}

static int
wm_set_eee_pchlan(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	struct ethercom *ec = &sc->sc_ethercom;
	uint16_t lpa, pcs_status, adv_addr, adv, lpi_ctrl, data;
	int rv;

	switch (sc->sc_phytype) {
	case WMPHY_82579:
		lpa = I82579_EEE_LP_ABILITY;
		pcs_status = I82579_EEE_PCS_STATUS;
		adv_addr = I82579_EEE_ADVERTISEMENT;
		break;
	case WMPHY_I217:
		lpa = I217_EEE_LP_ABILITY;
		pcs_status = I217_EEE_PCS_STATUS;
		adv_addr = I217_EEE_ADVERTISEMENT;
		break;
	default:
		return 0;
	}

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(dev, "%s: failed to get semaphore\n", __func__);
		return rv;
	}

	rv = sc->phy.readreg_locked(dev, 1, I82579_LPI_CTRL, &lpi_ctrl);
	if (rv != 0)
		goto release;

	/* Clear bits that enable EEE in various speeds */
	lpi_ctrl &= ~I82579_LPI_CTRL_ENABLE;

	if ((ec->ec_capenable & ETHERCAP_EEE) != 0) {
		/* Save off link partner's EEE ability */
		rv = wm_read_emi_reg_locked(dev, lpa, &sc->eee_lp_ability);
		if (rv != 0)
			goto release;

		/* Read EEE advertisement */
		if ((rv = wm_read_emi_reg_locked(dev, adv_addr, &adv)) != 0)
			goto release;

		/*
		 * Enable EEE only for speeds in which the link partner is
		 * EEE capable and for which we advertise EEE.
		 */
		if (adv & sc->eee_lp_ability & AN_EEEADVERT_1000_T)
			lpi_ctrl |= I82579_LPI_CTRL_EN_1000;
		if (adv & sc->eee_lp_ability & AN_EEEADVERT_100_TX) {
			sc->phy.readreg_locked(dev, 2, MII_ANLPAR, &data);
			if ((data & ANLPAR_TX_FD) != 0)
				lpi_ctrl |= I82579_LPI_CTRL_EN_100;
			else {
				/*
				 * EEE is not supported in 100Half, so ignore
				 * partner's EEE in 100 ability if full-duplex
				 * is not advertised.
				 */
				sc->eee_lp_ability
				    &= ~AN_EEEADVERT_100_TX;
			}
		}
	}

	if (sc->sc_phytype == WMPHY_82579) {
		rv = wm_read_emi_reg_locked(dev, I82579_LPI_PLL_SHUT, &data);
		if (rv != 0)
			goto release;

		data &= ~I82579_LPI_PLL_SHUT_100;
		rv = wm_write_emi_reg_locked(dev, I82579_LPI_PLL_SHUT, data);
	}

	/* R/Clr IEEE MMD 3.1 bits 11:10 - Tx/Rx LPI Received */
	if ((rv = wm_read_emi_reg_locked(dev, pcs_status, &data)) != 0)
		goto release;

	rv = sc->phy.writereg_locked(dev, 1, I82579_LPI_CTRL, lpi_ctrl);
release:
	sc->phy.release(sc);

	return rv;
}

static int
wm_set_eee(struct wm_softc *sc)
{
	struct ethercom *ec = &sc->sc_ethercom;

	if ((ec->ec_capabilities & ETHERCAP_EEE) == 0)
		return 0;

	if (sc->sc_type == WM_T_I354) {
		/* I354 uses an external PHY */
		return 0; /* not yet */
	} else if ((sc->sc_type >= WM_T_I350) && (sc->sc_type <= WM_T_I211))
		return wm_set_eee_i350(sc);
	else if (sc->sc_type >= WM_T_PCH2)
		return wm_set_eee_pchlan(sc);

	return 0;
}

/*
 * Workarounds (mainly PHY related).
 * Basically, PHY's workarounds are in the PHY drivers.
 */

/* Workaround for 82566 Kumeran PCS lock loss */
static int
wm_kmrn_lock_loss_workaround_ich8lan(struct wm_softc *sc)
{
	struct mii_data *mii = &sc->sc_mii;
	uint32_t status = CSR_READ(sc, WMREG_STATUS);
	int i, reg, rv;
	uint16_t phyreg;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	/* If the link is not up, do nothing */
	if ((status & STATUS_LU) == 0)
		return 0;

	/* Nothing to do if the link is other than 1Gbps */
	if (__SHIFTOUT(status, STATUS_SPEED) != STATUS_SPEED_1000)
		return 0;

	for (i = 0; i < 10; i++) {
		/* read twice */
		rv = mii->mii_readreg(sc->sc_dev, 1, IGP3_KMRN_DIAG, &phyreg);
		if (rv != 0)
			return rv;
		rv = mii->mii_readreg(sc->sc_dev, 1, IGP3_KMRN_DIAG, &phyreg);
		if (rv != 0)
			return rv;

		if ((phyreg & IGP3_KMRN_DIAG_PCS_LOCK_LOSS) == 0)
			goto out;	/* GOOD! */

		/* Reset the PHY */
		wm_reset_phy(sc);
		delay(5*1000);
	}

	/* Disable GigE link negotiation */
	reg = CSR_READ(sc, WMREG_PHY_CTRL);
	reg |= PHY_CTRL_GBE_DIS | PHY_CTRL_NOND0A_GBE_DIS;
	CSR_WRITE(sc, WMREG_PHY_CTRL, reg);

	/*
	 * Call gig speed drop workaround on Gig disable before accessing
	 * any PHY registers.
	 */
	wm_gig_downshift_workaround_ich8lan(sc);

out:
	return 0;
}

/*
 *  wm_gig_downshift_workaround_ich8lan - WoL from S5 stops working
 *  @sc: pointer to the HW structure
 *
 *  Steps to take when dropping from 1Gb/s (eg. link cable removal (LSC),
 *  LPLU, Gig disable, MDIC PHY reset):
 *    1) Set Kumeran Near-end loopback
 *    2) Clear Kumeran Near-end loopback
 *  Should only be called for ICH8[m] devices with any 1G Phy.
 */
static void
wm_gig_downshift_workaround_ich8lan(struct wm_softc *sc)
{
	uint16_t kmreg;

	/* Only for igp3 */
	if (sc->sc_phytype == WMPHY_IGP_3) {
		if (wm_kmrn_readreg(sc, KUMCTRLSTA_OFFSET_DIAG, &kmreg) != 0)
			return;
		kmreg |= KUMCTRLSTA_DIAG_NELPBK;
		if (wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_DIAG, kmreg) != 0)
			return;
		kmreg &= ~KUMCTRLSTA_DIAG_NELPBK;
		wm_kmrn_writereg(sc, KUMCTRLSTA_OFFSET_DIAG, kmreg);
	}
}

/*
 * Workaround for pch's PHYs
 * XXX should be moved to new PHY driver?
 */
static int
wm_hv_phy_workarounds_ich8lan(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	struct mii_data *mii = &sc->sc_mii;
	struct mii_softc *child;
	uint16_t phy_data, phyrev = 0;
	int phytype = sc->sc_phytype;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));
	KASSERT(sc->sc_type == WM_T_PCH);

	/* Set MDIO slow mode before any other MDIO access */
	if (phytype == WMPHY_82577)
		if ((rv = wm_set_mdio_slow_mode_hv(sc)) != 0)
			return rv;

	child = LIST_FIRST(&mii->mii_phys);
	if (child != NULL)
		phyrev = child->mii_mpd_rev;

	/* (82577 && (phy rev 1 or 2)) || (82578 & phy rev 1)*/
	if ((child != NULL) &&
	    (((phytype == WMPHY_82577) && ((phyrev == 1) || (phyrev == 2))) ||
		((phytype == WMPHY_82578) && (phyrev == 1)))) {
		/* Disable generation of early preamble (0x4431) */
		rv = mii->mii_readreg(dev, 2, BM_RATE_ADAPTATION_CTRL,
		    &phy_data);
		if (rv != 0)
			return rv;
		phy_data &= ~(BM_RATE_ADAPTATION_CTRL_RX_RXDV_PRE |
		    BM_RATE_ADAPTATION_CTRL_RX_CRS_PRE);
		rv = mii->mii_writereg(dev, 2, BM_RATE_ADAPTATION_CTRL,
		    phy_data);
		if (rv != 0)
			return rv;

		/* Preamble tuning for SSC */
		rv = mii->mii_writereg(dev, 2, HV_KMRN_FIFO_CTRLSTA, 0xa204);
		if (rv != 0)
			return rv;
	}

	/* 82578 */
	if (phytype == WMPHY_82578) {
		/*
		 * Return registers to default by doing a soft reset then
		 * writing 0x3140 to the control register
		 * 0x3140 == BMCR_SPEED0 | BMCR_AUTOEN | BMCR_FDX | BMCR_SPEED1
		 */
		if ((child != NULL) && (phyrev < 2)) {
			PHY_RESET(child);
			rv = mii->mii_writereg(dev, 2, MII_BMCR, 0x3140);
			if (rv != 0)
				return rv;
		}
	}

	/* Select page 0 */
	if ((rv = sc->phy.acquire(sc)) != 0)
		return rv;
	rv = wm_gmii_mdic_writereg(dev, 1, IGPHY_PAGE_SELECT, 0);
	sc->phy.release(sc);
	if (rv != 0)
		return rv;

	/*
	 * Configure the K1 Si workaround during phy reset assuming there is
	 * link so that it disables K1 if link is in 1Gbps.
	 */
	if ((rv = wm_k1_gig_workaround_hv(sc, 1)) != 0)
		return rv;

	/* Workaround for link disconnects on a busy hub in half duplex */
	rv = sc->phy.acquire(sc);
	if (rv)
		return rv;
	rv = sc->phy.readreg_locked(dev, 2, BM_PORT_GEN_CFG, &phy_data);
	if (rv)
		goto release;
	rv = sc->phy.writereg_locked(dev, 2, BM_PORT_GEN_CFG,
	    phy_data & 0x00ff);
	if (rv)
		goto release;

	/* Set MSE higher to enable link to stay up when noise is high */
	rv = wm_write_emi_reg_locked(dev, I82577_MSE_THRESHOLD, 0x0034);
release:
	sc->phy.release(sc);

	return rv;
}

/*
 *  wm_copy_rx_addrs_to_phy_ich8lan - Copy Rx addresses from MAC to PHY
 *  @sc:   pointer to the HW structure
 */
static void
wm_copy_rx_addrs_to_phy_ich8lan(struct wm_softc *sc)
{

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (sc->phy.acquire(sc) != 0)
		return;

	wm_copy_rx_addrs_to_phy_ich8lan_locked(sc);

	sc->phy.release(sc);
}

static void
wm_copy_rx_addrs_to_phy_ich8lan_locked(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	uint32_t mac_reg;
	uint16_t i, wuce;
	int count;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));

	if (wm_enable_phy_wakeup_reg_access_bm(dev, &wuce) != 0)
		return;

	/* Copy both RAL/H (rar_entry_count) and SHRAL/H to PHY */
	count = wm_rar_count(sc);
	for (i = 0; i < count; i++) {
		uint16_t lo, hi;
		mac_reg = CSR_READ(sc, WMREG_CORDOVA_RAL(i));
		lo = (uint16_t)(mac_reg & 0xffff);
		hi = (uint16_t)((mac_reg >> 16) & 0xffff);
		wm_access_phy_wakeup_reg_bm(dev, BM_RAR_L(i), &lo, 0, true);
		wm_access_phy_wakeup_reg_bm(dev, BM_RAR_M(i), &hi, 0, true);

		mac_reg = CSR_READ(sc, WMREG_CORDOVA_RAH(i));
		lo = (uint16_t)(mac_reg & 0xffff);
		hi = (uint16_t)((mac_reg & RAL_AV) >> 16);
		wm_access_phy_wakeup_reg_bm(dev, BM_RAR_H(i), &lo, 0, true);
		wm_access_phy_wakeup_reg_bm(dev, BM_RAR_CTRL(i), &hi, 0, true);
	}

	wm_disable_phy_wakeup_reg_access_bm(dev, &wuce);
}

/*
 *  wm_lv_jumbo_workaround_ich8lan - required for jumbo frame operation
 *  with 82579 PHY
 *  @enable: flag to enable/disable workaround when enabling/disabling jumbos
 */
static int
wm_lv_jumbo_workaround_ich8lan(struct wm_softc *sc, bool enable)
{
	device_t dev = sc->sc_dev;
	int rar_count;
	int rv;
	uint32_t mac_reg;
	uint16_t dft_ctrl, data;
	uint16_t i;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));

	if (sc->sc_type < WM_T_PCH2)
		return 0;

	/* Acquire PHY semaphore */
	rv = sc->phy.acquire(sc);
	if (rv != 0)
		return rv;

	/* Disable Rx path while enabling/disabling workaround */
	rv = sc->phy.readreg_locked(dev, 2, I82579_DFT_CTRL, &dft_ctrl);
	if (rv != 0)
		goto out;
	rv = sc->phy.writereg_locked(dev, 2, I82579_DFT_CTRL,
	    dft_ctrl | (1 << 14));
	if (rv != 0)
		goto out;

	if (enable) {
		/* Write Rx addresses (rar_entry_count for RAL/H, and
		 * SHRAL/H) and initial CRC values to the MAC
		 */
		rar_count = wm_rar_count(sc);
		for (i = 0; i < rar_count; i++) {
			uint8_t mac_addr[ETHER_ADDR_LEN] = {0};
			uint32_t addr_high, addr_low;

			addr_high = CSR_READ(sc, WMREG_CORDOVA_RAH(i));
			if (!(addr_high & RAL_AV))
				continue;
			addr_low = CSR_READ(sc, WMREG_CORDOVA_RAL(i));
			mac_addr[0] = (addr_low & 0xFF);
			mac_addr[1] = ((addr_low >> 8) & 0xFF);
			mac_addr[2] = ((addr_low >> 16) & 0xFF);
			mac_addr[3] = ((addr_low >> 24) & 0xFF);
			mac_addr[4] = (addr_high & 0xFF);
			mac_addr[5] = ((addr_high >> 8) & 0xFF);

			CSR_WRITE(sc, WMREG_PCH_RAICC(i),
			    ~ether_crc32_le(mac_addr, ETHER_ADDR_LEN));
		}

		/* Write Rx addresses to the PHY */
		wm_copy_rx_addrs_to_phy_ich8lan_locked(sc);
	}

	/*
	 * If enable ==
	 *	true: Enable jumbo frame workaround in the MAC.
	 *	false: Write MAC register values back to h/w defaults.
	 */
	mac_reg = CSR_READ(sc, WMREG_FFLT_DBG);
	if (enable) {
		mac_reg &= ~(1 << 14);
		mac_reg |= (7 << 15);
	} else
		mac_reg &= ~(0xf << 14);
	CSR_WRITE(sc, WMREG_FFLT_DBG, mac_reg);

	mac_reg = CSR_READ(sc, WMREG_RCTL);
	if (enable) {
		mac_reg |= RCTL_SECRC;
		sc->sc_rctl |= RCTL_SECRC;
		sc->sc_flags |= WM_F_CRC_STRIP;
	} else {
		mac_reg &= ~RCTL_SECRC;
		sc->sc_rctl &= ~RCTL_SECRC;
		sc->sc_flags &= ~WM_F_CRC_STRIP;
	}
	CSR_WRITE(sc, WMREG_RCTL, mac_reg);

	rv = wm_kmrn_readreg_locked(sc, KUMCTRLSTA_OFFSET_CTRL, &data);
	if (rv != 0)
		goto out;
	if (enable)
		data |= 1 << 0;
	else
		data &= ~(1 << 0);
	rv = wm_kmrn_writereg_locked(sc, KUMCTRLSTA_OFFSET_CTRL, data);
	if (rv != 0)
		goto out;

	rv = wm_kmrn_readreg_locked(sc, KUMCTRLSTA_OFFSET_HD_CTRL, &data);
	if (rv != 0)
		goto out;
	/*
	 * XXX FreeBSD and Linux do the same thing that they set the same value
	 * on both the enable case and the disable case. Is it correct?
	 */
	data &= ~(0xf << 8);
	data |= (0xb << 8);
	rv = wm_kmrn_writereg_locked(sc, KUMCTRLSTA_OFFSET_HD_CTRL, data);
	if (rv != 0)
		goto out;

	/*
	 * If enable ==
	 *	true: Enable jumbo frame workaround in the PHY.
	 *	false: Write PHY register values back to h/w defaults.
	 */
	rv = sc->phy.readreg_locked(dev, 2, BME1000_REG(769, 23), &data);
	if (rv != 0)
		goto out;
	data &= ~(0x7F << 5);
	if (enable)
		data |= (0x37 << 5);
	rv = sc->phy.writereg_locked(dev, 2, BME1000_REG(769, 23), data);
	if (rv != 0)
		goto out;

	rv = sc->phy.readreg_locked(dev, 2, BME1000_REG(769, 16), &data);
	if (rv != 0)
		goto out;
	if (enable)
		data &= ~(1 << 13);
	else
		data |= (1 << 13);
	rv = sc->phy.writereg_locked(dev, 2, BME1000_REG(769, 16), data);
	if (rv != 0)
		goto out;

	rv = sc->phy.readreg_locked(dev, 2, I82579_UNKNOWN1, &data);
	if (rv != 0)
		goto out;
	data &= ~(0x3FF << 2);
	if (enable)
		data |= (I82579_TX_PTR_GAP << 2);
	else
		data |= (0x8 << 2);
	rv = sc->phy.writereg_locked(dev, 2, I82579_UNKNOWN1, data);
	if (rv != 0)
		goto out;

	rv = sc->phy.writereg_locked(dev, 2, BME1000_REG(776, 23),
	    enable ? 0xf100 : 0x7e00);
	if (rv != 0)
		goto out;

	rv = sc->phy.readreg_locked(dev, 2, HV_PM_CTRL, &data);
	if (rv != 0)
		goto out;
	if (enable)
		data |= 1 << 10;
	else
		data &= ~(1 << 10);
	rv = sc->phy.writereg_locked(dev, 2, HV_PM_CTRL, data);
	if (rv != 0)
		goto out;

	/* Re-enable Rx path after enabling/disabling workaround */
	rv = sc->phy.writereg_locked(dev, 2, I82579_DFT_CTRL,
	    dft_ctrl & ~(1 << 14));

out:
	sc->phy.release(sc);

	return rv;
}

/*
 *  wm_lv_phy_workarounds_ich8lan - A series of Phy workarounds to be
 *  done after every PHY reset.
 */
static int
wm_lv_phy_workarounds_ich8lan(struct wm_softc *sc)
{
	device_t dev = sc->sc_dev;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(dev), __func__));
	KASSERT(sc->sc_type == WM_T_PCH2);

	/* Set MDIO slow mode before any other MDIO access */
	rv = wm_set_mdio_slow_mode_hv(sc);
	if (rv != 0)
		return rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0)
		return rv;
	/* Set MSE higher to enable link to stay up when noise is high */
	rv = wm_write_emi_reg_locked(dev, I82579_MSE_THRESHOLD, 0x0034);
	if (rv != 0)
		goto release;
	/* Drop link after 5 times MSE threshold was reached */
	rv = wm_write_emi_reg_locked(dev, I82579_MSE_LINK_DOWN, 0x0005);
release:
	sc->phy.release(sc);

	return rv;
}

/**
 *  wm_k1_workaround_lpt_lp - K1 workaround on Lynxpoint-LP
 *  @link: link up bool flag
 *
 *  When K1 is enabled for 1Gbps, the MAC can miss 2 DMA completion indications
 *  preventing further DMA write requests.  Workaround the issue by disabling
 *  the de-assertion of the clock request when in 1Gpbs mode.
 *  Also, set appropriate Tx re-transmission timeouts for 10 and 100Half link
 *  speeds in order to avoid Tx hangs.
 **/
static int
wm_k1_workaround_lpt_lp(struct wm_softc *sc, bool link)
{
	uint32_t fextnvm6 = CSR_READ(sc, WMREG_FEXTNVM6);
	uint32_t status = CSR_READ(sc, WMREG_STATUS);
	uint32_t speed = __SHIFTOUT(status, STATUS_SPEED);
	uint16_t phyreg;

	if (link && (speed == STATUS_SPEED_1000)) {
		int rv;

		rv = sc->phy.acquire(sc);
		if (rv != 0)
			return rv;
		rv = wm_kmrn_readreg_locked(sc, KUMCTRLSTA_OFFSET_K1_CONFIG,
		    &phyreg);
		if (rv != 0)
			goto release;
		rv = wm_kmrn_writereg_locked(sc, KUMCTRLSTA_OFFSET_K1_CONFIG,
		    phyreg & ~KUMCTRLSTA_K1_ENABLE);
		if (rv != 0)
			goto release;
		delay(20);
		CSR_WRITE(sc, WMREG_FEXTNVM6, fextnvm6 | FEXTNVM6_REQ_PLL_CLK);

		rv = wm_kmrn_readreg_locked(sc, KUMCTRLSTA_OFFSET_K1_CONFIG,
		    &phyreg);
release:
		sc->phy.release(sc);
		return rv;
	}

	fextnvm6 &= ~FEXTNVM6_REQ_PLL_CLK;

	struct mii_softc *child = LIST_FIRST(&sc->sc_mii.mii_phys);
	if (((child != NULL) && (child->mii_mpd_rev > 5))
	    || !link
	    || ((speed == STATUS_SPEED_100) && (status & STATUS_FD)))
		goto update_fextnvm6;

	wm_gmii_hv_readreg(sc->sc_dev, 2, I217_INBAND_CTRL, &phyreg);

	/* Clear link status transmit timeout */
	phyreg &= ~I217_INBAND_CTRL_LINK_STAT_TX_TIMEOUT_MASK;
	if (speed == STATUS_SPEED_100) {
		/* Set inband Tx timeout to 5x10us for 100Half */
		phyreg |= 5 << I217_INBAND_CTRL_LINK_STAT_TX_TIMEOUT_SHIFT;

		/* Do not extend the K1 entry latency for 100Half */
		fextnvm6 &= ~FEXTNVM6_ENABLE_K1_ENTRY_CONDITION;
	} else {
		/* Set inband Tx timeout to 50x10us for 10Full/Half */
		phyreg |= 50 << I217_INBAND_CTRL_LINK_STAT_TX_TIMEOUT_SHIFT;

		/* Extend the K1 entry latency for 10 Mbps */
		fextnvm6 |= FEXTNVM6_ENABLE_K1_ENTRY_CONDITION;
	}

	wm_gmii_hv_writereg(sc->sc_dev, 2, I217_INBAND_CTRL, phyreg);

update_fextnvm6:
	CSR_WRITE(sc, WMREG_FEXTNVM6, fextnvm6);
	return 0;
}

/*
 *  wm_k1_gig_workaround_hv - K1 Si workaround
 *  @sc:   pointer to the HW structure
 *  @link: link up bool flag
 *
 *  If K1 is enabled for 1Gbps, the MAC might stall when transitioning
 *  from a lower speed.  This workaround disables K1 whenever link is at 1Gig
 *  If link is down, the function will restore the default K1 setting located
 *  in the NVM.
 */
static int
wm_k1_gig_workaround_hv(struct wm_softc *sc, int link)
{
	int k1_enable = sc->sc_nvm_k1_enabled;
	int rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	rv = sc->phy.acquire(sc);
	if (rv != 0)
		return rv;

	if (link) {
		k1_enable = 0;

		/* Link stall fix for link up */
		wm_gmii_hv_writereg_locked(sc->sc_dev, 1, IGP3_KMRN_DIAG,
		    0x0100);
	} else {
		/* Link stall fix for link down */
		wm_gmii_hv_writereg_locked(sc->sc_dev, 1, IGP3_KMRN_DIAG,
		    0x4100);
	}

	wm_configure_k1_ich8lan(sc, k1_enable);
	sc->phy.release(sc);

	return 0;
}

/*
 *  wm_k1_workaround_lv - K1 Si workaround
 *  @sc:   pointer to the HW structure
 *
 *  Workaround to set the K1 beacon duration for 82579 parts in 10Mbps
 *  Disable K1 for 1000 and 100 speeds
 */
static int
wm_k1_workaround_lv(struct wm_softc *sc)
{
	uint32_t reg;
	uint16_t phyreg;
	int rv;

	if (sc->sc_type != WM_T_PCH2)
		return 0;

	/* Set K1 beacon duration based on 10Mbps speed */
	rv = wm_gmii_hv_readreg(sc->sc_dev, 2, HV_M_STATUS, &phyreg);
	if (rv != 0)
		return rv;

	if ((phyreg & (HV_M_STATUS_LINK_UP | HV_M_STATUS_AUTONEG_COMPLETE))
	    == (HV_M_STATUS_LINK_UP | HV_M_STATUS_AUTONEG_COMPLETE)) {
		if (phyreg &
		    (HV_M_STATUS_SPEED_1000 | HV_M_STATUS_SPEED_100)) {
			/* LV 1G/100 Packet drop issue wa  */
			rv = wm_gmii_hv_readreg(sc->sc_dev, 1, HV_PM_CTRL,
			    &phyreg);
			if (rv != 0)
				return rv;
			phyreg &= ~HV_PM_CTRL_K1_ENA;
			rv = wm_gmii_hv_writereg(sc->sc_dev, 1, HV_PM_CTRL,
			    phyreg);
			if (rv != 0)
				return rv;
		} else {
			/* For 10Mbps */
			reg = CSR_READ(sc, WMREG_FEXTNVM4);
			reg &= ~FEXTNVM4_BEACON_DURATION;
			reg |= FEXTNVM4_BEACON_DURATION_16US;
			CSR_WRITE(sc, WMREG_FEXTNVM4, reg);
		}
	}

	return 0;
}

/*
 *  wm_link_stall_workaround_hv - Si workaround
 *  @sc: pointer to the HW structure
 *
 *  This function works around a Si bug where the link partner can get
 *  a link up indication before the PHY does. If small packets are sent
 *  by the link partner they can be placed in the packet buffer without
 *  being properly accounted for by the PHY and will stall preventing
 *  further packets from being received.  The workaround is to clear the
 *  packet buffer after the PHY detects link up.
 */
static int
wm_link_stall_workaround_hv(struct wm_softc *sc)
{
	uint16_t phyreg;

	if (sc->sc_phytype != WMPHY_82578)
		return 0;

	/* Do not apply workaround if in PHY loopback bit 14 set */
	wm_gmii_hv_readreg(sc->sc_dev, 2, MII_BMCR, &phyreg);
	if ((phyreg & BMCR_LOOP) != 0)
		return 0;

	/* Check if link is up and at 1Gbps */
	wm_gmii_hv_readreg(sc->sc_dev, 2, BM_CS_STATUS, &phyreg);
	phyreg &= BM_CS_STATUS_LINK_UP | BM_CS_STATUS_RESOLVED
	    | BM_CS_STATUS_SPEED_MASK;
	if (phyreg != (BM_CS_STATUS_LINK_UP | BM_CS_STATUS_RESOLVED
		| BM_CS_STATUS_SPEED_1000))
		return 0;

	delay(200 * 1000);	/* XXX too big */

	/* Flush the packets in the fifo buffer */
	wm_gmii_hv_writereg(sc->sc_dev, 1, HV_MUX_DATA_CTRL,
	    HV_MUX_DATA_CTRL_GEN_TO_MAC | HV_MUX_DATA_CTRL_FORCE_SPEED);
	wm_gmii_hv_writereg(sc->sc_dev, 1, HV_MUX_DATA_CTRL,
	    HV_MUX_DATA_CTRL_GEN_TO_MAC);

	return 0;
}

static int
wm_set_mdio_slow_mode_hv(struct wm_softc *sc)
{
	int rv;

	rv = sc->phy.acquire(sc);
	if (rv != 0) {
		device_printf(sc->sc_dev, "%s: failed to get semaphore\n",
		    __func__);
		return rv;
	}

	rv = wm_set_mdio_slow_mode_hv_locked(sc);

	sc->phy.release(sc);

	return rv;
}

static int
wm_set_mdio_slow_mode_hv_locked(struct wm_softc *sc)
{
	int rv;
	uint16_t reg;

	rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 1, HV_KMRN_MODE_CTRL, &reg);
	if (rv != 0)
		return rv;

	return wm_gmii_hv_writereg_locked(sc->sc_dev, 1, HV_KMRN_MODE_CTRL,
	    reg | HV_KMRN_MDIO_SLOW);
}

/*
 *  wm_configure_k1_ich8lan - Configure K1 power state
 *  @sc: pointer to the HW structure
 *  @enable: K1 state to configure
 *
 *  Configure the K1 power state based on the provided parameter.
 *  Assumes semaphore already acquired.
 */
static void
wm_configure_k1_ich8lan(struct wm_softc *sc, int k1_enable)
{
	uint32_t ctrl, ctrl_ext, tmp;
	uint16_t kmreg;
	int rv;

	KASSERT(CSR_READ(sc, WMREG_EXTCNFCTR) & EXTCNFCTR_MDIO_SW_OWNERSHIP);

	rv = wm_kmrn_readreg_locked(sc, KUMCTRLSTA_OFFSET_K1_CONFIG, &kmreg);
	if (rv != 0)
		return;

	if (k1_enable)
		kmreg |= KUMCTRLSTA_K1_ENABLE;
	else
		kmreg &= ~KUMCTRLSTA_K1_ENABLE;

	rv = wm_kmrn_writereg_locked(sc, KUMCTRLSTA_OFFSET_K1_CONFIG, kmreg);
	if (rv != 0)
		return;

	delay(20);

	ctrl = CSR_READ(sc, WMREG_CTRL);
	ctrl_ext = CSR_READ(sc, WMREG_CTRL_EXT);

	tmp = ctrl & ~(CTRL_SPEED_1000 | CTRL_SPEED_100);
	tmp |= CTRL_FRCSPD;

	CSR_WRITE(sc, WMREG_CTRL, tmp);
	CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext | CTRL_EXT_SPD_BYPS);
	CSR_WRITE_FLUSH(sc);
	delay(20);

	CSR_WRITE(sc, WMREG_CTRL, ctrl);
	CSR_WRITE(sc, WMREG_CTRL_EXT, ctrl_ext);
	CSR_WRITE_FLUSH(sc);
	delay(20);

	return;
}

/* special case - for 82575 - need to do manual init ... */
static void
wm_reset_init_script_82575(struct wm_softc *sc)
{
	/*
	 * Remark: this is untested code - we have no board without EEPROM
	 *  same setup as mentioned int the FreeBSD driver for the i82575
	 */

	/* SerDes configuration via SERDESCTRL */
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCTL, 0x00, 0x0c);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCTL, 0x01, 0x78);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCTL, 0x1b, 0x23);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCTL, 0x23, 0x15);

	/* CCM configuration via CCMCTL register */
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_CCMCTL, 0x14, 0x00);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_CCMCTL, 0x10, 0x00);

	/* PCIe lanes configuration */
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_GIOCTL, 0x00, 0xec);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_GIOCTL, 0x61, 0xdf);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_GIOCTL, 0x34, 0x05);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_GIOCTL, 0x2f, 0x81);

	/* PCIe PLL Configuration */
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCCTL, 0x02, 0x47);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCCTL, 0x14, 0x00);
	wm_82575_write_8bit_ctlr_reg(sc, WMREG_SCCTL, 0x10, 0x00);
}

static void
wm_reset_mdicnfg_82580(struct wm_softc *sc)
{
	uint32_t reg;
	uint16_t nvmword;
	int rv;

	if (sc->sc_type != WM_T_82580)
		return;
	if ((sc->sc_flags & WM_F_SGMII) == 0)
		return;

	rv = wm_nvm_read(sc, NVM_OFF_LAN_FUNC_82580(sc->sc_funcid)
	    + NVM_OFF_CFG3_PORTA, 1, &nvmword);
	if (rv != 0) {
		aprint_error_dev(sc->sc_dev, "%s: failed to read NVM\n",
		    __func__);
		return;
	}

	reg = CSR_READ(sc, WMREG_MDICNFG);
	if (nvmword & NVM_CFG3_PORTA_EXT_MDIO)
		reg |= MDICNFG_DEST;
	if (nvmword & NVM_CFG3_PORTA_COM_MDIO)
		reg |= MDICNFG_COM_MDIO;
	CSR_WRITE(sc, WMREG_MDICNFG, reg);
}

#define MII_INVALIDID(x)	(((x) == 0x0000) || ((x) == 0xffff))

static bool
wm_phy_is_accessible_pchlan(struct wm_softc *sc)
{
	uint32_t reg;
	uint16_t id1, id2;
	int i, rv;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT(CSR_READ(sc, WMREG_EXTCNFCTR) & EXTCNFCTR_MDIO_SW_OWNERSHIP);

	id1 = id2 = 0xffff;
	for (i = 0; i < 2; i++) {
		rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, MII_PHYIDR1,
		    &id1);
		if ((rv != 0) || MII_INVALIDID(id1))
			continue;
		rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, MII_PHYIDR2,
		    &id2);
		if ((rv != 0) || MII_INVALIDID(id2))
			continue;
		break;
	}
	if ((rv == 0) && !MII_INVALIDID(id1) && !MII_INVALIDID(id2))
		goto out;

	/*
	 * In case the PHY needs to be in mdio slow mode,
	 * set slow mode and try to get the PHY id again.
	 */
	rv = 0;
	if (sc->sc_type < WM_T_PCH_LPT) {
		wm_set_mdio_slow_mode_hv_locked(sc);
		rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2, MII_PHYIDR1,
		    &id1);
		rv |= wm_gmii_hv_readreg_locked(sc->sc_dev, 2, MII_PHYIDR2,
		    &id2);
	}
	if ((rv != 0) || MII_INVALIDID(id1) || MII_INVALIDID(id2)) {
		device_printf(sc->sc_dev, "XXX return with false\n");
		return false;
	}
out:
	if (sc->sc_type >= WM_T_PCH_LPT) {
		/* Only unforce SMBus if ME is not active */
		if ((CSR_READ(sc, WMREG_FWSM) & FWSM_FW_VALID) == 0) {
			uint16_t phyreg;

			/* Unforce SMBus mode in PHY */
			rv = wm_gmii_hv_readreg_locked(sc->sc_dev, 2,
			    CV_SMB_CTRL, &phyreg);
			phyreg &= ~CV_SMB_CTRL_FORCE_SMBUS;
			wm_gmii_hv_writereg_locked(sc->sc_dev, 2,
			    CV_SMB_CTRL, phyreg);

			/* Unforce SMBus mode in MAC */
			reg = CSR_READ(sc, WMREG_CTRL_EXT);
			reg &= ~CTRL_EXT_FORCE_SMBUS;
			CSR_WRITE(sc, WMREG_CTRL_EXT, reg);
		}
	}
	return true;
}

static void
wm_toggle_lanphypc_pch_lpt(struct wm_softc *sc)
{
	uint32_t reg;
	int i;

	/* Set PHY Config Counter to 50msec */
	reg = CSR_READ(sc, WMREG_FEXTNVM3);
	reg &= ~FEXTNVM3_PHY_CFG_COUNTER_MASK;
	reg |= FEXTNVM3_PHY_CFG_COUNTER_50MS;
	CSR_WRITE(sc, WMREG_FEXTNVM3, reg);

	/* Toggle LANPHYPC */
	reg = CSR_READ(sc, WMREG_CTRL);
	reg |= CTRL_LANPHYPC_OVERRIDE;
	reg &= ~CTRL_LANPHYPC_VALUE;
	CSR_WRITE(sc, WMREG_CTRL, reg);
	CSR_WRITE_FLUSH(sc);
	delay(1000);
	reg &= ~CTRL_LANPHYPC_OVERRIDE;
	CSR_WRITE(sc, WMREG_CTRL, reg);
	CSR_WRITE_FLUSH(sc);

	if (sc->sc_type < WM_T_PCH_LPT)
		delay(50 * 1000);
	else {
		i = 20;

		do {
			delay(5 * 1000);
		} while (((CSR_READ(sc, WMREG_CTRL_EXT) & CTRL_EXT_LPCD) == 0)
		    && i--);

		delay(30 * 1000);
	}
}

static int
wm_platform_pm_pch_lpt(struct wm_softc *sc, bool link)
{
	uint32_t reg = __SHIFTIN(link, LTRV_NONSNOOP_REQ)
	    | __SHIFTIN(link, LTRV_SNOOP_REQ) | LTRV_SEND;
	uint32_t rxa;
	uint16_t scale = 0, lat_enc = 0;
	int32_t obff_hwm = 0;
	int64_t lat_ns, value;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));

	if (link) {
		uint16_t max_snoop, max_nosnoop, max_ltr_enc;
		uint32_t status;
		uint16_t speed;
		pcireg_t preg;

		status = CSR_READ(sc, WMREG_STATUS);
		switch (__SHIFTOUT(status, STATUS_SPEED)) {
		case STATUS_SPEED_10:
			speed = 10;
			break;
		case STATUS_SPEED_100:
			speed = 100;
			break;
		case STATUS_SPEED_1000:
			speed = 1000;
			break;
		default:
			device_printf(sc->sc_dev, "Unknown speed "
			    "(status = %08x)\n", status);
			return -1;
		}

		/* Rx Packet Buffer Allocation size (KB) */
		rxa = CSR_READ(sc, WMREG_PBA) & PBA_RXA_MASK;

		/*
		 * Determine the maximum latency tolerated by the device.
		 *
		 * Per the PCIe spec, the tolerated latencies are encoded as
		 * a 3-bit encoded scale (only 0-5 are valid) multiplied by
		 * a 10-bit value (0-1023) to provide a range from 1 ns to
		 * 2^25*(2^10-1) ns.  The scale is encoded as 0=2^0ns,
		 * 1=2^5ns, 2=2^10ns,...5=2^25ns.
		 */
		lat_ns = ((int64_t)rxa * 1024 -
		    (2 * ((int64_t)sc->sc_ethercom.ec_if.if_mtu
			+ ETHER_HDR_LEN))) * 8 * 1000;
		if (lat_ns < 0)
			lat_ns = 0;
		else
			lat_ns /= speed;
		value = lat_ns;

		while (value > LTRV_VALUE) {
			scale ++;
			value = howmany(value, __BIT(5));
		}
		if (scale > LTRV_SCALE_MAX) {
			device_printf(sc->sc_dev,
			    "Invalid LTR latency scale %d\n", scale);
			return -1;
		}
		lat_enc = (uint16_t)(__SHIFTIN(scale, LTRV_SCALE) | value);

		/* Determine the maximum latency tolerated by the platform */
		preg = pci_conf_read(sc->sc_pc, sc->sc_pcitag,
		    WM_PCI_LTR_CAP_LPT);
		max_snoop = preg & 0xffff;
		max_nosnoop = preg >> 16;

		max_ltr_enc = MAX(max_snoop, max_nosnoop);

		if (lat_enc > max_ltr_enc) {
			lat_enc = max_ltr_enc;
			lat_ns = __SHIFTOUT(lat_enc, PCI_LTR_MAXSNOOPLAT_VAL)
			    * PCI_LTR_SCALETONS(
				    __SHIFTOUT(lat_enc,
					PCI_LTR_MAXSNOOPLAT_SCALE));
		}

		if (lat_ns) {
			lat_ns *= speed * 1000;
			lat_ns /= 8;
			lat_ns /= 1000000000;
			obff_hwm = (int32_t)(rxa - lat_ns);
		}
		if ((obff_hwm < 0) || (obff_hwm > SVT_OFF_HWM)) {
			device_printf(sc->sc_dev, "Invalid high water mark %d"
			    "(rxa = %d, lat_ns = %d)\n",
			    obff_hwm, (int32_t)rxa, (int32_t)lat_ns);
			return -1;
		}
	}
	/* Snoop and No-Snoop latencies the same */
	reg |= lat_enc | __SHIFTIN(lat_enc, LTRV_NONSNOOP);
	CSR_WRITE(sc, WMREG_LTRV, reg);

	/* Set OBFF high water mark */
	reg = CSR_READ(sc, WMREG_SVT) & ~SVT_OFF_HWM;
	reg |= obff_hwm;
	CSR_WRITE(sc, WMREG_SVT, reg);

	/* Enable OBFF */
	reg = CSR_READ(sc, WMREG_SVCR);
	reg |= SVCR_OFF_EN | SVCR_OFF_MASKINT;
	CSR_WRITE(sc, WMREG_SVCR, reg);

	return 0;
}

/*
 * I210 Errata 25 and I211 Errata 10
 * Slow System Clock.
 *
 * Note that this function is called on both FLASH and iNVM case on NetBSD.
 */
static int
wm_pll_workaround_i210(struct wm_softc *sc)
{
	uint32_t mdicnfg, wuc;
	uint32_t reg;
	pcireg_t pcireg;
	uint32_t pmreg;
	uint16_t nvmword, tmp_nvmword;
	uint16_t phyval;
	bool wa_done = false;
	int i, rv = 0;

	/* Get Power Management cap offset */
	if (pci_get_capability(sc->sc_pc, sc->sc_pcitag, PCI_CAP_PWRMGMT,
	    &pmreg, NULL) == 0)
		return -1;

	/* Save WUC and MDICNFG registers */
	wuc = CSR_READ(sc, WMREG_WUC);
	mdicnfg = CSR_READ(sc, WMREG_MDICNFG);

	reg = mdicnfg & ~MDICNFG_DEST;
	CSR_WRITE(sc, WMREG_MDICNFG, reg);

	if (wm_nvm_read(sc, INVM_AUTOLOAD, 1, &nvmword) != 0) {
		/*
		 * The default value of the Initialization Control Word 1
		 * is the same on both I210's FLASH_HW and I21[01]'s iNVM.
		 */
		nvmword = INVM_DEFAULT_AL;
	}
	tmp_nvmword = nvmword | INVM_PLL_WO_VAL;

	for (i = 0; i < WM_MAX_PLL_TRIES; i++) {
		wm_gmii_gs40g_readreg(sc->sc_dev, 1,
		    GS40G_PHY_PLL_FREQ_PAGE | GS40G_PHY_PLL_FREQ_REG, &phyval);

		if ((phyval & GS40G_PHY_PLL_UNCONF) != GS40G_PHY_PLL_UNCONF) {
			rv = 0;
			break; /* OK */
		} else
			rv = -1;

		wa_done = true;
		/* Directly reset the internal PHY */
		reg = CSR_READ(sc, WMREG_CTRL);
		CSR_WRITE(sc, WMREG_CTRL, reg | CTRL_PHY_RESET);

		reg = CSR_READ(sc, WMREG_CTRL_EXT);
		reg |= CTRL_EXT_PHYPDEN | CTRL_EXT_SDLPE;
		CSR_WRITE(sc, WMREG_CTRL_EXT, reg);

		CSR_WRITE(sc, WMREG_WUC, 0);
		reg = (INVM_AUTOLOAD << 4) | (tmp_nvmword << 16);
		CSR_WRITE(sc, WMREG_EEARBC_I210, reg);

		pcireg = pci_conf_read(sc->sc_pc, sc->sc_pcitag,
		    pmreg + PCI_PMCSR);
		pcireg |= PCI_PMCSR_STATE_D3;
		pci_conf_write(sc->sc_pc, sc->sc_pcitag,
		    pmreg + PCI_PMCSR, pcireg);
		delay(1000);
		pcireg &= ~PCI_PMCSR_STATE_D3;
		pci_conf_write(sc->sc_pc, sc->sc_pcitag,
		    pmreg + PCI_PMCSR, pcireg);

		reg = (INVM_AUTOLOAD << 4) | (nvmword << 16);
		CSR_WRITE(sc, WMREG_EEARBC_I210, reg);

		/* Restore WUC register */
		CSR_WRITE(sc, WMREG_WUC, wuc);
	}

	/* Restore MDICNFG setting */
	CSR_WRITE(sc, WMREG_MDICNFG, mdicnfg);
	if (wa_done)
		aprint_verbose_dev(sc->sc_dev, "I210 workaround done\n");
	return rv;
}

static void
wm_legacy_irq_quirk_spt(struct wm_softc *sc)
{
	uint32_t reg;

	DPRINTF(sc, WM_DEBUG_INIT, ("%s: %s called\n",
		device_xname(sc->sc_dev), __func__));
	KASSERT((sc->sc_type == WM_T_PCH_SPT)
	    || (sc->sc_type == WM_T_PCH_CNP) || (sc->sc_type == WM_T_PCH_TGP));

	reg = CSR_READ(sc, WMREG_FEXTNVM7);
	reg |= FEXTNVM7_SIDE_CLK_UNGATE;
	CSR_WRITE(sc, WMREG_FEXTNVM7, reg);

	reg = CSR_READ(sc, WMREG_FEXTNVM9);
	reg |= FEXTNVM9_IOSFSB_CLKGATE_DIS | FEXTNVM9_IOSFSB_CLKREQ_DIS;
	CSR_WRITE(sc, WMREG_FEXTNVM9, reg);
}

/* Sysctl functions */
static int
wm_sysctl_tdh_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct wm_txqueue *txq = (struct wm_txqueue *)node.sysctl_data;
	struct wm_queue *wmq = container_of(txq, struct wm_queue, wmq_txq);
	struct wm_softc *sc = txq->txq_sc;
	uint32_t reg;

	reg = CSR_READ(sc, WMREG_TDH(wmq->wmq_id));
	node.sysctl_data = &reg;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

static int
wm_sysctl_tdt_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct wm_txqueue *txq = (struct wm_txqueue *)node.sysctl_data;
	struct wm_queue *wmq = container_of(txq, struct wm_queue, wmq_txq);
	struct wm_softc *sc = txq->txq_sc;
	uint32_t reg;

	reg = CSR_READ(sc, WMREG_TDT(wmq->wmq_id));
	node.sysctl_data = &reg;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

#ifdef WM_DEBUG
static int
wm_sysctl_debug(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct wm_softc *sc = (struct wm_softc *)node.sysctl_data;
	uint32_t dflags;
	int error;

	dflags = sc->sc_debug;
	node.sysctl_data = &dflags;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error || newp == NULL)
		return error;

	sc->sc_debug = dflags;
	device_printf(sc->sc_dev, "TARC0: %08x\n", CSR_READ(sc, WMREG_TARC0));
	device_printf(sc->sc_dev, "TDT0: %08x\n", CSR_READ(sc, WMREG_TDT(0)));

	return 0;
}
#endif
