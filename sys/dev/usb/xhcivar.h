/*	$NetBSD: xhcivar.h,v 1.25 2025/01/30 00:42:47 jmcneill Exp $	*/

/*
 * Copyright (c) 2013 Jonathan A. Kollasch
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEV_USB_XHCIVAR_H_
#define _DEV_USB_XHCIVAR_H_

#include <sys/types.h>

#include <sys/condvar.h>
#include <sys/device.h>
#include <sys/mutex.h>
#include <sys/pmf.h>
#include <sys/pool.h>

#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>

#define XHCI_MAX_DCI	31

struct xhci_soft_trb {
	uint64_t trb_0;
	uint32_t trb_2;
	uint32_t trb_3;
};

struct xhci_xfer {
	struct usbd_xfer xx_xfer;
	struct xhci_soft_trb *xx_trb;
	u_int xx_ntrb;
	u_int xx_isoc_done;
};

#define XHCI_BUS2SC(bus)	((bus)->ub_hcpriv)
#define XHCI_PIPE2SC(pipe)	XHCI_BUS2SC((pipe)->up_dev->ud_bus)
#define XHCI_XFER2SC(xfer)	XHCI_BUS2SC((xfer)->ux_bus)
#define XHCI_XFER2BUS(xfer)	((xfer)->ux_bus)
#define XHCI_XPIPE2SC(d)	XHCI_BUS2SC((d)->xp_pipe.up_dev->ud_bus)

#define XHCI_XFER2XXFER(xfer)	((struct xhci_xfer *)(xfer))

struct xhci_ring {
	usb_dma_t xr_dma;
	kmutex_t xr_lock;
	struct xhci_trb * xr_trb;
	void **xr_cookies;
	u_int xr_ntrb;			/* number of elements for above */
	u_int xr_ep;			/* enqueue pointer */
	u_int xr_cs;			/* cycle state */
	bool is_halted;
};

struct xhci_slot {
	usb_dma_t xs_dc_dma;		/* device context page */
	usb_dma_t xs_ic_dma;		/* input context page */
	struct xhci_ring *xs_xr[XHCI_MAX_DCI + 1];
					/* transfer rings */
	u_int xs_idx;			/* slot index */
};

struct xhci_softc {
	device_t sc_dev;
	device_t sc_child;
	device_t sc_child2;
	bus_size_t sc_ios;
	bus_space_tag_t sc_iot;
	bus_space_handle_t sc_ioh;	/* Base */
	bus_space_handle_t sc_cbh;	/* Capability Base */
	bus_space_handle_t sc_obh;	/* Operational Base */
	bus_space_handle_t sc_rbh;	/* Runtime Base */
	bus_space_handle_t sc_dbh;	/* Doorbell Registers */
	struct usbd_bus sc_bus;		/* USB 3 bus */
	struct usbd_bus sc_bus2;	/* USB 2 bus */

	kmutex_t sc_rhlock;
	kmutex_t sc_lock;
	kmutex_t sc_intr_lock;

	pool_cache_t sc_xferpool;

	bus_size_t sc_pgsz;		/* xHCI page size */
	uint32_t sc_ctxsz;
	int sc_maxslots;
	int sc_maxintrs;
	int sc_maxspbuf;

	/*
	 * Port routing and root hub - xHCI 4.19.7
	 */
	int sc_maxports;		/* number of controller ports */
	int sc_usb3nports;
	int sc_usb2nports;

	uint8_t *sc_ctlrportbus;	/* a bus bit per port */

	int *sc_ctlrportmap;
	int *sc_rhportmap[2];
	int sc_rhportcount[2];
	struct usbd_xfer *sc_intrxfer[2];
	bool sc_intrxfer_deferred[2];

	struct xhci_slot * sc_slots;

	struct xhci_ring *sc_cr;	/* command ring */
	struct xhci_ring *sc_er;	/* event ring */

	usb_dma_t sc_eventst_dma;
	usb_dma_t sc_dcbaa_dma;
	usb_dma_t sc_spbufarray_dma;
	usb_dma_t *sc_spbuf_dma;

	kcondvar_t sc_cmdbusy_cv;
	kcondvar_t sc_command_cv;
	bus_addr_t sc_command_addr;
	struct xhci_soft_trb sc_result_trb;
	bool sc_resultpending;

	bool sc_dying;
	bool sc_suspendresume_failed;
	struct lwp *sc_suspender;

	void (*sc_vendor_init)(struct xhci_softc *);
	int (*sc_vendor_port_status)(struct xhci_softc *, uint32_t, int);

	int sc_quirks;
#define XHCI_QUIRK_INTEL	__BIT(0) /* Intel xhci chip */
#define XHCI_DEFERRED_START	__BIT(1)
#define XHCI_32BIT_ACCESS	__BIT(2)
	uint32_t sc_hcc;		/* copy of HCCPARAMS1 */
	uint32_t sc_hcc2;		/* copy of HCCPARAMS2 */

	struct xhci_registers {
		uint32_t	usbcmd;
		uint32_t	dnctrl;
		uint64_t	dcbaap;
		uint32_t	config;
		uint32_t	erstsz0;
		uint64_t	erstba0;
		uint64_t	erdp0;
		uint32_t	iman0;
		uint32_t	imod0;
	} sc_regs;
};

int	xhci_init(struct xhci_softc *);
void	xhci_start(struct xhci_softc *);
int	xhci_intr(void *);
int	xhci_detach(struct xhci_softc *, int);
int	xhci_activate(device_t, enum devact);
void	xhci_childdet(device_t, device_t);
bool	xhci_suspend(device_t, const pmf_qual_t *);
bool	xhci_resume(device_t, const pmf_qual_t *);
bool	xhci_shutdown(device_t, int);

#define XHCI_TRANSFER_RING_TRBS 256

#endif /* _DEV_USB_XHCIVAR_H_ */
