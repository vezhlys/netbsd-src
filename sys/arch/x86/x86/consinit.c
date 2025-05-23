/*	$NetBSD: consinit.c,v 1.41 2025/04/30 05:15:08 imil Exp $	*/

/*
 * Copyright (c) 1998
 *	Matthias Drochner.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: consinit.c,v 1.41 2025/04/30 05:15:08 imil Exp $");

#include "opt_kgdb.h"
#include "opt_puc.h"
#include "opt_xen.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <machine/bootinfo.h>
#include <arch/x86/include/genfb_machdep.h>

#include <dev/cons.h>

#include "nullcons.h"
#include "genfb.h"
#include "vga.h"
#include "ega.h"
#include "pcdisplay.h"
#include "com_puc.h"
#if (NVGA > 0) || (NEGA > 0) || (NPCDISPLAY > 0)
#include <dev/ic/mc6845reg.h>
#include <dev/ic/pcdisplayvar.h>
#if (NVGA > 0)
#include <dev/ic/vgareg.h>
#include <dev/ic/vgavar.h>
#endif
#if (NEGA > 0)
#include <dev/isa/egavar.h>
#endif
#if (NPCDISPLAY > 0)
#include <dev/isa/pcdisplayvar.h>
#endif
#endif

#include "pckbc.h"
#if (NPCKBC > 0)
#include <dev/isa/isareg.h>
#include <dev/ic/i8042reg.h>
#include <dev/ic/pckbcvar.h>
#include <dev/pckbport/pckbportvar.h>
#endif
#include "pckbd.h" /* for pckbc_machdep_cnattach */

#if (NGENFB > 0)
#include <dev/wsfb/genfbvar.h>
#endif

#include "com.h"
#if (NCOM > 0)
#include <sys/termios.h>
#include <dev/ic/comreg.h>
#include <dev/ic/comvar.h>
#endif
#if (NCOM_PUC > 0)
#include <dev/pci/puccn.h>
#endif

#include "ukbd.h"
#if (NUKBD > 0)
#include <dev/usb/ukbdvar.h>
#endif

#ifndef XENPV
#include "hvkbd.h"
#if NHVKBD > 0
#include <dev/hyperv/hvkbdvar.h>
#endif
#endif

#ifdef XENPVHVM
#include <xen/hypervisor.h>
#include <xen/xen.h>
#endif

#ifndef CONSDEVNAME
#define CONSDEVNAME "pc"
#endif

#if (NCOM > 0)
#ifndef CONADDR
#define CONADDR 0x3f8
#endif
#ifndef CONSPEED
#define CONSPEED TTYDEF_SPEED
#endif
#ifndef CONMODE
#define CONMODE ((TTYDEF_CFLAG & ~(CSIZE | CSTOPB | PARENB)) | CS8) /* 8N1 */
#endif
int comcnmode = CONMODE;
#endif /* NCOM */

const struct btinfo_console default_consinfo = {
	{0, 0},
	CONSDEVNAME,
#if (NCOM > 0)
	CONADDR, CONSPEED
#else
	0, 0
#endif
};

#ifdef KGDB
#ifndef KGDB_DEVNAME
#define KGDB_DEVNAME "com"
#endif
const char kgdb_devname[] = KGDB_DEVNAME;

#if (NCOM > 0)
#ifndef KGDB_DEVADDR
#define KGDB_DEVADDR 0x3f8
#endif
int comkgdbaddr = KGDB_DEVADDR;
#ifndef KGDB_DEVRATE
#define KGDB_DEVRATE TTYDEF_SPEED
#endif
int comkgdbrate = KGDB_DEVRATE;
#ifndef KGDB_DEVMODE
#define KGDB_DEVMODE ((TTYDEF_CFLAG & ~(CSIZE | CSTOPB | PARENB)) | CS8) /* 8N1 */
#endif
int comkgdbmode = KGDB_DEVMODE;
#endif /* NCOM */

#endif /* KGDB */

/*
 * consinit:
 * initialize the system console.
 * XXX - shouldn't deal with this initted thing, but then,
 * it shouldn't be called from init386 either.
 */
void
consinit(void)
{
	const struct btinfo_console *consinfo;
#if (NGENFB > 0)
	const struct btinfo_framebuffer *fbinfo = NULL;
#endif
	static int initted;
#if (NCOM > 0)
	int rv;
#endif
	char console_devname[16] = "";

#ifdef XENPVHVM
	if (vm_guest == VM_GUEST_XENPVH) {
		if (xen_pvh_consinit() != 0)
			return;
		/* fallback to native console selection, useful for dom0 PVH */
	}
	if (pvh_boot) { /* GENPVH */
		union xen_cmdline_parseinfo xcp;
		/* get console= parameter from generic PVH VMM */
		xen_parse_cmdline(XEN_PARSE_CONSOLE, &xcp);
		strncpy(console_devname, xcp.xcp_console,
			sizeof(console_devname));
	}
#endif
	if (initted)
		return;
	initted = 1;

#ifndef CONS_OVERRIDE
	consinfo = lookup_bootinfo(BTINFO_CONSOLE);
	if (!consinfo)
#endif
		consinfo = &default_consinfo;
	/* console= parameter was not passed via a generic PVH VMM */
	if (!console_devname[0])
		strncpy(console_devname, consinfo->devname,
			sizeof(console_devname));
#if (NGENFB > 0)
#if defined(XENPVHVM) && defined(DOM0OPS)
	if (vm_guest == VM_GUEST_XENPVH && xendomain_is_dom0())
		fbinfo = xen_genfb_getbtinfo();
	else
#endif /* XENPVHVM */
		fbinfo = lookup_bootinfo(BTINFO_FRAMEBUFFER);
#endif
	if (!strcmp(console_devname, "pc")) {
		int error;
#if (NGENFB > 0)
		if (fbinfo && fbinfo->physaddr > 0) {
			/*
			 * If we have a framebuffer address, and
			 * x86_genfb_cnattach can map it, then
			 * genfb_cnattach causes genfb_is_console to
			 * later return true.  device_pci_register will
			 * use this to set up the device properties for
			 * a PCI display-class device to notify it that
			 * it has been selected as the console.
			 */
			if (x86_genfb_cnattach() == -1) {
				initted = 0;	/* defer */
				return;
			}
			genfb_cnattach();
			goto dokbd;
		}
		genfb_disable();
#endif
#if (NVGA > 0)
		if (!vga_cnattach(x86_bus_space_io, x86_bus_space_mem,
				  -1, 1))
			goto dokbd;
#endif
#if (NEGA > 0)
		if (!ega_cnattach(x86_bus_space_io, x86_bus_space_mem))
			goto dokbd;
#endif
#if (NPCDISPLAY > 0)
		if (!pcdisplay_cnattach(x86_bus_space_io, x86_bus_space_mem))
			goto dokbd;
#endif
		if (0) goto dokbd; /* XXX stupid gcc */
dokbd:
		error = ENODEV;
#if (NPCKBC > 0)
		error = pckbc_cnattach(x86_bus_space_io, IO_KBD, KBCMDP,
		    PCKBC_KBD_SLOT, 0);
#endif
#if (NHVKBD > 0)
		if (error && vm_guest == VM_GUEST_HV)
			error = hvkbd_cnattach();
#endif
#if (NUKBD > 0)
		if (error)
			error = ukbd_cnattach();
#endif
		if (error)
			printf("WARNING: no console keyboard, error=%d\n",
			       error);
		return;
	}
#if (NCOM > 0)
	if (!strcmp(console_devname, "com")) {
		int addr = consinfo->addr;
		int speed = consinfo->speed;

#if (NCOM_PUC > 0) && defined(PUC_CNAUTO)
		puc_cnprobe(NULL);
		rv = puc_cninit(NULL);
		if (rv == 0)
			return;
#endif

		if (addr == 0)
			addr = CONADDR;
		if (speed == 0)
			speed = CONSPEED;

		rv = comcnattach(x86_bus_space_io, addr, speed,
				 COM_FREQ, COM_TYPE_NORMAL, comcnmode);
		if (rv != 0)
			panic("can't init serial console @%x", consinfo->addr);
		return;
	}
#endif
#if (NNULLCONS > 0)
	if (!strcmp(console_devname, "nullcons")) {
		void nullcninit(struct consdev *cn);

		nullcninit(0);
		return;
	}
#endif
	panic("invalid console device %s", console_devname);
}

#ifdef KGDB
void
kgdb_port_init(void)
{
#if (NCOM > 0)
	if (!strcmp(kgdb_devname, "com")) {
		com_kgdb_attach(x86_bus_space_io, comkgdbaddr, comkgdbrate,
		    COM_FREQ, COM_TYPE_NORMAL, comkgdbmode);
	}
#endif
}
#endif
