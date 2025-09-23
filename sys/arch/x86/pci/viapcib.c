/* $NetBSD: viapcib.c,v 1.20 2025/09/15 13:23:01 thorpej Exp $ */
/* $FreeBSD: src/sys/pci/viapm.c,v 1.10 2005/05/29 04:42:29 nyan Exp $ */

/*-
 * Copyright (c) 2005, 2006 Jared D. McNeill <jmcneill@invisible.ca>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions, and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*-
 * Copyright (c) 2001 Alcove - Nicolas Souchu
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: viapcib.c,v 1.20 2025/09/15 13:23:01 thorpej Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/mutex.h>
#include <sys/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/i2c/i2cvar.h>

#include <x86/pci/viapcibreg.h>
#include <x86/pci/pcibvar.h>

/*#define VIAPCIB_DEBUG*/

#ifdef	VIAPCIB_DEBUG
#define	DPRINTF(x)	printf x
#else
#define	DPRINTF(x)
#endif

struct viapcib_softc {
	/* we call pcibattach(), which assumes softc starts like this: */
	struct pcib_softc sc_pcib;
};

static int	viapcib_match(device_t, cfdata_t, void *);
static void	viapcib_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(viapcib, sizeof(struct viapcib_softc),
    viapcib_match, viapcib_attach, NULL, NULL);

static int
viapcib_match(device_t parent, cfdata_t match, void *opaque)
{
	struct pci_attach_args *pa = opaque;

	if (PCI_VENDOR(pa->pa_id) != PCI_VENDOR_VIATECH)
		return 0;

	switch (PCI_PRODUCT(pa->pa_id)) {
	case PCI_PRODUCT_VIATECH_VT8235:
	case PCI_PRODUCT_VIATECH_VT8237:
	case PCI_PRODUCT_VIATECH_VT8237A_ISA:
	case PCI_PRODUCT_VIATECH_VT8237S_ISA:
	case PCI_PRODUCT_VIATECH_VT8251:
	case PCI_PRODUCT_VIATECH_VT8261:
	case PCI_PRODUCT_VIATECH_CX700:
	case PCI_PRODUCT_VIATECH_VX800:
	case PCI_PRODUCT_VIATECH_VX855:
	case PCI_PRODUCT_VIATECH_VX900:
	//case PCI_PRODUCT_VIATECH_VX11_ISA:
		return 2; /* match above generic pcib(4) */
	}

	return 0;
}

static void
viapcib_attach(device_t parent, device_t self, void *opaque)
{
	struct pci_attach_args *pa = opaque;
	pcibattach(parent, self, opaque);
	
	/* Attach the VIA device bus (for SMBus etc.) */
	config_found(self, pa, NULL, CFARGS(.iattr = "viadevbus"));
}
