/* $NetBSD$ */

/*
 * Copyright (c) 2006 Manuel Bouyer.
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

/*
 * Copyright (c) 2007, 2008 Jonathan A. Kollasch.
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
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <dev/cardbus/cardbusvar.h>
#include <dev/pci/pcidevs.h>
#include <dev/pci/pciidereg.h>
#include <dev/pci/pciidevar.h>

struct viaide_cardbus_softc {
	struct pciide_softc si_sc;
	cardbus_chipset_tag_t sc_cc;
	cardbus_function_tag_t sc_cf;
	cardbus_devfunc_t sc_ct;
	pcitag_t sc_tag;
	bus_space_tag_t sc_iot;		/* CardBus I/O space tag */
	bus_space_tag_t sc_memt;	/* CardBus MEM space tag */
	rbus_tag_t sc_rbus_iot;		/* CardBus i/o rbus tag */
	rbus_tag_t sc_rbus_memt;	/* CardBus mem rbus tag */

	bus_size_t sc_grsize;
	bus_size_t sc_prsize;
	void *sc_ih;
};

static int viaide_cardbus_match(device_t, cfdata_t, void *);
static void viaide_cardbus_attach(device_t, device_t, void *);
static int viaide_cardbus_detach(device_t, int);
static bool viaide_cardbus_resume(device_t, const pmf_qual_t *);
void via_sata_chip_map_new(struct pciide_softc *sc, const struct pci_attach_args *pa);

static const struct pciide_product_desc  viaide_cardbus_products[] = {
	{ PCI_PRODUCT_VIATECH_VT6421_RAID,
	  0,
	  "VIA Technologies VT6421 Serial ATA RAID Controller",
	  via_sata_chip_map_new
	},
	{ 0,
	  0,
	  NULL,
	  NULL
	},
};

CFATTACH_DECL_NEW(viaide_cardbus, sizeof(struct viaide_cardbus_softc),
    viaide_cardbus_match, viaide_cardbus_attach, viaide_cardbus_detach,
    NULL);

static const struct pciide_product_desc *
viaide_cardbus_lookup(const struct cardbus_attach_args *ca)
{
	pcireg_t ca_id;
	pci_product_id_t ca_product;
	pci_class_t ca_class;
	
	ca_id = PCI_VENDOR(ca->ca_id);
	ca_product = PCI_PRODUCT(ca->ca_id);
	ca_class = PCI_CLASS(ca->ca_class);

	aprint_debug("VIA cardbus lookup 0x%04x 0x%04x\n", ca_id, ca_product);

	if (ca_id == PCI_VENDOR_VIATECH && ca_class == PCI_CLASS_MASS_STORAGE)
		return pciide_lookup_product(ca->ca_id, viaide_cardbus_products);

	return NULL;
}

static int
viaide_cardbus_match(device_t parent, cfdata_t match, void *aux)
{
	struct cardbus_attach_args *ca = aux;

	if (viaide_cardbus_lookup(ca) != NULL)
		return 2;

	return 0;
}

static void
viaide_cardbus_attach(device_t parent, device_t self, void *aux)
{
	struct cardbus_attach_args *ca = aux;
	struct viaide_cardbus_softc *csc = device_private(self);
	struct pciide_softc *sc = &csc->si_sc;
	static struct pci_attach_args *pca;
	cardbus_devfunc_t ct = ca->ca_ct;
	cardbus_chipset_tag_t cc = ct->ct_cc;
	cardbus_function_tag_t cf = ct->ct_cf;
	pcireg_t reg;
	int csr;
	char devinfo[256];
	
	csc->sc_cc = cc;
	csc->sc_cf = cf;
	csc->sc_ct = ct;
	csc->sc_tag = ca->ca_tag;

	sc->sc_wdcdev.sc_atac.atac_dev = self;

	/*
	 * Map the device.
	 */
	csr = PCI_COMMAND_MASTER_ENABLE;
  
	/* Enable the appropriate bits in the PCI CSR. */
	reg = Cardbus_conf_read(ct, ca->ca_tag, PCI_COMMAND_STATUS_REG);
	reg &= ~(PCI_COMMAND_IO_ENABLE|PCI_COMMAND_MEM_ENABLE);
	reg |= csr;
	Cardbus_conf_write(ct, ca->ca_tag, PCI_COMMAND_STATUS_REG, reg);

	csc->sc_iot = ca->ca_iot;
	csc->sc_memt = ca->ca_memt;
	csc->sc_rbus_iot = ca->ca_rbus_iot;
	csc->sc_rbus_memt = ca->ca_rbus_memt;
	csc->sc_tag = ca->ca_tag;

	pci_devinfo(ca->ca_id, ca->ca_class, 0, devinfo, sizeof(devinfo));
	aprint_naive(": SATA HBA\n");
	aprint_normal(": %s\n", devinfo);

	/* map interrupt */
	csc->sc_ih = Cardbus_intr_establish(ct, IPL_BIO, pciide_pci_intr, sc);
	const struct pciide_product_desc * pp = viaide_cardbus_lookup(ca);
	pca = malloc(sizeof(struct pci_attach_args), M_DEVBUF, M_WAIT|M_ZERO);
	pca->pa_bus = ca->ca_bus;
	pca->pa_iot = ca->ca_iot;
	pca->pa_memt = ca->ca_memt;
	pca->pa_dmat = ca->ca_dmat;
	pca->pa_tag = ca->ca_tag;
	pca->pa_function = ca->ca_function;
	pca->pa_class = ca->ca_class;
	pca->pa_id = ca->ca_id;
	pca->pa_device = ca->ca_cis.product;
	pca->pa_flags = ca->ca_cis.bar[5].flags;
	//pca->pa_flags |= PCI_FLAGS_IO_OKAY;

	pciide_common_attach(sc, pca, pp);

	if (!pmf_device_register(self, NULL, viaide_cardbus_resume))
		aprint_error_dev(self, "couldn't establish power handler\n");
}

static int
viaide_cardbus_detach(device_t self, int flags)
{
	struct viaide_cardbus_softc *csc = device_private(self);
	struct pciide_softc *sc = &csc->si_sc;
	struct cardbus_devfunc *ct = csc->sc_ct;
	int rv;

	rv = pciide_common_detach(sc, flags);
	if (rv)
		return (rv);
	if (csc->sc_ih != NULL) {
		Cardbus_intr_disestablish(ct, csc->sc_ih);
		csc->sc_ih = NULL;
	}
	free(sc, M_DEVBUF);

	return 0;
}

static bool
viaide_cardbus_resume(device_t dv, const pmf_qual_t *qual)
{
	/*struct viaide_cardbus_softc *csc = device_private(dv);
	struct pciide_softc *sc = &csc->si_sc;*/
	int s;

	s = splbio();
	//viaide_resume(sc);
	splx(s);
	
	return true;
}
