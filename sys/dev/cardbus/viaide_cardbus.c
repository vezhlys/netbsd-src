/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <dev/cardbus/cardbusvar.h>

#include <dev/pci/pcidevs.h>
#include <dev/pci/pciide_apollo_reg.h>
#include <dev/pci/pciidereg.h>
#include <dev/pci/pciidevar.h>

#include <dev/ic/vt6421var.h>

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
	void *sc_ih;
};

static int viaide_cardbus_match(device_t, cfdata_t, void *);
static void viaide_cardbus_attach(device_t, device_t, void *);
static int viaide_cardbus_detach(device_t, int);
static bool viaide_cardbus_suspend(device_t, const pmf_qual_t *);
static bool viaide_cardbus_resume(device_t, const pmf_qual_t *);
void via_sata_chip_map_new(struct pciide_softc *sc, const struct pci_attach_args *pa);

static const struct viaide_cardbus_product {

	uint32_t ide_product;
	const char *ide_name;
} viaide_cardbus_products[] = {
	{ PCI_PRODUCT_VIATECH_VT6421_RAID,
	  "VIA Technologies VT6421 Serial ATA Controller"
	},
	{ 0,
	  NULL
	},
};

CFATTACH_DECL_NEW(viaide_cardbus, sizeof(struct viaide_cardbus_softc),
    viaide_cardbus_match, viaide_cardbus_attach, viaide_cardbus_detach,
    NULL);

static const struct viaide_cardbus_product *
viaide_cardbus_lookup(const struct cardbus_attach_args *ca)
{
	const struct viaide_cardbus_product *vcp;

	for (vcp = viaide_cardbus_products; vcp->ide_product != 0; vcp++) {
		if (PCI_VENDOR(ca->ca_id) == PCI_VENDOR_VIATECH &&
		    PCI_PRODUCT(ca->ca_id) == vcp->ide_product)
			return vcp;
	}

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
	const struct cardbus_attach_args *ca = aux;
	const struct viaide_cardbus_product *vcp;
	struct viaide_cardbus_softc *csc = device_private(self);
	struct pciide_softc *sc = &csc->si_sc;
	cardbus_devfunc_t ct = ca->ca_ct;
	cardbus_chipset_tag_t cc = ct->ct_cc;
	cardbus_function_tag_t cf = ct->ct_cf;
	pcireg_t reg;
	struct vt6421_chan_handler chan_handlers[VT6421_NCHANNELS];
	struct vt6421_chan_handler *vch;
	int csr, channel;

	vcp = viaide_cardbus_lookup(ca);

	aprint_naive(": SATA HBA\n");
	aprint_normal(": %s\n", vcp->ide_name);

	/* Map I/O registers */
	csc->si_sc.sc_dma_ok = (Cardbus_mapreg_map(ct, PCIIDE_REG_BUS_MASTER_DMA,
                PCI_MAPREG_TYPE_IO, 0, &sc->sc_dma_iot, &sc->sc_dma_ioh, NULL, 
			    &sc->sc_dma_ios)  == 0);

	sc->sc_wdcdev.sc_atac.atac_dev = self;
	aprint_verbose_dev(self, "bus-master DMA support present");
	vt6421_mapreg_dma(sc, ca->ca_dmat);
	aprint_verbose("\n");

	if (Cardbus_mapreg_map(ct, PCI_BAR5, PCI_MAPREG_TYPE_IO, 0,
			   &sc->sc_ba5_st, &sc->sc_ba5_sh, NULL, &sc->sc_ba5_ss)) {
		aprint_error_dev(self, "couldn't map SATA regs\n");
		return;
	}

	csc->sc_cc = cc;
	csc->sc_cf = cf;
	csc->sc_ct = ct;
	csc->sc_tag = ca->ca_tag;

#if NATA_DMA
	/* Set up DMA defaults; these might be adjusted by chip_map. */
	sc->sc_dma_maxsegsz = IDEDMA_BYTE_COUNT_MAX;
	sc->sc_dma_boundary = IDEDMA_BYTE_COUNT_ALIGN;
#endif

	/*
	 * Map the device.
	 */
	csr = PCI_COMMAND_MASTER_ENABLE;
  
	/* Enable the appropriate bits in the PCI CSR. */
	reg = Cardbus_conf_read(ct, ca->ca_tag, PCI_COMMAND_STATUS_REG);
	csr |= PCI_COMMAND_IO_ENABLE;
	csr |= PCI_COMMAND_MEM_ENABLE;
	reg |= csr;
	Cardbus_conf_write(ct, ca->ca_tag, PCI_COMMAND_STATUS_REG, reg);

	csc->sc_iot = ca->ca_iot;
	csc->sc_memt = ca->ca_memt;
	csc->sc_rbus_iot = ca->ca_rbus_iot;
	csc->sc_rbus_memt = ca->ca_rbus_memt;
	csc->sc_tag = ca->ca_tag;

	csc->sc_ih = Cardbus_intr_establish(ct, IPL_BIO, pciide_pci_intr, sc);
	csc->si_sc.sc_pci_ih = csc->sc_ih;

	for (channel = 0; channel < VT6421_NCHANNELS; channel++) {
		vch = &chan_handlers[channel];
		if (Cardbus_mapreg_map(ct, PCI_BAR(channel), PCI_MAPREG_TYPE_IO, 0,
			    &vch->sc_cmd_st, &vch->sc_cmd_sh, NULL, &vch->sc_cmd_ios) != 0)
			aprint_error_dev(sc->sc_wdcdev.sc_atac.atac_dev,
			    "couldn't map channel %d regs\n", channel);
	}

	vt6421_chip_map(sc, chan_handlers);

	if (!pmf_device_register(self, viaide_cardbus_suspend, viaide_cardbus_resume))
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
		csc->si_sc.sc_pci_ih = NULL;
	}

	return 0;
}

static bool
viaide_cardbus_suspend(device_t dv, const pmf_qual_t *qual)
{
	struct viaide_cardbus_softc *csc = device_private(dv);
	struct pciide_softc *sc = &csc->si_sc;
	struct cardbus_devfunc *ct = csc->sc_ct;
	int s;

	s = splvm();

	sc->sc_pm_reg[0] = Cardbus_conf_read(ct, csc->sc_tag, APO_IDECONF(sc));
	/* APO_DATATIM(sc) includes APO_UDMA(sc) */
	sc->sc_pm_reg[1] = Cardbus_conf_read(ct, csc->sc_tag, APO_DATATIM(sc));
	sc->sc_pm_reg[2] = Cardbus_conf_read(ct, csc->sc_tag, APO_CTLMISC(sc));
	sc->sc_pm_reg[3] = Cardbus_conf_read(ct, csc->sc_tag, APO_MISCTIM(sc));

	splx(s);

	return true;
}

static bool
viaide_cardbus_resume(device_t dv, const pmf_qual_t *qual)
{
	struct viaide_cardbus_softc *csc = device_private(dv);
	struct pciide_softc *sc = &csc->si_sc;
	struct cardbus_devfunc *ct = csc->sc_ct;
	int s;

	s = splvm();

	Cardbus_conf_write(ct, csc->sc_tag, APO_IDECONF(sc), sc->sc_pm_reg[0]);
	Cardbus_conf_write(ct, csc->sc_tag, APO_DATATIM(sc), sc->sc_pm_reg[1]);
	Cardbus_conf_write(ct, csc->sc_tag, APO_CTLMISC(sc), sc->sc_pm_reg[2]);
	Cardbus_conf_write(ct, csc->sc_tag, APO_MISCTIM(sc), sc->sc_pm_reg[3]);

	splx(s);

	return true;
}
