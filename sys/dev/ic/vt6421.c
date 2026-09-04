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

#include <sys/param.h>
#include <sys/systm.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pciidereg.h>
#include <dev/pci/pciidevar.h>
#include <dev/pci/pciide_apollo_reg.h>

#include "vt6421var.h"

void
vt6421_mapreg_dma(struct pciide_softc *sc, bus_dma_tag_t sc_dmat)
{
	struct pciide_channel *pc;
	int chan, reg;
	bus_size_t size;

	sc->sc_dmat = sc_dmat;
	if (sc->sc_dma_ok == 0) {
		aprint_verbose(", but unused (couldn't map registers)");
	} else {
		sc->sc_wdcdev.dma_arg = sc;
		sc->sc_wdcdev.dma_init = pciide_dma_init;
		sc->sc_wdcdev.dma_start = pciide_dma_start;
		sc->sc_wdcdev.dma_finish = pciide_dma_finish;
	}

	if (device_cfdata(sc->sc_wdcdev.sc_atac.atac_dev)->cf_flags &
	    PCIIDE_OPTIONS_NODMA) {
		aprint_verbose(
		    ", but unused (forced off by config file)");
		sc->sc_dma_ok = 0;
	}

	if (sc->sc_dma_ok == 0)
		return;

	for (chan = 0; chan < 4; chan++) {
		pc = &sc->pciide_channels[chan];
		for (reg = 0; reg < IDEDMA_NREGS; reg++) {
			size = 4;
			if (size > (IDEDMA_SCH_OFFSET - reg))
				size = IDEDMA_SCH_OFFSET - reg;
			if (bus_space_subregion(sc->sc_dma_iot, sc->sc_dma_ioh,
			    IDEDMA_SCH_OFFSET * chan + reg, size,
			    &pc->dma_iohs[reg]) != 0) {
				sc->sc_dma_ok = 0;
				aprint_verbose(", but can't subregion offset "
				               "%d size %lu",
					       reg, (u_long)size);
				return;
			}
		}
	}
}

static int
via_vt6421_chansetup(struct pciide_softc *sc, int channel)
{
	struct pciide_channel *cp = &sc->pciide_channels[channel];

	sc->wdc_chanarray[channel] = &cp->ata_channel;

	cp->ata_channel.ch_channel = channel;
	cp->ata_channel.ch_atac = &sc->sc_wdcdev.sc_atac;

	return 1;
}

void
vt6421_chip_map(struct pciide_softc *sc, struct vt6421_chan_handler *chan_handler)
{
	struct pciide_channel *cp;
	struct ata_channel *wdc_cp;
	struct wdc_regs *wdr;
	int channel;
	int i;

	sc->sc_apo_regbase = APO_VIA_VT6421_REGBASE;

	sc->sc_wdcdev.sc_atac.atac_cap |= ATAC_CAP_DATA16 | ATAC_CAP_DATA32;
	sc->sc_wdcdev.sc_atac.atac_pio_cap = 4;
	if (sc->sc_dma_ok) {
		sc->sc_wdcdev.sc_atac.atac_cap |= ATAC_CAP_DMA | ATAC_CAP_UDMA;
		sc->sc_wdcdev.irqack = pciide_irqack;
		sc->sc_wdcdev.sc_atac.atac_dma_cap = 2;
		sc->sc_wdcdev.sc_atac.atac_udma_cap = 6;
	}
	sc->sc_wdcdev.sc_atac.atac_set_modes = sata_setup_channel;

	sc->sc_wdcdev.sc_atac.atac_channels = sc->wdc_chanarray;
	sc->sc_wdcdev.sc_atac.atac_nchannels = VT6421_NCHANNELS;
	sc->sc_wdcdev.wdc_maxdrives = 2;

	wdc_allocate_regs(&sc->sc_wdcdev);

	for (channel = 0; channel < sc->sc_wdcdev.sc_atac.atac_nchannels;
	     channel++) {
		cp = &sc->pciide_channels[channel];
		if (via_vt6421_chansetup(sc, channel) == 0)
			continue;
		wdc_cp = &cp->ata_channel;
		wdr = CHAN_TO_WDC_REGS(wdc_cp);

		wdr->sata_iot = sc->sc_ba5_st;
		wdr->sata_baseioh = sc->sc_ba5_sh;
		if (bus_space_subregion(wdr->sata_iot, wdr->sata_baseioh,
		    (wdc_cp->ch_channel << 6) + 0x0, 4,
		    &wdr->sata_status) != 0) {
			aprint_error_dev(sc->sc_wdcdev.sc_atac.atac_dev,
			    "couldn't map channel %d sata_status regs\n",
			    wdc_cp->ch_channel);
			continue;
		}
		if (bus_space_subregion(wdr->sata_iot, wdr->sata_baseioh,
		    (wdc_cp->ch_channel << 6) + 0x4, 4,
		    &wdr->sata_error) != 0) {
			aprint_error_dev(sc->sc_wdcdev.sc_atac.atac_dev,
			    "couldn't map channel %d sata_error regs\n",
			    wdc_cp->ch_channel);
			continue;
		}
		if (bus_space_subregion(wdr->sata_iot, wdr->sata_baseioh,
		    (wdc_cp->ch_channel << 6) + 0x8, 4,
		    &wdr->sata_control) != 0) {
			aprint_error_dev(sc->sc_wdcdev.sc_atac.atac_dev,
			    "couldn't map channel %d sata_control regs\n",
			    wdc_cp->ch_channel);
			continue;
		}
		

		wdr->cmd_iot = chan_handler[channel].sc_cmd_st;
		wdr->cmd_baseioh = chan_handler[channel].sc_cmd_sh;
		wdr->cmd_ios = chan_handler[channel].sc_cmd_ios;

		wdr->ctl_iot = wdr->cmd_iot;
		for (i = 0; i < WDC_NREG; i++) {
			if (bus_space_subregion(wdr->cmd_iot,
			    wdr->cmd_baseioh, i, i == 0 ? 4 : 1,
			    &wdr->cmd_iohs[i]) != 0) {
				aprint_error_dev(
				    sc->sc_wdcdev.sc_atac.atac_dev,
				    "couldn't subregion channel %d "
				    "cmd regs\n", channel);
				return;
			}
		}
		if (bus_space_subregion(wdr->cmd_iot, wdr->cmd_baseioh,
		    WDC_NREG + 2, 1,  &wdr->ctl_ioh) != 0) {
			aprint_error_dev(sc->sc_wdcdev.sc_atac.atac_dev,
			    "couldn't map channel %d ctl regs\n", channel);
			return;
		}
		wdc_init_shadow_regs(wdr);
		wdr->data32iot = wdr->cmd_iot;
		wdr->data32ioh = wdr->cmd_iohs[wd_data];
		wdcattach(wdc_cp);
	}
}