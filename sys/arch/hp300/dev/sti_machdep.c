/*	$NetBSD: sti_machdep.c,v 1.7 2025/05/31 03:05:25 tsutsui Exp $	*/
/*	$OpenBSD: sti_sgc.c,v 1.14 2007/05/26 00:36:03 krw Exp $	*/

/*
 * Copyright (c) 2005, Miodrag Vallat
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
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
/*-
 * Copyright (c) 2020, 2025 Izumi Tsutsui.  All rights reserved.
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
__KERNEL_RCSID(0, "$NetBSD: sti_machdep.c,v 1.7 2025/05/31 03:05:25 tsutsui Exp $");

#include <sys/param.h>
#include <sys/device.h>
#include <sys/bus.h>

#include <dev/wscons/wsconsio.h>

#include <hp300/dev/sti_machdep.h>

/*
 * 425e and 362/382 EVRX specific hardware
 */
/*
 * RAMDAC (Bt458) on 425e EVRX is found at offset 0x00060000 from SGC bus PA.
 * RAMDAC (Bt474) on 362/382 EVRX is also found at offset 0x00060000
 * from DIO scode (132) + STI_DIO_SCODE_OFFSET PA (i.e. 0x01800000).
 *
 * Offset 0x040000 length 0x1c0000 is mapped in MI sti via ROM region 2
 * on both 425e and 362/382.
 */
#define STI_EVRX_REGNO2OFFSET	0x00020000	/* 0x00060000 - 0x00040000 */

/* bitmap memory can be accessed at offset +0x200000 */
#define STI_EVRX_FBOFFSET	0x00200000

#define EVRX_BT458_ADDR		(STI_EVRX_REGNO2OFFSET + 0x200 + 2)
#define EVRX_BT458_CMAP		(STI_EVRX_REGNO2OFFSET + 0x204 + 2)
#define EVRX_BT458_CTRL		(STI_EVRX_REGNO2OFFSET + 0x208 + 2)
#define EVRX_BT458_OMAP		(STI_EVRX_REGNO2OFFSET + 0x20C + 2)

/* These registers are partially common between Bt474 and Bt458 */
#define EVRX_BT4xx_ADDR		EVRX_BT458_ADDR
#define EVRX_BT4xx_CMAP		EVRX_BT458_CMAP
#define EVRX_BT4xx_CTRL		EVRX_BT458_CTRL

/* from HP-UX /usr/lib/libddevrx.a */
#define EVRX_MAGIC00		(STI_EVRX_REGNO2OFFSET + 0x600)
#define EVRX_MAGIC04		(STI_EVRX_REGNO2OFFSET + 0x604)
#define EVRX_MAGIC08		(STI_EVRX_REGNO2OFFSET + 0x608)
#define EVRX_MAGIC0C		(STI_EVRX_REGNO2OFFSET + 0x60c)
#define EVRX_MAGIC10		(STI_EVRX_REGNO2OFFSET + 0x610)
#define EVRX_MAGIC10_BSY	0x00010000
#define EVRX_MAGIC18		(STI_EVRX_REGNO2OFFSET + 0x618)
#define EVRX_MAGIC1C		(STI_EVRX_REGNO2OFFSET + 0x61c)

/*
 * HP A1659A CRX specific hardware
 */
/* bitmap memory can be accessed at offset +0x1000000 */
#define STI_CRX_FBOFFSET	0x01000000

/* hp300 EVRX and CRX specific access functions */
static int sti_evrx_putcmap(struct sti_screen *, u_int, u_int);
static void sti_evrx_resetramdac(struct sti_screen *);
static void sti_evrx_resetcmap(struct sti_screen *);
static void sti_evrx_setupfb(struct sti_screen *);
static paddr_t sti_m68k_mmap(void *, void *, off_t, int);

static struct bus_space_tag sticn_tag;
static struct sti_rom sticn_rom;
static struct sti_screen sticn_scr;
static bus_addr_t sticn_bases[STI_REGION_MAX];

static const struct wsdisplay_accessops sti_m68k_accessops = {
	.ioctl        = sti_ioctl,
	.mmap         = sti_m68k_mmap,
	.alloc_screen = sti_alloc_screen,
	.free_screen  = sti_free_screen,
	.show_screen  = sti_show_screen,
	.load_font    = sti_load_font
};

void
sti_machdep_attach_console(struct sti_machdep_softc *sc)
{
	struct sti_softc *ssc = &sc->sc_sti;

	ssc->sc_flags |= STI_CONSOLE | STI_ATTACHED;
	ssc->sc_rom = &sticn_rom;
	ssc->sc_rom->rom_softc = ssc;
	ssc->sc_scr = &sticn_scr;
	ssc->sc_scr->scr_rom = ssc->sc_rom;
	memcpy(ssc->bases, sticn_bases, sizeof(ssc->bases));

	sti_describe(ssc);
}

void
sti_machdep_attach(struct sti_machdep_softc *sc)
{
	struct sti_softc *ssc = &sc->sc_sti;
	struct sti_screen *scr;
	paddr_t base = sc->sc_base;
	struct wsemuldisplaydev_attach_args waa;
	struct sti_dd *rom_dd;
	uint32_t grid0;

	/* Identify the board model by dd_grid */
	rom_dd = &ssc->sc_rom->rom_dd;
	grid0 = rom_dd->dd_grid[0];
	scr = ssc->sc_scr;

	switch (grid0) {
	case STI_DD_EVRX:
	case STI_DD_382C:
	case STI_DD_3X2V:
		/*
		 * 425e and 362/382 on-board EVRX framebuffer.
		 */
		sc->sc_bitmap = base + STI_EVRX_FBOFFSET;

		/*
		 * initialize Bt458/474 RAMDAC and preserve initial color map
		 */
		sti_evrx_resetramdac(scr);
		sti_evrx_resetcmap(scr);
		scr->setupfb = sti_evrx_setupfb;
		scr->putcmap = sti_evrx_putcmap;
		break;

	case STI_DD_CRX:
		/*
		 * HP A1659A CRX on some 425t variants.
		 */
		sc->sc_bitmap = base + STI_CRX_FBOFFSET;
		break;

	default:
		/*
		 * Unsupported variants.
		 * Use default common sti(4) attachment (no bitmap support).
		 */
		sti_end_attach(ssc);
		return;
	}

	aprint_normal_dev(ssc->sc_dev, "Enable mmap support\n");

	scr->scr_wsmode = WSDISPLAYIO_MODE_EMUL;
	waa.console = ssc->sc_flags & STI_CONSOLE ? 1 : 0;
	waa.scrdata = &scr->scr_screenlist;
	waa.accessops = &sti_m68k_accessops;
	waa.accesscookie = scr;

	config_found(ssc->sc_dev, &waa, wsemuldisplaydevprint,
	    CFARGS_NONE);
}

static int
sti_evrx_putcmap(struct sti_screen *scr, u_int index, u_int count)
{
	struct sti_rom *rom = scr->scr_rom;
	bus_space_tag_t bst = rom->memt;
	bus_space_handle_t bsh = rom->regh[2];
	int i;

	/* magic setup from HP-UX */
	bus_space_write_4(bst, bsh, EVRX_MAGIC08, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC00, 0x00000001);
	for (i = index; i < index + count; i++) {
		/* this is what HP-UX woodDownloadCmap() does */
		while ((bus_space_read_4(bst, bsh, EVRX_MAGIC10) &
		    EVRX_MAGIC10_BSY) != 0)
			continue;
		bus_space_write_1(bst, bsh, EVRX_BT4xx_ADDR, i);
		bus_space_write_1(bst, bsh, EVRX_BT4xx_CMAP, scr->scr_rcmap[i]);
		bus_space_write_1(bst, bsh, EVRX_BT4xx_CMAP, scr->scr_gcmap[i]);
		bus_space_write_4(bst, bsh, EVRX_MAGIC10,    scr->scr_bcmap[i]);
	}
	return 0;
}

static void
sti_evrx_resetramdac(struct sti_screen *scr)
{
	struct sti_rom *rom = scr->scr_rom;
	bus_space_tag_t bst = rom->memt;
	bus_space_handle_t bsh = rom->regh[2];
#if 0
	int i;
#endif

	/*
	 * Initialize the Bt458.  When we write to control registers,
	 * the address is not incremented automatically. So we specify
	 * it ourselves for each control register.
	 */

	/* all planes will be read */
	bus_space_write_1(bst, bsh, EVRX_BT4xx_ADDR, 0x04);
	bus_space_write_1(bst, bsh, EVRX_BT4xx_CTRL, 0xff);

#if 0
	/*
	 * HP-UX woodInitializeHardware() doesn't touch these
	 * Bt458 specific registers. Maybe initialized by STI ROM?
	 */
	/* all planes have non-blink */
	bus_space_write_1(bst, bsh, EVRX_BT458_ADDR, 0x05);
	bus_space_write_1(bst, bsh, EVRX_BT458_CTRL, 0x00);

	/* palette enabled, ovly plane disabled */
	bus_space_write_1(bst, bsh, EVRX_BT458_ADDR, 0x06);
	bus_space_write_1(bst, bsh, EVRX_BT458_CTRL, 0x40);

	/* no test mode */
	bus_space_write_1(bst, bsh, EVRX_BT458_ADDR, 0x07);
	bus_space_write_1(bst, bsh, EVRX_BT458_CTRL, 0x00);
#endif

	/* magic initialization from HP-UX woodInitializeHardware() */
	bus_space_write_4(bst, bsh, EVRX_MAGIC00, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC04, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC08, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC0C, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC18, 0xFFFFFFFF);
	bus_space_write_4(bst, bsh, EVRX_MAGIC1C, 0x00000000);

#if 0
	bus_space_write_1(bst, bsh, EVRX_BT458_ADDR, 0x00);
	for (i = 0; i < 4; i++) {
		bus_space_write_1(bst, bsh, EVRX_BT458_OMAP, 0x00);
		bus_space_write_1(bst, bsh, EVRX_BT458_OMAP, 0x00);
		bus_space_write_1(bst, bsh, EVRX_BT458_OMAP, 0x00);
	}
#endif
}

static void
sti_evrx_resetcmap(struct sti_screen *scr)
{
	struct sti_rom *rom = scr->scr_rom;
	bus_space_tag_t bst = rom->memt;
	bus_space_handle_t bsh = rom->regh[2];
	int i;

	/* magic setup from HP-UX */
	bus_space_write_4(bst, bsh, EVRX_MAGIC08, 0x00000001);
	bus_space_write_4(bst, bsh, EVRX_MAGIC00, 0x00000001);

	/* preserve palette values initialized by STI firmware */
	for (i = 0; i < STI_NCMAP; i++) {
		/* this is what HP-UX woodUploadCmap() does */
		while ((bus_space_read_4(bst, bsh, EVRX_MAGIC10) &
		    EVRX_MAGIC10_BSY) != 0)
			continue;
		bus_space_write_1(bst, bsh, EVRX_BT458_ADDR, i);
		scr->scr_rcmap[i] = bus_space_read_1(bst, bsh, EVRX_BT4xx_CMAP);
		scr->scr_gcmap[i] = bus_space_read_1(bst, bsh, EVRX_BT4xx_CMAP);
		scr->scr_bcmap[i] = bus_space_read_1(bst, bsh, EVRX_BT4xx_CMAP);
	}
}

static void
sti_evrx_setupfb(struct sti_screen *scr)
{

	sti_init(scr, 0);
	sti_evrx_resetramdac(scr);
}

static paddr_t
sti_m68k_mmap(void *v, void *vs, off_t offset, int prot)
{
	struct sti_screen *scr = (struct sti_screen *)v;
	struct sti_rom *rom = scr->scr_rom;
	struct sti_softc *ssc = rom->rom_softc;
	struct sti_machdep_softc *sc = device_private(ssc->sc_dev);
	paddr_t cookie = -1;

	if ((offset & PAGE_MASK) != 0)
		return -1;

	switch (scr->scr_wsmode) {
	case WSDISPLAYIO_MODE_MAPPED:
		/* not implemented yet; what should be shown? */
		break;
	case WSDISPLAYIO_MODE_DUMBFB:
		if (offset >= 0 && offset < (scr->fbwidth * scr->fbheight))
			cookie = m68k_btop(sc->sc_bitmap + offset);
		break;
	default:
		break;
	}

	return cookie;
}

void
sti_machdep_cnattach(bus_space_tag_t bst, paddr_t base)
{
	int i;

	sticn_tag = *bst;

	/* sticn_bases[0] will be fixed in sti_cnattach() */
	for (i = 0; i < STI_REGION_MAX; i++)
		sticn_bases[i] = (bus_addr_t)base;

	sti_cnattach(&sticn_rom, &sticn_scr, &sticn_tag, sticn_bases,
	    STI_CODEBASE_M68K);
}
