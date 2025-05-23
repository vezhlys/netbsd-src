/*	$NetBSD: wsdisplay_vcons.c,v 1.70 2025/04/28 07:43:41 macallan Exp $ */

/*-
 * Copyright (c) 2005, 2006 Michael Lorenz
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
__KERNEL_RCSID(0, "$NetBSD: wsdisplay_vcons.c,v 1.70 2025/04/28 07:43:41 macallan Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/tprintf.h>
#include <sys/atomic.h>
#include <sys/kmem.h>

#include <dev/wscons/wsdisplayvar.h>
#include <dev/wscons/wsconsio.h>
#include <dev/wsfont/wsfont.h>
#include <dev/rasops/rasops.h>

#include <dev/wscons/wsdisplay_vconsvar.h>

#ifdef _KERNEL_OPT
#include "opt_wsemul.h"
#include "opt_wsdisplay_compat.h"
#include "opt_vcons.h"
#endif

#ifdef VCONS_DEBUG
#define DPRINTF printf
#else
#define DPRINTF if (0) printf
#endif

struct vcons_data_private {
	/* accessops */
	int (*ioctl)(void *, void *, u_long, void *, int, struct lwp *);

	/* rasops */
	void (*copycols)(void *, int, int, int, int);
	void (*erasecols)(void *, int, int, int, long);
	void (*copyrows)(void *, int, int, int);
	void (*eraserows)(void *, int, int, long);
	void (*cursor)(void *, int, int, int);

	/* virtual screen management stuff */
	void (*switch_cb)(void *, int, int);
	void *switch_cb_arg;
	struct callout switch_callout;
	uint32_t switch_pending;
	LIST_HEAD(, vcons_screen) screens;
	struct vcons_screen *wanted;
	const struct wsscreen_descr *currenttype;
	struct wsscreen_descr *defaulttype;
	int switch_poll_count;

#ifdef VCONS_DRAW_INTR
	int cells;
	long *attrs;
	uint32_t *chars;
	int cursor_offset;
	callout_t intr;
	int intr_valid;
	void *intr_softint;
	int use_intr;		/* use intr drawing when non-zero */
#endif
};

static void vcons_dummy_init_screen(void *, struct vcons_screen *, int,
	    long *);

static int  vcons_ioctl(void *, void *, u_long, void *, int, struct lwp *);
static int  vcons_alloc_screen(void *, const struct wsscreen_descr *, void **,
	    int *, int *, long *);
static void vcons_free_screen(void *, void *);
static int  vcons_show_screen(void *, void *, int, void (*)(void *, int, int),
	    void *);
static int  vcons_load_font(void *, void *, struct wsdisplay_font *);

#ifdef WSDISPLAY_SCROLLSUPPORT
static void vcons_scroll(void *, void *, int);
static void vcons_do_scroll(struct vcons_screen *);
#endif

static void vcons_do_switch(void *);

/* methods that work only on text buffers */
static void vcons_copycols_buffer(void *, int, int, int, int);
static void vcons_erasecols_buffer(void *, int, int, int, long);
static void vcons_copyrows_buffer(void *, int, int, int);
static void vcons_eraserows_buffer(void *, int, int, long);
static int vcons_putchar_buffer(void *, int, int, u_int, long);

/*
 * actual wrapper methods which call both the _buffer ones above and the
 * driver supplied ones to do the drawing
 */
static void vcons_copycols(void *, int, int, int, int);
static void vcons_erasecols(void *, int, int, int, long);
static void vcons_copyrows(void *, int, int, int);
static void vcons_eraserows(void *, int, int, long);
static void vcons_putchar(void *, int, int, u_int, long);
#ifdef VCONS_DRAW_INTR
static void vcons_erasecols_cached(void *, int, int, int, long);
static void vcons_eraserows_cached(void *, int, int, long);
static void vcons_putchar_cached(void *, int, int, u_int, long);
#endif
static void vcons_cursor(void *, int, int, int);
static void vcons_cursor_noread(void *, int, int, int);

/*
 * methods that avoid framebuffer reads
 */
static void vcons_copycols_noread(void *, int, int, int, int);
static void vcons_copyrows_noread(void *, int, int, int);


/* support for reading/writing text buffers. For wsmoused */
static int  vcons_putwschar(struct vcons_screen *, struct wsdisplay_char *);
static int  vcons_getwschar(struct vcons_screen *, struct wsdisplay_char *);

static void vcons_lock(struct vcons_screen *);
static void vcons_unlock(struct vcons_screen *);

#ifdef VCONS_DRAW_INTR
static void vcons_intr(void *);
static void vcons_softintr(void *);
static void vcons_init_thread(void *);
static void vcons_invalidate_cache(struct vcons_data *);
#endif

static inline bool
vcons_use_intr(const struct vcons_screen *scr)
{
#ifdef VCONS_DRAW_INTR
	return scr->scr_vd->private->use_intr;
#else
	return false;
#endif
}

static inline void
vcons_dirty(struct vcons_screen *scr)
{
#ifdef VCONS_DRAW_INTR
	membar_release();
	atomic_inc_uint(&scr->scr_dirty);
#endif
}

static int
vcons_init_common(struct vcons_data *vd, void *cookie,
    struct wsscreen_descr *def, struct wsdisplay_accessops *ao,
    int enable_intr)
{
	struct vcons_data_private *vdp;

	/* zero out everything so we can rely on untouched fields being 0 */
	memset(vd, 0, sizeof(struct vcons_data));

	vd->private = vdp = kmem_zalloc(sizeof(*vdp), KM_SLEEP);
	vd->cookie = cookie;

	vd->init_screen = vcons_dummy_init_screen;
	vd->show_screen_cb = NULL;

	/* keep a copy of the accessops that we replace below with our
	 * own wrappers */
	vdp->ioctl = ao->ioctl;

	/* configure the accessops */
	ao->ioctl = vcons_ioctl;
	ao->alloc_screen = vcons_alloc_screen;
	ao->free_screen = vcons_free_screen;
	ao->show_screen = vcons_show_screen;
	ao->load_font = vcons_load_font;
#ifdef WSDISPLAY_SCROLLSUPPORT
	ao->scroll = vcons_scroll;
#endif

	LIST_INIT(&vdp->screens);
	vd->active = NULL;
	vdp->wanted = NULL;
	vdp->currenttype = def;
	vdp->defaulttype = def;
	callout_init(&vdp->switch_callout, 0);
	callout_setfunc(&vdp->switch_callout, vcons_do_switch, vd);
#ifdef VCONS_DRAW_INTR
	vdp->cells = 0;
	vdp->attrs = NULL;
	vdp->chars = NULL;
	vdp->cursor_offset = -1;
#endif

	/*
	 * a lock to serialize access to the framebuffer.
	 * when switching screens we need to make sure there's no rasops
	 * operation in progress
	 */
#ifdef DIAGNOSTIC
	vdp->switch_poll_count = 0;
#endif
#ifdef VCONS_DRAW_INTR
	if (enable_intr) {
		vdp->intr_softint = softint_establish(SOFTINT_SERIAL,
		    vcons_softintr, vd);
		callout_init(&vdp->intr, CALLOUT_MPSAFE);
		callout_setfunc(&vdp->intr, vcons_intr, vd);
		vdp->intr_valid = 1;

		if (kthread_create(PRI_NONE, 0, NULL, vcons_init_thread, vd,
		    NULL, "vcons_init") != 0) {
			printf("%s: unable to create thread.\n", __func__);
			return -1;
		}
	}
#endif
	return 0;
}

int
vcons_init(struct vcons_data *vd, void *cookie,
    struct wsscreen_descr *def, struct wsdisplay_accessops *ao)
{
	return vcons_init_common(vd, cookie, def, ao, 1);
}

int
vcons_earlyinit(struct vcons_data *vd, void *cookie,
    struct wsscreen_descr *def, struct wsdisplay_accessops *ao)
{
	return vcons_init_common(vd, cookie, def, ao, 0);
}

static void
vcons_lock(struct vcons_screen *scr)
{
#ifdef VCONS_PARANOIA
	int s;

	s = splhigh();
#endif
	SCREEN_BUSY(scr);
#ifdef VCONS_PARANOIA
	splx(s);
#endif
}

static void
vcons_unlock(struct vcons_screen *scr)
{
#ifdef VCONS_PARANOIA
	int s;

	s = splhigh();
#endif
	SCREEN_IDLE(scr);
#ifdef VCONS_PARANOIA
	splx(s);
#endif
}

static void
vcons_dummy_init_screen(void *cookie,
    struct vcons_screen *scr, int exists,
    long *defattr)
{

	/*
	 * default init_screen() method.
	 * Needs to be overwritten so we bitch and whine in case anyone ends
	 * up in here.
	 */
	printf("vcons_init_screen: dummy function called. Your driver is "
	       "supposed to supply a replacement for proper operation\n");
}

static int
vcons_alloc_buffers(struct vcons_data *vd, struct vcons_screen *scr)
{
	struct rasops_info *ri = &scr->scr_ri;
	int cnt, i;
#ifdef VCONS_DRAW_INTR
	struct vcons_data_private *vdp = vd->private;
	int size;
#endif

	/*
	 * we allocate both chars and attributes in one chunk, attributes first
	 * because they have the (potentially) bigger alignment
	 */
#ifdef WSDISPLAY_SCROLLSUPPORT
	cnt = (ri->ri_rows + WSDISPLAY_SCROLLBACK_LINES) * ri->ri_cols;
	scr->scr_lines_in_buffer = WSDISPLAY_SCROLLBACK_LINES;
	scr->scr_current_line = 0;
	scr->scr_line_wanted = 0;
	scr->scr_offset_to_zero = ri->ri_cols * WSDISPLAY_SCROLLBACK_LINES;
	scr->scr_current_offset = scr->scr_offset_to_zero;
#else
	cnt = ri->ri_rows * ri->ri_cols;
#endif
	scr->scr_attrs = malloc(cnt * (sizeof(long) +
	    sizeof(uint32_t)), M_DEVBUF, M_WAITOK);
	if (scr->scr_attrs == NULL)
		return ENOMEM;

	scr->scr_chars = (uint32_t *)&scr->scr_attrs[cnt];

	/*
	 * fill the attribute buffer with *defattr, chars with 0x20
	 * since we don't know if the driver tries to mimic firmware output or
	 * reset everything we do nothing to VRAM here, any driver that feels
	 * the need to clear screen or something will have to do it on its own
	 * Additional screens will start out in the background anyway so
	 * cleaning or not only really affects the initial console screen
	 */
	for (i = 0; i < cnt; i++) {
		scr->scr_attrs[i] = scr->scr_defattr;
		scr->scr_chars[i] = 0x20;
	}

#ifdef VCONS_DRAW_INTR
	size = ri->ri_cols * ri->ri_rows;
	if (size > vdp->cells) {
		if (vdp->chars != NULL)
			free(vdp->chars, M_DEVBUF);
		if (vdp->attrs != NULL)
			free(vdp->attrs, M_DEVBUF);
		vdp->cells = size;
		vdp->chars = malloc(size * sizeof(uint32_t), M_DEVBUF,
		    M_WAITOK|M_ZERO);
		vdp->attrs = malloc(size * sizeof(long), M_DEVBUF,
		    M_WAITOK|M_ZERO);
		vcons_invalidate_cache(vd);
	} else if (SCREEN_IS_VISIBLE(scr))
		vcons_invalidate_cache(vd);
#endif
	return 0;
}

int
vcons_init_screen(struct vcons_data *vd, struct vcons_screen *scr,
    int existing, long *defattr)
{
	struct vcons_data_private *vdp = vd->private;
	struct rasops_info *ri = &scr->scr_ri;
	int i;

	scr->scr_cookie = vd->cookie;
	scr->scr_vd = scr->scr_origvd = vd;
	scr->scr_busy = 0;

	if (scr->scr_type == NULL)
		scr->scr_type = vdp->defaulttype;

	/*
	 * call the driver-supplied init_screen function which is expected
	 * to set up rasops_info, override cursor() and probably others
	 */
	vd->init_screen(vd->cookie, scr, existing, defattr);

	/*
	 * save the non virtual console aware rasops and replace them with
	 * our wrappers
	 */
	vdp->eraserows = ri->ri_ops.eraserows;
	vdp->erasecols = ri->ri_ops.erasecols;
	scr->putchar   = ri->ri_ops.putchar;

	if (scr->scr_flags & VCONS_NO_COPYCOLS) {
		vdp->copycols  = vcons_copycols_noread;
	} else {
		vdp->copycols = ri->ri_ops.copycols;
	}

	if (scr->scr_flags & VCONS_NO_COPYROWS) {
		vdp->copyrows  = vcons_copyrows_noread;
	} else {
		vdp->copyrows = ri->ri_ops.copyrows;
	}

	if (scr->scr_flags & VCONS_NO_CURSOR) {
		vdp->cursor  = vcons_cursor_noread;
	} else {
		vdp->cursor = ri->ri_ops.cursor;
	}

	ri->ri_ops.eraserows = vcons_eraserows;
	ri->ri_ops.erasecols = vcons_erasecols;
	ri->ri_ops.putchar   = vcons_putchar;
	ri->ri_ops.cursor    = vcons_cursor;
	ri->ri_ops.copycols  = vcons_copycols;
	ri->ri_ops.copyrows  = vcons_copyrows;


	ri->ri_hw = scr;

	i = ri->ri_ops.allocattr(ri, WS_DEFAULT_FG, WS_DEFAULT_BG, 0, defattr);
	if (i != 0) {
#ifdef DIAGNOSTIC
		printf("vcons: error allocating attribute %d\n", i);
#endif
		scr->scr_defattr = 0;
	} else
		scr->scr_defattr = *defattr;

	vcons_alloc_buffers(vd, scr);

	if (vd->active == NULL) {
		vd->active = scr;
		SCREEN_VISIBLE(scr);
	}

	if (existing) {
		SCREEN_VISIBLE(scr);
		vd->active = scr;
	} else {
		SCREEN_INVISIBLE(scr);
	}

	LIST_INSERT_HEAD(&vdp->screens, scr, next);
	return 0;
}

static int
vcons_load_font(void *v, void *cookie, struct wsdisplay_font *f)
{
	struct vcons_data *vd = v;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr = cookie;
	struct rasops_info *ri;
	struct wsdisplay_font *font;
	char buf[64], *at;
	int flags = WSFONT_FIND_BITMAP, fcookie, h = 0;

	/* see if we're asked to add a font or use it */
	if (scr == NULL)
		return 0;

	ri = &scr->scr_ri;

	/* see if the driver knows how to handle multiple fonts */
	if ((scr->scr_flags & VCONS_LOADFONT) == 0) {
		return EOPNOTSUPP;
	}

	/* now see what fonts we can use */
	if (ri->ri_flg & RI_ENABLE_ALPHA) {
		flags |= WSFONT_FIND_ALPHA;
	}

	strncpy(buf, f->name, 63);
	buf[63] = 0;
	at = strchr(buf, '@');
	if (at != NULL) {
		int stat;
		at[0] = 0;
		at++;
		DPRINTF("got '%s'\n", at);
		h = strtoi(at, NULL, 10, 1, 99, &stat);
		if (stat != 0) h = 0;
		DPRINTF("looking for %d\n", h);
	}
	fcookie = wsfont_find(buf, 0, h, 0,
	    /* bitorder */
	    scr->scr_flags & VCONS_FONT_BITS_R2L ?
	      WSDISPLAY_FONTORDER_R2L : WSDISPLAY_FONTORDER_L2R,
	    /* byteorder */
	    scr->scr_flags & VCONS_FONT_BYTES_R2L ?
	      WSDISPLAY_FONTORDER_R2L : WSDISPLAY_FONTORDER_L2R,
	    flags);
	if (fcookie == -1)
		return ENOENT;

	wsfont_lock(fcookie, &font);
	if (font == NULL)
		return EINVAL;

	/* ok, we got a font. Now clear the screen with the old parameters */
	if (SCREEN_IS_VISIBLE(scr))
		vdp->eraserows(ri, 0, ri->ri_rows, scr->scr_defattr);

	vcons_lock(vd->active);
#ifdef VCONS_DRAW_INTR
	callout_halt(&vdp->intr, NULL);
#endif
	/* set the new font and re-initialize things */
	ri->ri_font = font;
	wsfont_unlock(ri->ri_wsfcookie);
	ri->ri_wsfcookie = fcookie;

	vd->init_screen(vd->cookie, scr, 1, &scr->scr_defattr);
	DPRINTF("caps %x %x\n", scr->scr_type->capabilities, ri->ri_caps);
	if (scr->scr_type->capabilities & WSSCREEN_RESIZE) {
		scr->scr_type->nrows = ri->ri_rows;
		scr->scr_type->ncols = ri->ri_cols;
		DPRINTF("new size %d %d\n", ri->ri_rows, ri->ri_cols);
	}


	/* now, throw the old buffers away */
	if (scr->scr_attrs)
		free(scr->scr_attrs, M_DEVBUF);
	/* allocate new buffers */
	vcons_alloc_buffers(vd, scr);

	/* save the potentially changed ri_ops */
	vdp->eraserows = ri->ri_ops.eraserows;
	vdp->erasecols = ri->ri_ops.erasecols;
	scr->putchar   = ri->ri_ops.putchar;
	vdp->cursor    = ri->ri_ops.cursor;

	if (scr->scr_flags & VCONS_NO_COPYCOLS) {
		vdp->copycols  = vcons_copycols_noread;
	} else {
		vdp->copycols = ri->ri_ops.copycols;
	}

	if (scr->scr_flags & VCONS_NO_COPYROWS) {
		vdp->copyrows  = vcons_copyrows_noread;
	} else {
		vdp->copyrows = ri->ri_ops.copyrows;
	}

	if (scr->scr_flags & VCONS_NO_CURSOR) {
		vdp->cursor  = vcons_cursor_noread;
	} else {
		vdp->cursor = ri->ri_ops.cursor;
	}

	/* and put our wrappers back */
	ri->ri_ops.eraserows = vcons_eraserows;
	ri->ri_ops.erasecols = vcons_erasecols;
	ri->ri_ops.putchar   = vcons_putchar;
	ri->ri_ops.cursor    = vcons_cursor;
	ri->ri_ops.copycols  = vcons_copycols;
	ri->ri_ops.copyrows  = vcons_copyrows;
	vcons_unlock(vd->active);

	/* notify things that we're about to redraw */
	if (vd->show_screen_cb != NULL)
		vd->show_screen_cb(scr, vd->show_screen_cookie);

#ifdef VCONS_DRAW_INTR
	/*
	 * XXX
	 * Something(tm) craps all over VRAM somewhere up there if we're
	 * using VCONS_DRAW_INTR. Until I figure out what causes it, just
	 * redraw the screen for now.
	 */
	vcons_redraw_screen(vd->active);
	callout_schedule(&vdp->intr, mstohz(33));
#endif
	/* no need to draw anything, wsdisplay should reset the terminal */

	return 0;
}

static void
vcons_do_switch(void *arg)
{
	struct vcons_data *vd = arg;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr, *oldscr;

	scr = vdp->wanted;
	if (!scr) {
		printf("vcons_switch_screen: disappeared\n");
		vdp->switch_cb(vdp->switch_cb_arg, EIO, 0);
		return;
	}
	oldscr = vd->active; /* can be NULL! */

	/*
	 * if there's an old, visible screen we mark it invisible and wait
	 * until it's not busy so we can safely switch
	 */
	if (oldscr != NULL) {
		SCREEN_INVISIBLE(oldscr);
		if (SCREEN_IS_BUSY(oldscr)) {
			callout_schedule(&vdp->switch_callout, 1);
#ifdef DIAGNOSTIC
			/* bitch if we wait too long */
			vdp->switch_poll_count++;
			if (vdp->switch_poll_count > 100) {
				panic("vcons: screen still busy");
			}
#endif
			return;
		}
		/* invisible screen -> no visible cursor image */
		oldscr->scr_ri.ri_flg &= ~RI_CURSOR;
#ifdef DIAGNOSTIC
		vdp->switch_poll_count = 0;
#endif
	}

	if (scr == oldscr)
		return;

#ifdef DIAGNOSTIC
	if (SCREEN_IS_VISIBLE(scr))
		printf("vcons_switch_screen: already active");
#endif

#ifdef notyet
	if (vdp->currenttype != type) {
		vcons_set_screentype(vd, type);
		vdp->currenttype = type;
	}
#endif

	SCREEN_VISIBLE(scr);
	vd->active = scr;
	vdp->wanted = NULL;

#ifdef VCONS_DRAW_INTR
	vcons_invalidate_cache(vd);
#endif

	if (vd->show_screen_cb != NULL)
		vd->show_screen_cb(scr, vd->show_screen_cookie);

	if ((scr->scr_flags & VCONS_NO_REDRAW) == 0)
		vcons_redraw_screen(scr);

	if (vdp->switch_cb)
		vdp->switch_cb(vdp->switch_cb_arg, 0, 0);
}

void
vcons_redraw_screen(struct vcons_screen *scr)
{
	uint32_t *charptr = scr->scr_chars, c;
	long *attrptr = scr->scr_attrs, a, last_a = 0, mask, cmp, acmp;
	struct rasops_info *ri = &scr->scr_ri;
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	int i, j, offset, boffset = 0, start = -1;

	mask = 0x00ff00ff;	/* background and flags */
	cmp = 0xffffffff;	/* never match anything */
	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {

		/*
		 * only clear the screen when RI_FULLCLEAR is set since we're
		 * going to overwrite every single character cell anyway
		 */
		if (ri->ri_flg & RI_FULLCLEAR) {
			vdp->eraserows(ri, 0, ri->ri_rows,
			    scr->scr_defattr);
			cmp = scr->scr_defattr & mask;
		}

		/* redraw the screen */
#ifdef WSDISPLAY_SCROLLSUPPORT
		offset = scr->scr_current_offset;
#else
		offset = 0;
#endif
		for (i = 0; i < ri->ri_rows; i++) {
			start = -1;
			for (j = 0; j < ri->ri_cols; j++) {
				/*
				 * no need to use the wrapper function - we
				 * don't change any characters or attributes
				 * and we already made sure the screen we're
				 * working on is visible
				 */
				c = charptr[offset];
				a = attrptr[offset];
				acmp = a & mask;
				if (c == ' ') {
					/*
					 * if we already erased the background
					 * and if this blank uses the same
					 * colour and flags we don't need to do
					 * anything here
					 */
					if (acmp == cmp && start == -1)
						goto next;
					/*
					 * see if we can optimize things a
					 * little bit by drawing stretches of
					 * blanks using erasecols
					 */

					if (start == -1) {
						start = j;
						last_a = acmp;
					} else if (acmp != last_a) {
						/*
						 * different attr, need to
						 * flush & restart
						 */
						vdp->erasecols(ri, i, start,
						    j - start, last_a);
						start = j;
						last_a = acmp;
					}
				} else {
					if (start != -1) {
						vdp->erasecols(ri, i, start,
						    j - start, last_a);
						start = -1;
					}

					scr->putchar(ri, i, j, c, a);
				}
next:
#ifdef VCONS_DRAW_INTR
				vdp->chars[boffset] = charptr[offset];
				vdp->attrs[boffset] = attrptr[offset];
#endif
				offset++;
				boffset++;
			}
			/* end of the line - draw all deferred blanks, if any */
			if (start != -1) {
				vdp->erasecols(ri, i, start, j - start, last_a);
			}
		}
		ri->ri_flg &= ~RI_CURSOR;
		scr->scr_vd->private->cursor(ri, 1, ri->ri_crow, ri->ri_ccol);
#ifdef VCONS_DRAW_INTR
		vdp->cursor_offset = ri->ri_crow * ri->ri_cols + ri->ri_ccol;
#endif
	}
	vcons_unlock(scr);
}

void
vcons_update_screen(struct vcons_screen *scr)
{
#ifdef VCONS_DRAW_INTR
	uint32_t *charptr = scr->scr_chars;
	long *attrptr = scr->scr_attrs;
	struct rasops_info *ri = &scr->scr_ri;
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	int i, j, offset, boffset = 0;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {

		/* redraw the screen */
#ifdef WSDISPLAY_SCROLLSUPPORT
		offset = scr->scr_current_offset;
#else
		offset = 0;
#endif
		/*
		 * we mark the character cell occupied by the cursor as dirty
		 * so we don't have to deal with it
		 * notice that this isn't necessarily the position where rasops
		 * thinks it is, just where we drew it the last time
		 */
		if (vdp->cursor_offset >= 0)
			vdp->attrs[vdp->cursor_offset] = 0xffffffff;

		for (i = 0; i < ri->ri_rows; i++) {
			for (j = 0; j < ri->ri_cols; j++) {
				/*
				 * no need to use the wrapper function - we
				 * don't change any characters or attributes
				 * and we already made sure the screen we're
				 * working on is visible
				 */
				if ((vdp->chars[boffset] != charptr[offset]) ||
				    (vdp->attrs[boffset] != attrptr[offset])) {
					scr->putchar(ri, i, j,
				 	   charptr[offset], attrptr[offset]);
					vdp->chars[boffset] = charptr[offset];
					vdp->attrs[boffset] = attrptr[offset];
				}
				offset++;
				boffset++;
			}
		}
		ri->ri_flg &= ~RI_CURSOR;
		scr->scr_vd->private->cursor(ri, 1, ri->ri_crow, ri->ri_ccol);
		vdp->cursor_offset = ri->ri_crow * ri->ri_cols + ri->ri_ccol;
	}
	vcons_unlock(scr);
#else  /* !VCONS_DRAW_INTR */
	vcons_redraw_screen(scr);
#endif
}

static int
vcons_ioctl(void *v, void *vs, u_long cmd, void *data, int flag,
	struct lwp *l)
{
	struct vcons_data *vd = v;
	struct vcons_data_private *vdp = vd->private;
	int error = 0;


	switch (cmd) {
	case WSDISPLAYIO_GETWSCHAR:
		error = vcons_getwschar((struct vcons_screen *)vs,
			(struct wsdisplay_char *)data);
		break;

	case WSDISPLAYIO_PUTWSCHAR:
		error = vcons_putwschar((struct vcons_screen *)vs,
			(struct wsdisplay_char *)data);
		break;

	case WSDISPLAYIO_SET_POLLING: {
		int poll = *(int *)data;

		/* first call the driver's ioctl handler */
		if (vdp->ioctl != NULL)
			error = (*vdp->ioctl)(v, vs, cmd, data, flag, l);
		if (poll) {
			vcons_enable_polling(vd);
			vcons_hard_switch(LIST_FIRST(&vdp->screens));
		} else
			vcons_disable_polling(vd);
		}
		break;

	case WSDISPLAYIO_GFONT: {
		struct wsdisplay_getfont *gf = data;
		size_t actual;
		struct wsdisplay_font *font;
		const char *fontname;

		font = ((struct vcons_screen *)vs)->scr_ri.ri_font;
		fontname = font && font->name ? font->name : "";
		error = copyoutstr(fontname, gf->gf_name, gf->gf_size, &actual);
		if (!error)
			gf->gf_actual = actual;
		}
		break;

	default:
		if (vdp->ioctl != NULL)
			error = (*vdp->ioctl)(v, vs, cmd, data, flag, l);
		else
			error = EPASSTHROUGH;
	}

	return error;
}

static int
vcons_alloc_screen(void *v, const struct wsscreen_descr *type, void **cookiep,
    int *curxp, int *curyp, long *defattrp)
{
	struct vcons_data *vd = v;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr;
	struct wsscreen_descr *t = __UNCONST(type);
	int ret;

	scr = malloc(sizeof(struct vcons_screen), M_DEVBUF, M_WAITOK | M_ZERO);
	if (scr == NULL)
		return ENOMEM;

	scr->scr_flags = 0;
	scr->scr_status = 0;
	scr->scr_busy = 0;
	scr->scr_type = __UNCONST(type);

	ret = vcons_init_screen(vd, scr, 0, defattrp);
	if (ret != 0) {
		free(scr, M_DEVBUF);
		return ret;
	}
	if (t->capabilities & WSSCREEN_RESIZE) {
		t->nrows = scr->scr_ri.ri_rows;
		t->ncols = scr->scr_ri.ri_cols;
	}

	if (vd->active == NULL) {
		SCREEN_VISIBLE(scr);
		vd->active = scr;
		vdp->currenttype = type;
	}

	*cookiep = scr;
	*curxp = scr->scr_ri.ri_ccol;
	*curyp = scr->scr_ri.ri_crow;
	return 0;
}

static void
vcons_free_screen(void *v, void *cookie)
{
	struct vcons_data *vd = v;
	struct vcons_screen *scr = cookie;

	vcons_lock(scr);
	/* there should be no rasops activity here */

	LIST_REMOVE(scr, next);

	if ((scr->scr_flags & VCONS_SCREEN_IS_STATIC) == 0) {
		free(scr->scr_attrs, M_DEVBUF);
		free(scr, M_DEVBUF);
	} else {
		/*
		 * maybe we should just restore the old rasops_info methods
		 * and free the character/attribute buffer here?
		 */
#ifdef VCONS_DEBUG
		panic("vcons_free_screen: console");
#else
		printf("vcons_free_screen: console\n");
#endif
	}

	if (vd->active == scr)
		vd->active = NULL;
}

static int
vcons_show_screen(void *v, void *cookie, int waitok,
    void (*cb)(void *, int, int), void *cb_arg)
{
	struct vcons_data *vd = v;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr;

	scr = cookie;
	if (scr == vd->active)
		return 0;

	vdp->wanted = scr;
	vdp->switch_cb = cb;
	vdp->switch_cb_arg = cb_arg;
	if (cb) {
		callout_schedule(&vdp->switch_callout, 0);
		return EAGAIN;
	}

	vcons_do_switch(vd);
	return 0;
}

/* wrappers for rasops_info methods */

static void
vcons_copycols_buffer(void *cookie, int row, int srccol, int dstcol, int ncols)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int from = srccol + row * ri->ri_cols;
	int to = dstcol + row * ri->ri_cols;
	int offset = vcons_offset_to_zero(scr);

	memmove(&scr->scr_attrs[offset + to], &scr->scr_attrs[offset + from],
	    ncols * sizeof(long));
	memmove(&scr->scr_chars[offset + to], &scr->scr_chars[offset + from],
	    ncols * sizeof(uint32_t));

	vcons_dirty(scr);
}

static void
vcons_copycols(void *cookie, int row, int srccol, int dstcol, int ncols)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;

	vcons_copycols_buffer(cookie, row, srccol, dstcol, ncols);

	if (vcons_use_intr(scr))
		return;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
#if defined(VCONS_DRAW_INTR)
		vcons_update_screen(scr);
#else
		scr->scr_vd->private->copycols(cookie, row, srccol, dstcol,
		    ncols);
#endif
	}
	vcons_unlock(scr);
}

static void
vcons_copycols_noread(void *cookie, int row, int srccol, int dstcol, int ncols)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
#ifdef VCONS_DRAW_INTR
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
#endif

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
		int pos, c, offset, ppos;

#ifdef WSDISPLAY_SCROLLSUPPORT
		offset = scr->scr_current_offset;
#else
		offset = 0;
#endif
		ppos = ri->ri_cols * row + dstcol;
		pos = ppos + offset;
		for (c = dstcol; c < (dstcol + ncols); c++) {
#ifdef VCONS_DRAW_INTR
			if ((scr->scr_chars[pos] != vdp->chars[ppos]) ||
			    (scr->scr_attrs[pos] != vdp->attrs[ppos])) {
				scr->putchar(cookie, row, c,
				   scr->scr_chars[pos], scr->scr_attrs[pos]);
				vdp->chars[ppos] = scr->scr_chars[pos];
				vdp->attrs[ppos] = scr->scr_attrs[pos];
			}
#else
			scr->putchar(cookie, row, c, scr->scr_chars[pos],
			    scr->scr_attrs[pos]);
#endif
			pos++;
			ppos++;
		}
		if (ri->ri_crow == row &&
		   (ri->ri_ccol >= dstcol && ri->ri_ccol < (dstcol + ncols )))
			ri->ri_flg &= ~RI_CURSOR;
	}
	vcons_unlock(scr);
}

static void
vcons_erasecols_buffer(void *cookie, int row, int startcol, int ncols, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int start = startcol + row * ri->ri_cols;
	int end = start + ncols, i;
	int offset = vcons_offset_to_zero(scr);

	for (i = start; i < end; i++) {
		scr->scr_attrs[offset + i] = fillattr;
		scr->scr_chars[offset + i] = 0x20;
	}

	vcons_dirty(scr);
}

#ifdef VCONS_DRAW_INTR
static void
vcons_erasecols_cached(void *cookie, int row, int startcol, int ncols, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	int i, pos = row * ri->ri_cols + startcol;

	vdp->erasecols(cookie, row, startcol, ncols, fillattr);
	for (i = pos; i < ncols; i++) {
		vdp->chars[i] = scr->scr_chars[i];
		vdp->attrs[i] = scr->scr_attrs[i];
	}
}
#endif

static void
vcons_erasecols(void *cookie, int row, int startcol, int ncols, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;

	vcons_erasecols_buffer(cookie, row, startcol, ncols, fillattr);

	if (vcons_use_intr(scr))
		return;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
#ifdef VCONS_DRAW_INTR
		vcons_erasecols_cached(cookie, row, startcol, ncols,
		    fillattr);
#else
		scr->scr_vd->private->erasecols(cookie, row, startcol, ncols,
		    fillattr);
#endif
	}
	vcons_unlock(scr);
}

static void
vcons_copyrows_buffer(void *cookie, int srcrow, int dstrow, int nrows)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int from, to, len;
	int offset = vcons_offset_to_zero(scr);

	/* do we need to scroll the back buffer? */
	if (dstrow == 0 && offset != 0) {
		from = ri->ri_cols * srcrow;
		to = ri->ri_cols * dstrow;

		memmove(&scr->scr_attrs[to], &scr->scr_attrs[from],
		    offset * sizeof(long));
		memmove(&scr->scr_chars[to], &scr->scr_chars[from],
		    offset * sizeof(uint32_t));
	}
	from = ri->ri_cols * srcrow + offset;
	to = ri->ri_cols * dstrow + offset;
	len = ri->ri_cols * nrows;

	memmove(&scr->scr_attrs[to], &scr->scr_attrs[from],
	    len * sizeof(long));
	memmove(&scr->scr_chars[to], &scr->scr_chars[from],
	    len * sizeof(uint32_t));

	vcons_dirty(scr);
}

static void
vcons_copyrows(void *cookie, int srcrow, int dstrow, int nrows)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;

	vcons_copyrows_buffer(cookie, srcrow, dstrow, nrows);

	if (vcons_use_intr(scr))
		return;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
#if defined(VCONS_DRAW_INTR)
		vcons_update_screen(scr);
#else
		scr->scr_vd->private->copyrows(cookie, srcrow, dstrow, nrows);
#endif
	}
	vcons_unlock(scr);
}

static void
vcons_copyrows_noread(void *cookie, int srcrow, int dstrow, int nrows)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
#ifdef VCONS_DRAW_INTR
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
#endif
	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
		int pos, l, c, offset, ppos;

#ifdef WSDISPLAY_SCROLLSUPPORT
		offset = scr->scr_current_offset;
#else
		offset = 0;
#endif
		ppos = ri->ri_cols * dstrow;
		pos = ppos + offset;
		for (l = dstrow; l < (dstrow + nrows); l++) {
			for (c = 0; c < ri->ri_cols; c++) {
#ifdef VCONS_DRAW_INTR
				if ((scr->scr_chars[pos] != vdp->chars[ppos]) ||
				    (scr->scr_attrs[pos] != vdp->attrs[ppos])) {
					scr->putchar(cookie, l, c,
					   scr->scr_chars[pos], scr->scr_attrs[pos]);
					vdp->chars[ppos] = scr->scr_chars[pos];
					vdp->attrs[ppos] = scr->scr_attrs[pos];
				}
#else
				scr->putchar(cookie, l, c, scr->scr_chars[pos],
				    scr->scr_attrs[pos]);
#endif
				pos++;
				ppos++;
			}
		}
		if (ri->ri_crow >= dstrow && ri->ri_crow < (dstrow + nrows))
			ri->ri_flg &= ~RI_CURSOR;
	}
	vcons_unlock(scr);
}

static void
vcons_eraserows_buffer(void *cookie, int row, int nrows, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int offset = vcons_offset_to_zero(scr);
	int start, end, i;

	start = ri->ri_cols * row + offset;
	end = ri->ri_cols * (row + nrows) + offset;

	for (i = start; i < end; i++) {
		scr->scr_attrs[i] = fillattr;
		scr->scr_chars[i] = 0x20;
	}

	vcons_dirty(scr);
}

#ifdef VCONS_DRAW_INTR
static void
vcons_eraserows_cached(void *cookie, int row, int nrows, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	int i, pos = row * ri->ri_cols, end = (row+nrows) * ri->ri_cols;

	for (i = pos; i < end; i++) {
		vdp->chars[i] = 0x20;
		vdp->attrs[i] = fillattr;
	}
	vdp->eraserows(cookie, row, nrows, fillattr);
}
#endif

static void
vcons_eraserows(void *cookie, int row, int nrows, long fillattr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;

	vcons_eraserows_buffer(cookie, row, nrows, fillattr);

	if (vcons_use_intr(scr))
		return;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
#ifdef VCONS_DRAW_INTR
		vcons_eraserows_cached(cookie, row, nrows, fillattr);
#else
		scr->scr_vd->private->eraserows(cookie, row, nrows, fillattr);
#endif
	}
	vcons_unlock(scr);
}

static int
vcons_putchar_buffer(void *cookie, int row, int col, u_int c, long attr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int offset = vcons_offset_to_zero(scr);
	int pos, ret = 0;

	if ((row >= 0) && (row < ri->ri_rows) && (col >= 0) &&
	    (col < ri->ri_cols)) {
		pos = col + row * ri->ri_cols;
		ret = (scr->scr_attrs[pos + offset] != attr) ||
		      (scr->scr_chars[pos + offset] != c);
		scr->scr_attrs[pos + offset] = attr;
		scr->scr_chars[pos + offset] = c;
	}

	if (ret)
		vcons_dirty(scr);
	return ret;
}

#ifdef VCONS_DRAW_INTR
static void
vcons_putchar_cached(void *cookie, int row, int col, u_int c, long attr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	int pos = row * ri->ri_cols + col;

	if ((vdp->chars == NULL) || (vdp->attrs == NULL)) {
		scr->putchar(cookie, row, col, c, attr);
		return;
	}
	if ((vdp->chars[pos] != c) || (vdp->attrs[pos] != attr)) {
		vdp->attrs[pos] = attr;
		vdp->chars[pos] = c;
		scr->putchar(cookie, row, col, c, attr);
	}
}
#endif

static void
vcons_putchar(void *cookie, int row, int col, u_int c, long attr)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int need_draw;

	need_draw = vcons_putchar_buffer(cookie, row, col, c, attr);

	if (vcons_use_intr(scr))
		return;

	vcons_lock(scr);
	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
#ifdef VCONS_DRAW_INTR
		if (need_draw)
			vcons_putchar_cached(cookie, row, col, c, attr);
#else
		if (row == ri->ri_crow && col == ri->ri_ccol) {
			ri->ri_flg &= ~RI_CURSOR;
			scr->putchar(cookie, row, col, c, attr);
		} else if (need_draw)
			scr->putchar(cookie, row, col, c, attr);
#endif
	}
	vcons_unlock(scr);
}

static void
vcons_cursor(void *cookie, int on, int row, int col)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;

	if (vcons_use_intr(scr)) {
		vcons_lock(scr);
		if (scr->scr_ri.ri_crow != row || scr->scr_ri.ri_ccol != col) {
			scr->scr_ri.ri_crow = row;
			scr->scr_ri.ri_ccol = col;
			vcons_dirty(scr);
		}
		vcons_unlock(scr);
		return;
	}

	vcons_lock(scr);

	if (SCREEN_IS_VISIBLE(scr) && SCREEN_CAN_DRAW(scr)) {
		scr->scr_vd->private->cursor(cookie, on, row, col);
	} else {
		scr->scr_ri.ri_crow = row;
		scr->scr_ri.ri_ccol = col;
	}
	vcons_unlock(scr);
}

static void
vcons_cursor_noread(void *cookie, int on, int row, int col)
{
	struct rasops_info *ri = cookie;
	struct vcons_screen *scr = ri->ri_hw;
	int offset = 0, ofs;

#ifdef WSDISPLAY_SCROLLSUPPORT
	offset = scr->scr_current_offset;
#endif
	ofs = offset + ri->ri_crow * ri->ri_cols + ri->ri_ccol;
	if ((ri->ri_flg & RI_CURSOR) &&
	   (((scr->scr_flags & VCONS_DONT_READ) != VCONS_DONT_READ) || on)) {
		scr->putchar(cookie, ri->ri_crow, ri->ri_ccol,
		    scr->scr_chars[ofs], scr->scr_attrs[ofs]);
		ri->ri_flg &= ~RI_CURSOR;
	}
	ri->ri_crow = row;
	ri->ri_ccol = col;
	ofs = offset + ri->ri_crow * ri->ri_cols + ri->ri_ccol;
	if (on) {
		scr->putchar(cookie, row, col, scr->scr_chars[ofs],
#ifdef VCONS_DEBUG_CURSOR_NOREAD
		/* draw a red cursor so we can tell which cursor()
		 * implementation is being used */
		    ((scr->scr_attrs[ofs] & 0xff00ffff) ^ 0x0f000000) |
		      0x00010000);
#else
		    scr->scr_attrs[ofs] ^ 0x0f0f0000);
#endif
		ri->ri_flg |= RI_CURSOR;
	}
}

/* methods to read/write characters via ioctl() */

static int
vcons_putwschar(struct vcons_screen *scr, struct wsdisplay_char *wsc)
{
	long attr;
	struct rasops_info *ri;
	int error;

	KASSERT(scr != NULL);
	KASSERT(wsc != NULL);

	ri = &scr->scr_ri;

	/* allow col as linear index if row == 0 */
	if (wsc->row == 0) {
		if (wsc->col < 0 || wsc->col > (ri->ri_cols * ri->ri_rows))
			return EINVAL;
	    	int rem;
	    	rem = wsc->col % ri->ri_cols;
	    	wsc->row = wsc->col / ri->ri_cols;
	    	DPRINTF("off %d -> %d, %d\n", wsc->col, rem, wsc->row);
	    	wsc->col = rem;
	} else {
		if (__predict_false(wsc->col < 0 || wsc->col >= ri->ri_cols))
			return EINVAL;

		if (__predict_false(wsc->row < 0 || wsc->row >= ri->ri_rows))
			return EINVAL;
	}

	error = ri->ri_ops.allocattr(ri, wsc->foreground,
	    wsc->background, wsc->flags, &attr);
	if (error)
		return error;
	vcons_putchar(ri, wsc->row, wsc->col, wsc->letter, attr);
	DPRINTF("vcons_putwschar(%d, %d, %x, %lx\n", wsc->row, wsc->col,
	    wsc->letter, attr);
	return 0;
}

static int
vcons_getwschar(struct vcons_screen *scr, struct wsdisplay_char *wsc)
{
	int offset;
	long attr;
	struct rasops_info *ri;
	int fg, bg, ul;

	KASSERT(scr != NULL);
	KASSERT(wsc != NULL);

	ri = &scr->scr_ri;

	/* allow col as linear index if row == 0 */
	if (wsc->row == 0) {
		if (wsc->col < 0 || wsc->col > (ri->ri_cols * ri->ri_rows))
			return EINVAL;
	    	int rem;
	    	rem = wsc->col % ri->ri_cols;
	    	wsc->row = wsc->col / ri->ri_cols;
	    	DPRINTF("off %d -> %d, %d\n", wsc->col, rem, wsc->row);
	    	wsc->col = rem;
	} else {
		if (__predict_false(wsc->col < 0 || wsc->col >= ri->ri_cols))
			return EINVAL;

		if (__predict_false(wsc->row < 0 || wsc->row >= ri->ri_rows))
			return EINVAL;
	}

	offset = ri->ri_cols * wsc->row + wsc->col;
	offset += vcons_offset_to_zero(scr);
	wsc->letter = scr->scr_chars[offset];
	attr = scr->scr_attrs[offset];

	DPRINTF("vcons_getwschar: %d, %d, %x, %lx\n", wsc->row,
	    wsc->col, wsc->letter, attr);

	/*
	 * this is ugly. We need to break up an attribute into colours and
	 * flags but there's no rasops method to do that so we must rely on
	 * the 'canonical' encoding.
	 */

	/* only fetches underline attribute */
	/* rasops_unpack_attr(attr, &fg, &bg, &ul); */
	fg = (attr >> 24) & 0xf;
	bg = (attr >> 16) & 0xf;
	ul = (attr & 1);

	wsc->foreground = fg;
	wsc->background = bg;

	/* clear trashed bits and restore underline flag */
	attr &= ~(WSATTR_HILIT | WSATTR_BLINK | WSATTR_UNDERLINE);
	if (ul)
		attr |= WSATTR_UNDERLINE;

	/* restore highlight boost */
	if (attr & WSATTR_HILIT)
		if (wsc->foreground >= 8)
			wsc->foreground -= 8;

	/* we always use colors, even when not stored */
	attr |= WSATTR_WSCOLORS;
	return 0;
}

int
vcons_offset_to_zero(const struct vcons_screen *scr)
{
#ifdef WSDISPLAY_SCROLLSUPPORT
	return scr->scr_offset_to_zero;
#else
	return 0;
#endif
}

#ifdef WSDISPLAY_SCROLLSUPPORT

static void
vcons_scroll(void *cookie, void *vs, int where)
{
	struct vcons_screen *scr = vs;

	if (where == 0) {
		scr->scr_line_wanted = 0;
	} else {
		scr->scr_line_wanted = scr->scr_line_wanted - where;
		if (scr->scr_line_wanted < 0)
			scr->scr_line_wanted = 0;
		if (scr->scr_line_wanted > scr->scr_lines_in_buffer)
			scr->scr_line_wanted = scr->scr_lines_in_buffer;
	}

	if (scr->scr_line_wanted != scr->scr_current_line) {

		vcons_do_scroll(scr);
	}
}

static void
vcons_do_scroll(struct vcons_screen *scr)
{
	int dist, from, to, num;
	int r_offset, r_start;
	int i, j;

	if (scr->scr_line_wanted == scr->scr_current_line)
		return;
	dist = scr->scr_line_wanted - scr->scr_current_line;
	scr->scr_current_line = scr->scr_line_wanted;
	scr->scr_current_offset = scr->scr_ri.ri_cols *
	    (scr->scr_lines_in_buffer - scr->scr_current_line);
	if (abs(dist) >= scr->scr_ri.ri_rows) {
		vcons_redraw_screen(scr);
		return;
	}
	/* scroll and redraw only what we really have to */
	if (dist > 0) {
		/* we scroll down */
		from = 0;
		to = dist;
		num = scr->scr_ri.ri_rows - dist;
		/* now the redraw parameters */
		r_offset = scr->scr_current_offset;
		r_start = 0;
	} else {
		/* scrolling up */
		to = 0;
		from = -dist;
		num = scr->scr_ri.ri_rows + dist;
		r_offset = scr->scr_current_offset + num * scr->scr_ri.ri_cols;
		r_start = num;
	}
	scr->scr_vd->private->copyrows(scr, from, to, num);
	for (i = 0; i < abs(dist); i++) {
		for (j = 0; j < scr->scr_ri.ri_cols; j++) {
#ifdef VCONS_DRAW_INTR
			vcons_putchar_cached(scr, i + r_start, j,
			    scr->scr_chars[r_offset],
			    scr->scr_attrs[r_offset]);
#else
			scr->putchar(scr, i + r_start, j,
			    scr->scr_chars[r_offset],
			    scr->scr_attrs[r_offset]);
#endif
			r_offset++;
		}
	}

	if (scr->scr_line_wanted == 0) {
		/* this was a reset - need to draw the cursor */
		scr->scr_ri.ri_flg &= ~RI_CURSOR;
		scr->scr_vd->private->cursor(scr, 1, scr->scr_ri.ri_crow,
		    scr->scr_ri.ri_ccol);
	}
}

#endif /* WSDISPLAY_SCROLLSUPPORT */

#ifdef VCONS_DRAW_INTR
static void
vcons_intr(void *cookie)
{
	struct vcons_data *vd = cookie;
	struct vcons_data_private *vdp = vd->private;

	softint_schedule(vdp->intr_softint);
}

static void
vcons_softintr(void *cookie)
{
	struct vcons_data *vd = cookie;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr = vd->active;
	unsigned int dirty;

	if (scr && vdp->use_intr) {
		if (!SCREEN_IS_BUSY(scr)) {
			dirty = atomic_swap_uint(&scr->scr_dirty, 0);
			membar_acquire();
			if (vdp->use_intr == 2) {
				if ((scr->scr_flags & VCONS_NO_REDRAW) == 0) {
					vdp->use_intr = 1;
					vcons_redraw_screen(scr);
				}
			} else if (dirty > 0) {
				if ((scr->scr_flags & VCONS_NO_REDRAW) == 0)
					vcons_update_screen(scr);
			}
		}
	}

	callout_schedule(&vdp->intr, mstohz(33));
}

static void
vcons_init_thread(void *cookie)
{
	struct vcons_data *vd = (struct vcons_data *)cookie;
	struct vcons_data_private *vdp = vd->private;

	vdp->use_intr = 2;
	callout_schedule(&vdp->intr, mstohz(33));
	kthread_exit(0);
}
#endif /* VCONS_DRAW_INTR */

void
vcons_enable_polling(struct vcons_data *vd)
{
	struct vcons_screen *scr = vd->active;

#ifdef VCONS_DRAW_INTR
	struct vcons_data_private *vdp = vd->private;

	vdp->use_intr = 0;
#endif

	if (scr && !SCREEN_IS_BUSY(scr)) {
		if ((scr->scr_flags & VCONS_NO_REDRAW) == 0)
			vcons_redraw_screen(scr);
	}
}

void
vcons_disable_polling(struct vcons_data *vd)
{
#ifdef VCONS_DRAW_INTR
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *scr = vd->active;

	if (!vdp->intr_valid)
		return;

	vdp->use_intr = 2;
	if (scr)
		vcons_dirty(scr);
#endif
}

void
vcons_hard_switch(struct vcons_screen *scr)
{
	struct vcons_data *vd = scr->scr_vd;
	struct vcons_data_private *vdp = vd->private;
	struct vcons_screen *oldscr = vd->active;

	if (oldscr) {
		SCREEN_INVISIBLE(oldscr);
		oldscr->scr_ri.ri_flg &= ~RI_CURSOR;
	}
	SCREEN_VISIBLE(scr);
	vd->active = scr;
	vdp->wanted = NULL;

	if (vd->show_screen_cb != NULL)
		vd->show_screen_cb(scr, vd->show_screen_cookie);
}

#ifdef VCONS_DRAW_INTR
static void
vcons_invalidate_cache(struct vcons_data *vd)
{
	struct vcons_data_private *vdp = vd->private;
	int i;

	for (i = 0; i < vdp->cells; i++) {
		vdp->chars[i] = -1;
		vdp->attrs[i] = -1;
	}
}
#endif
