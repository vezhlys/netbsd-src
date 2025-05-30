/*	$NetBSD: stat.c,v 1.55 2025/05/15 19:11:44 nia Exp $ */

/*
 * Copyright (c) 2002-2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Brown.
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

#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
/* config checked libc, we need the prototype as well */
#undef HAVE_DEVNAME
#endif

#include <sys/cdefs.h>
#if !defined(lint)
__RCSID("$NetBSD: stat.c,v 1.55 2025/05/15 19:11:44 nia Exp $");
#endif

#if ! HAVE_NBTOOL_CONFIG_H
#define HAVE_STRUCT_STAT_ST_FLAGS 1
#define HAVE_STRUCT_STAT_ST_GEN 1
#define HAVE_STRUCT_STAT_ST_BIRTHTIME 1
#define HAVE_STRUCT_STAT_ST_BIRTHTIMENSEC 1
#define HAVE_STRUCT_STAT_ST_MTIMENSEC 1
#define HAVE_DEVNAME 1
#endif /* HAVE_NBTOOL_CONFIG_H */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if HAVE_STRUCT_STAT_ST_FLAGS && !HAVE_NBTOOL_CONFIG_H
#include <util.h>
#endif
#include <vis.h>

#if HAVE_STRUCT_STAT_ST_FLAGS
#define DEF_F "%#Xf "
#define RAW_F "%f "
#define SHELL_F " st_flags=%f"
#else /* HAVE_STRUCT_STAT_ST_FLAGS */
#define DEF_F
#define RAW_F
#define SHELL_F
#endif /* HAVE_STRUCT_STAT_ST_FLAGS */

#if HAVE_STRUCT_STAT_ST_BIRTHTIME
#define DEF_B "\"%SB\" "
#define RAW_B "%B "
#define SHELL_B "st_birthtime=%SB "
#define LINUX_B	"%n Birth: %SB"
#else /* HAVE_STRUCT_STAT_ST_BIRTHTIME */
#define DEF_B
#define RAW_B
#define SHELL_B
#define LINUX_B
#endif /* HAVE_STRUCT_STAT_ST_BIRTHTIME */

#if HAVE_STRUCT_STAT_ST_ATIM
#define st_atimespec st_atim
#define st_ctimespec st_ctim
#define st_mtimespec st_mtim
#endif /* HAVE_STRUCT_STAT_ST_ATIM */

#define DEF_FORMAT \
	"%d %i %Sp %l %Su %Sg %r %z \"%Sa\" \"%Sm\" \"%Sc\" " DEF_B \
	"%k %b " DEF_F "%N"
#define RAW_FORMAT	"%d %i %#p %l %u %g %r %z %a %m %c " RAW_B \
	"%k %b " RAW_F "%N"
#define LS_FORMAT	"%Sp %l %Su %Sg %Z %Sm %N%SY"
#define LSF_FORMAT	"%Sp %l %Su %Sg %Z %Sm %N%T%SY"
#define SHELL_FORMAT \
	"st_dev=%d st_ino=%i st_mode=%#p st_nlink=%l " \
	"st_uid=%u st_gid=%g st_rdev=%r st_size=%z " \
	"st_atime=%Sa st_mtime=%Sm st_ctime=%Sc " SHELL_B \
	"st_blksize=%k st_blocks=%b" SHELL_F
#define LINUX_FORMAT \
	"  File: \"%N\"%n" \
	"  Size: %-11z  Blocks: %-11b  IO Block: %-11k  %HT%n" \
	"Device: %Hd,%Ld   Inode: %i    Links: %l%n" \
	"  Mode: (%Mp%03OLp/%.10Sp)         Uid: (%5u/%8Su)  Gid: (%5g/%8Sg)%n" \
	"Access: %Sa%n" \
	"Modify: %Sm%n" \
	"Change: %Sc" \
	LINUX_B

#define TIME_FORMAT	"%b %e %T %Y"

#define FLAG_POUND	0x01
#define FLAG_SPACE	0x02
#define FLAG_PLUS	0x04
#define FLAG_ZERO	0x08
#define FLAG_MINUS	0x10

/*
 * These format characters must all be unique, except the magic one.
 */
#define FMT_MAGIC	'%'
#define FMT_DOT		'.'

#define SIMPLE_NEWLINE	'n'
#define SIMPLE_TAB	't'
#define SIMPLE_PERCENT	'%'
#define SIMPLE_NUMBER	'@'

#define FMT_POUND	'#'
#define FMT_SPACE	' '
#define FMT_PLUS	'+'
#define FMT_ZERO	'0'
#define FMT_MINUS	'-'

#define FMT_DECIMAL 	'D'
#define FMT_OCTAL 	'O'
#define FMT_UNSIGNED 	'U'
#define FMT_HEX 	'X'
#define FMT_FLOAT 	'F'
#define FMT_STRING 	'S'

#define FMTF_DECIMAL	0x01
#define FMTF_OCTAL	0x02
#define FMTF_UNSIGNED	0x04
#define FMTF_HEX	0x08
#define FMTF_FLOAT	0x10
#define FMTF_STRING	0x20

#define HIGH_PIECE	'H'
#define MIDDLE_PIECE	'M'
#define LOW_PIECE	'L'

#define	SHOW_realpath	'R'
#define SHOW_st_dev	'd'
#define SHOW_st_ino	'i'
#define SHOW_st_mode	'p'
#define SHOW_st_nlink	'l'
#define SHOW_st_uid	'u'
#define SHOW_st_gid	'g'
#define SHOW_st_rdev	'r'
#define SHOW_st_atime	'a'
#define SHOW_st_mtime	'm'
#define SHOW_st_ctime	'c'
#define SHOW_st_btime	'B'
#define SHOW_st_size	'z'
#define SHOW_st_blocks	'b'
#define SHOW_st_blksize	'k'
#define SHOW_st_flags	'f'
#define SHOW_st_gen	'v'
#define SHOW_symlink	'Y'
#define SHOW_filetype	'T'
#define SHOW_filename	'N'
#define SHOW_sizerdev	'Z'

static void	usage(const char *) __dead;
static void	output(const struct stat *, const char *,
	    const char *, int, int, int);
static int	format1(const struct stat *,	/* stat info */
	    const char *,		/* the file name */
	    const char *, int,		/* the format string itself */
	    char *, size_t,		/* a place to put the output */
	    int, int, int, int,		/* the parsed format */
	    int, int, int);

static const char *timefmt;
static int linkfail;

#define addchar(s, c, nl) \
	do { \
		(void)fputc((c), (s)); \
		(*nl) = ((c) == '\n'); \
	} while (0/*CONSTCOND*/)

int
main(int argc, char *argv[])
{
	struct stat st;
	int ch, rc, errs, am_readlink;
	int lsF, fmtchar, usestat, fn, nonl, quiet;
	const char *statfmt, *options, *synopsis;

	am_readlink = 0;
	lsF = 0;
	fmtchar = '\0';
	usestat = 0;
	nonl = 0;
	quiet = 0;
	linkfail = 0;
	statfmt = NULL;
	timefmt = NULL;

	setprogname(argv[0]);

	if (strcmp(getprogname(), "readlink") == 0) {
		am_readlink = 1;
		options = "fnqsv";
		synopsis = "[-fnqsv] file ...";
		statfmt = "%Y";
		fmtchar = 'f';
		if (getenv("POSIXLY_CORRECT") == NULL)
			quiet = 1;
	} else {
		options = "f:FlLnqrst:x";
		synopsis = "[-FlLnqrsx] [-f format] [-t timefmt] [file ...]";
	}

	while ((ch = getopt(argc, argv, options)) != -1)
		switch (ch) {
		case 'F':
			lsF = 1;
			break;
		case 'L':
			usestat = 1;
			break;
		case 'n':
			nonl = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'f':
			if (am_readlink) {
				statfmt = "%R";
				break;
			}
			statfmt = optarg;
			/* FALLTHROUGH */
		case 'l':
		case 'r':
		case 's':
			if (am_readlink) {
				quiet = 1;
				break;
			}
			/*FALLTHROUGH*/
		case 'x':
			if (fmtchar != 0)
				errx(1, "can't use format '%c' with '%c'",
				    fmtchar, ch);
			fmtchar = ch;
			break;
		case 't':
			timefmt = optarg;
			break;
		case 'v':
			quiet = 0;
			break;
		default:
			usage(synopsis);
		}

	argc -= optind;
	argv += optind;
	fn = 1;

	if (am_readlink && argc == 0)
		usage(synopsis);

	if (fmtchar == '\0') {
		if (lsF)
			fmtchar = 'l';
		else {
			fmtchar = 'f';
			statfmt = DEF_FORMAT;
		}
	}

	if (lsF && fmtchar != 'l')
		errx(1, "can't use format '%c' with -F", fmtchar);

	switch (fmtchar) {
	case 'f':
		/* statfmt already set */
		break;
	case 'l':
		statfmt = lsF ? LSF_FORMAT : LS_FORMAT;
		break;
	case 'r':
		statfmt = RAW_FORMAT;
		break;
	case 's':
		statfmt = SHELL_FORMAT;
		if (timefmt == NULL)
			timefmt = "%s";
		break;
	case 'x':
		statfmt = LINUX_FORMAT;
		if (timefmt == NULL)
			timefmt = "%Y-%m-%d %H:%M:%S.%f %z";
		break;
	default:
		usage(synopsis);
		/*NOTREACHED*/
	}

	if (timefmt == NULL)
		timefmt = TIME_FORMAT;

	errs = 0;
	do {
		if (argc == 0) {
			fn = 0;
			rc = fstat(STDIN_FILENO, &st);
		} else if (usestat) {
			/*
			 * Try stat() and if it fails, fall back to
			 * lstat() just in case we're examining a
			 * broken symlink.
			 */
			if ((rc = stat(argv[0], &st)) == -1 &&
			    errno == ENOENT &&
			    (rc = lstat(argv[0], &st)) == -1)
				errno = ENOENT;
		} else
			rc = lstat(argv[0], &st);

		if (rc == -1) {
			errs = 1;
			linkfail = 1;
			if (!quiet) {
				if (argc == 0)
					warn("%s: %s",
					    "(stdin)", "fstat");
				else
					warn("%s: %s", argv[0],
					    usestat ? "stat" : "lstat");
			}
		} else if (am_readlink && statfmt[1] == 'Y' &&
		    (st.st_mode & S_IFMT) != S_IFLNK) {
			linkfail = 1;
			if (!quiet)
				warnx("%s: Not a symbolic link", argv[0]);
		} else
			output(&st, argv[0], statfmt, fn, nonl, quiet);

		argv++;
		argc--;
		fn++;
	} while (argc > 0);

	return (am_readlink ? linkfail : errs);
}

static void
usage(const char *synopsis)
{

	(void)fprintf(stderr, "usage: %s %s\n", getprogname(), synopsis);
	exit(1);
}

/* 
 * Parses a format string.
 */
static void
output(const struct stat *st, const char *file,
    const char *statfmt, int fn, int nonl, int quiet)
{
	int flags, size, prec, ofmt, hilo, what;
	/*
	 * buf size is enough for an item of length PATH_MAX,
	 * multiplied by 4 for vis encoding, plus 4 for symlink
	 * " -> " prefix, plus 1 for \0 terminator.
	 */
	char buf[PATH_MAX * 4 + 4 + 1];
	const char *subfmt;
	int nl, t, i;

	nl = 1;
	while (*statfmt != '\0') {

		/*
		 * Non-format characters go straight out.
		 */
		if (*statfmt != FMT_MAGIC) {
			addchar(stdout, *statfmt, &nl);
			statfmt++;
			continue;
		}

		/*
		 * The current format "substring" starts here,
		 * and then we skip the magic.
		 */
		subfmt = statfmt;
		statfmt++;

		/*
		 * Some simple one-character "formats".
		 */
		switch (*statfmt) {
		case SIMPLE_NEWLINE:
			addchar(stdout, '\n', &nl);
			statfmt++;
			continue;
		case SIMPLE_TAB:
			addchar(stdout, '\t', &nl);
			statfmt++;
			continue;
		case SIMPLE_PERCENT:
			addchar(stdout, '%', &nl);
			statfmt++;
			continue;
		case SIMPLE_NUMBER: {
			char num[12], *p;

			snprintf(num, sizeof(num), "%d", fn);
			for (p = &num[0]; *p; p++)
				addchar(stdout, *p, &nl);
			statfmt++;
			continue;
		}
		}

		/*
		 * This must be an actual format string.  Format strings are
		 * similar to printf(3) formats up to a point, and are of
		 * the form:
		 *
		 *	%	required start of format
		 *	[-# +0]	opt. format characters
		 *	size	opt. field width
		 *	.	opt. decimal separator, followed by
		 *	prec	opt. precision
		 *	fmt	opt. output specifier (string, numeric, etc.)
		 *	sub	opt. sub field specifier (high, middle, low)
		 *	datum	required field specifier (size, mode, etc)
		 *
		 * Only the % and the datum selector are required.  All data
		 * have reasonable default output forms.  The "sub" specifier
		 * only applies to certain data (mode, dev, rdev, filetype).
		 * The symlink output defaults to STRING, yet will only emit
		 * the leading " -> " if STRING is explicitly specified.  The
		 * sizerdev datum will generate rdev output for character or
		 * block devices, and size output for all others.
		 * For STRING output, the # format requests vis encoding.
		 */
		flags = 0;
		do {
			if      (*statfmt == FMT_POUND)
				flags |= FLAG_POUND;
			else if (*statfmt == FMT_SPACE)
				flags |= FLAG_SPACE;
			else if (*statfmt == FMT_PLUS)
				flags |= FLAG_PLUS;
			else if (*statfmt == FMT_ZERO)
				flags |= FLAG_ZERO;
			else if (*statfmt == FMT_MINUS)
				flags |= FLAG_MINUS;
			else
				break;
			statfmt++;
		} while (1/*CONSTCOND*/);

		size = -1;
		if (isdigit((unsigned char)*statfmt)) {
			size = 0;
			while (isdigit((unsigned char)*statfmt)) {
				size = (size * 10) + (*statfmt - '0');
				statfmt++;
				if (size < 0)
					goto badfmt;
			}
		}

		prec = -1;
		if (*statfmt == FMT_DOT) {
			statfmt++;

			prec = 0;
			while (isdigit((unsigned char)*statfmt)) {
				prec = (prec * 10) + (*statfmt - '0');
				statfmt++;
				if (prec < 0)
					goto badfmt;
			}
		}

#define fmtcase(x, y)		case (y): (x) = (y); statfmt++; break
#define fmtcasef(x, y, z)	case (y): (x) = (z); statfmt++; break
		switch (*statfmt) {
			fmtcasef(ofmt, FMT_DECIMAL,	FMTF_DECIMAL);
			fmtcasef(ofmt, FMT_OCTAL,	FMTF_OCTAL);
			fmtcasef(ofmt, FMT_UNSIGNED,	FMTF_UNSIGNED);
			fmtcasef(ofmt, FMT_HEX,		FMTF_HEX);
			fmtcasef(ofmt, FMT_FLOAT,	FMTF_FLOAT);
			fmtcasef(ofmt, FMT_STRING,	FMTF_STRING);
		default:
			ofmt = 0;
			break;
		}

		switch (*statfmt) {
			fmtcase(hilo, HIGH_PIECE);
			fmtcase(hilo, MIDDLE_PIECE);
			fmtcase(hilo, LOW_PIECE);
		default:
			hilo = 0;
			break;
		}

		switch (*statfmt) {
			fmtcase(what, SHOW_realpath);
			fmtcase(what, SHOW_st_dev);
			fmtcase(what, SHOW_st_ino);
			fmtcase(what, SHOW_st_mode);
			fmtcase(what, SHOW_st_nlink);
			fmtcase(what, SHOW_st_uid);
			fmtcase(what, SHOW_st_gid);
			fmtcase(what, SHOW_st_rdev);
			fmtcase(what, SHOW_st_atime);
			fmtcase(what, SHOW_st_mtime);
			fmtcase(what, SHOW_st_ctime);
			fmtcase(what, SHOW_st_btime);
			fmtcase(what, SHOW_st_size);
			fmtcase(what, SHOW_st_blocks);
			fmtcase(what, SHOW_st_blksize);
			fmtcase(what, SHOW_st_flags);
			fmtcase(what, SHOW_st_gen);
			fmtcase(what, SHOW_symlink);
			fmtcase(what, SHOW_filetype);
			fmtcase(what, SHOW_filename);
			fmtcase(what, SHOW_sizerdev);
		default:
			goto badfmt;
		}
#undef fmtcasef
#undef fmtcase

		t = format1(st,
		     file,
		     subfmt, statfmt - subfmt,
		     buf, sizeof(buf),
		     flags, size, prec, ofmt, hilo, what, quiet);

		for (i = 0; i < t && i < (int)(sizeof(buf) - 1); i++)
			addchar(stdout, buf[i], &nl);

		continue;

	badfmt:
		errx(1, "%.*s: bad format",
		    (int)(statfmt - subfmt + 1), subfmt);
	}

	if (!nl && !nonl)
		(void)fputc('\n', stdout);
	(void)fflush(stdout);
}

static const char *
fmttime(char *buf, size_t len, const char *fmt, time_t secs, long nsecs)
{
	struct tm tm;
	const char *fpb, *fp1, *fp2;	/* pointers into fmt */
	char *fmt2 = NULL;		/* replacement fmt (if not NULL) */
				/* XXX init of next twp for stupid gcc only */
	char *f2p = NULL;		/* ptr into fmt2 - last added */
	size_t flen = 0;
	size_t o;
	int sl;

	if (localtime_r(&secs, &tm) == NULL) {
		secs = 0;
		(void)localtime_r(&secs, &tm);
	}
	for (fp1 = fpb = fmt; (fp2 = strchr(fp1, '%')) != NULL; ) {
		if (fp2[1] != 'f') {
			/* make sure we don't find the 2nd '%' in "%%" */
			fp1 = fp2 + 1 + (fp2[1] != '\0');
			continue;
		}
		if (fmt2 == NULL) {
			/* allow for ~100 %f's in the format ... */
			flen = strlen(fmt) + 1024;

			if ((fmt2 = calloc(flen, 1)) == NULL) {
				fp1 = fp2 + 2;
				continue;
			}
			f2p = fmt2;

			o = (size_t)(fp2 - fpb);
			memcpy(f2p, fpb, o);	/* must fit */
			fmt = fmt2;
		} else {
			o = (size_t)(fp2 - fpb);
			if (flen > o)
				memcpy(f2p, fpb, o);
		}
		if (flen < o + 10) {	/* 9 digits + \0 == 10 */
			*f2p = '\0';
			break;
		}
		f2p += o;
		flen -= o;
		sl = snprintf(f2p, flen, "%.9ld", nsecs);
		if (sl == -1)
			sl = 0;
		f2p += sl;
		*f2p = '\0';
		flen -= sl;
		fp1 = fp2 + 2;
		fpb = fp1;
	}
	if (fmt2 != NULL) {
		o = strlen(fpb);
		if (flen > o) {
			memcpy(f2p, fpb, o);
			f2p[o] = '\0';
		}
	}

	(void)strftime(buf, len, fmt, &tm);
	free(fmt2);
	return buf;
}

/*
 * Arranges output according to a single parsed format substring.
 */
static int
format1(const struct stat *st,
    const char *file,
    const char *fmt, int flen,
    char *buf, size_t blen,
    int flags, int size, int prec, int ofmt,
    int hilo, int what, int quiet)
{
	uint64_t data;
	char *stmp, lfmt[24], tmp[20];
	const char *sdata;
	char smode[12], sid[13], path[PATH_MAX + 4], visbuf[PATH_MAX * 4 + 4];
	struct passwd *pw;
	struct group *gr;
	time_t secs;
	long nsecs;
	int l;
	int formats;	/* bitmap of allowed formats for this datum */
	int small;	/* true if datum is a small integer */
	int gottime;	/* true if secs and nsecs are valid */
	int shift;	/* powers of 2 to scale numbers before printing */
	size_t prefixlen; /* length of constant prefix for string data */

	formats = 0;
	small = 0;
	gottime = 0;
	secs = 0;
	nsecs = 0;
	shift = 0;
	prefixlen = 0;

	/*
	 * First, pick out the data and tweak it based on hilo or
	 * specified output format (symlink output only).
	 */
	switch (what) {
	case SHOW_st_dev:
	case SHOW_st_rdev:
		small = (sizeof(st->st_dev) == 4);
		data = (what == SHOW_st_dev) ? st->st_dev : st->st_rdev;
#if HAVE_DEVNAME
		sdata = (what == SHOW_st_dev) ?
		    devname(st->st_dev, S_IFBLK) :
		    devname(st->st_rdev, 
			S_ISCHR(st->st_mode) ? S_IFCHR :
			S_ISBLK(st->st_mode) ? S_IFBLK :
			0U);
		if (sdata == NULL)
			sdata = "???";
#endif /* HAVE_DEVNAME */
		if (hilo == HIGH_PIECE) {
			data = major(data);
			hilo = 0;
		}
		else if (hilo == LOW_PIECE) {
			data = minor((unsigned)data);
			hilo = 0;
		}
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX |
#if HAVE_DEVNAME
		    FMTF_STRING;
#else /* HAVE_DEVNAME */
		    0;
#endif /* HAVE_DEVNAME */
		if (ofmt == 0) {
			if (data == (uint64_t)-1)
				ofmt = FMTF_DECIMAL;
			else
				ofmt = FMTF_UNSIGNED;
		}
		break;
	case SHOW_st_ino:
		small = (sizeof(st->st_ino) == 4);
		data = st->st_ino;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
	case SHOW_st_mode:
		small = (sizeof(st->st_mode) == 4);
		data = st->st_mode;
		strmode(st->st_mode, smode);
		stmp = smode;
		l = strlen(stmp);
		if (stmp[l - 1] == ' ')
			stmp[--l] = '\0';
		if (hilo == HIGH_PIECE) {
			data >>= 12;
			stmp += 1;
			stmp[3] = '\0';
			hilo = 0;
		}
		else if (hilo == MIDDLE_PIECE) {
			data = (data >> 9) & 07;
			stmp += 4;
			stmp[3] = '\0';
			hilo = 0;
		}
		else if (hilo == LOW_PIECE) {
			data &= 0777;
			stmp += 7;
			stmp[3] = '\0';
			hilo = 0;
		}
		sdata = stmp;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX |
		    FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_OCTAL;
		break;
	case SHOW_st_nlink:
		small = (sizeof(st->st_dev) == 4);
		data = st->st_nlink;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
	case SHOW_st_uid:
		small = (sizeof(st->st_uid) == 4);
		data = st->st_uid;
		if ((pw = getpwuid(st->st_uid)) != NULL)
			sdata = pw->pw_name;
		else {
			snprintf(sid, sizeof(sid), "(%ld)", (long)st->st_uid);
			sdata = sid;
		}
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX |
		    FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
	case SHOW_st_gid:
		small = (sizeof(st->st_gid) == 4);
		data = st->st_gid;
		if ((gr = getgrgid(st->st_gid)) != NULL)
			sdata = gr->gr_name;
		else {
			snprintf(sid, sizeof(sid), "(%ld)", (long)st->st_gid);
			sdata = sid;
		}
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX |
		    FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
	case SHOW_st_atime:
		gottime = 1;
		secs = st->st_atime;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
		nsecs = st->st_atimensec;
#endif
		/* FALLTHROUGH */
	case SHOW_st_mtime:
		if (!gottime) {
			gottime = 1;
			secs = st->st_mtime;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
			nsecs = st->st_mtimensec;
#endif
		}
		/* FALLTHROUGH */
	case SHOW_st_ctime:
		if (!gottime) {
			gottime = 1;
			secs = st->st_ctime;
#if HAVE_STRUCT_STAT_ST_MTIMENSEC
			nsecs = st->st_ctimensec;
#endif
		}
#if HAVE_STRUCT_STAT_ST_BIRTHTIME
		/* FALLTHROUGH */
	case SHOW_st_btime:
		if (!gottime) {
			gottime = 1;
			secs = st->st_birthtime;
#if HAVE_STRUCT_STAT_ST_BIRTHTIMENSEC
			nsecs = st->st_birthtimensec;
#endif /* HAVE_STRUCT_STAT_ST_BIRTHTIMENSEC */
		}
#endif /* HAVE_STRUCT_STAT_ST_BIRTHTIME */
		small = (sizeof(secs) == 4);
		data = secs;
		sdata = fmttime(path, sizeof(path), timefmt, secs, nsecs);

		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX |
		    FMTF_FLOAT | FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_DECIMAL;
		break;
	case SHOW_st_size:
		small = (sizeof(st->st_size) == 4);
		data = st->st_size;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		switch (hilo) {
		case HIGH_PIECE:
			shift = 30;	/* gigabytes */
			hilo = 0;
			break;
		case MIDDLE_PIECE:
			shift = 20;	/* megabytes */
			hilo = 0;
			break;
		case LOW_PIECE:
			shift = 10;	/* kilobytes */
			hilo = 0;
			break;
		}
		break;
	case SHOW_st_blocks:
		small = (sizeof(st->st_blocks) == 4);
		data = st->st_blocks;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
	case SHOW_st_blksize:
		small = (sizeof(st->st_blksize) == 4);
		data = st->st_blksize;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
#if HAVE_STRUCT_STAT_ST_FLAGS
	case SHOW_st_flags:
		small = (sizeof(st->st_flags) == 4);
		data = st->st_flags;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
#if !HAVE_NBTOOL_CONFIG_H
		sdata = flags_to_string((u_long)st->st_flags, "-");
		formats |= FMT_STRING;
#endif
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
#endif /* HAVE_STRUCT_STAT_ST_FLAGS */
#if HAVE_STRUCT_STAT_ST_GEN
	case SHOW_st_gen:
		small = (sizeof(st->st_gen) == 4);
		data = st->st_gen;
		sdata = NULL;
		formats = FMTF_DECIMAL | FMTF_OCTAL | FMTF_UNSIGNED | FMTF_HEX;
		if (ofmt == 0)
			ofmt = FMTF_UNSIGNED;
		break;
#endif /* HAVE_STRUCT_STAT_ST_GEN */
	case SHOW_realpath:
		small = 0;
		data = 0;
		if (file == NULL) {
			(void)strlcpy(path, "(stdin)", sizeof(path));
			sdata = path;
		} else {
			snprintf(path, sizeof(path), " -> ");
			if (realpath(file, path + 4) == NULL) {
				if (!quiet)
					warn("realpath `%s'", file);
				linkfail = 1;
				l = 0;
				path[0] = '\0';
			}
			sdata = path + (ofmt == FMTF_STRING ? 0 : 4);
			prefixlen = (ofmt == FMTF_STRING ? 4 : 0);
		}

		formats = FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_STRING;
		break;
	case SHOW_symlink:
		small = 0;
		data = 0;
		if (S_ISLNK(st->st_mode)) {
			snprintf(path, sizeof(path), " -> ");
			l = readlink(file, path + 4, sizeof(path) - 4 - 1);
			if (l == -1) {
				if (!quiet)
					warn("readlink `%s'", file);
				linkfail = 1;
				l = 0;
				path[0] = '\0';
			}
			path[l + 4] = '\0';
			sdata = path + (ofmt == FMTF_STRING ? 0 : 4);
			prefixlen = (ofmt == FMTF_STRING ? 4 : 0);
		}
		else {
			linkfail = 1;
			sdata = "";
		}
		formats = FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_STRING;
		break;
	case SHOW_filetype:
		small = 0;
		data = 0;
		sdata = "";
		if (hilo == 0 || hilo == LOW_PIECE) {
			switch (st->st_mode & S_IFMT) {
			case S_IFIFO:	sdata = "|";			break;
			case S_IFDIR:	sdata = "/";			break;
			case S_IFREG:
				if (st->st_mode &
				    (S_IXUSR | S_IXGRP | S_IXOTH))
					sdata = "*";
				break;
			case S_IFLNK:	sdata = "@";			break;
#ifdef S_IFSOCK
			case S_IFSOCK:	sdata = "=";			break;
#endif
#ifdef S_IFWHT
			case S_IFWHT:	sdata = "%";			break;
#endif /* S_IFWHT */
#ifdef S_IFDOOR
			case S_IFDOOR:	sdata = ">";			break;
#endif /* S_IFDOOR */
			}
			hilo = 0;
		}
		else if (hilo == HIGH_PIECE) {
			switch (st->st_mode & S_IFMT) {
			case S_IFIFO:	sdata = "Fifo File";		break;
			case S_IFCHR:	sdata = "Character Device";	break;
			case S_IFDIR:	sdata = "Directory";		break;
			case S_IFBLK:	sdata = "Block Device";		break;
			case S_IFREG:	sdata = "Regular File";		break;
			case S_IFLNK:	sdata = "Symbolic Link";	break;
#ifdef S_IFSOCK
			case S_IFSOCK:	sdata = "Socket";		break;
#endif
#ifdef S_IFWHT
			case S_IFWHT:	sdata = "Whiteout File";	break;
#endif /* S_IFWHT */
#ifdef S_IFDOOR
			case S_IFDOOR:	sdata = "Door";			break;
#endif /* S_IFDOOR */
			default:	sdata = "???";			break;
			}
			hilo = 0;
		}
		formats = FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_STRING;
		break;
	case SHOW_filename:
		small = 0;
		data = 0;
		if (file == NULL) {
			(void)strlcpy(path, "(stdin)", sizeof(path));
			if (hilo == HIGH_PIECE || hilo == LOW_PIECE)
				hilo = 0;
		}
		else if (hilo == 0)
			(void)strlcpy(path, file, sizeof(path));
		else {
			char *s;
			(void)strlcpy(path, file, sizeof(path));
			s = strrchr(path, '/');
			if (s != NULL) {
				/* trim off trailing /'s */
				while (s != path &&
				    s[0] == '/' && s[1] == '\0')
					*s-- = '\0';
				s = strrchr(path, '/');
			}
			if (hilo == HIGH_PIECE) {
				if (s == NULL)
					(void)strlcpy(path, ".", sizeof(path));
				else {
					while (s != path && s[0] == '/')
						*s-- = '\0';
				}
				hilo = 0;
			}
			else if (hilo == LOW_PIECE) {
				if (s != NULL && s[1] != '\0')
					(void)strlcpy(path, s + 1,
						      sizeof(path));
				hilo = 0;
			}
		}
		sdata = path;
		formats = FMTF_STRING;
		if (ofmt == 0)
			ofmt = FMTF_STRING;
		break;
	case SHOW_sizerdev:
		if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) {
			char majdev[20], mindev[20];
			int l1, l2;

			if (size == 0)		/* avoid -1/2 */
				size++;		/* 1/2 == 0/2 so this is safe */
			l1 = format1(st,
			    file,
			    fmt, flen,
			    majdev, sizeof(majdev),
			    flags, (size - 1) / 2, prec,
			    ofmt, HIGH_PIECE, SHOW_st_rdev, quiet);
			l2 = format1(st,
			    file,
			    fmt, flen,
			    mindev, sizeof(mindev),
			    flags | FLAG_MINUS , size / 2, prec,
			    ofmt, LOW_PIECE, SHOW_st_rdev, quiet);
			return (snprintf(buf, blen, "%.*s,%.*s",
			    l1, majdev, l2, mindev));
		}
		else {
			return (format1(st,
			    file,
			    fmt, flen,
			    buf, blen,
			    flags, size, prec,
			    ofmt, 0, SHOW_st_size, quiet));
		}
		/*NOTREACHED*/
	default:
		errx(1, "%.*s: bad format", (int)flen, fmt);
	}

	if (hilo != 0			// subdatum not supported
	    || !(ofmt & formats)	// output format not supported
	    || (ofmt == FMTF_STRING && flags & FLAG_SPACE)
	    || (ofmt == FMTF_STRING && flags & FLAG_PLUS)
	    || (ofmt == FMTF_STRING && flags & FLAG_ZERO))
		errx(1, "%.*s: bad format", (int)flen, fmt);

	/*
	 * FLAG_POUND with FMTF_STRING means use vis(3) encoding.
	 * First prefixlen chars are not encoded.
	 */
	if ((flags & FLAG_POUND) != 0 && ofmt == FMTF_STRING) {
		flags &= ~FLAG_POUND;
		strncpy(visbuf, sdata, prefixlen);
		/* Avoid GCC warnings. */
		visbuf[prefixlen] = 0;
		strnvis(visbuf + prefixlen, sizeof(visbuf) - prefixlen,
		    sdata + prefixlen, VIS_WHITE | VIS_OCTAL | VIS_CSTYLE);
		sdata = visbuf;
	}

	/*
	 * Assemble the format string for passing to printf(3).
	 */
	lfmt[0] = '\0';
	(void)strcat(lfmt, "%");
	if (flags & FLAG_POUND)
		(void)strcat(lfmt, "#");
	if (flags & FLAG_SPACE)
		(void)strcat(lfmt, " ");
	if (flags & FLAG_PLUS)
		(void)strcat(lfmt, "+");
	if (flags & FLAG_MINUS)
		(void)strcat(lfmt, "-");
	if (flags & FLAG_ZERO)
		(void)strcat(lfmt, "0");

	/*
	 * Only the timespecs support the FLOAT output format, and that
	 * requires work that differs from the other formats.
	 */ 
	if (ofmt == FMTF_FLOAT) {
		/*
		 * Nothing after the decimal point, so just print seconds.
		 */
		if (prec == 0) {
			if (size != -1) {
				(void)snprintf(tmp, sizeof(tmp), "%d", size);
				(void)strcat(lfmt, tmp);
			}
			(void)strcat(lfmt, "lld");
			return (snprintf(buf, blen, lfmt,
			    (long long)secs));
		}

		/*
		 * Unspecified precision gets all the precision we have:
		 * 9 digits.
		 */
		if (prec == -1)
			prec = 9;

		/*
		 * Adjust the size for the decimal point and the digits
		 * that will follow.
		 */
		size -= prec + 1;

		/*
		 * Any leftover size that's legitimate will be used.
		 */
		if (size > 0) {
			(void)snprintf(tmp, sizeof(tmp), "%d", size);
			(void)strcat(lfmt, tmp);
		}
		/* Seconds: time_t cast to long long. */
		(void)strcat(lfmt, "lld");

		/*
		 * The stuff after the decimal point always needs zero
		 * filling.
		 */
		(void)strcat(lfmt, ".%0");

		/*
		 * We can "print" at most nine digits of precision.  The
		 * rest we will pad on at the end.
		 *
		 * Nanoseconds: long.
		 */
		(void)snprintf(tmp, sizeof(tmp), "%dld", prec > 9 ? 9 : prec);
		(void)strcat(lfmt, tmp);

		/*
		 * For precision of less that nine digits, trim off the
		 * less significant figures.
		 */
		for (; prec < 9; prec++)
			nsecs /= 10;

		/*
		 * Use the format, and then tack on any zeroes that
		 * might be required to make up the requested precision.
		 */
		l = snprintf(buf, blen, lfmt, (long long)secs, nsecs);
		for (; prec > 9 && l < (int)blen; prec--, l++)
			(void)strcat(buf, "0");
		return (l);
	}

	/*
	 * Add on size and precision, if specified, to the format.
	 */
	if (size != -1) {
		(void)snprintf(tmp, sizeof(tmp), "%d", size);
		(void)strcat(lfmt, tmp);
	}
	if (prec != -1) {
		(void)snprintf(tmp, sizeof(tmp), ".%d", prec);
		(void)strcat(lfmt, tmp);
	}

	/*
	 * String output uses the temporary sdata.
	 */
	if (ofmt == FMTF_STRING) {
		if (sdata == NULL)
			errx(1, "%.*s: bad format", (int)flen, fmt);
		(void)strcat(lfmt, "s");
		return (snprintf(buf, blen, lfmt, sdata));
	}

	/*
	 * Ensure that sign extension does not cause bad looking output
	 * for some forms.
	 */
	if (small && ofmt != FMTF_DECIMAL)
		data = (uint32_t)data;

	/*
	 * The four "numeric" output forms.
	 */
	(void)strcat(lfmt, "ll");
	switch (ofmt) {
	case FMTF_DECIMAL:	(void)strcat(lfmt, "d");	break;
	case FMTF_OCTAL:	(void)strcat(lfmt, "o");	break;
	case FMTF_UNSIGNED:	(void)strcat(lfmt, "u");	break;
	case FMTF_HEX:		(void)strcat(lfmt, "x");	break;
	}

	/*
	 * shift and round to nearest for kilobytes, megabytes,
	 * gigabytes.
	 */
	if (shift > 0) {
		data >>= (shift - 1);
		data++;
		data >>= 1;
	}

	return (snprintf(buf, blen, lfmt, data));
}
