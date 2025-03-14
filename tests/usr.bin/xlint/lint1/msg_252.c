/*	$NetBSD: msg_252.c,v 1.8 2024/06/08 06:42:59 rillig Exp $	*/
# 3 "msg_252.c"

// Test for message: integer constant out of range [252]

/*
 * See also:
 *	platform_ilp32_trad.c
 *	platform_ilp32_c90.c
 *	platform_ilp32_c99.c
 *	platform_lp64_trad.c
 *	platform_lp64_c90.c
 *	platform_lp64_c99.c
 */

/*
 * On ILP32 platforms, lint additionally and unnecessarily warns:
 *
 *	conversion of 'unsigned long' to 'int' is out of range [119]
 *
 * On an ILP32 platform, lex_integer_constant interprets this number as
 * having type ULONG, which is stored as 'ULONG 0x0000_0000_ffff_ffff'.
 * This number is passed to convert_constant, which calls convert_integer,
 * which sign-extends the number to 'INT 0xffff_ffff_ffff_ffff'.  This
 * converted number is passed to convert_constant_check_range, and at this
 * point, v->u.integer != nv->u.integer, due to the sign extension.  This
 * triggers an additional warning 119.
 *
 * On a 64-bit platform, lex_integer_constant stores the number as
 * 'ULONG 0xffff_ffff_ffff_ffff', which has the same representation as the
 * 'INT 0xffff_ffff_ffff_ffff', therefore no warning.
 *
 * Due to this unnecessary difference, disable this test on ILP32 platforms
 * for now (2021-08-28).
 */
/* lint1-only-if: lp64 */

/* lint1-extra-flags: -X 351 */

/* expect+1: warning: integer constant out of range [252] */
int constant = 1111111111111111111111111111111111111111111111111111;
