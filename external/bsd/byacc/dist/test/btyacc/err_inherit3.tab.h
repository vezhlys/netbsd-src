/*	$NetBSD: err_inherit3.tab.h,v 1.2 2024/09/14 21:29:03 christos Exp $	*/

#ifndef _err_inherit3__defines_h_
#define _err_inherit3__defines_h_

#define GLOBAL 257
#define LOCAL 258
#define REAL 259
#define INTEGER 260
#define NAME 261
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union YYSTYPE
{
    class	cval;
    type	tval;
    namelist *	nlist;
    name	id;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
extern YYSTYPE err_inherit3_lval;

#endif /* _err_inherit3__defines_h_ */
