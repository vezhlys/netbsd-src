/*	$NetBSD: user_acl.h,v 1.3 2025/02/25 19:15:46 christos Exp $	*/

#ifndef _USER_ACL_H_INCLUDED_
#define _USER_ACL_H_INCLUDED_
/*++
/* NAME
/*	user_acl 3h
/* SUMMARY
/*	Convert uid to username and check against given ACL.
/* SYNOPSIS
/*	#include <user_acl.h>
/*
/* DESCRIPTION
/* .nf

 /*
  * System library
  */
#include <unistd.h>			/* getuid()/geteuid() */
#include <sys/types.h>			/* uid_t */

 /*
  * Utility library.
  */
#include <vstring.h>

 /*
  * External interface
  */
extern const char *check_user_acl_byuid(const char *, const char *, uid_t);

/* AUTHOR(S)
/*	Wietse Venema
/*	IBM T.J. Watson Research
/*	P.O. Box 704
/*	Yorktown Heights, NY 10598, USA
/*
/*	Victor Duchovni
/*	Morgan Stanley
/*--*/
#endif
