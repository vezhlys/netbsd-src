/* Base configuration file for all NetBSD targets.
   Copyright (C) 1997-2022 Free Software Foundation, Inc.

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3, or (at your option)
any later version.

GCC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

/* TARGET_OS_CPP_BUILTINS() common to all NetBSD targets.  */
#define NETBSD_OS_CPP_BUILTINS_COMMON()		\
  do						\
    {						\
      builtin_define ("__NetBSD__");		\
      builtin_define ("__unix__");		\
      builtin_define ("__syslog_attribute__");	\
      builtin_assert ("system=bsd");		\
      builtin_assert ("system=unix");		\
      builtin_assert ("system=NetBSD");		\
    }						\
  while (0)

/* CPP_SPEC parts common to all NetBSD targets.  */
#define NETBSD_CPP_SPEC				\
  "%{posix:-D_POSIX_SOURCE} \
   %{pthread:-D_REENTRANT -D_PTHREADS}"

/* NETBSD_NATIVE is defined when gcc is integrated into the NetBSD
   source tree so it can be configured appropriately without using
   the GNU configure/build mechanism.

   NETBSD_TOOLS is defined when gcc is built as cross-compiler for
   the in-tree toolchain.
 */

#if defined(NETBSD_NATIVE) || defined(NETBSD_TOOLS)

/* Look for the include files in the system-defined places.  */

#undef GPLUSPLUS_INCLUDE_DIR
#define GPLUSPLUS_INCLUDE_DIR "/usr/include/g++"

#undef GPLUSPLUS_INCLUDE_DIR_ADD_SYSROOT
#define GPLUSPLUS_INCLUDE_DIR_ADD_SYSROOT 1

#undef GPLUSPLUS_BACKWARD_INCLUDE_DIR
#define GPLUSPLUS_BACKWARD_INCLUDE_DIR "/usr/include/g++/backward"

#undef GCC_INCLUDE_DIR_ADD_SYSROOT
#define GCC_INCLUDE_DIR_ADD_SYSROOT 1

/*
 * XXX figure out a better way to do this
 */
#undef GCC_INCLUDE_DIR
#define GCC_INCLUDE_DIR "/usr/include/gcc-12"

/* Under NetBSD, the normal location of the various *crt*.o files is the
   /usr/lib directory.  */

#undef STANDARD_STARTFILE_PREFIX
#define STANDARD_STARTFILE_PREFIX	"/usr/lib/"
#undef STANDARD_STARTFILE_PREFIX_1
#define STANDARD_STARTFILE_PREFIX_1	"/usr/lib/"

#endif /* NETBSD_NATIVE || NETBSD_TOOLS */

#if defined(NETBSD_NATIVE)
/* Under NetBSD, the normal location of the compiler back ends is the
   /usr/libexec directory.  */

#undef STANDARD_EXEC_PREFIX
#define STANDARD_EXEC_PREFIX		"/usr/libexec/"

#undef TOOLDIR_BASE_PREFIX
#define TOOLDIR_BASE_PREFIX		"../"

#undef STANDARD_BINDIR_PREFIX
#define STANDARD_BINDIR_PREFIX		"/usr/bin"

#undef STANDARD_LIBEXEC_PREFIX
#define STANDARD_LIBEXEC_PREFIX		STANDARD_EXEC_PREFIX

#endif /* NETBSD_NATIVE */


/* Provide a LIB_SPEC appropriate for NetBSD.  Here we:

   1. Select the appropriate set of libs, depending on whether we're
      profiling.

   2. Include the pthread library if -pthread is specified.

   3. Include the posix library if -posix is specified. */

#define NETBSD_LIB_SPEC		\
  "%{pthread:			\
     %{!p:			\
       %{!pg:-lpthread}}	\
     %{p:-lpthread_p}		\
     %{pg:-lpthread_p}}		\
   %{posix:			\
     %{!p:			\
       %{!pg:-lposix}}		\
     %{p:-lposix_p}		\
     %{pg:-lposix_p}}		\
   %{shared:			\
     %{!p:			\
       %{!pg:-lc}}		\
     %{p:-lc_p}			\
       %{pg:-lc_p}}		\
   %{!shared:			\
     %{!symbolic:		\
       %{!p:			\
	 %{!pg:-lc}}		\
       %{p:-lc_p}		\
       %{pg:-lc_p}}}"

#undef LIB_SPEC
#define LIB_SPEC NETBSD_LIB_SPEC

#define LIBSTDCXX_PROFILE "stdc++_p"
#define MATH_LIBRARY_PROFILE "m_p"

/* Provide a LIBGCC_SPEC appropriate for NetBSD.  */
#ifdef NETBSD_NATIVE
#define NETBSD_LIBGCC_SPEC	\
  "%{!symbolic:			\
     %{!shared:			\
       %{!p:			\
	 %{!pg: -lgcc}}}	\
     %{shared: -lgcc_pic}	\
     %{p: -lgcc_p}		\
     %{pg: -lgcc_p}}"
#else
#define NETBSD_LIBGCC_SPEC "-lgcc"
#endif

/* Pass -cxx-isystem to cc1/cc1plus.  */
#define NETBSD_CC1_AND_CC1PLUS_SPEC		\
  "%{cxx-isystem}"

#undef CC1_SPEC
#define CC1_SPEC NETBSD_CC1_AND_CC1PLUS_SPEC

#undef CC1PLUS_SPEC
#define CC1PLUS_SPEC NETBSD_CC1_AND_CC1PLUS_SPEC

#if defined(HAVE_LD_EH_FRAME_HDR)
#define LINK_EH_SPEC "%{!static|static-pie:--eh-frame-hdr} "
#endif

#undef TARGET_LIBC_HAS_FUNCTION
#define TARGET_LIBC_HAS_FUNCTION no_c99_libc_has_function

/* When building shared libraries, the initialization and finalization 
   functions for the library are .init and .fini respectively.  */

#define COLLECT_SHARED_INIT_FUNC(STREAM,FUNC)				\
  do {									\
    fprintf ((STREAM), "void __init() __asm__ (\".init\");");		\
    fprintf ((STREAM), "void __init() {\n\t%s();\n}\n", (FUNC));	\
  } while (0)

#define COLLECT_SHARED_FINI_FUNC(STREAM,FUNC)				\
  do {									\
    fprintf ((STREAM), "void __fini() __asm__ (\".fini\");");		\
    fprintf ((STREAM), "void __fini() {\n\t%s();\n}\n", (FUNC));	\
  } while (0)

#undef TARGET_POSIX_IO
#define TARGET_POSIX_IO

/* Define some types that are the same on all NetBSD platforms,
   making them agree with <machine/ansi.h>.  */

#undef WCHAR_TYPE
#define WCHAR_TYPE "int"

#undef WCHAR_TYPE_SIZE
#define WCHAR_TYPE_SIZE 32

#undef WINT_TYPE
#define WINT_TYPE "int"

/* Use --as-needed -lgcc_s for eh support.  */
#ifdef HAVE_LD_AS_NEEDED
#define USE_LD_AS_NEEDED 1
#endif

#undef  SUBTARGET_INIT_BUILTINS
#define SUBTARGET_INIT_BUILTINS						\
  do {									\
    netbsd_patch_builtins ();						\
  } while(0)
/* Link -lasan early on the command line.  For -static-libasan, don't link
   it for -shared link, the executable should be compiled with -static-libasan
   in that case, and for executable link with --{,no-}whole-archive around
   it to force everything into the executable.  And similarly for -ltsan,
   -lhwasan, and -llsan.  */
#if defined(HAVE_LD_STATIC_DYNAMIC)
#undef LIBASAN_EARLY_SPEC
#define LIBASAN_EARLY_SPEC "%{!shared:libasan_preinit%O%s} " \
  "%{static-libasan:%{!shared:" \
  LD_STATIC_OPTION " --whole-archive -lasan --no-whole-archive " \
  LD_DYNAMIC_OPTION "}}%{!static-libasan:-lasan}"
#undef LIBHWASAN_EARLY_SPEC
#define LIBHWASAN_EARLY_SPEC "%{static-libhwasan:%{!shared:" \
  LD_STATIC_OPTION " --whole-archive -lhwasan --no-whole-archive " \
  LD_DYNAMIC_OPTION "}}%{!static-libhwasan:-lhwasan}"
#undef LIBTSAN_EARLY_SPEC
#define LIBTSAN_EARLY_SPEC "%{!shared:libtsan_preinit%O%s} " \
  "%{static-libtsan:%{!shared:" \
  LD_STATIC_OPTION " --whole-archive -ltsan --no-whole-archive " \
  LD_DYNAMIC_OPTION "}}%{!static-libtsan:-ltsan}"
#undef LIBLSAN_EARLY_SPEC
#define LIBLSAN_EARLY_SPEC "%{!shared:liblsan_preinit%O%s} " \
  "%{static-liblsan:%{!shared:" \
  LD_STATIC_OPTION " --whole-archive -llsan --no-whole-archive " \
  LD_DYNAMIC_OPTION "}}%{!static-liblsan:-llsan}"
#endif
