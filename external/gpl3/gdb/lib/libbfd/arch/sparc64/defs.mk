# This file is automatically generated.  DO NOT EDIT!
# Generated from: NetBSD: mknative-gdb,v 1.17 2024/08/18 03:47:55 rin Exp 
# Generated from: NetBSD: mknative.common,v 1.16 2018/04/15 15:13:37 christos Exp 
#
G_libbfd_la_DEPENDENCIES=elf64-sparc.lo elfxx-sparc.lo elf-vxworks.lo elf64.lo elf.lo elflink.lo elf-attrs.lo elf-strtab.lo elf-eh-frame.lo elf-sframe.lo dwarf1.lo dwarf2.lo elf32-sparc.lo elf32.lo elf64-gen.lo elf32-gen.lo plugin.lo cpu-sparc.lo  archive64.lo ofiles ../libsframe/libsframe.la
G_libbfd_la_OBJECTS=archive.lo archures.lo bfd.lo bfdio.lo cache.lo coff-bfd.lo compress.lo corefile.lo elf-properties.lo format.lo hash.lo libbfd.lo linker.lo merge.lo opncls.lo reloc.lo section.lo simple.lo stab-syms.lo stabs.lo syms.lo targets.lo binary.lo ihex.lo srec.lo tekhex.lo verilog.lo
G_DEFS=-DHAVE_CONFIG_H
G_INCLUDES=
G_TDEFAULTS=-DDEFAULT_VECTOR=sparc_elf64_vec -DSELECT_VECS='&sparc_elf64_vec,&sparc_elf32_vec,&elf64_le_vec,&elf64_be_vec,&elf32_le_vec,&elf32_be_vec' -DSELECT_ARCHITECTURES='&bfd_sparc_arch'
