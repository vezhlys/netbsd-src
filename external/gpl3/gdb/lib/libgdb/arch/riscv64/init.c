/* This file is automatically generated.  DO NOT EDIT! */
/* Generated from: NetBSD: mknative-gdb,v 1.17 2024/08/18 03:47:55 rin Exp  */
/* Generated from: NetBSD: mknative.common,v 1.16 2018/04/15 15:13:37 christos Exp  */

/* Do not modify this file.  */
/* It is created automatically by the Makefile.  */
#include <algorithm>

extern initialize_file_ftype _initialize_riscv_tdep;
extern initialize_file_ftype _initialize_riscv_none_tdep;
extern initialize_file_ftype _initialize_ravenscar;
extern initialize_file_ftype _initialize_svr4_solib;
extern initialize_file_ftype _initialize_riscv_nbsd_tdep;
extern initialize_file_ftype _initialize_ser_hardwire;
extern initialize_file_ftype _initialize_ser_pipe;
extern initialize_file_ftype _initialize_ser_tcp;
extern initialize_file_ftype _initialize_ser_socket;
extern initialize_file_ftype _initialize_fork_child;
extern initialize_file_ftype _initialize_riscv_nbsd_nat;
extern initialize_file_ftype _initialize_tui;
extern initialize_file_ftype _initialize_tui_disasm;
extern initialize_file_ftype _initialize_tui_hooks;
extern initialize_file_ftype _initialize_tui_interp;
extern initialize_file_ftype _initialize_tui_layout;
extern initialize_file_ftype _initialize_tui_regs;
extern initialize_file_ftype _initialize_tui_stack;
extern initialize_file_ftype _initialize_tui_win;
extern initialize_file_ftype _initialize_python;
extern initialize_file_ftype _initialize_guile;
extern initialize_file_ftype _initialize_elfread;
extern initialize_file_ftype _initialize_stap_probe;
extern initialize_file_ftype _initialize_dtrace_probe;
extern initialize_file_ftype _initialize_cp_name_parser;
extern initialize_file_ftype _initialize_ada_language;
extern initialize_file_ftype _initialize_tasks;
extern initialize_file_ftype _initialize_addrmap;
extern initialize_file_ftype _initialize_agent;
extern initialize_file_ftype _initialize_annotate;
extern initialize_file_ftype _initialize_gdbarch_utils;
extern initialize_file_ftype _initialize_auto_load;
extern initialize_file_ftype _initialize_auxv;
extern initialize_file_ftype _initialize_ax_gdb;
extern initialize_file_ftype _initialize_break_catch_exec;
extern initialize_file_ftype _initialize_break_catch_fork;
extern initialize_file_ftype _initialize_break_catch_load;
extern initialize_file_ftype _initialize_break_catch_sig;
extern initialize_file_ftype _initialize_break_catch_syscall;
extern initialize_file_ftype _initialize_break_catch_throw;
extern initialize_file_ftype _initialize_breakpoint;
extern initialize_file_ftype _initialize_btrace;
extern initialize_file_ftype _initialize_charset;
extern initialize_file_ftype _initialize_coff_pe_read;
extern initialize_file_ftype _initialize_coffread;
extern initialize_file_ftype _initialize_complaints;
extern initialize_file_ftype _initialize_completer;
extern initialize_file_ftype _initialize_copying;
extern initialize_file_ftype _initialize_core;
extern initialize_file_ftype _initialize_corelow;
extern initialize_file_ftype _initialize_cp_abi;
extern initialize_file_ftype _initialize_cp_namespace;
extern initialize_file_ftype _initialize_cp_support;
extern initialize_file_ftype _initialize_cp_valprint;
extern initialize_file_ftype _initialize_dbxread;
extern initialize_file_ftype _initialize_dcache;
extern initialize_file_ftype _initialize_debuginfod;
extern initialize_file_ftype _initialize_disasm;
extern initialize_file_ftype _initialize_displaced_stepping;
extern initialize_file_ftype _initialize_dummy_frame;
extern initialize_file_ftype _initialize_cooked_index;
extern initialize_file_ftype _initialize_tailcall_frame;
extern initialize_file_ftype _initialize_dwarf2_frame;
extern initialize_file_ftype _initialize_index_cache;
extern initialize_file_ftype _initialize_dwarf_index_write;
extern initialize_file_ftype _initialize_dwarf2loc;
extern initialize_file_ftype _initialize_dwarf2_read;
extern initialize_file_ftype _initialize_read_gdb_index;
extern initialize_file_ftype _initialize_extract_store_integer;
extern initialize_file_ftype _initialize_event_top;
extern initialize_file_ftype _initialize_exec;
extern initialize_file_ftype _initialize_extension;
extern initialize_file_ftype _initialize_f_language;
extern initialize_file_ftype _initialize_f_valprint;
extern initialize_file_ftype _initialize_filesystem;
extern initialize_file_ftype _initialize_mem_search;
extern initialize_file_ftype _initialize_frame;
extern initialize_file_ftype _initialize_frame_unwind;
extern initialize_file_ftype _initialize_gcore;
extern initialize_file_ftype _initialize_gdb_demangle;
extern initialize_file_ftype _initialize_gdb_bfd;
extern initialize_file_ftype _initialize_gdbtypes;
extern initialize_file_ftype _initialize_gmp_utils;
extern initialize_file_ftype _initialize_gnu_v2_abi;
extern initialize_file_ftype _initialize_gnu_v3_abi;
extern initialize_file_ftype _initialize_infcall;
extern initialize_file_ftype _initialize_infcmd;
extern initialize_file_ftype _initialize_inflow;
extern initialize_file_ftype _initialize_infrun;
extern initialize_file_ftype _initialize_interpreter;
extern initialize_file_ftype _initialize_jit;
extern initialize_file_ftype _initialize_language;
extern initialize_file_ftype _initialize_macrocmd;
extern initialize_file_ftype _initialize_macroscope;
extern initialize_file_ftype _initialize_maint_cmds;
extern initialize_file_ftype _initialize_maint_test_options;
extern initialize_file_ftype _initialize_maint_test_settings;
extern initialize_file_ftype _initialize_mdebugread;
extern initialize_file_ftype _initialize_mem;
extern initialize_file_ftype _initialize_mipsread;
extern initialize_file_ftype _initialize_objc_language;
extern initialize_file_ftype _initialize_observer;
extern initialize_file_ftype _initialize_gdb_osabi;
extern initialize_file_ftype _initialize_osdata;
extern initialize_file_ftype _initialize_pascal_valprint;
extern initialize_file_ftype _initialize_parse;
extern initialize_file_ftype _initialize_printcmd;
extern initialize_file_ftype _initialize_probe;
extern initialize_file_ftype _initialize_producer;
extern initialize_file_ftype _initialize_psymtab;
extern initialize_file_ftype _initialize_record;
extern initialize_file_ftype _initialize_record_btrace;
extern initialize_file_ftype _initialize_record_full;
extern initialize_file_ftype _initialize_regcache;
extern initialize_file_ftype _initialize_regcache_dump;
extern initialize_file_ftype _initialize_reggroup;
extern initialize_file_ftype _initialize_remote;
extern initialize_file_ftype _initialize_notif;
extern initialize_file_ftype _initialize_reverse;
extern initialize_file_ftype _initialize_run_on_main_thread;
extern initialize_file_ftype _initialize_rust_exp;
extern initialize_file_ftype _initialize_serial;
extern initialize_file_ftype _initialize_step_skip;
extern initialize_file_ftype _initialize_solib;
extern initialize_file_ftype _initialize_source;
extern initialize_file_ftype _initialize_source_cache;
extern initialize_file_ftype _initialize_stabsread;
extern initialize_file_ftype _initialize_stack;
extern initialize_file_ftype _initialize_frame_reg;
extern initialize_file_ftype _initialize_symfile;
extern initialize_file_ftype _initialize_symfile_debug;
extern initialize_file_ftype _initialize_symmisc;
extern initialize_file_ftype _initialize_symtab;
extern initialize_file_ftype _initialize_target;
extern initialize_file_ftype _initialize_target_connection;
extern initialize_file_ftype _initialize_target_dcache;
extern initialize_file_ftype _initialize_target_descriptions;
extern initialize_file_ftype _initialize_thread;
extern initialize_file_ftype _initialize_top;
extern initialize_file_ftype _initialize_ctf;
extern initialize_file_ftype _initialize_tracefile;
extern initialize_file_ftype _initialize_tracefile_tfile;
extern initialize_file_ftype _initialize_tracepoint;
extern initialize_file_ftype _initialize_typeprint;
extern initialize_file_ftype _initialize_ui;
extern initialize_file_ftype _initialize_ui_style;
extern initialize_file_ftype _initialize_user_regs;
extern initialize_file_ftype _initialize_utils;
extern initialize_file_ftype _initialize_valops;
extern initialize_file_ftype _initialize_valprint;
extern initialize_file_ftype _initialize_values;
extern initialize_file_ftype _initialize_varobj;
extern initialize_file_ftype _initialize_xml_support;
extern initialize_file_ftype _initialize_cli_cmds;
extern initialize_file_ftype _initialize_cli_dump;
extern initialize_file_ftype _initialize_cli_interp;
extern initialize_file_ftype _initialize_cli_logging;
extern initialize_file_ftype _initialize_cli_script;
extern initialize_file_ftype _initialize_cli_style;
extern initialize_file_ftype _initialize_mi_cmd_env;
extern initialize_file_ftype _initialize_mi_cmds;
extern initialize_file_ftype _initialize_mi_interp;
extern initialize_file_ftype _initialize_mi_main;
extern initialize_file_ftype _initialize_compile;
extern initialize_file_ftype _initialize_compile_cplus_types;

void initialize_all_files ();
void
initialize_all_files ()
{
  std::vector<initialize_file_ftype *> functions =
    {
      _initialize_riscv_tdep,
      _initialize_riscv_none_tdep,
      _initialize_ravenscar,
      _initialize_svr4_solib,
      _initialize_riscv_nbsd_tdep,
      _initialize_ser_hardwire,
      _initialize_ser_pipe,
      _initialize_ser_tcp,
      _initialize_ser_socket,
      _initialize_fork_child,
      _initialize_riscv_nbsd_nat,
      _initialize_tui,
      _initialize_tui_disasm,
      _initialize_tui_hooks,
      _initialize_tui_interp,
      _initialize_tui_layout,
      _initialize_tui_regs,
      _initialize_tui_stack,
      _initialize_tui_win,
      _initialize_python,
      _initialize_guile,
      _initialize_elfread,
      _initialize_stap_probe,
      _initialize_dtrace_probe,
      _initialize_cp_name_parser,
      _initialize_ada_language,
      _initialize_tasks,
      _initialize_addrmap,
      _initialize_agent,
      _initialize_annotate,
      _initialize_gdbarch_utils,
      _initialize_auto_load,
      _initialize_auxv,
      _initialize_ax_gdb,
      _initialize_break_catch_exec,
      _initialize_break_catch_fork,
      _initialize_break_catch_load,
      _initialize_break_catch_sig,
      _initialize_break_catch_syscall,
      _initialize_break_catch_throw,
      _initialize_breakpoint,
      _initialize_btrace,
      _initialize_charset,
      _initialize_coff_pe_read,
      _initialize_coffread,
      _initialize_complaints,
      _initialize_completer,
      _initialize_copying,
      _initialize_core,
      _initialize_corelow,
      _initialize_cp_abi,
      _initialize_cp_namespace,
      _initialize_cp_support,
      _initialize_cp_valprint,
      _initialize_dbxread,
      _initialize_dcache,
      _initialize_debuginfod,
      _initialize_disasm,
      _initialize_displaced_stepping,
      _initialize_dummy_frame,
      _initialize_cooked_index,
      _initialize_tailcall_frame,
      _initialize_dwarf2_frame,
      _initialize_index_cache,
      _initialize_dwarf_index_write,
      _initialize_dwarf2loc,
      _initialize_dwarf2_read,
      _initialize_read_gdb_index,
      _initialize_extract_store_integer,
      _initialize_event_top,
      _initialize_exec,
      _initialize_extension,
      _initialize_f_language,
      _initialize_f_valprint,
      _initialize_filesystem,
      _initialize_mem_search,
      _initialize_frame,
      _initialize_frame_unwind,
      _initialize_gcore,
      _initialize_gdb_demangle,
      _initialize_gdb_bfd,
      _initialize_gdbtypes,
      _initialize_gmp_utils,
      _initialize_gnu_v2_abi,
      _initialize_gnu_v3_abi,
      _initialize_infcall,
      _initialize_infcmd,
      _initialize_inflow,
      _initialize_infrun,
      _initialize_interpreter,
      _initialize_jit,
      _initialize_language,
      _initialize_macrocmd,
      _initialize_macroscope,
      _initialize_maint_cmds,
      _initialize_maint_test_options,
      _initialize_maint_test_settings,
      _initialize_mdebugread,
      _initialize_mem,
      _initialize_mipsread,
      _initialize_objc_language,
      _initialize_observer,
      _initialize_gdb_osabi,
      _initialize_osdata,
      _initialize_pascal_valprint,
      _initialize_parse,
      _initialize_printcmd,
      _initialize_probe,
      _initialize_producer,
      _initialize_psymtab,
      _initialize_record,
      _initialize_record_btrace,
      _initialize_record_full,
      _initialize_regcache,
      _initialize_regcache_dump,
      _initialize_reggroup,
      _initialize_remote,
      _initialize_notif,
      _initialize_reverse,
      _initialize_run_on_main_thread,
      _initialize_rust_exp,
      _initialize_serial,
      _initialize_step_skip,
      _initialize_solib,
      _initialize_source,
      _initialize_source_cache,
      _initialize_stabsread,
      _initialize_stack,
      _initialize_frame_reg,
      _initialize_symfile,
      _initialize_symfile_debug,
      _initialize_symmisc,
      _initialize_symtab,
      _initialize_target,
      _initialize_target_connection,
      _initialize_target_dcache,
      _initialize_target_descriptions,
      _initialize_thread,
      _initialize_top,
      _initialize_ctf,
      _initialize_tracefile,
      _initialize_tracefile_tfile,
      _initialize_tracepoint,
      _initialize_typeprint,
      _initialize_ui,
      _initialize_ui_style,
      _initialize_user_regs,
      _initialize_utils,
      _initialize_valops,
      _initialize_valprint,
      _initialize_values,
      _initialize_varobj,
      _initialize_xml_support,
      _initialize_cli_cmds,
      _initialize_cli_dump,
      _initialize_cli_interp,
      _initialize_cli_logging,
      _initialize_cli_script,
      _initialize_cli_style,
      _initialize_mi_cmd_env,
      _initialize_mi_cmds,
      _initialize_mi_interp,
      _initialize_mi_main,
      _initialize_compile,
      _initialize_compile_cplus_types,
    };

  /* If GDB_REVERSE_INIT_FUNCTIONS is set (any value), reverse the
     order in which initialization functions are called.  This is
     used by the testsuite.  */
  if (getenv ("GDB_REVERSE_INIT_FUNCTIONS") != nullptr)
    std::reverse (functions.begin (), functions.end ());

  for (initialize_file_ftype *function : functions)
    function ();
}
