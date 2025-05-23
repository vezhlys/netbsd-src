/* $NetBSD: ixgbe.c,v 1.354 2024/07/10 03:26:30 msaitoh Exp $ */

/******************************************************************************

  Copyright (c) 2001-2017, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD: head/sys/dev/ixgbe/if_ix.c 331224 2018-03-19 20:55:05Z erj $*/

/*
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Coyote Point Systems, Inc.
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
__KERNEL_RCSID(0, "$NetBSD: ixgbe.c,v 1.354 2024/07/10 03:26:30 msaitoh Exp $");

#ifdef _KERNEL_OPT
#include "opt_inet.h"
#include "opt_inet6.h"
#endif

#include "ixgbe.h"
#include "ixgbe_phy.h"
#include "ixgbe_sriov.h"

#include <sys/cprng.h>
#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

/************************************************************************
 * Driver version
 ************************************************************************/
static const char ixgbe_driver_version[] = "4.0.1-k";
/* XXX NetBSD: + 3.3.24 */

/************************************************************************
 * PCI Device ID Table
 *
 *   Used by probe to select devices to load on
 *   Last field stores an index into ixgbe_strings
 *   Last entry must be all 0s
 *
 *   { Vendor ID, Device ID, SubVendor ID, SubDevice ID, String Index }
 ************************************************************************/
static const ixgbe_vendor_info_t ixgbe_vendor_info_array[] =
{
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AF_DUAL_PORT, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AF_SINGLE_PORT, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_CX4, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AT, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598AT2, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_BX, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_DA_DUAL_PORT, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_CX4_DUAL_PORT, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_XF_LR, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598_SR_DUAL_PORT_EM, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82598EB_SFP_LOM, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_KR, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_KX4, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_KX4_MEZZ, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_EM, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_XAUI_LOM, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_CX4, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_T3_LOM, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_LS, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_COMBO_BACKPLANE, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_BACKPLANE_FCOE, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_SF2, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_FCOE, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599EN_SFP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_SFP_SF_QP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_QSFP_SF_QP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540T1, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550T1, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_KR, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_KX4, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_10G_T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_1G_T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_SFP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_XFI, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_KR, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_KR_L, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_QSFP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_QSFP_N, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_SFP, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_SFP_N, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_SGMII, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_SGMII_L, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_10G_T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_1G_T, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_A_1G_T_L, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540_BYPASS, 0, 0, 0},
	{IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_BYPASS, 0, 0, 0},
	/* required last entry */
	{0, 0, 0, 0, 0}
};

/************************************************************************
 * Table of branding strings
 ************************************************************************/
static const char    *ixgbe_strings[] = {
	"Intel(R) PRO/10GbE PCI-Express Network Driver"
};

/************************************************************************
 * Function prototypes
 ************************************************************************/
static int	ixgbe_probe(device_t, cfdata_t, void *);
static void	ixgbe_quirks(struct ixgbe_softc *);
static void	ixgbe_attach(device_t, device_t, void *);
static int	ixgbe_detach(device_t, int);
#if 0
static int	ixgbe_shutdown(device_t);
#endif
static bool	ixgbe_suspend(device_t, const pmf_qual_t *);
static bool	ixgbe_resume(device_t, const pmf_qual_t *);
static int	ixgbe_ifflags_cb(struct ethercom *);
static int	ixgbe_ioctl(struct ifnet *, u_long, void *);
static int	ixgbe_init(struct ifnet *);
static void	ixgbe_init_locked(struct ixgbe_softc *);
static void	ixgbe_ifstop(struct ifnet *, int);
static void	ixgbe_stop_locked(void *);
static void	ixgbe_init_device_features(struct ixgbe_softc *);
static int	ixgbe_check_fan_failure(struct ixgbe_softc *, u32, bool);
static void	ixgbe_add_media_types(struct ixgbe_softc *);
static void	ixgbe_media_status(struct ifnet *, struct ifmediareq *);
static int	ixgbe_media_change(struct ifnet *);
static int	ixgbe_allocate_pci_resources(struct ixgbe_softc *,
		    const struct pci_attach_args *);
static void	ixgbe_free_deferred_handlers(struct ixgbe_softc *);
static void	ixgbe_get_slot_info(struct ixgbe_softc *);
static int	ixgbe_allocate_msix(struct ixgbe_softc *,
		    const struct pci_attach_args *);
static int	ixgbe_allocate_legacy(struct ixgbe_softc *,
		    const struct pci_attach_args *);
static int	ixgbe_configure_interrupts(struct ixgbe_softc *);
static void	ixgbe_free_pciintr_resources(struct ixgbe_softc *);
static void	ixgbe_free_pci_resources(struct ixgbe_softc *);
static void	ixgbe_local_timer(void *);
static void	ixgbe_handle_timer(struct work *, void *);
static void	ixgbe_recovery_mode_timer(void *);
static void	ixgbe_handle_recovery_mode_timer(struct work *, void *);
static int	ixgbe_setup_interface(device_t, struct ixgbe_softc *);
static void	ixgbe_config_gpie(struct ixgbe_softc *);
static void	ixgbe_config_dmac(struct ixgbe_softc *);
static void	ixgbe_config_delay_values(struct ixgbe_softc *);
static void	ixgbe_schedule_admin_tasklet(struct ixgbe_softc *);
static void	ixgbe_config_link(struct ixgbe_softc *);
static void	ixgbe_check_wol_support(struct ixgbe_softc *);
static int	ixgbe_setup_low_power_mode(struct ixgbe_softc *);
#if 0
static void	ixgbe_rearm_queues(struct ixgbe_softc *, u64);
#endif

static void	ixgbe_initialize_transmit_units(struct ixgbe_softc *);
static void	ixgbe_initialize_receive_units(struct ixgbe_softc *);
static void	ixgbe_enable_rx_drop(struct ixgbe_softc *);
static void	ixgbe_disable_rx_drop(struct ixgbe_softc *);
static void	ixgbe_initialize_rss_mapping(struct ixgbe_softc *);

static void	ixgbe_enable_intr(struct ixgbe_softc *);
static void	ixgbe_disable_intr(struct ixgbe_softc *);
static void	ixgbe_update_stats_counters(struct ixgbe_softc *);
static void	ixgbe_set_rxfilter(struct ixgbe_softc *);
static void	ixgbe_update_link_status(struct ixgbe_softc *);
static void	ixgbe_set_ivar(struct ixgbe_softc *, u8, u8, s8);
static void	ixgbe_configure_ivars(struct ixgbe_softc *);
static u8 *	ixgbe_mc_array_itr(struct ixgbe_hw *, u8 **, u32 *);
static void	ixgbe_eitr_write(struct ixgbe_softc *, uint32_t, uint32_t);

static void	ixgbe_setup_vlan_hw_tagging(struct ixgbe_softc *);
static void	ixgbe_setup_vlan_hw_support(struct ixgbe_softc *);
static int	ixgbe_vlan_cb(struct ethercom *, uint16_t, bool);
static int	ixgbe_register_vlan(struct ixgbe_softc *, u16);
static int	ixgbe_unregister_vlan(struct ixgbe_softc *, u16);

static void	ixgbe_add_device_sysctls(struct ixgbe_softc *);
static void	ixgbe_add_hw_stats(struct ixgbe_softc *);
static void	ixgbe_clear_evcnt(struct ixgbe_softc *);
static int	ixgbe_set_flowcntl(struct ixgbe_softc *, int);
static int	ixgbe_set_advertise(struct ixgbe_softc *, int);
static int	ixgbe_get_default_advertise(struct ixgbe_softc *);

/* Sysctl handlers */
static int	ixgbe_sysctl_flowcntl(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_advertise(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_interrupt_rate_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_dmac(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_phy_temp(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_phy_overtemp_occurred(SYSCTLFN_PROTO);
#ifdef IXGBE_DEBUG
static int	ixgbe_sysctl_power_state(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_print_rss_config(SYSCTLFN_PROTO);
#endif
static int	ixgbe_sysctl_next_to_check_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_next_to_refresh_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_rdh_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_rdt_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_tdt_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_tdh_handler(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_eee_state(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_debug(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_rx_copy_len(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_tx_process_limit(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_rx_process_limit(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_wol_enable(SYSCTLFN_PROTO);
static int	ixgbe_sysctl_wufc(SYSCTLFN_PROTO);

/* Interrupt functions */
static int	ixgbe_msix_que(void *);
static int	ixgbe_msix_admin(void *);
static void	ixgbe_intr_admin_common(struct ixgbe_softc *, u32, u32 *);
static int	ixgbe_legacy_irq(void *);

/* Event handlers running on workqueue */
static void	ixgbe_handle_que(void *);
static void	ixgbe_handle_link(void *);
static void	ixgbe_handle_msf(void *);
static void	ixgbe_handle_mod(void *, bool);
static void	ixgbe_handle_phy(void *);

/* Deferred workqueue handlers */
static void	ixgbe_handle_admin(struct work *, void *);
static void	ixgbe_handle_que_work(struct work *, void *);

static const ixgbe_vendor_info_t *ixgbe_lookup(const struct pci_attach_args *);

/************************************************************************
 *  NetBSD Device Interface Entry Points
 ************************************************************************/
CFATTACH_DECL3_NEW(ixg, sizeof(struct ixgbe_softc),
    ixgbe_probe, ixgbe_attach, ixgbe_detach, NULL, NULL, NULL,
    DVF_DETACH_SHUTDOWN);

#if 0
devclass_t ix_devclass;
DRIVER_MODULE(ix, pci, ix_driver, ix_devclass, 0, 0);

MODULE_DEPEND(ix, pci, 1, 1, 1);
MODULE_DEPEND(ix, ether, 1, 1, 1);
#ifdef DEV_NETMAP
MODULE_DEPEND(ix, netmap, 1, 1, 1);
#endif
#endif

/*
 * TUNEABLE PARAMETERS:
 */

/*
 * AIM: Adaptive Interrupt Moderation
 * which means that the interrupt rate
 * is varied over time based on the
 * traffic for that interrupt vector
 */
static bool ixgbe_enable_aim = true;
#define SYSCTL_INT(_a1, _a2, _a3, _a4, _a5, _a6, _a7)
SYSCTL_INT(_hw_ix, OID_AUTO, enable_aim, CTLFLAG_RDTUN, &ixgbe_enable_aim, 0,
    "Enable adaptive interrupt moderation");

static int ixgbe_max_interrupt_rate = (4000000 / IXGBE_LOW_LATENCY);
SYSCTL_INT(_hw_ix, OID_AUTO, max_interrupt_rate, CTLFLAG_RDTUN,
    &ixgbe_max_interrupt_rate, 0, "Maximum interrupts per second");

/* How many packets rxeof tries to clean at a time */
static int ixgbe_rx_process_limit = 256;
SYSCTL_INT(_hw_ix, OID_AUTO, rx_process_limit, CTLFLAG_RDTUN,
    &ixgbe_rx_process_limit, 0, "Maximum number of received packets to process at a time, -1 means unlimited");

/* How many packets txeof tries to clean at a time */
static int ixgbe_tx_process_limit = 256;
SYSCTL_INT(_hw_ix, OID_AUTO, tx_process_limit, CTLFLAG_RDTUN,
    &ixgbe_tx_process_limit, 0,
    "Maximum number of sent packets to process at a time, -1 means unlimited");

/* Flow control setting, default to full */
static int ixgbe_flow_control = ixgbe_fc_full;
SYSCTL_INT(_hw_ix, OID_AUTO, flow_control, CTLFLAG_RDTUN,
    &ixgbe_flow_control, 0, "Default flow control used for all adapters");

/* Which packet processing uses workqueue or softint */
static bool ixgbe_txrx_workqueue = false;

/*
 * Smart speed setting, default to on
 * this only works as a compile option
 * right now as its during attach, set
 * this to 'ixgbe_smart_speed_off' to
 * disable.
 */
static int ixgbe_smart_speed = ixgbe_smart_speed_on;

/*
 * MSI-X should be the default for best performance,
 * but this allows it to be forced off for testing.
 */
static int ixgbe_enable_msix = 1;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_msix, CTLFLAG_RDTUN, &ixgbe_enable_msix, 0,
    "Enable MSI-X interrupts");

/*
 * Number of Queues, can be set to 0,
 * it then autoconfigures based on the
 * number of cpus and number of MSI-X vectors.
 * This can be overridden manually here.
 */
static int ixgbe_num_queues = 0;
SYSCTL_INT(_hw_ix, OID_AUTO, num_queues, CTLFLAG_RDTUN, &ixgbe_num_queues, 0,
    "Number of queues to configure, 0 indicates autoconfigure");

/*
 * Number of TX descriptors per ring,
 * setting higher than RX as this seems
 * the better performing choice.
 */
static int ixgbe_txd = DEFAULT_TXD;
SYSCTL_INT(_hw_ix, OID_AUTO, txd, CTLFLAG_RDTUN, &ixgbe_txd, 0,
    "Number of transmit descriptors per queue");

/* Number of RX descriptors per ring */
static int ixgbe_rxd = DEFAULT_RXD;
SYSCTL_INT(_hw_ix, OID_AUTO, rxd, CTLFLAG_RDTUN, &ixgbe_rxd, 0,
    "Number of receive descriptors per queue");

/*
 * Defining this on will allow the use
 * of unsupported SFP+ modules, note that
 * doing so you are on your own :)
 */
static int allow_unsupported_sfp = false;
#define TUNABLE_INT(__x, __y)
TUNABLE_INT("hw.ix.unsupported_sfp", &allow_unsupported_sfp);

/*
 * Not sure if Flow Director is fully baked,
 * so we'll default to turning it off.
 */
static int ixgbe_enable_fdir = 0;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_fdir, CTLFLAG_RDTUN, &ixgbe_enable_fdir, 0,
    "Enable Flow Director");

/* Legacy Transmit (single queue) */
static int ixgbe_enable_legacy_tx = 0;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_legacy_tx, CTLFLAG_RDTUN,
    &ixgbe_enable_legacy_tx, 0, "Enable Legacy TX flow");

/* Receive-Side Scaling */
static int ixgbe_enable_rss = 1;
SYSCTL_INT(_hw_ix, OID_AUTO, enable_rss, CTLFLAG_RDTUN, &ixgbe_enable_rss, 0,
    "Enable Receive-Side Scaling (RSS)");

#if 0
static int (*ixgbe_start_locked)(struct ifnet *, struct tx_ring *);
static int (*ixgbe_ring_empty)(struct ifnet *, pcq_t *);
#endif

#define IXGBE_WORKQUEUE_PRI PRI_SOFTNET

/* Interval between reports of errors */
static const struct timeval ixgbe_errlog_intrvl = { 60, 0 };	/* 60s */

/************************************************************************
 * ixgbe_initialize_rss_mapping
 ************************************************************************/
static void
ixgbe_initialize_rss_mapping(struct ixgbe_softc *sc)
{
	struct ixgbe_hw	*hw = &sc->hw;
	u32		reta = 0, mrqc, rss_key[10];
	int		queue_id, table_size, index_mult;
	int		i, j;
	u32		rss_hash_config;

	/* force use default RSS key. */
#ifdef __NetBSD__
	rss_getkey((uint8_t *) &rss_key);
#else
	if (sc->feat_en & IXGBE_FEATURE_RSS) {
		/* Fetch the configured RSS key */
		rss_getkey((uint8_t *) &rss_key);
	} else {
		/* set up random bits */
		cprng_fast(&rss_key, sizeof(rss_key));
	}
#endif

	/* Set multiplier for RETA setup and table size based on MAC */
	index_mult = 0x1;
	table_size = 128;
	switch (sc->hw.mac.type) {
	case ixgbe_mac_82598EB:
		index_mult = 0x11;
		break;
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		table_size = 512;
		break;
	default:
		break;
	}

	/* Set up the redirection table */
	for (i = 0, j = 0; i < table_size; i++, j++) {
		if (j == sc->num_queues)
			j = 0;

		if (sc->feat_en & IXGBE_FEATURE_RSS) {
			/*
			 * Fetch the RSS bucket id for the given indirection
			 * entry. Cap it at the number of configured buckets
			 * (which is num_queues.)
			 */
			queue_id = rss_get_indirection_to_bucket(i);
			queue_id = queue_id % sc->num_queues;
		} else
			queue_id = (j * index_mult);

		/*
		 * The low 8 bits are for hash value (n+0);
		 * The next 8 bits are for hash value (n+1), etc.
		 */
		reta = reta >> 8;
		reta = reta | (((uint32_t) queue_id) << 24);
		if ((i & 3) == 3) {
			if (i < 128)
				IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), reta);
			else
				IXGBE_WRITE_REG(hw, IXGBE_ERETA((i >> 2) - 32),
				    reta);
			reta = 0;
		}
	}

	/* Now fill our hash function seeds */
	for (i = 0; i < 10; i++)
		IXGBE_WRITE_REG(hw, IXGBE_RSSRK(i), rss_key[i]);

	/* Perform hash on these packet types */
	if (sc->feat_en & IXGBE_FEATURE_RSS)
		rss_hash_config = rss_gethashconfig();
	else {
		/*
		 * Disable UDP - IP fragments aren't currently being handled
		 * and so we end up with a mix of 2-tuple and 4-tuple
		 * traffic.
		 */
		rss_hash_config = RSS_HASHTYPE_RSS_IPV4
				| RSS_HASHTYPE_RSS_TCP_IPV4
				| RSS_HASHTYPE_RSS_IPV6
				| RSS_HASHTYPE_RSS_TCP_IPV6
				| RSS_HASHTYPE_RSS_IPV6_EX
				| RSS_HASHTYPE_RSS_TCP_IPV6_EX;
	}

	mrqc = IXGBE_MRQC_RSSEN;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6_EX)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_EX_UDP;
	mrqc |= ixgbe_get_mrqc(sc->iov_mode);
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
} /* ixgbe_initialize_rss_mapping */

/************************************************************************
 * ixgbe_initialize_receive_units - Setup receive registers and features.
 ************************************************************************/
#define BSIZEPKT_ROUNDUP ((1<<IXGBE_SRRCTL_BSIZEPKT_SHIFT)-1)

static void
ixgbe_initialize_receive_units(struct ixgbe_softc *sc)
{
	struct rx_ring	*rxr = sc->rx_rings;
	struct ixgbe_hw	*hw = &sc->hw;
	struct ifnet	*ifp = sc->ifp;
	int		i, j;
	u32		bufsz, fctrl, srrctl, rxcsum;
	u32		hlreg;

	/*
	 * Make sure receives are disabled while
	 * setting up the descriptor ring
	 */
	ixgbe_disable_rx(hw);

	/* Enable broadcasts */
	fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	fctrl |= IXGBE_FCTRL_BAM;
	if (sc->hw.mac.type == ixgbe_mac_82598EB) {
		fctrl |= IXGBE_FCTRL_DPF;
		fctrl |= IXGBE_FCTRL_PMCF;
	}
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);

	/* Set for Jumbo Frames? */
	hlreg = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	if (ifp->if_mtu > ETHERMTU)
		hlreg |= IXGBE_HLREG0_JUMBOEN;
	else
		hlreg &= ~IXGBE_HLREG0_JUMBOEN;

#ifdef DEV_NETMAP
	/* CRC stripping is conditional in Netmap */
	if ((sc->feat_en & IXGBE_FEATURE_NETMAP) &&
	    (ifp->if_capenable & IFCAP_NETMAP) &&
	    !ix_crcstrip)
		hlreg &= ~IXGBE_HLREG0_RXCRCSTRP;
	else
#endif /* DEV_NETMAP */
		hlreg |= IXGBE_HLREG0_RXCRCSTRP;

	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hlreg);

	bufsz = (sc->rx_mbuf_sz + BSIZEPKT_ROUNDUP) >>
	    IXGBE_SRRCTL_BSIZEPKT_SHIFT;

	for (i = 0; i < sc->num_queues; i++, rxr++) {
		u64 rdba = rxr->rxdma.dma_paddr;
		u32 reg;
		int regnum = i / 4;	/* 1 register per 4 queues */
		int regshift = i % 4;	/* 4 bits per 1 queue */
		j = rxr->me;

		/* Setup the Base and Length of the Rx Descriptor Ring */
		IXGBE_WRITE_REG(hw, IXGBE_RDBAL(j),
		    (rdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_RDBAH(j), (rdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_RDLEN(j),
		    sc->num_rx_desc * sizeof(union ixgbe_adv_rx_desc));

		/* Set up the SRRCTL register */
		srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(j));
		srrctl &= ~IXGBE_SRRCTL_BSIZEHDR_MASK;
		srrctl &= ~IXGBE_SRRCTL_BSIZEPKT_MASK;
		srrctl |= bufsz;
		srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

		/* Set RQSMR (Receive Queue Statistic Mapping) register */
		reg = IXGBE_READ_REG(hw, IXGBE_RQSMR(regnum));
		reg &= ~(0x000000ffUL << (regshift * 8));
		reg |= i << (regshift * 8);
		IXGBE_WRITE_REG(hw, IXGBE_RQSMR(regnum), reg);

		/*
		 * Set DROP_EN iff we have no flow control and >1 queue.
		 * Note that srrctl was cleared shortly before during reset,
		 * so we do not need to clear the bit, but do it just in case
		 * this code is moved elsewhere.
		 */
		if ((sc->num_queues > 1) &&
		    (sc->hw.fc.requested_mode == ixgbe_fc_none))
			srrctl |= IXGBE_SRRCTL_DROP_EN;
		else
			srrctl &= ~IXGBE_SRRCTL_DROP_EN;

		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(j), srrctl);

		/* Setup the HW Rx Head and Tail Descriptor Pointers */
		IXGBE_WRITE_REG(hw, IXGBE_RDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_RDT(j), 0);

		/* Set the driver rx tail address */
		rxr->tail =  IXGBE_RDT(rxr->me);
	}

	if (sc->hw.mac.type != ixgbe_mac_82598EB) {
		u32 psrtype = IXGBE_PSRTYPE_TCPHDR
			    | IXGBE_PSRTYPE_UDPHDR
			    | IXGBE_PSRTYPE_IPV4HDR
			    | IXGBE_PSRTYPE_IPV6HDR;
		IXGBE_WRITE_REG(hw, IXGBE_PSRTYPE(0), psrtype);
	}

	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);

	ixgbe_initialize_rss_mapping(sc);

	if (sc->num_queues > 1) {
		/* RSS and RX IPP Checksum are mutually exclusive */
		rxcsum |= IXGBE_RXCSUM_PCSD;
	}

	if (ifp->if_capenable & IFCAP_RXCSUM)
		rxcsum |= IXGBE_RXCSUM_PCSD;

	/* This is useful for calculating UDP/IP fragment checksums */
	if (!(rxcsum & IXGBE_RXCSUM_PCSD))
		rxcsum |= IXGBE_RXCSUM_IPPCSE;

	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);

} /* ixgbe_initialize_receive_units */

/************************************************************************
 * ixgbe_initialize_transmit_units - Enable transmit units.
 ************************************************************************/
static void
ixgbe_initialize_transmit_units(struct ixgbe_softc *sc)
{
	struct tx_ring	*txr = sc->tx_rings;
	struct ixgbe_hw	*hw = &sc->hw;
	int i;

	INIT_DEBUGOUT("ixgbe_initialize_transmit_units");

	/* Setup the Base and Length of the Tx Descriptor Ring */
	for (i = 0; i < sc->num_queues; i++, txr++) {
		u64 tdba = txr->txdma.dma_paddr;
		u32 txctrl = 0;
		u32 tqsmreg, reg;
		int regnum = i / 4;	/* 1 register per 4 queues */
		int regshift = i % 4;	/* 4 bits per 1 queue */
		int j = txr->me;

		IXGBE_WRITE_REG(hw, IXGBE_TDBAL(j),
		    (tdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_TDBAH(j), (tdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_TDLEN(j),
		    sc->num_tx_desc * sizeof(union ixgbe_adv_tx_desc));

		/*
		 * Set TQSMR (Transmit Queue Statistic Mapping) register.
		 * Register location is different between 82598 and others.
		 */
		if (sc->hw.mac.type == ixgbe_mac_82598EB)
			tqsmreg = IXGBE_TQSMR(regnum);
		else
			tqsmreg = IXGBE_TQSM(regnum);
		reg = IXGBE_READ_REG(hw, tqsmreg);
		reg &= ~(0x000000ffUL << (regshift * 8));
		reg |= i << (regshift * 8);
		IXGBE_WRITE_REG(hw, tqsmreg, reg);

		/* Setup the HW Tx Head and Tail descriptor pointers */
		IXGBE_WRITE_REG(hw, IXGBE_TDH(j), 0);
		IXGBE_WRITE_REG(hw, IXGBE_TDT(j), 0);

		/* Cache the tail address */
		txr->tail = IXGBE_TDT(j);

		txr->txr_no_space = false;

		/* Disable relax ordering */
		/*
		 * Note: for X550 series devices, these registers are actually
		 * prefixed with TPH_ instead of DCA_, but the addresses and
		 * fields remain the same.
		 */
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL(j));
			break;
		default:
			txctrl = IXGBE_READ_REG(hw, IXGBE_DCA_TXCTRL_82599(j));
			break;
		}
		txctrl &= ~IXGBE_DCA_TXCTRL_DESC_WRO_EN;
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL(j), txctrl);
			break;
		default:
			IXGBE_WRITE_REG(hw, IXGBE_DCA_TXCTRL_82599(j), txctrl);
			break;
		}

	}

	if (hw->mac.type != ixgbe_mac_82598EB) {
		u32 dmatxctl, rttdcs;

		dmatxctl = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
		dmatxctl |= IXGBE_DMATXCTL_TE;
		IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL, dmatxctl);
		/* Disable arbiter to set MTQC */
		rttdcs = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
		rttdcs |= IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);
		IXGBE_WRITE_REG(hw, IXGBE_MTQC,
		    ixgbe_get_mtqc(sc->iov_mode));
		rttdcs &= ~IXGBE_RTTDCS_ARBDIS;
		IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);
	}
} /* ixgbe_initialize_transmit_units */

static void
ixgbe_quirks(struct ixgbe_softc *sc)
{
	device_t dev = sc->dev;
	struct ixgbe_hw *hw = &sc->hw;
	const char *vendor, *product;

	if (hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP_N) {
		/*
		 * Quirk for inverted logic of SFP+'s MOD_ABS on GIGABYTE
		 * MA10-ST0.
		 */
		vendor = pmf_get_platform("system-vendor");
		product = pmf_get_platform("system-product");

		if ((vendor == NULL) || (product == NULL))
			return;

		if ((strcmp(vendor, "GIGABYTE") == 0) &&
		    (strcmp(product, "MA10-ST0") == 0)) {
			aprint_verbose_dev(dev,
			    "Enable SFP+ MOD_ABS inverse quirk\n");
			sc->hw.quirks |= IXGBE_QUIRK_MOD_ABS_INVERT;
		}
	}
}

/************************************************************************
 * ixgbe_attach - Device initialization routine
 *
 *   Called when the driver is being loaded.
 *   Identifies the type of hardware, allocates all resources
 *   and initializes the hardware.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static void
ixgbe_attach(device_t parent, device_t dev, void *aux)
{
	struct ixgbe_softc *sc;
	struct ixgbe_hw *hw;
	int		error = -1;
	u32		ctrl_ext;
	u16		high, low, nvmreg, dev_caps;
	pcireg_t	id, subid;
	const ixgbe_vendor_info_t *ent;
	struct pci_attach_args *pa = aux;
	bool unsupported_sfp = false;
	const char *str;
	char wqname[MAXCOMLEN];
	char buf[256];

	INIT_DEBUGOUT("ixgbe_attach: begin");

	/* Allocate, clear, and link in our adapter structure */
	sc = device_private(dev);
	sc->hw.back = sc;
	sc->dev = dev;
	hw = &sc->hw;
	sc->osdep.pc = pa->pa_pc;
	sc->osdep.tag = pa->pa_tag;
	if (pci_dma64_available(pa))
		sc->osdep.dmat = pa->pa_dmat64;
	else
		sc->osdep.dmat = pa->pa_dmat;
	sc->osdep.attached = false;
	sc->osdep.detaching = false;

	ent = ixgbe_lookup(pa);

	KASSERT(ent != NULL);

	aprint_normal(": %s, Version - %s\n",
	    ixgbe_strings[ent->index], ixgbe_driver_version);

	/* Core Lock Init */
	IXGBE_CORE_LOCK_INIT(sc, device_xname(dev));

	/* Set up the timer callout and workqueue */
	callout_init(&sc->timer, CALLOUT_MPSAFE);
	snprintf(wqname, sizeof(wqname), "%s-timer", device_xname(dev));
	error = workqueue_create(&sc->timer_wq, wqname,
	    ixgbe_handle_timer, sc, IXGBE_WORKQUEUE_PRI, IPL_NET, WQ_MPSAFE);
	if (error) {
		aprint_error_dev(dev,
		    "could not create timer workqueue (%d)\n", error);
		goto err_out;
	}

	/* Determine hardware revision */
	id = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_ID_REG);
	subid = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_SUBSYS_ID_REG);

	hw->vendor_id = PCI_VENDOR(id);
	hw->device_id = PCI_PRODUCT(id);
	hw->revision_id =
	    PCI_REVISION(pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_CLASS_REG));
	hw->subsystem_vendor_id = PCI_SUBSYS_VENDOR(subid);
	hw->subsystem_device_id = PCI_SUBSYS_ID(subid);

	/* Set quirk flags */
	ixgbe_quirks(sc);

	/*
	 * Make sure BUSMASTER is set
	 */
	ixgbe_pci_enable_busmaster(pa->pa_pc, pa->pa_tag);

	/* Do base PCI setup - map BAR0 */
	if (ixgbe_allocate_pci_resources(sc, pa)) {
		aprint_error_dev(dev, "Allocation of PCI resources failed\n");
		error = ENXIO;
		goto err_out;
	}

	/* let hardware know driver is loaded */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext |= IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);

	/*
	 * Initialize the shared code
	 */
	if (ixgbe_init_shared_code(hw) != 0) {
		aprint_error_dev(dev,
		    "Unable to initialize the shared code\n");
		error = ENXIO;
		goto err_out;
	}

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		str = "82598EB";
		break;
	case ixgbe_mac_82599EB:
		str = "82599EB";
		break;
	case ixgbe_mac_X540:
		str = "X540";
		break;
	case ixgbe_mac_X550:
		str = "X550";
		break;
	case ixgbe_mac_X550EM_x:
		str = "X550EM X";
		break;
	case ixgbe_mac_X550EM_a:
		str = "X550EM A";
		break;
	default:
		str = "Unknown";
		break;
	}
	aprint_normal_dev(dev, "device %s\n", str);

	hw->allow_unsupported_sfp = allow_unsupported_sfp;

	/* Pick up the 82599 settings */
	if (hw->mac.type != ixgbe_mac_82598EB)
		hw->phy.smart_speed = ixgbe_smart_speed;

	/* Set the right number of segments */
	KASSERT(IXGBE_82599_SCATTER_MAX >= IXGBE_SCATTER_DEFAULT);
	sc->num_segs = IXGBE_SCATTER_DEFAULT;

	/* Ensure SW/FW semaphore is free */
	ixgbe_init_swfw_semaphore(hw);

	hw->mac.ops.set_lan_id(hw);
	ixgbe_init_device_features(sc);

	if (ixgbe_configure_interrupts(sc)) {
		error = ENXIO;
		goto err_out;
	}

	/* Allocate multicast array memory. */
	sc->mta = malloc(sizeof(*sc->mta) *
	    MAX_NUM_MULTICAST_ADDRESSES, M_DEVBUF, M_WAITOK);

	/* Enable WoL (if supported) */
	ixgbe_check_wol_support(sc);

	/* Register for VLAN events */
	ether_set_vlan_cb(&sc->osdep.ec, ixgbe_vlan_cb);

	/* Verify adapter fan is still functional (if applicable) */
	if (sc->feat_en & IXGBE_FEATURE_FAN_FAIL) {
		u32 esdp = IXGBE_READ_REG(hw, IXGBE_ESDP);
		ixgbe_check_fan_failure(sc, esdp, FALSE);
	}

	/* Set an initial default flow control value */
	hw->fc.requested_mode = ixgbe_flow_control;

	/* Do descriptor calc and sanity checks */
	if (((ixgbe_txd * sizeof(union ixgbe_adv_tx_desc)) % DBA_ALIGN) != 0 ||
	    ixgbe_txd < MIN_TXD || ixgbe_txd > MAX_TXD) {
		aprint_error_dev(dev, "Invalid TX ring size (%d). "
		    "It must be between %d and %d, "
		    "inclusive, and must be a multiple of %zu. "
		    "Using default value of %d instead.\n",
		    ixgbe_txd, MIN_TXD, MAX_TXD,
		    DBA_ALIGN / sizeof(union ixgbe_adv_tx_desc),
		    DEFAULT_TXD);
		sc->num_tx_desc = DEFAULT_TXD;
	} else
		sc->num_tx_desc = ixgbe_txd;

	if (((ixgbe_rxd * sizeof(union ixgbe_adv_rx_desc)) % DBA_ALIGN) != 0 ||
	    ixgbe_rxd < MIN_RXD || ixgbe_rxd > MAX_RXD) {
		aprint_error_dev(dev, "Invalid RX ring size (%d). "
		    "It must be between %d and %d, "
		    "inclusive, and must be a multiple of %zu. "
		    "Using default value of %d instead.\n",
		    ixgbe_rxd, MIN_RXD, MAX_RXD,
		    DBA_ALIGN / sizeof(union ixgbe_adv_rx_desc),
		    DEFAULT_RXD);
		sc->num_rx_desc = DEFAULT_RXD;
	} else
		sc->num_rx_desc = ixgbe_rxd;

	/* Sysctls for limiting the amount of work done in the taskqueues */
	sc->rx_process_limit
	    = (ixgbe_rx_process_limit <= sc->num_rx_desc)
	    ? ixgbe_rx_process_limit : sc->num_rx_desc;
	sc->tx_process_limit
	    = (ixgbe_tx_process_limit <= sc->num_tx_desc)
	    ? ixgbe_tx_process_limit : sc->num_tx_desc;

	/* Set default high limit of copying mbuf in rxeof */
	sc->rx_copy_len = IXGBE_RX_COPY_LEN_MAX;

	/* Allocate our TX/RX Queues */
	if (ixgbe_allocate_queues(sc)) {
		error = ENOMEM;
		goto err_out;
	}

	hw->phy.reset_if_overtemp = TRUE;
	error = ixgbe_reset_hw(hw);
	hw->phy.reset_if_overtemp = FALSE;
	if (error == IXGBE_ERR_SFP_NOT_PRESENT)
		error = IXGBE_SUCCESS;
	else if (error == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		aprint_error_dev(dev,
		    "Unsupported SFP+ module type was detected.\n");
		unsupported_sfp = true;
		error = IXGBE_SUCCESS;
	} else if (error) {
		aprint_error_dev(dev,
		    "Hardware initialization failed(error = %d)\n", error);
		error = EIO;
		goto err_late;
	}

	/* Make sure we have a good EEPROM before we read from it */
	if (ixgbe_validate_eeprom_checksum(&sc->hw, NULL) < 0) {
		aprint_error_dev(dev, "The EEPROM Checksum Is Not Valid\n");
		error = EIO;
		goto err_late;
	}

	aprint_normal("%s:", device_xname(dev));
	/* NVM Image Version */
	high = low = 0;
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		/*
		 * Print version from the dev starter version (0x29). The
		 * location is the same as newer device's IXGBE_NVM_MAP_VER.
		 */
		hw->eeprom.ops.read(hw, IXGBE_NVM_MAP_VER, &nvmreg);
		if (nvmreg == 0xffff)
			break;
		high = (nvmreg >> 12) & 0x0f;
		low = (nvmreg >> 4) & 0xff;
		id = nvmreg & 0x0f;
		/*
		 * The following output might not be correct. Some 82598 cards
		 * have 0x1070 or 0x2090. 82598 spec update notes about 2.9.0.
		 */
		aprint_normal(" NVM Image Version %u.%u.%u,", high, low, id);
		break;
	case ixgbe_mac_X540:
	case ixgbe_mac_X550EM_a:
		hw->eeprom.ops.read(hw, IXGBE_NVM_IMAGE_VER, &nvmreg);
		if (nvmreg == 0xffff)
			break;
		high = (nvmreg >> 12) & 0x0f;
		low = (nvmreg >> 4) & 0xff;
		id = nvmreg & 0x0f;
		aprint_normal(" NVM Image Version %u.", high);
		if (hw->mac.type == ixgbe_mac_X540)
			str = "%x";
		else
			str = "%02x";
		aprint_normal(str, low);
		aprint_normal(" ID 0x%x,", id);
		break;
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550:
		hw->eeprom.ops.read(hw, IXGBE_NVM_IMAGE_VER, &nvmreg);
		if (nvmreg == 0xffff)
			break;
		high = (nvmreg >> 12) & 0x0f;
		low = nvmreg & 0xff;
		aprint_normal(" NVM Image Version %u.%02x,", high, low);
		break;
	default:
		break;
	}
	hw->eeprom.nvm_image_ver_high = high;
	hw->eeprom.nvm_image_ver_low = low;

	/* PHY firmware revision */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
		hw->eeprom.ops.read(hw, IXGBE_PHYFW_REV, &nvmreg);
		if (nvmreg == 0xffff)
			break;
		high = (nvmreg >> 12) & 0x0f;
		low = (nvmreg >> 4) & 0xff;
		id = nvmreg & 0x000f;
		aprint_normal(" PHY FW Revision %u.", high);
		if (hw->mac.type == ixgbe_mac_X540)
			str = "%x";
		else
			str = "%02x";
		aprint_normal(str, low);
		aprint_normal(" ID 0x%x,", id);
		break;
	default:
		break;
	}

	/* NVM Map version & OEM NVM Image version */
	switch (hw->mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		hw->eeprom.ops.read(hw, IXGBE_NVM_MAP_VER, &nvmreg);
		if (nvmreg != 0xffff) {
			high = (nvmreg >> 12) & 0x0f;
			low = nvmreg & 0x00ff;
			aprint_normal(" NVM Map version %u.%02x,", high, low);
		}
		hw->eeprom.ops.read(hw, IXGBE_OEM_NVM_IMAGE_VER, &nvmreg);
		if (nvmreg != 0xffff) {
			high = (nvmreg >> 12) & 0x0f;
			low = nvmreg & 0x00ff;
			aprint_verbose(" OEM NVM Image version %u.%02x,", high,
			    low);
		}
		break;
	default:
		break;
	}

	/* Print the ETrackID */
	hw->eeprom.ops.read(hw, IXGBE_ETRACKID_H, &high);
	hw->eeprom.ops.read(hw, IXGBE_ETRACKID_L, &low);
	aprint_normal(" ETrackID %08x\n", ((uint32_t)high << 16) | low);

	/* Printed Board Assembly number */
	error = ixgbe_read_pba_string(hw, buf, IXGBE_PBANUM_LENGTH);
	aprint_normal_dev(dev, "PBA number %s\n", error ? "unknown" : buf);

	/* Recovery mode */
	switch (sc->hw.mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		/* >= 2.00 */
		if (hw->eeprom.nvm_image_ver_high >= 2) {
			sc->feat_cap |= IXGBE_FEATURE_RECOVERY_MODE;
			sc->feat_en |= IXGBE_FEATURE_RECOVERY_MODE;
		}
		break;
	default:
		break;
	}

	if (sc->feat_en & IXGBE_FEATURE_MSIX) {
		error = ixgbe_allocate_msix(sc, pa);
		if (error) {
			/* Free allocated queue structures first */
			ixgbe_free_queues(sc);

			/* Fallback to legacy interrupt */
			if (sc->feat_cap & IXGBE_FEATURE_MSI)
				sc->feat_en |= IXGBE_FEATURE_MSI;
			sc->num_queues = 1;

			/* Allocate our TX/RX Queues again */
			if (ixgbe_allocate_queues(sc)) {
				error = ENOMEM;
				goto err_out;
			}
		}
	}

	if ((sc->feat_en & IXGBE_FEATURE_MSIX) == 0)
		error = ixgbe_allocate_legacy(sc, pa);
	if (error)
		goto err_late;

	/* Tasklets for Link, SFP, Multispeed Fiber and Flow Director */
	mutex_init(&(sc)->admin_mtx, MUTEX_DEFAULT, IPL_NET);
	snprintf(wqname, sizeof(wqname), "%s-admin", device_xname(dev));
	error = workqueue_create(&sc->admin_wq, wqname,
	    ixgbe_handle_admin, sc, IXGBE_WORKQUEUE_PRI, IPL_NET, WQ_MPSAFE);
	if (error) {
		aprint_error_dev(dev,
		    "could not create admin workqueue (%d)\n", error);
		goto err_out;
	}

	error = ixgbe_start_hw(hw);
	switch (error) {
	case IXGBE_ERR_EEPROM_VERSION:
		aprint_error_dev(dev,
		    "This device is a pre-production adapter/"
		    "LOM.  Please be aware there may be issues associated "
		    "with your hardware.\nIf you are experiencing problems "
		    "please contact your Intel or hardware representative "
		    "who provided you with this hardware.\n");
		break;
	default:
		break;
	}

	/* Setup OS specific network interface */
	if (ixgbe_setup_interface(dev, sc) != 0)
		goto err_late;

	/*
	 *  Print PHY ID only for copper PHY. On device which has SFP(+) cage
	 * and a module is inserted, phy.id is not MII PHY id but SFF 8024 ID.
	 */
	if (hw->phy.media_type == ixgbe_media_type_copper) {
		uint16_t id1, id2;
		int oui, model, rev;
		char descr[MII_MAX_DESCR_LEN];

		id1 = hw->phy.id >> 16;
		id2 = hw->phy.id & 0xffff;
		oui = MII_OUI(id1, id2);
		model = MII_MODEL(id2);
		rev = MII_REV(id2);
		mii_get_descr(descr, sizeof(descr), oui, model);
		if (descr[0])
			aprint_normal_dev(dev, "PHY: %s, rev. %d\n",
			    descr, rev);
		else
			aprint_normal_dev(dev,
			    "PHY OUI 0x%06x, model 0x%04x, rev. %d\n",
			    oui, model, rev);
	}

	/* Enable EEE power saving */
	if (sc->feat_cap & IXGBE_FEATURE_EEE)
		hw->mac.ops.setup_eee(hw,
		    sc->feat_en & IXGBE_FEATURE_EEE);

	/* Enable power to the phy. */
	if (!unsupported_sfp) {
		/* Enable the optics for 82599 SFP+ fiber */
		ixgbe_enable_tx_laser(hw);

		/*
		 * XXX Currently, ixgbe_set_phy_power() supports only copper
		 * PHY, so it's not required to test with !unsupported_sfp.
		 */
		ixgbe_set_phy_power(hw, TRUE);
	}

	/* Initialize statistics */
	ixgbe_update_stats_counters(sc);

	/* Check PCIE slot type/speed/width */
	ixgbe_get_slot_info(sc);

	/*
	 * Do time init and sysctl init here, but
	 * only on the first port of a bypass adapter.
	 */
	ixgbe_bypass_init(sc);

	/* Set an initial dmac value */
	sc->dmac = 0;
	/* Set initial advertised speeds (if applicable) */
	sc->advertise = ixgbe_get_default_advertise(sc);

	if (sc->feat_cap & IXGBE_FEATURE_SRIOV)
		ixgbe_define_iov_schemas(dev, &error);

	/* Add sysctls */
	ixgbe_add_device_sysctls(sc);
	ixgbe_add_hw_stats(sc);

	/* For Netmap */
	sc->init_locked = ixgbe_init_locked;
	sc->stop_locked = ixgbe_stop_locked;

	if (sc->feat_en & IXGBE_FEATURE_NETMAP)
		ixgbe_netmap_attach(sc);

	/* Print some flags */
	snprintb(buf, sizeof(buf), IXGBE_FEATURE_FLAGS, sc->feat_cap);
	aprint_verbose_dev(dev, "feature cap %s\n", buf);
	snprintb(buf, sizeof(buf), IXGBE_FEATURE_FLAGS, sc->feat_en);
	aprint_verbose_dev(dev, "feature ena %s\n", buf);
	if (ixgbe_get_device_caps(hw, &dev_caps) == 0) {
		snprintb(buf, sizeof(buf), IXGBE_DEVICE_CAPS_FLAGS, dev_caps);
		aprint_verbose_dev(dev, "device cap %s\n", buf);
	}

	if (pmf_device_register(dev, ixgbe_suspend, ixgbe_resume))
		pmf_class_network_register(dev, sc->ifp);
	else
		aprint_error_dev(dev, "couldn't establish power handler\n");

	/* Init recovery mode timer and state variable */
	if (sc->feat_en & IXGBE_FEATURE_RECOVERY_MODE) {
		sc->recovery_mode = 0;

		/* Set up the timer callout */
		callout_init(&sc->recovery_mode_timer, CALLOUT_MPSAFE);
		snprintf(wqname, sizeof(wqname), "%s-recovery",
		    device_xname(dev));
		error = workqueue_create(&sc->recovery_mode_timer_wq,
		    wqname, ixgbe_handle_recovery_mode_timer, sc,
		    IXGBE_WORKQUEUE_PRI, IPL_NET, WQ_MPSAFE);
		if (error) {
			aprint_error_dev(dev, "could not create "
			    "recovery_mode_timer workqueue (%d)\n", error);
			goto err_out;
		}

		/* Start the task */
		callout_reset(&sc->recovery_mode_timer, hz,
		    ixgbe_recovery_mode_timer, sc);
	}

	INIT_DEBUGOUT("ixgbe_attach: end");
	sc->osdep.attached = true;

	return;

err_late:
	ixgbe_free_queues(sc);
err_out:
	ctrl_ext = IXGBE_READ_REG(&sc->hw, IXGBE_CTRL_EXT);
	ctrl_ext &= ~IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(&sc->hw, IXGBE_CTRL_EXT, ctrl_ext);
	ixgbe_free_deferred_handlers(sc);
	ixgbe_free_pci_resources(sc);
	if (sc->mta != NULL)
		free(sc->mta, M_DEVBUF);
	mutex_destroy(&(sc)->admin_mtx); /* XXX appropriate order? */
	IXGBE_CORE_LOCK_DESTROY(sc);

	return;
} /* ixgbe_attach */

/************************************************************************
 * ixgbe_check_wol_support
 *
 *   Checks whether the adapter's ports are capable of
 *   Wake On LAN by reading the adapter's NVM.
 *
 *   Sets each port's hw->wol_enabled value depending
 *   on the value read here.
 ************************************************************************/
static void
ixgbe_check_wol_support(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	u16		dev_caps = 0;

	/* Find out WoL support for port */
	sc->wol_support = hw->wol_enabled = 0;
	ixgbe_get_device_caps(hw, &dev_caps);
	if ((dev_caps & IXGBE_DEVICE_CAPS_WOL_PORT0_1) ||
	    ((dev_caps & IXGBE_DEVICE_CAPS_WOL_PORT0) &&
	     hw->bus.func == 0))
		sc->wol_support = hw->wol_enabled = 1;

	/* Save initial wake up filter configuration */
	sc->wufc = IXGBE_READ_REG(hw, IXGBE_WUFC);

	return;
} /* ixgbe_check_wol_support */

/************************************************************************
 * ixgbe_setup_interface
 *
 *   Setup networking device structure and register an interface.
 ************************************************************************/
static int
ixgbe_setup_interface(device_t dev, struct ixgbe_softc *sc)
{
	struct ethercom *ec = &sc->osdep.ec;
	struct ifnet   *ifp;

	INIT_DEBUGOUT("ixgbe_setup_interface: begin");

	ifp = sc->ifp = &ec->ec_if;
	strlcpy(ifp->if_xname, device_xname(dev), IFNAMSIZ);
	ifp->if_baudrate = IF_Gbps(10);
	ifp->if_init = ixgbe_init;
	ifp->if_stop = ixgbe_ifstop;
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_extflags = IFEF_MPSAFE;
	ifp->if_ioctl = ixgbe_ioctl;
#if __FreeBSD_version >= 1100045
	/* TSO parameters */
	ifp->if_hw_tsomax = 65518;
	ifp->if_hw_tsomaxsegcount = IXGBE_82599_SCATTER;
	ifp->if_hw_tsomaxsegsize = 2048;
#endif
	if (sc->feat_en & IXGBE_FEATURE_LEGACY_TX) {
#if 0
		ixgbe_start_locked = ixgbe_legacy_start_locked;
#endif
	} else {
		ifp->if_transmit = ixgbe_mq_start;
#if 0
		ixgbe_start_locked = ixgbe_mq_start_locked;
#endif
	}
	ifp->if_start = ixgbe_legacy_start;
	IFQ_SET_MAXLEN(&ifp->if_snd, sc->num_tx_desc - 2);
	IFQ_SET_READY(&ifp->if_snd);

	if_initialize(ifp);
	sc->ipq = if_percpuq_create(&sc->osdep.ec.ec_if);
	/*
	 * We use per TX queue softint, so if_deferred_start_init() isn't
	 * used.
	 */

	sc->max_frame_size = ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	/*
	 * Tell the upper layer(s) we support long frames.
	 */
	ifp->if_hdrlen = sizeof(struct ether_vlan_header);

	/* Set capability flags */
	ifp->if_capabilities |= IFCAP_RXCSUM
			     |	IFCAP_TXCSUM
			     |	IFCAP_TSOv4
			     |	IFCAP_TSOv6;
	ifp->if_capenable = 0;

	ec->ec_capabilities |= ETHERCAP_VLAN_HWTAGGING
			    |  ETHERCAP_VLAN_HWCSUM
			    |  ETHERCAP_JUMBO_MTU
			    |  ETHERCAP_VLAN_MTU;

	/* Enable the above capabilities by default */
	ec->ec_capenable = ec->ec_capabilities;

	ether_ifattach(ifp, sc->hw.mac.addr);
	aprint_normal_dev(dev, "Ethernet address %s\n",
	    ether_sprintf(sc->hw.mac.addr));
	ether_set_ifflags_cb(ec, ixgbe_ifflags_cb);

	/*
	 * Don't turn this on by default, if vlans are
	 * created on another pseudo device (eg. lagg)
	 * then vlan events are not passed thru, breaking
	 * operation, but with HW FILTER off it works. If
	 * using vlans directly on the ixgbe driver you can
	 * enable this and get full hardware tag filtering.
	 */
	ec->ec_capabilities |= ETHERCAP_VLAN_HWFILTER;

	/*
	 * Specify the media types supported by this adapter and register
	 * callbacks to update media and link information
	 */
	ec->ec_ifmedia = &sc->media;
	ifmedia_init_with_lock(&sc->media, IFM_IMASK, ixgbe_media_change,
	    ixgbe_media_status, &sc->core_mtx);

	sc->phy_layer = ixgbe_get_supported_physical_layer(&sc->hw);
	ixgbe_add_media_types(sc);

	/* Set autoselect media by default */
	ifmedia_set(&sc->media, IFM_ETHER | IFM_AUTO);

	if_register(ifp);

	return (0);
} /* ixgbe_setup_interface */

/************************************************************************
 * ixgbe_add_media_types
 ************************************************************************/
static void
ixgbe_add_media_types(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	u64		layer;

	layer = sc->phy_layer;

#define	ADD(mm, dd)							\
	ifmedia_add(&sc->media, IFM_ETHER | (mm), (dd), NULL);

	ADD(IFM_NONE, 0);

	/* Media types with matching NetBSD media defines */
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_T)
		ADD(IFM_10G_T | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_T)
		ADD(IFM_1000_T | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_100BASE_TX)
		ADD(IFM_100_TX | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_10BASE_T)
		ADD(IFM_10_T | IFM_FDX, 0);

	if (layer & IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU ||
	    layer & IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA)
		ADD(IFM_10G_TWINAX | IFM_FDX, 0);

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LR) {
		ADD(IFM_10G_LR | IFM_FDX, 0);
		if (hw->phy.multispeed_fiber)
			ADD(IFM_1000_LX | IFM_FDX, 0);
	}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_SR) {
		ADD(IFM_10G_SR | IFM_FDX, 0);
		if (hw->phy.multispeed_fiber)
			ADD(IFM_1000_SX | IFM_FDX, 0);
	} else if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_SX)
		ADD(IFM_1000_SX | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_CX4)
		ADD(IFM_10G_CX4 | IFM_FDX, 0);

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR)
		ADD(IFM_10G_KR | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4)
		ADD(IFM_10G_KX4 | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX)
		ADD(IFM_1000_KX | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_2500BASE_KX)
		ADD(IFM_2500_KX | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_2500BASE_T)
		ADD(IFM_2500_T | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_5GBASE_T)
		ADD(IFM_5000_T | IFM_FDX, 0);
	if (layer & IXGBE_PHYSICAL_LAYER_1000BASE_BX)
		ADD(IFM_1000_BX10 | IFM_FDX, 0);
	/* XXX no ifmedia_set? */

	ADD(IFM_AUTO, 0);

#undef ADD
} /* ixgbe_add_media_types */

/************************************************************************
 * ixgbe_is_sfp
 ************************************************************************/
static inline bool
ixgbe_is_sfp(struct ixgbe_hw *hw)
{
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		if (hw->phy.type == ixgbe_phy_nl)
			return (TRUE);
		return (FALSE);
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		switch (hw->mac.ops.get_media_type(hw)) {
		case ixgbe_media_type_fiber:
		case ixgbe_media_type_fiber_qsfp:
			return (TRUE);
		default:
			return (FALSE);
		}
	default:
		return (FALSE);
	}
} /* ixgbe_is_sfp */

static void
ixgbe_schedule_admin_tasklet(struct ixgbe_softc *sc)
{

	KASSERT(mutex_owned(&sc->admin_mtx));

	if (__predict_true(sc->osdep.detaching == false)) {
		if (sc->admin_pending == 0)
			workqueue_enqueue(sc->admin_wq,
			    &sc->admin_wc, NULL);
		sc->admin_pending = 1;
	}
}

/************************************************************************
 * ixgbe_config_link
 ************************************************************************/
static void
ixgbe_config_link(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	u32		autoneg, err = 0;
	u32		task_requests = 0;
	bool		sfp, negotiate = false;

	sfp = ixgbe_is_sfp(hw);

	if (sfp) {
		if (hw->phy.multispeed_fiber) {
			ixgbe_enable_tx_laser(hw);
			task_requests |= IXGBE_REQUEST_TASK_MSF_WOI;
		}
		task_requests |= IXGBE_REQUEST_TASK_MOD_WOI;

		mutex_enter(&sc->admin_mtx);
		sc->task_requests |= task_requests;
		ixgbe_schedule_admin_tasklet(sc);
		mutex_exit(&sc->admin_mtx);
	} else {
		struct ifmedia	*ifm = &sc->media;

		if (hw->mac.ops.check_link)
			err = ixgbe_check_link(hw, &sc->link_speed,
			    &sc->link_up, FALSE);
		if (err)
			return;

		/*
		 * Check if it's the first call. If it's the first call,
		 * get value for auto negotiation.
		 */
		autoneg = hw->phy.autoneg_advertised;
		if ((IFM_SUBTYPE(ifm->ifm_cur->ifm_media) != IFM_NONE)
		    && ((!autoneg) && (hw->mac.ops.get_link_capabilities)))
			err = hw->mac.ops.get_link_capabilities(hw, &autoneg,
			    &negotiate);
		if (err)
			return;
		if (hw->mac.ops.setup_link)
			err = hw->mac.ops.setup_link(hw, autoneg,
			    sc->link_up);
	}
} /* ixgbe_config_link */

/************************************************************************
 * ixgbe_update_stats_counters - Update board statistics counters.
 ************************************************************************/
static void
ixgbe_update_stats_counters(struct ixgbe_softc *sc)
{
	struct ifnet	      *ifp = sc->ifp;
	struct ixgbe_hw	      *hw = &sc->hw;
	struct ixgbe_hw_stats *stats = &sc->stats.pf;
	u32		      missed_rx = 0, bprc, lxontxc, lxofftxc;
	u64		      total, total_missed_rx = 0, total_qprdc = 0;
	uint64_t	      crcerrs, illerrc, rlec, ruc, rfc, roc, rjc;
	unsigned int	      queue_counters;
	int		      i;

	IXGBE_EVC_REGADD2(hw, stats, IXGBE_CRCERRS, crcerrs);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_ILLERRC, illerrc);

	IXGBE_EVC_REGADD(hw, stats, IXGBE_ERRBC, errbc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_MSPDC, mspdc);
	if (hw->mac.type >= ixgbe_mac_X550)
		IXGBE_EVC_REGADD(hw, stats, IXGBE_MBSDC, mbsdc);

	/* 16 registers exist */
	queue_counters = uimin(__arraycount(stats->qprc), sc->num_queues);
	for (i = 0; i < queue_counters; i++) {
		IXGBE_EVC_REGADD(hw, stats, IXGBE_QPRC(i), qprc[i]);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_QPTC(i), qptc[i]);
		if (hw->mac.type >= ixgbe_mac_82599EB) {
			uint32_t qprdc;

			IXGBE_EVC_ADD(&stats->qbrc[i],
			    IXGBE_READ_REG(hw, IXGBE_QBRC_L(i)) +
			    ((u64)IXGBE_READ_REG(hw, IXGBE_QBRC_H(i)) << 32));
			IXGBE_EVC_ADD(&stats->qbtc[i],
			    IXGBE_READ_REG(hw, IXGBE_QBTC_L(i)) +
			    ((u64)IXGBE_READ_REG(hw, IXGBE_QBTC_H(i)) << 32));
			/* QPRDC will be added to iqdrops. */
			qprdc = IXGBE_READ_REG(hw, IXGBE_QPRDC(i));
			IXGBE_EVC_ADD(&stats->qprdc[i], qprdc);
			total_qprdc += qprdc;
		} else {
			/* 82598 */
			IXGBE_EVC_REGADD(hw, stats, IXGBE_QBRC(i), qbrc[i]);
			IXGBE_EVC_REGADD(hw, stats, IXGBE_QBTC(i), qbtc[i]);
		}
	}

	/* 8 registers exist */
	for (i = 0; i < IXGBE_TC_COUNTER_NUM; i++) {
		uint32_t mp;

		/* MPC */
		mp = IXGBE_READ_REG(hw, IXGBE_MPC(i));
		/* global total per queue */
		IXGBE_EVC_ADD(&stats->mpc[i], mp);
		/* running comprehensive total for stats display */
		total_missed_rx += mp;

		if (hw->mac.type == ixgbe_mac_82598EB)
			IXGBE_EVC_REGADD(hw, stats, IXGBE_RNBC(i), rnbc[i]);

		IXGBE_EVC_REGADD(hw, stats, IXGBE_PXONTXC(i), pxontxc[i]);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_PXOFFTXC(i), pxofftxc[i]);
		if (hw->mac.type >= ixgbe_mac_82599EB) {
			IXGBE_EVC_REGADD(hw, stats,
			    IXGBE_PXONRXCNT(i), pxonrxc[i]);
			IXGBE_EVC_REGADD(hw, stats,
			    IXGBE_PXOFFRXCNT(i), pxoffrxc[i]);
			IXGBE_EVC_REGADD(hw, stats,
			    IXGBE_PXON2OFFCNT(i), pxon2offc[i]);
		} else {
			IXGBE_EVC_REGADD(hw, stats,
			    IXGBE_PXONRXC(i), pxonrxc[i]);
			IXGBE_EVC_REGADD(hw, stats,
			    IXGBE_PXOFFRXC(i), pxoffrxc[i]);
		}
	}
	IXGBE_EVC_ADD(&stats->mpctotal, total_missed_rx);

	/* Document says M[LR]FC are valid when link is up and 10Gbps */
	if ((sc->link_active == LINK_STATE_UP)
	    && (sc->link_speed == IXGBE_LINK_SPEED_10GB_FULL)) {
		IXGBE_EVC_REGADD(hw, stats, IXGBE_MLFC, mlfc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_MRFC, mrfc);
	}
	if (hw->mac.type == ixgbe_mac_X550EM_a)
		IXGBE_EVC_REGADD(hw, stats, IXGBE_LINK_DN_CNT, link_dn_cnt);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_RLEC, rlec);

	/* Hardware workaround, gprc counts missed packets */
	IXGBE_EVC_ADD(&stats->gprc,
	    IXGBE_READ_REG(hw, IXGBE_GPRC) - missed_rx);

	IXGBE_EVC_REGADD2(hw, stats, IXGBE_LXONTXC, lxontxc);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_LXOFFTXC, lxofftxc);
	total = lxontxc + lxofftxc;

	if (hw->mac.type != ixgbe_mac_82598EB) {
		IXGBE_EVC_ADD(&stats->gorc, IXGBE_READ_REG(hw, IXGBE_GORCL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_GORCH) << 32));
		IXGBE_EVC_ADD(&stats->gotc, IXGBE_READ_REG(hw, IXGBE_GOTCL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_GOTCH) << 32)
		    - total * ETHER_MIN_LEN);
		IXGBE_EVC_ADD(&stats->tor, IXGBE_READ_REG(hw, IXGBE_TORL) +
		    ((u64)IXGBE_READ_REG(hw, IXGBE_TORH) << 32));
		IXGBE_EVC_REGADD(hw, stats, IXGBE_LXONRXCNT, lxonrxc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_LXOFFRXCNT, lxoffrxc);
	} else {
		IXGBE_EVC_REGADD(hw, stats, IXGBE_LXONRXC, lxonrxc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_LXOFFRXC, lxoffrxc);
		/* 82598 only has a counter in the high register */
		IXGBE_EVC_REGADD(hw, stats, IXGBE_GORCH, gorc);
		IXGBE_EVC_ADD(&stats->gotc, IXGBE_READ_REG(hw, IXGBE_GOTCH)
		    - total * ETHER_MIN_LEN);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_TORH, tor);
	}

	/*
	 * Workaround: mprc hardware is incorrectly counting
	 * broadcasts, so for now we subtract those.
	 */
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_BPRC, bprc);
	IXGBE_EVC_ADD(&stats->mprc, IXGBE_READ_REG(hw, IXGBE_MPRC)
	    - ((hw->mac.type == ixgbe_mac_82598EB) ? bprc : 0));

	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC64, prc64);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC127, prc127);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC255, prc255);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC511, prc511);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC1023, prc1023);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PRC1522, prc1522);

	IXGBE_EVC_ADD(&stats->gptc, IXGBE_READ_REG(hw, IXGBE_GPTC) - total);
	IXGBE_EVC_ADD(&stats->mptc, IXGBE_READ_REG(hw, IXGBE_MPTC) - total);
	IXGBE_EVC_ADD(&stats->ptc64, IXGBE_READ_REG(hw, IXGBE_PTC64) - total);

	IXGBE_EVC_REGADD2(hw, stats, IXGBE_RUC, ruc);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_RFC, rfc);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_ROC, roc);
	IXGBE_EVC_REGADD2(hw, stats, IXGBE_RJC, rjc);

	IXGBE_EVC_REGADD(hw, stats, IXGBE_MNGPRC, mngprc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_MNGPDC, mngpdc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_MNGPTC, mngptc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_TPR, tpr);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_TPT, tpt);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PTC127, ptc127);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PTC255, ptc255);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PTC511, ptc511);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PTC1023, ptc1023);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_PTC1522, ptc1522);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_BPTC, bptc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_XEC, xec);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_FCCRC, fccrc);
	IXGBE_EVC_REGADD(hw, stats, IXGBE_FCLAST, fclast);
	/* Only read FCOE on 82599 */
	if (hw->mac.type != ixgbe_mac_82598EB) {
		IXGBE_EVC_REGADD(hw, stats, IXGBE_FCOERPDC, fcoerpdc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_FCOEPRC, fcoeprc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_FCOEPTC, fcoeptc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_FCOEDWRC, fcoedwrc);
		IXGBE_EVC_REGADD(hw, stats, IXGBE_FCOEDWTC, fcoedwtc);
	}

	/*
	 * Fill out the OS statistics structure. Only RX errors are required
	 * here because all TX counters are incremented in the TX path and
	 * normal RX counters are prepared in ether_input().
	 */
	net_stat_ref_t nsr = IF_STAT_GETREF(ifp);
	if_statadd_ref(ifp, nsr, if_iqdrops, total_missed_rx + total_qprdc);

	/*
	 * Aggregate following types of errors as RX errors:
	 * - CRC error count,
	 * - illegal byte error count,
	 * - length error count,
	 * - undersized packets count,
	 * - fragmented packets count,
	 * - oversized packets count,
	 * - jabber count.
	 */
	if_statadd_ref(ifp, nsr, if_ierrors,
	    crcerrs + illerrc + rlec + ruc + rfc + roc + rjc);

	IF_STAT_PUTREF(ifp);
} /* ixgbe_update_stats_counters */

/************************************************************************
 * ixgbe_add_hw_stats
 *
 *   Add sysctl variables, one per statistic, to the system.
 ************************************************************************/
static void
ixgbe_add_hw_stats(struct ixgbe_softc *sc)
{
	device_t dev = sc->dev;
	const struct sysctlnode *rnode, *cnode;
	struct sysctllog **log = &sc->sysctllog;
	struct tx_ring *txr = sc->tx_rings;
	struct rx_ring *rxr = sc->rx_rings;
	struct ixgbe_hw *hw = &sc->hw;
	struct ixgbe_hw_stats *stats = &sc->stats.pf;
	const char *xname = device_xname(dev);
	int i;

	/* Driver Statistics */
	evcnt_attach_dynamic(&sc->efbig_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma soft fail EFBIG");
	evcnt_attach_dynamic(&sc->mbuf_defrag_failed, EVCNT_TYPE_MISC,
	    NULL, xname, "m_defrag() failed");
	evcnt_attach_dynamic(&sc->efbig2_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma hard fail EFBIG");
	evcnt_attach_dynamic(&sc->einval_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma hard fail EINVAL");
	evcnt_attach_dynamic(&sc->other_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma hard fail other");
	evcnt_attach_dynamic(&sc->eagain_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma soft fail EAGAIN");
	evcnt_attach_dynamic(&sc->enomem_tx_dma_setup, EVCNT_TYPE_MISC,
	    NULL, xname, "Driver tx dma soft fail ENOMEM");
	evcnt_attach_dynamic(&sc->watchdog_events, EVCNT_TYPE_MISC,
	    NULL, xname, "Watchdog timeouts");
	evcnt_attach_dynamic(&sc->tso_err, EVCNT_TYPE_MISC,
	    NULL, xname, "TSO errors");
	evcnt_attach_dynamic(&sc->admin_irqev, EVCNT_TYPE_INTR,
	    NULL, xname, "Admin MSI-X IRQ Handled");
	evcnt_attach_dynamic(&sc->link_workev, EVCNT_TYPE_INTR,
	    NULL, xname, "Link event");
	evcnt_attach_dynamic(&sc->mod_workev, EVCNT_TYPE_INTR,
	    NULL, xname, "SFP+ module event");
	evcnt_attach_dynamic(&sc->msf_workev, EVCNT_TYPE_INTR,
	    NULL, xname, "Multispeed event");
	evcnt_attach_dynamic(&sc->phy_workev, EVCNT_TYPE_INTR,
	    NULL, xname, "External PHY event");

	/* Max number of traffic class is 8 */
	KASSERT(IXGBE_DCB_MAX_TRAFFIC_CLASS == 8);
	for (i = 0; i < IXGBE_TC_COUNTER_NUM; i++) {
		snprintf(sc->tcs[i].evnamebuf,
		    sizeof(sc->tcs[i].evnamebuf), "%s tc%d", xname, i);
		if (i < __arraycount(stats->mpc)) {
			evcnt_attach_dynamic(&stats->mpc[i],
			    EVCNT_TYPE_MISC, NULL, sc->tcs[i].evnamebuf,
			    "RX Missed Packet Count");
			if (hw->mac.type == ixgbe_mac_82598EB)
				evcnt_attach_dynamic(&stats->rnbc[i],
				    EVCNT_TYPE_MISC, NULL,
				    sc->tcs[i].evnamebuf,
				    "Receive No Buffers");
		}
		if (i < __arraycount(stats->pxontxc)) {
			evcnt_attach_dynamic(&stats->pxontxc[i],
			    EVCNT_TYPE_MISC, NULL, sc->tcs[i].evnamebuf,
			    "Priority XON Transmitted");
			evcnt_attach_dynamic(&stats->pxofftxc[i],
			    EVCNT_TYPE_MISC, NULL, sc->tcs[i].evnamebuf,
			    "Priority XOFF Transmitted");
			if (hw->mac.type >= ixgbe_mac_82599EB)
				evcnt_attach_dynamic(&stats->pxon2offc[i],
				    EVCNT_TYPE_MISC, NULL,
				    sc->tcs[i].evnamebuf,
				    "Priority XON to XOFF");
			evcnt_attach_dynamic(&stats->pxonrxc[i],
			    EVCNT_TYPE_MISC, NULL, sc->tcs[i].evnamebuf,
			    "Priority XON Received");
			evcnt_attach_dynamic(&stats->pxoffrxc[i],
			    EVCNT_TYPE_MISC, NULL, sc->tcs[i].evnamebuf,
			    "Priority XOFF Received");
		}
	}

	for (i = 0; i < sc->num_queues; i++, rxr++, txr++) {
#ifdef LRO
		struct lro_ctrl *lro = &rxr->lro;
#endif

		snprintf(sc->queues[i].evnamebuf,
		    sizeof(sc->queues[i].evnamebuf), "%s q%d", xname, i);
		snprintf(sc->queues[i].namebuf,
		    sizeof(sc->queues[i].namebuf), "q%d", i);

		if ((rnode = ixgbe_sysctl_instance(sc)) == NULL) {
			aprint_error_dev(dev,
			    "could not create sysctl root\n");
			break;
		}

		if (sysctl_createv(log, 0, &rnode, &rnode,
		    0, CTLTYPE_NODE,
		    sc->queues[i].namebuf, SYSCTL_DESCR("Queue Name"),
		    NULL, 0, NULL, 0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READWRITE, CTLTYPE_INT,
		    "interrupt_rate", SYSCTL_DESCR("Interrupt Rate"),
		    ixgbe_sysctl_interrupt_rate_handler, 0,
		    (void *)&sc->queues[i], 0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txd_head", SYSCTL_DESCR("Transmit Descriptor Head"),
		    ixgbe_sysctl_tdh_handler, 0, (void *)txr,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT,
		    "txd_tail", SYSCTL_DESCR("Transmit Descriptor Tail"),
		    ixgbe_sysctl_tdt_handler, 0, (void *)txr,
		    0, CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT, "rxd_nxck",
		    SYSCTL_DESCR("Receive Descriptor next to check"),
		    ixgbe_sysctl_next_to_check_handler, 0, (void *)rxr, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT, "rxd_nxrf",
		    SYSCTL_DESCR("Receive Descriptor next to refresh"),
		    ixgbe_sysctl_next_to_refresh_handler, 0, (void *)rxr, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT, "rxd_head",
		    SYSCTL_DESCR("Receive Descriptor Head"),
		    ixgbe_sysctl_rdh_handler, 0, (void *)rxr, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			break;

		if (sysctl_createv(log, 0, &rnode, &cnode,
		    CTLFLAG_READONLY, CTLTYPE_INT, "rxd_tail",
		    SYSCTL_DESCR("Receive Descriptor Tail"),
		    ixgbe_sysctl_rdt_handler, 0, (void *)rxr, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			break;

		evcnt_attach_dynamic(&sc->queues[i].irqs, EVCNT_TYPE_INTR,
		    NULL, sc->queues[i].evnamebuf, "IRQs on queue");
		evcnt_attach_dynamic(&sc->queues[i].handleq,
		    EVCNT_TYPE_MISC, NULL, sc->queues[i].evnamebuf,
		    "Handled queue in softint");
		evcnt_attach_dynamic(&sc->queues[i].req, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf, "Requeued in softint");
		if (i < __arraycount(stats->qbtc))
			evcnt_attach_dynamic(&stats->qbtc[i], EVCNT_TYPE_MISC,
			    NULL, sc->queues[i].evnamebuf,
			    "Queue Bytes Transmitted (reg)");
		evcnt_attach_dynamic(&txr->total_packets, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf,
		    "Queue Packets Transmitted (soft)");
		if (i < __arraycount(stats->qptc))
			evcnt_attach_dynamic(&stats->qptc[i], EVCNT_TYPE_MISC,
			    NULL, sc->queues[i].evnamebuf,
			    "Queue Packets Transmitted (reg)");
#ifndef IXGBE_LEGACY_TX
		evcnt_attach_dynamic(&txr->pcq_drops, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf,
		    "Packets dropped in pcq");
#endif
		evcnt_attach_dynamic(&txr->no_desc_avail, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf,
		    "TX Queue No Descriptor Available");
		evcnt_attach_dynamic(&txr->tso_tx, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf, "TSO");

		evcnt_attach_dynamic(&rxr->rx_bytes, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf,
		    "Queue Bytes Received (soft)");
		if (i < __arraycount(stats->qbrc))
			evcnt_attach_dynamic(&stats->qbrc[i], EVCNT_TYPE_MISC,
			    NULL, sc->queues[i].evnamebuf,
			    "Queue Bytes Received (reg)");
		evcnt_attach_dynamic(&rxr->rx_packets, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf,
		    "Queue Packets Received (soft)");
		if (i < __arraycount(stats->qprc))
			evcnt_attach_dynamic(&stats->qprc[i], EVCNT_TYPE_MISC,
			    NULL, sc->queues[i].evnamebuf,
			    "Queue Packets Received (reg)");
		if ((i < __arraycount(stats->qprdc)) &&
		    (hw->mac.type >= ixgbe_mac_82599EB))
				evcnt_attach_dynamic(&stats->qprdc[i],
				    EVCNT_TYPE_MISC, NULL,
				    sc->queues[i].evnamebuf,
				    "Queue Packets Received Drop");

		evcnt_attach_dynamic(&rxr->no_mbuf, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf, "Rx no mbuf");
		evcnt_attach_dynamic(&rxr->rx_discarded, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf, "Rx discarded");
		evcnt_attach_dynamic(&rxr->rx_copies, EVCNT_TYPE_MISC,
		    NULL, sc->queues[i].evnamebuf, "Copied RX Frames");
#ifdef LRO
		SYSCTL_ADD_INT(ctx, queue_list, OID_AUTO, "lro_queued",
				CTLFLAG_RD, &lro->lro_queued, 0,
				"LRO Queued");
		SYSCTL_ADD_INT(ctx, queue_list, OID_AUTO, "lro_flushed",
				CTLFLAG_RD, &lro->lro_flushed, 0,
				"LRO Flushed");
#endif /* LRO */
	}

	/* MAC stats get their own sub node */

	snprintf(stats->namebuf,
	    sizeof(stats->namebuf), "%s MAC Statistics", xname);

	evcnt_attach_dynamic(&stats->ipcs, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "rx csum offload - IP");
	evcnt_attach_dynamic(&stats->l4cs, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "rx csum offload - L4");
	evcnt_attach_dynamic(&stats->ipcs_bad, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "rx csum offload - IP bad");
	evcnt_attach_dynamic(&stats->l4cs_bad, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "rx csum offload - L4 bad");
	evcnt_attach_dynamic(&stats->intzero, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Interrupt conditions zero");
	evcnt_attach_dynamic(&stats->legint, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Legacy interrupts");

	evcnt_attach_dynamic(&stats->crcerrs, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "CRC Errors");
	evcnt_attach_dynamic(&stats->illerrc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Illegal Byte Errors");
	evcnt_attach_dynamic(&stats->errbc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Byte Errors");
	evcnt_attach_dynamic(&stats->mspdc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "MAC Short Packets Discarded");
	if (hw->mac.type >= ixgbe_mac_X550)
		evcnt_attach_dynamic(&stats->mbsdc, EVCNT_TYPE_MISC, NULL,
		    stats->namebuf, "Bad SFD");
	evcnt_attach_dynamic(&stats->mpctotal, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Total Packets Missed");
	evcnt_attach_dynamic(&stats->mlfc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "MAC Local Faults");
	evcnt_attach_dynamic(&stats->mrfc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "MAC Remote Faults");
	if (hw->mac.type == ixgbe_mac_X550EM_a)
		evcnt_attach_dynamic(&stats->link_dn_cnt, EVCNT_TYPE_MISC,
		    NULL, stats->namebuf, "Link down event in the MAC");
	evcnt_attach_dynamic(&stats->rlec, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Receive Length Errors");
	evcnt_attach_dynamic(&stats->lxontxc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Link XON Transmitted");
	evcnt_attach_dynamic(&stats->lxofftxc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Link XOFF Transmitted");
	evcnt_attach_dynamic(&stats->lxonrxc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Link XON Received");
	evcnt_attach_dynamic(&stats->lxoffrxc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Link XOFF Received");

	/* Packet Reception Stats */
	evcnt_attach_dynamic(&stats->tor, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Total Octets Received");
	evcnt_attach_dynamic(&stats->gorc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Good Octets Received");
	evcnt_attach_dynamic(&stats->tpr, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Total Packets Received");
	evcnt_attach_dynamic(&stats->gprc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Good Packets Received");
	evcnt_attach_dynamic(&stats->mprc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Multicast Packets Received");
	evcnt_attach_dynamic(&stats->bprc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Broadcast Packets Received");
	evcnt_attach_dynamic(&stats->prc64, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "64 byte frames received ");
	evcnt_attach_dynamic(&stats->prc127, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "65-127 byte frames received");
	evcnt_attach_dynamic(&stats->prc255, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "128-255 byte frames received");
	evcnt_attach_dynamic(&stats->prc511, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "256-511 byte frames received");
	evcnt_attach_dynamic(&stats->prc1023, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "512-1023 byte frames received");
	evcnt_attach_dynamic(&stats->prc1522, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "1023-1522 byte frames received");
	evcnt_attach_dynamic(&stats->ruc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Receive Undersized");
	evcnt_attach_dynamic(&stats->rfc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Fragmented Packets Received ");
	evcnt_attach_dynamic(&stats->roc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Oversized Packets Received");
	evcnt_attach_dynamic(&stats->rjc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Received Jabber");
	evcnt_attach_dynamic(&stats->mngprc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Management Packets Received");
	evcnt_attach_dynamic(&stats->mngpdc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Management Packets Dropped");
	evcnt_attach_dynamic(&stats->xec, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Checksum Errors");

	/* Packet Transmission Stats */
	evcnt_attach_dynamic(&stats->gotc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Good Octets Transmitted");
	evcnt_attach_dynamic(&stats->tpt, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Total Packets Transmitted");
	evcnt_attach_dynamic(&stats->gptc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Good Packets Transmitted");
	evcnt_attach_dynamic(&stats->bptc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Broadcast Packets Transmitted");
	evcnt_attach_dynamic(&stats->mptc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Multicast Packets Transmitted");
	evcnt_attach_dynamic(&stats->mngptc, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "Management Packets Transmitted");
	evcnt_attach_dynamic(&stats->ptc64, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "64 byte frames transmitted ");
	evcnt_attach_dynamic(&stats->ptc127, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "65-127 byte frames transmitted");
	evcnt_attach_dynamic(&stats->ptc255, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "128-255 byte frames transmitted");
	evcnt_attach_dynamic(&stats->ptc511, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "256-511 byte frames transmitted");
	evcnt_attach_dynamic(&stats->ptc1023, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "512-1023 byte frames transmitted");
	evcnt_attach_dynamic(&stats->ptc1522, EVCNT_TYPE_MISC, NULL,
	    stats->namebuf, "1024-1522 byte frames transmitted");
} /* ixgbe_add_hw_stats */

static void
ixgbe_clear_evcnt(struct ixgbe_softc *sc)
{
	struct tx_ring *txr = sc->tx_rings;
	struct rx_ring *rxr = sc->rx_rings;
	struct ixgbe_hw *hw = &sc->hw;
	struct ixgbe_hw_stats *stats = &sc->stats.pf;
	int i;

	IXGBE_EVC_STORE(&sc->efbig_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->mbuf_defrag_failed, 0);
	IXGBE_EVC_STORE(&sc->efbig2_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->einval_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->other_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->eagain_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->enomem_tx_dma_setup, 0);
	IXGBE_EVC_STORE(&sc->tso_err, 0);
	IXGBE_EVC_STORE(&sc->watchdog_events, 0);
	IXGBE_EVC_STORE(&sc->admin_irqev, 0);
	IXGBE_EVC_STORE(&sc->link_workev, 0);
	IXGBE_EVC_STORE(&sc->mod_workev, 0);
	IXGBE_EVC_STORE(&sc->msf_workev, 0);
	IXGBE_EVC_STORE(&sc->phy_workev, 0);

	for (i = 0; i < IXGBE_TC_COUNTER_NUM; i++) {
		if (i < __arraycount(stats->mpc)) {
			IXGBE_EVC_STORE(&stats->mpc[i], 0);
			if (hw->mac.type == ixgbe_mac_82598EB)
				IXGBE_EVC_STORE(&stats->rnbc[i], 0);
		}
		if (i < __arraycount(stats->pxontxc)) {
			IXGBE_EVC_STORE(&stats->pxontxc[i], 0);
			IXGBE_EVC_STORE(&stats->pxonrxc[i], 0);
			IXGBE_EVC_STORE(&stats->pxofftxc[i], 0);
			IXGBE_EVC_STORE(&stats->pxoffrxc[i], 0);
			if (hw->mac.type >= ixgbe_mac_82599EB)
				IXGBE_EVC_STORE(&stats->pxon2offc[i], 0);
		}
	}

	txr = sc->tx_rings;
	for (i = 0; i < sc->num_queues; i++, rxr++, txr++) {
		IXGBE_EVC_STORE(&sc->queues[i].irqs, 0);
		IXGBE_EVC_STORE(&sc->queues[i].handleq, 0);
		IXGBE_EVC_STORE(&sc->queues[i].req, 0);
		IXGBE_EVC_STORE(&txr->total_packets, 0);
#ifndef IXGBE_LEGACY_TX
		IXGBE_EVC_STORE(&txr->pcq_drops, 0);
#endif
		IXGBE_EVC_STORE(&txr->no_desc_avail, 0);
		IXGBE_EVC_STORE(&txr->tso_tx, 0);
		txr->q_efbig_tx_dma_setup = 0;
		txr->q_mbuf_defrag_failed = 0;
		txr->q_efbig2_tx_dma_setup = 0;
		txr->q_einval_tx_dma_setup = 0;
		txr->q_other_tx_dma_setup = 0;
		txr->q_eagain_tx_dma_setup = 0;
		txr->q_enomem_tx_dma_setup = 0;
		txr->q_tso_err = 0;

		if (i < __arraycount(stats->qprc)) {
			IXGBE_EVC_STORE(&stats->qprc[i], 0);
			IXGBE_EVC_STORE(&stats->qptc[i], 0);
			IXGBE_EVC_STORE(&stats->qbrc[i], 0);
			IXGBE_EVC_STORE(&stats->qbtc[i], 0);
			if (hw->mac.type >= ixgbe_mac_82599EB)
				IXGBE_EVC_STORE(&stats->qprdc[i], 0);
		}

		IXGBE_EVC_STORE(&rxr->rx_packets, 0);
		IXGBE_EVC_STORE(&rxr->rx_bytes, 0);
		IXGBE_EVC_STORE(&rxr->rx_copies, 0);
		IXGBE_EVC_STORE(&rxr->no_mbuf, 0);
		IXGBE_EVC_STORE(&rxr->rx_discarded, 0);
	}
	IXGBE_EVC_STORE(&stats->ipcs, 0);
	IXGBE_EVC_STORE(&stats->l4cs, 0);
	IXGBE_EVC_STORE(&stats->ipcs_bad, 0);
	IXGBE_EVC_STORE(&stats->l4cs_bad, 0);
	IXGBE_EVC_STORE(&stats->intzero, 0);
	IXGBE_EVC_STORE(&stats->legint, 0);
	IXGBE_EVC_STORE(&stats->crcerrs, 0);
	IXGBE_EVC_STORE(&stats->illerrc, 0);
	IXGBE_EVC_STORE(&stats->errbc, 0);
	IXGBE_EVC_STORE(&stats->mspdc, 0);
	if (hw->mac.type >= ixgbe_mac_X550)
		IXGBE_EVC_STORE(&stats->mbsdc, 0);
	IXGBE_EVC_STORE(&stats->mpctotal, 0);
	IXGBE_EVC_STORE(&stats->mlfc, 0);
	IXGBE_EVC_STORE(&stats->mrfc, 0);
	if (hw->mac.type == ixgbe_mac_X550EM_a)
		IXGBE_EVC_STORE(&stats->link_dn_cnt, 0);
	IXGBE_EVC_STORE(&stats->rlec, 0);
	IXGBE_EVC_STORE(&stats->lxontxc, 0);
	IXGBE_EVC_STORE(&stats->lxonrxc, 0);
	IXGBE_EVC_STORE(&stats->lxofftxc, 0);
	IXGBE_EVC_STORE(&stats->lxoffrxc, 0);

	/* Packet Reception Stats */
	IXGBE_EVC_STORE(&stats->tor, 0);
	IXGBE_EVC_STORE(&stats->gorc, 0);
	IXGBE_EVC_STORE(&stats->tpr, 0);
	IXGBE_EVC_STORE(&stats->gprc, 0);
	IXGBE_EVC_STORE(&stats->mprc, 0);
	IXGBE_EVC_STORE(&stats->bprc, 0);
	IXGBE_EVC_STORE(&stats->prc64, 0);
	IXGBE_EVC_STORE(&stats->prc127, 0);
	IXGBE_EVC_STORE(&stats->prc255, 0);
	IXGBE_EVC_STORE(&stats->prc511, 0);
	IXGBE_EVC_STORE(&stats->prc1023, 0);
	IXGBE_EVC_STORE(&stats->prc1522, 0);
	IXGBE_EVC_STORE(&stats->ruc, 0);
	IXGBE_EVC_STORE(&stats->rfc, 0);
	IXGBE_EVC_STORE(&stats->roc, 0);
	IXGBE_EVC_STORE(&stats->rjc, 0);
	IXGBE_EVC_STORE(&stats->mngprc, 0);
	IXGBE_EVC_STORE(&stats->mngpdc, 0);
	IXGBE_EVC_STORE(&stats->xec, 0);

	/* Packet Transmission Stats */
	IXGBE_EVC_STORE(&stats->gotc, 0);
	IXGBE_EVC_STORE(&stats->tpt, 0);
	IXGBE_EVC_STORE(&stats->gptc, 0);
	IXGBE_EVC_STORE(&stats->bptc, 0);
	IXGBE_EVC_STORE(&stats->mptc, 0);
	IXGBE_EVC_STORE(&stats->mngptc, 0);
	IXGBE_EVC_STORE(&stats->ptc64, 0);
	IXGBE_EVC_STORE(&stats->ptc127, 0);
	IXGBE_EVC_STORE(&stats->ptc255, 0);
	IXGBE_EVC_STORE(&stats->ptc511, 0);
	IXGBE_EVC_STORE(&stats->ptc1023, 0);
	IXGBE_EVC_STORE(&stats->ptc1522, 0);
}

/************************************************************************
 * ixgbe_sysctl_tdh_handler - Transmit Descriptor Head handler function
 *
 *   Retrieves the TDH value from the hardware
 ************************************************************************/
static int
ixgbe_sysctl_tdh_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct tx_ring *txr = (struct tx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!txr)
		return (0);

	sc = txr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = IXGBE_READ_REG(&sc->hw, IXGBE_TDH(txr->me));
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_tdh_handler */

/************************************************************************
 * ixgbe_sysctl_tdt_handler - Transmit Descriptor Tail handler function
 *
 *   Retrieves the TDT value from the hardware
 ************************************************************************/
static int
ixgbe_sysctl_tdt_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct tx_ring *txr = (struct tx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!txr)
		return (0);

	sc = txr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = IXGBE_READ_REG(&sc->hw, IXGBE_TDT(txr->me));
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_tdt_handler */

/************************************************************************
 * ixgbe_sysctl_next_to_check_handler - Receive Descriptor next to check
 * handler function
 *
 *   Retrieves the next_to_check value
 ************************************************************************/
static int
ixgbe_sysctl_next_to_check_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct rx_ring *rxr = (struct rx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!rxr)
		return (0);

	sc = rxr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = rxr->next_to_check;
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_next_to_check_handler */

/************************************************************************
 * ixgbe_sysctl_next_to_refresh_handler - Receive Descriptor next to check
 * handler function
 *
 *   Retrieves the next_to_refresh value
 ************************************************************************/
static int
ixgbe_sysctl_next_to_refresh_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct rx_ring *rxr = (struct rx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!rxr)
		return (0);

	sc = rxr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = rxr->next_to_refresh;
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_next_to_refresh_handler */

/************************************************************************
 * ixgbe_sysctl_rdh_handler - Receive Descriptor Head handler function
 *
 *   Retrieves the RDH value from the hardware
 ************************************************************************/
static int
ixgbe_sysctl_rdh_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct rx_ring *rxr = (struct rx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!rxr)
		return (0);

	sc = rxr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = IXGBE_READ_REG(&sc->hw, IXGBE_RDH(rxr->me));
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_rdh_handler */

/************************************************************************
 * ixgbe_sysctl_rdt_handler - Receive Descriptor Tail handler function
 *
 *   Retrieves the RDT value from the hardware
 ************************************************************************/
static int
ixgbe_sysctl_rdt_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct rx_ring *rxr = (struct rx_ring *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t val;

	if (!rxr)
		return (0);

	sc = rxr->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	val = IXGBE_READ_REG(&sc->hw, IXGBE_RDT(rxr->me));
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
} /* ixgbe_sysctl_rdt_handler */

static int
ixgbe_vlan_cb(struct ethercom *ec, uint16_t vid, bool set)
{
	struct ifnet *ifp = &ec->ec_if;
	struct ixgbe_softc *sc = ifp->if_softc;
	int rv;

	if (set)
		rv = ixgbe_register_vlan(sc, vid);
	else
		rv = ixgbe_unregister_vlan(sc, vid);

	if (rv != 0)
		return rv;

	/*
	 * Control VLAN HW tagging when ec_nvlan is changed from 1 to 0
	 * or 0 to 1.
	 */
	if ((set && (ec->ec_nvlans == 1)) || (!set && (ec->ec_nvlans == 0)))
		ixgbe_setup_vlan_hw_tagging(sc);

	return rv;
}

/************************************************************************
 * ixgbe_register_vlan
 *
 *   Run via vlan config EVENT, it enables us to use the
 *   HW Filter table since we can get the vlan id. This
 *   just creates the entry in the soft version of the
 *   VFTA, init will repopulate the real table.
 ************************************************************************/
static int
ixgbe_register_vlan(struct ixgbe_softc *sc, u16 vtag)
{
	u16		index, bit;
	int		error;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return EINVAL;

	IXGBE_CORE_LOCK(sc);
	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	sc->shadow_vfta[index] |= ((u32)1 << bit);
	error = sc->hw.mac.ops.set_vfta(&sc->hw, vtag, 0, true,
	    true);
	IXGBE_CORE_UNLOCK(sc);
	if (error != 0)
		error = EACCES;

	return error;
} /* ixgbe_register_vlan */

/************************************************************************
 * ixgbe_unregister_vlan
 *
 *   Run via vlan unconfig EVENT, remove our entry in the soft vfta.
 ************************************************************************/
static int
ixgbe_unregister_vlan(struct ixgbe_softc *sc, u16 vtag)
{
	u16		index, bit;
	int		error;

	if ((vtag == 0) || (vtag > 4095))	/* Invalid */
		return EINVAL;

	IXGBE_CORE_LOCK(sc);
	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	sc->shadow_vfta[index] &= ~((u32)1 << bit);
	error = sc->hw.mac.ops.set_vfta(&sc->hw, vtag, 0, false,
	    true);
	IXGBE_CORE_UNLOCK(sc);
	if (error != 0)
		error = EACCES;

	return error;
} /* ixgbe_unregister_vlan */

static void
ixgbe_setup_vlan_hw_tagging(struct ixgbe_softc *sc)
{
	struct ethercom *ec = &sc->osdep.ec;
	struct ixgbe_hw *hw = &sc->hw;
	struct rx_ring	*rxr;
	u32		ctrl;
	int		i;
	bool		hwtagging;

	/* Enable HW tagging only if any vlan is attached */
	hwtagging = (ec->ec_capenable & ETHERCAP_VLAN_HWTAGGING)
	    && VLAN_ATTACHED(ec);

	/* Setup the queues for vlans */
	for (i = 0; i < sc->num_queues; i++) {
		rxr = &sc->rx_rings[i];
		/*
		 * On 82599 and later, the VLAN enable is per/queue in RXDCTL.
		 */
		if (hw->mac.type != ixgbe_mac_82598EB) {
			ctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me));
			if (hwtagging)
				ctrl |= IXGBE_RXDCTL_VME;
			else
				ctrl &= ~IXGBE_RXDCTL_VME;
			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxr->me), ctrl);
		}
		rxr->vtag_strip = hwtagging ? TRUE : FALSE;
	}

	/* VLAN hw tagging for 82598 */
	if (hw->mac.type == ixgbe_mac_82598EB) {
		ctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
		if (hwtagging)
			ctrl |= IXGBE_VLNCTRL_VME;
		else
			ctrl &= ~IXGBE_VLNCTRL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, ctrl);
	}
} /* ixgbe_setup_vlan_hw_tagging */

static void
ixgbe_setup_vlan_hw_support(struct ixgbe_softc *sc)
{
	struct ethercom *ec = &sc->osdep.ec;
	struct ixgbe_hw *hw = &sc->hw;
	int		i;
	u32		ctrl;
	struct vlanid_list *vlanidp;

	/*
	 * This function is called from both if_init and ifflags_cb()
	 * on NetBSD.
	 */

	/*
	 * Part 1:
	 * Setup VLAN HW tagging
	 */
	ixgbe_setup_vlan_hw_tagging(sc);

	/*
	 * Part 2:
	 * Setup VLAN HW filter
	 */
	/* Cleanup shadow_vfta */
	for (i = 0; i < IXGBE_VFTA_SIZE; i++)
		sc->shadow_vfta[i] = 0;
	/* Generate shadow_vfta from ec_vids */
	ETHER_LOCK(ec);
	SIMPLEQ_FOREACH(vlanidp, &ec->ec_vids, vid_list) {
		uint32_t idx;

		idx = vlanidp->vid / 32;
		KASSERT(idx < IXGBE_VFTA_SIZE);
		sc->shadow_vfta[idx] |= (u32)1 << (vlanidp->vid % 32);
	}
	ETHER_UNLOCK(ec);
	for (i = 0; i < IXGBE_VFTA_SIZE; i++)
		IXGBE_WRITE_REG(hw, IXGBE_VFTA(i), sc->shadow_vfta[i]);

	ctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
	/* Enable the Filter Table if enabled */
	if (ec->ec_capenable & ETHERCAP_VLAN_HWFILTER)
		ctrl |= IXGBE_VLNCTRL_VFE;
	else
		ctrl &= ~IXGBE_VLNCTRL_VFE;
	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, ctrl);
} /* ixgbe_setup_vlan_hw_support */

/************************************************************************
 * ixgbe_get_slot_info
 *
 *   Get the width and transaction speed of
 *   the slot this adapter is plugged into.
 ************************************************************************/
static void
ixgbe_get_slot_info(struct ixgbe_softc *sc)
{
	device_t		dev = sc->dev;
	struct ixgbe_hw		*hw = &sc->hw;
	u32		      offset;
	u16			link;
	int		      bus_info_valid = TRUE;

	/* Some devices are behind an internal bridge */
	switch (hw->device_id) {
	case IXGBE_DEV_ID_82599_SFP_SF_QP:
	case IXGBE_DEV_ID_82599_QSFP_SF_QP:
		goto get_parent_info;
	default:
		break;
	}

	ixgbe_get_bus_info(hw);

	/*
	 * Some devices don't use PCI-E, but there is no need
	 * to display "Unknown" for bus speed and width.
	 */
	switch (hw->mac.type) {
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		return;
	default:
		goto display;
	}

get_parent_info:
	/*
	 * For the Quad port adapter we need to parse back
	 * up the PCI tree to find the speed of the expansion
	 * slot into which this adapter is plugged. A bit more work.
	 */
	dev = device_parent(device_parent(dev));
#if 0
#ifdef IXGBE_DEBUG
	device_printf(dev, "parent pcib = %x,%x,%x\n", pci_get_bus(dev),
	    pci_get_slot(dev), pci_get_function(dev));
#endif
	dev = device_parent(device_parent(dev));
#ifdef IXGBE_DEBUG
	device_printf(dev, "slot pcib = %x,%x,%x\n", pci_get_bus(dev),
	    pci_get_slot(dev), pci_get_function(dev));
#endif
#endif
	/* Now get the PCI Express Capabilities offset */
	if (pci_get_capability(sc->osdep.pc, sc->osdep.tag,
	    PCI_CAP_PCIEXPRESS, &offset, NULL)) {
		/*
		 * Hmm...can't get PCI-Express capabilities.
		 * Falling back to default method.
		 */
		bus_info_valid = FALSE;
		ixgbe_get_bus_info(hw);
		goto display;
	}
	/* ...and read the Link Status Register */
	link = pci_conf_read(sc->osdep.pc, sc->osdep.tag,
	    offset + PCIE_LCSR) >> 16;
	ixgbe_set_pci_config_data_generic(hw, link);

display:
	device_printf(dev, "PCI Express Bus: Speed %s Width %s\n",
	    ((hw->bus.speed == ixgbe_bus_speed_8000)	? "8.0GT/s" :
	     (hw->bus.speed == ixgbe_bus_speed_5000)	? "5.0GT/s" :
	     (hw->bus.speed == ixgbe_bus_speed_2500)	? "2.5GT/s" :
	     "Unknown"),
	    ((hw->bus.width == ixgbe_bus_width_pcie_x8) ? "x8" :
	     (hw->bus.width == ixgbe_bus_width_pcie_x4) ? "x4" :
	     (hw->bus.width == ixgbe_bus_width_pcie_x1) ? "x1" :
	     "Unknown"));

	if (bus_info_valid) {
		if ((hw->device_id != IXGBE_DEV_ID_82599_SFP_SF_QP) &&
		    ((hw->bus.width <= ixgbe_bus_width_pcie_x4) &&
			(hw->bus.speed == ixgbe_bus_speed_2500))) {
			device_printf(dev, "PCI-Express bandwidth available"
			    " for this card\n     is not sufficient for"
			    " optimal performance.\n");
			device_printf(dev, "For optimal performance a x8 "
			    "PCIE, or x4 PCIE Gen2 slot is required.\n");
		}
		if ((hw->device_id == IXGBE_DEV_ID_82599_SFP_SF_QP) &&
		    ((hw->bus.width <= ixgbe_bus_width_pcie_x8) &&
			(hw->bus.speed < ixgbe_bus_speed_8000))) {
			device_printf(dev, "PCI-Express bandwidth available"
			    " for this card\n     is not sufficient for"
			    " optimal performance.\n");
			device_printf(dev, "For optimal performance a x8 "
			    "PCIE Gen3 slot is required.\n");
		}
	} else
		device_printf(dev,
		    "Unable to determine slot speed/width. The speed/width "
		    "reported are that of the internal switch.\n");

	return;
} /* ixgbe_get_slot_info */

/************************************************************************
 * ixgbe_enable_queue - Queue Interrupt Enabler
 ************************************************************************/
static inline void
ixgbe_enable_queue(struct ixgbe_softc *sc, u32 vector)
{
	struct ixgbe_hw *hw = &sc->hw;
	struct ix_queue *que = &sc->queues[vector];
	u64		queue = 1ULL << vector;
	u32		mask;

	mutex_enter(&que->dc_mtx);
	if (que->disabled_count > 0 && --que->disabled_count > 0)
		goto out;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		mask = (IXGBE_EIMS_RTX_QUEUE & queue);
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, mask);
	} else {
		mask = (queue & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(0), mask);
		mask = (queue >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(1), mask);
	}
out:
	mutex_exit(&que->dc_mtx);
} /* ixgbe_enable_queue */

/************************************************************************
 * ixgbe_disable_queue_internal
 ************************************************************************/
static inline void
ixgbe_disable_queue_internal(struct ixgbe_softc *sc, u32 vector, bool nestok)
{
	struct ixgbe_hw *hw = &sc->hw;
	struct ix_queue *que = &sc->queues[vector];
	u64		queue = 1ULL << vector;
	u32		mask;

	mutex_enter(&que->dc_mtx);

	if (que->disabled_count > 0) {
		if (nestok)
			que->disabled_count++;
		goto out;
	}
	que->disabled_count++;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		mask = (IXGBE_EIMS_RTX_QUEUE & queue);
		IXGBE_WRITE_REG(hw, IXGBE_EIMC, mask);
	} else {
		mask = (queue & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(0), mask);
		mask = (queue >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(1), mask);
	}
out:
	mutex_exit(&que->dc_mtx);
} /* ixgbe_disable_queue_internal */

/************************************************************************
 * ixgbe_disable_queue
 ************************************************************************/
static inline void
ixgbe_disable_queue(struct ixgbe_softc *sc, u32 vector)
{

	ixgbe_disable_queue_internal(sc, vector, true);
} /* ixgbe_disable_queue */

/************************************************************************
 * ixgbe_sched_handle_que - schedule deferred packet processing
 ************************************************************************/
static inline void
ixgbe_sched_handle_que(struct ixgbe_softc *sc, struct ix_queue *que)
{

	if (que->txrx_use_workqueue) {
		/*
		 * sc->que_wq is bound to each CPU instead of
		 * each NIC queue to reduce workqueue kthread. As we
		 * should consider about interrupt affinity in this
		 * function, the workqueue kthread must be WQ_PERCPU.
		 * If create WQ_PERCPU workqueue kthread for each NIC
		 * queue, that number of created workqueue kthread is
		 * (number of used NIC queue) * (number of CPUs) =
		 * (number of CPUs) ^ 2 most often.
		 *
		 * The same NIC queue's interrupts are avoided by
		 * masking the queue's interrupt. And different
		 * NIC queue's interrupts use different struct work
		 * (que->wq_cookie). So, "enqueued flag" to avoid
		 * twice workqueue_enqueue() is not required .
		 */
		workqueue_enqueue(sc->que_wq, &que->wq_cookie, curcpu());
	} else
		softint_schedule(que->que_si);
}

/************************************************************************
 * ixgbe_msix_que - MSI-X Queue Interrupt Service routine
 ************************************************************************/
static int
ixgbe_msix_que(void *arg)
{
	struct ix_queue	*que = arg;
	struct ixgbe_softc *sc = que->sc;
	struct ifnet	*ifp = sc->ifp;
	struct tx_ring	*txr = que->txr;
	struct rx_ring	*rxr = que->rxr;
	u32		newitr = 0;

	/* Protect against spurious interrupts */
	if ((ifp->if_flags & IFF_RUNNING) == 0)
		return 0;

	ixgbe_disable_queue(sc, que->msix);
	IXGBE_EVC_ADD(&que->irqs, 1);

	/*
	 * Don't change "que->txrx_use_workqueue" from this point to avoid
	 * flip-flopping softint/workqueue mode in one deferred processing.
	 */
	que->txrx_use_workqueue = sc->txrx_use_workqueue;

	IXGBE_TX_LOCK(txr);
	ixgbe_txeof(txr);
	IXGBE_TX_UNLOCK(txr);

	/* Do AIM now? */

	if (sc->enable_aim == false)
		goto no_calc;
	/*
	 * Do Adaptive Interrupt Moderation:
	 *  - Write out last calculated setting
	 *  - Calculate based on average size over
	 *    the last interval.
	 */
	if (que->eitr_setting)
		ixgbe_eitr_write(sc, que->msix, que->eitr_setting);

	que->eitr_setting = 0;

	/* Idle, do nothing */
	if ((txr->bytes == 0) && (rxr->bytes == 0))
		goto no_calc;

	if ((txr->bytes) && (txr->packets))
		newitr = txr->bytes/txr->packets;
	if ((rxr->bytes) && (rxr->packets))
		newitr = uimax(newitr, (rxr->bytes / rxr->packets));
	newitr += 24; /* account for hardware frame, crc */

	/* set an upper boundary */
	newitr = uimin(newitr, 3000);

	/* Be nice to the mid range */
	if ((newitr > 300) && (newitr < 1200))
		newitr = (newitr / 3);
	else
		newitr = (newitr / 2);

	/*
	 * When RSC is used, ITR interval must be larger than RSC_DELAY.
	 * Currently, we use 2us for RSC_DELAY. The minimum value is always
	 * greater than 2us on 100M (and 10M?(not documented)), but it's not
	 * on 1G and higher.
	 */
	if ((sc->link_speed != IXGBE_LINK_SPEED_100_FULL)
	    && (sc->link_speed != IXGBE_LINK_SPEED_10_FULL))
		if (newitr < IXGBE_MIN_RSC_EITR_10G1G)
			newitr = IXGBE_MIN_RSC_EITR_10G1G;

	/* save for next interrupt */
	que->eitr_setting = newitr;

	/* Reset state */
	txr->bytes = 0;
	txr->packets = 0;
	rxr->bytes = 0;
	rxr->packets = 0;

no_calc:
	ixgbe_sched_handle_que(sc, que);

	return 1;
} /* ixgbe_msix_que */

/************************************************************************
 * ixgbe_media_status - Media Ioctl callback
 *
 *   Called whenever the user queries the status of
 *   the interface using ifconfig.
 ************************************************************************/
static void
ixgbe_media_status(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct ixgbe_softc *sc = ifp->if_softc;
	struct ixgbe_hw *hw = &sc->hw;
	int layer;

	INIT_DEBUGOUT("ixgbe_media_status: begin");
	ixgbe_update_link_status(sc);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (sc->link_active != LINK_STATE_UP) {
		ifmr->ifm_active |= IFM_NONE;
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;
	layer = sc->phy_layer;

	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_5GBASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_2500BASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_1000BASE_T ||
	    layer & IXGBE_PHYSICAL_LAYER_100BASE_TX ||
	    layer & IXGBE_PHYSICAL_LAYER_10BASE_T)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_5GB_FULL:
			ifmr->ifm_active |= IFM_5000_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_100_FULL:
			ifmr->ifm_active |= IFM_100_TX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_10_FULL:
			ifmr->ifm_active |= IFM_10_T | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU ||
	    layer & IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_TWINAX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LR)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_LR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_LX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_LRM)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_LRM | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_LX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_SR ||
	    layer & IXGBE_PHYSICAL_LAYER_1000BASE_SX)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_SR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_SX | IFM_FDX;
			break;
		}
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_CX4)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_CX4 | IFM_FDX;
			break;
		}
	/*
	 * XXX: These need to use the proper media types once
	 * they're added.
	 */
	if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KR)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_KR | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_KX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_KX | IFM_FDX;
			break;
		}
	else if (layer & IXGBE_PHYSICAL_LAYER_10GBASE_KX4 ||
	    layer & IXGBE_PHYSICAL_LAYER_2500BASE_KX ||
	    layer & IXGBE_PHYSICAL_LAYER_1000BASE_KX)
		switch (sc->link_speed) {
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_KX4 | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_2_5GB_FULL:
			ifmr->ifm_active |= IFM_2500_KX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_KX | IFM_FDX;
			break;
		}

	/* If nothing is recognized... */
#if 0
	if (IFM_SUBTYPE(ifmr->ifm_active) == 0)
		ifmr->ifm_active |= IFM_UNKNOWN;
#endif

	ifp->if_baudrate = ifmedia_baudrate(ifmr->ifm_active);

	/* Display current flow control setting used on link */
	if (hw->fc.current_mode == ixgbe_fc_rx_pause ||
	    hw->fc.current_mode == ixgbe_fc_full)
		ifmr->ifm_active |= IFM_ETH_RXPAUSE;
	if (hw->fc.current_mode == ixgbe_fc_tx_pause ||
	    hw->fc.current_mode == ixgbe_fc_full)
		ifmr->ifm_active |= IFM_ETH_TXPAUSE;

	return;
} /* ixgbe_media_status */

/************************************************************************
 * ixgbe_media_change - Media Ioctl callback
 *
 *   Called when the user changes speed/duplex using
 *   media/mediopt option with ifconfig.
 ************************************************************************/
static int
ixgbe_media_change(struct ifnet *ifp)
{
	struct ixgbe_softc *sc = ifp->if_softc;
	struct ifmedia	 *ifm = &sc->media;
	struct ixgbe_hw	 *hw = &sc->hw;
	ixgbe_link_speed speed = 0;
	ixgbe_link_speed link_caps = 0;
	bool negotiate = false;
	s32 err = IXGBE_NOT_IMPLEMENTED;

	INIT_DEBUGOUT("ixgbe_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	if (hw->phy.media_type == ixgbe_media_type_backplane)
		return (EPERM);

	/*
	 * We don't actually need to check against the supported
	 * media types of the adapter; ifmedia will take care of
	 * that for us.
	 */
	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		err = hw->mac.ops.get_link_capabilities(hw, &link_caps,
		    &negotiate);
		if (err != IXGBE_SUCCESS) {
			device_printf(sc->dev, "Unable to determine "
			    "supported advertise speeds\n");
			return (ENODEV);
		}
		speed |= link_caps;
		break;
	case IFM_10G_T:
	case IFM_10G_LRM:
	case IFM_10G_LR:
	case IFM_10G_TWINAX:
	case IFM_10G_SR:
	case IFM_10G_CX4:
	case IFM_10G_KR:
	case IFM_10G_KX4:
		speed |= IXGBE_LINK_SPEED_10GB_FULL;
		break;
	case IFM_5000_T:
		speed |= IXGBE_LINK_SPEED_5GB_FULL;
		break;
	case IFM_2500_T:
	case IFM_2500_KX:
		speed |= IXGBE_LINK_SPEED_2_5GB_FULL;
		break;
	case IFM_1000_T:
	case IFM_1000_LX:
	case IFM_1000_SX:
	case IFM_1000_KX:
		speed |= IXGBE_LINK_SPEED_1GB_FULL;
		break;
	case IFM_100_TX:
		speed |= IXGBE_LINK_SPEED_100_FULL;
		break;
	case IFM_10_T:
		speed |= IXGBE_LINK_SPEED_10_FULL;
		break;
	case IFM_NONE:
		break;
	default:
		goto invalid;
	}

	hw->mac.autotry_restart = TRUE;
	hw->mac.ops.setup_link(hw, speed, TRUE);
	sc->advertise = 0;
	if (IFM_SUBTYPE(ifm->ifm_media) != IFM_AUTO) {
		if ((speed & IXGBE_LINK_SPEED_10GB_FULL) != 0)
			sc->advertise |= 1 << 2;
		if ((speed & IXGBE_LINK_SPEED_1GB_FULL) != 0)
			sc->advertise |= 1 << 1;
		if ((speed & IXGBE_LINK_SPEED_100_FULL) != 0)
			sc->advertise |= 1 << 0;
		if ((speed & IXGBE_LINK_SPEED_10_FULL) != 0)
			sc->advertise |= 1 << 3;
		if ((speed & IXGBE_LINK_SPEED_2_5GB_FULL) != 0)
			sc->advertise |= 1 << 4;
		if ((speed & IXGBE_LINK_SPEED_5GB_FULL) != 0)
			sc->advertise |= 1 << 5;
	}

	return (0);

invalid:
	device_printf(sc->dev, "Invalid media type!\n");

	return (EINVAL);
} /* ixgbe_media_change */

/************************************************************************
 * ixgbe_msix_admin - Link status change ISR (MSI-X)
 ************************************************************************/
static int
ixgbe_msix_admin(void *arg)
{
	struct ixgbe_softc *sc = arg;
	struct ixgbe_hw *hw = &sc->hw;
	u32		eicr;
	u32		eims_orig;
	u32		eims_disable = 0;

	IXGBE_EVC_ADD(&sc->admin_irqev, 1);

	eims_orig = IXGBE_READ_REG(hw, IXGBE_EIMS);
	/* Pause other interrupts */
	IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_MSIX_OTHER_CLEAR_MASK);

	/*
	 * First get the cause.
	 *
	 * The specifications of 82598, 82599, X540 and X550 say EICS register
	 * is write only. However, Linux says it is a workaround for silicon
	 * errata to read EICS instead of EICR to get interrupt cause.
	 * At least, reading EICR clears lower 16bits of EIMS on 82598.
	 */
	eicr = IXGBE_READ_REG(hw, IXGBE_EICS);
	/* Be sure the queue bits are not cleared */
	eicr &= ~IXGBE_EICR_RTX_QUEUE;
	/* Clear all OTHER interrupts with write */
	IXGBE_WRITE_REG(hw, IXGBE_EICR, eicr);

	ixgbe_intr_admin_common(sc, eicr, &eims_disable);

	/* Re-enable some OTHER interrupts */
	IXGBE_WRITE_REG(hw, IXGBE_EIMS, eims_orig & ~eims_disable);

	return 1;
} /* ixgbe_msix_admin */

static void
ixgbe_intr_admin_common(struct ixgbe_softc *sc, u32 eicr, u32 *eims_disable)
{
	struct ixgbe_hw *hw = &sc->hw;
	u32		task_requests = 0;
	s32		retval;

	/* Link status change */
	if (eicr & IXGBE_EICR_LSC) {
		task_requests |= IXGBE_REQUEST_TASK_LSC;
		*eims_disable |= IXGBE_EIMS_LSC;
	}

	if (ixgbe_is_sfp(hw)) {
		u32 eicr_mask;

		/* Pluggable optics-related interrupt */
		if (hw->mac.type >= ixgbe_mac_X540)
			eicr_mask = IXGBE_EICR_GPI_SDP0_X540;
		else
			eicr_mask = IXGBE_EICR_GPI_SDP2_BY_MAC(hw);

		/*
		 *  An interrupt might not arrive when a module is inserted.
		 * When an link status change interrupt occurred and the driver
		 * still regard SFP as unplugged, issue the module softint
		 * and then issue LSC interrupt.
		 */
		if ((eicr & eicr_mask)
		    || ((hw->phy.sfp_type == ixgbe_sfp_type_not_present)
			&& (eicr & IXGBE_EICR_LSC))) {
			task_requests |= IXGBE_REQUEST_TASK_MOD;
			*eims_disable |= IXGBE_EIMS_LSC;
		}

		if ((hw->mac.type == ixgbe_mac_82599EB) &&
		    (eicr & IXGBE_EICR_GPI_SDP1_BY_MAC(hw))) {
			task_requests |= IXGBE_REQUEST_TASK_MSF;
			*eims_disable |= IXGBE_EIMS_GPI_SDP1_BY_MAC(hw);
		}
	}

	if (sc->hw.mac.type != ixgbe_mac_82598EB) {
#ifdef IXGBE_FDIR
		if ((sc->feat_en & IXGBE_FEATURE_FDIR) &&
		    (eicr & IXGBE_EICR_FLOW_DIR)) {
			if (!atomic_cas_uint(&sc->fdir_reinit, 0, 1)) {
				task_requests |= IXGBE_REQUEST_TASK_FDIR;
				/* Disable the interrupt */
				*eims_disable |= IXGBE_EIMS_FLOW_DIR;
			}
		}
#endif

		if (eicr & IXGBE_EICR_ECC) {
			if (ratecheck(&sc->lasterr_time,
			    &ixgbe_errlog_intrvl))
				device_printf(sc->dev,
				    "CRITICAL: ECC ERROR!! Please Reboot!!\n");
		}

		/* Check for over temp condition */
		if (sc->feat_en & IXGBE_FEATURE_TEMP_SENSOR) {
			switch (sc->hw.mac.type) {
			case ixgbe_mac_X550EM_a:
				if (!(eicr & IXGBE_EICR_GPI_SDP0_X550EM_a))
					break;
				retval = hw->phy.ops.check_overtemp(hw);
				if (retval != IXGBE_ERR_OVERTEMP)
					break;
				if (ratecheck(&sc->lasterr_time,
				    &ixgbe_errlog_intrvl)) {
					device_printf(sc->dev,
					    "CRITICAL: OVER TEMP!! "
					    "PHY IS SHUT DOWN!!\n");
					device_printf(sc->dev,
					    "System shutdown required!\n");
				}
				break;
			default:
				if (!(eicr & IXGBE_EICR_TS))
					break;
				retval = hw->phy.ops.check_overtemp(hw);
				if (retval != IXGBE_ERR_OVERTEMP)
					break;
				if (ratecheck(&sc->lasterr_time,
				    &ixgbe_errlog_intrvl)) {
					device_printf(sc->dev,
					    "CRITICAL: OVER TEMP!! "
					    "PHY IS SHUT DOWN!!\n");
					device_printf(sc->dev,
					    "System shutdown required!\n");
				}
				break;
			}
		}

		/* Check for VF message */
		if ((sc->feat_en & IXGBE_FEATURE_SRIOV) &&
		    (eicr & IXGBE_EICR_MAILBOX)) {
			task_requests |= IXGBE_REQUEST_TASK_MBX;
			*eims_disable |= IXGBE_EIMS_MAILBOX;
		}
	}

	/* Check for fan failure */
	if (sc->feat_en & IXGBE_FEATURE_FAN_FAIL)
		ixgbe_check_fan_failure(sc, eicr, true);

	/* External PHY interrupt */
	if ((hw->phy.type == ixgbe_phy_x550em_ext_t) &&
	    (eicr & IXGBE_EICR_GPI_SDP0_X540)) {
		task_requests |= IXGBE_REQUEST_TASK_PHY;
		*eims_disable |= IXGBE_EICR_GPI_SDP0_X540;
	}

	if (task_requests != 0) {
		mutex_enter(&sc->admin_mtx);
		sc->task_requests |= task_requests;
		ixgbe_schedule_admin_tasklet(sc);
		mutex_exit(&sc->admin_mtx);
	}
}

static void
ixgbe_eitr_write(struct ixgbe_softc *sc, uint32_t index, uint32_t itr)
{

	if (sc->hw.mac.type == ixgbe_mac_82598EB)
		itr |= itr << 16;
	else
		itr |= IXGBE_EITR_CNT_WDIS;

	IXGBE_WRITE_REG(&sc->hw, IXGBE_EITR(index), itr);
}


/************************************************************************
 * ixgbe_sysctl_interrupt_rate_handler
 ************************************************************************/
static int
ixgbe_sysctl_interrupt_rate_handler(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ix_queue *que = (struct ix_queue *)node.sysctl_data;
	struct ixgbe_softc *sc;
	uint32_t reg, usec, rate;
	int error;

	if (que == NULL)
		return 0;

	sc = que->sc;
	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	reg = IXGBE_READ_REG(&sc->hw, IXGBE_EITR(que->msix));
	usec = ((reg & 0x0FF8) >> 3);
	if (usec > 0)
		rate = 500000 / usec;
	else
		rate = 0;
	node.sysctl_data = &rate;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;
	reg &= ~0xfff; /* default, no limitation */
	if (rate > 0 && rate < 500000) {
		if (rate < 1000)
			rate = 1000;
		reg |= ((4000000 / rate) & 0xff8);
		/*
		 * When RSC is used, ITR interval must be larger than
		 * RSC_DELAY. Currently, we use 2us for RSC_DELAY.
		 * The minimum value is always greater than 2us on 100M
		 * (and 10M?(not documented)), but it's not on 1G and higher.
		 */
		if ((sc->link_speed != IXGBE_LINK_SPEED_100_FULL)
		    && (sc->link_speed != IXGBE_LINK_SPEED_10_FULL)) {
			if ((sc->num_queues > 1)
			    && (reg < IXGBE_MIN_RSC_EITR_10G1G))
				return EINVAL;
		}
		sc->max_interrupt_rate = rate;
	} else
		sc->max_interrupt_rate = 0;
	ixgbe_eitr_write(sc, que->msix, reg);

	return (0);
} /* ixgbe_sysctl_interrupt_rate_handler */

const struct sysctlnode *
ixgbe_sysctl_instance(struct ixgbe_softc *sc)
{
	const char *dvname;
	struct sysctllog **log;
	int rc;
	const struct sysctlnode *rnode;

	if (sc->sysctltop != NULL)
		return sc->sysctltop;

	log = &sc->sysctllog;
	dvname = device_xname(sc->dev);

	if ((rc = sysctl_createv(log, 0, NULL, &rnode,
	    0, CTLTYPE_NODE, dvname,
	    SYSCTL_DESCR("ixgbe information and settings"),
	    NULL, 0, NULL, 0, CTL_HW, CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	return rnode;
err:
	device_printf(sc->dev,
	    "%s: sysctl_createv failed, rc = %d\n", __func__, rc);
	return NULL;
}

/************************************************************************
 * ixgbe_add_device_sysctls
 ************************************************************************/
static void
ixgbe_add_device_sysctls(struct ixgbe_softc *sc)
{
	device_t	       dev = sc->dev;
	struct ixgbe_hw	       *hw = &sc->hw;
	struct sysctllog **log;
	const struct sysctlnode *rnode, *cnode;

	log = &sc->sysctllog;

	if ((rnode = ixgbe_sysctl_instance(sc)) == NULL) {
		aprint_error_dev(dev, "could not create sysctl root\n");
		return;
	}

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "debug", SYSCTL_DESCR("Debug Info"),
	    ixgbe_sysctl_debug, 0, (void *)sc, 0, CTL_CREATE, CTL_EOL)
	    != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "rx_copy_len", SYSCTL_DESCR("RX Copy Length"),
	    ixgbe_sysctl_rx_copy_len, 0,
	    (void *)sc, 0, CTL_CREATE, CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READONLY, CTLTYPE_INT,
	    "num_tx_desc", SYSCTL_DESCR("Number of TX descriptors"),
	    NULL, 0, &sc->num_tx_desc, 0, CTL_CREATE, CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READONLY, CTLTYPE_INT,
	    "num_rx_desc", SYSCTL_DESCR("Number of RX descriptors"),
	    NULL, 0, &sc->num_rx_desc, 0, CTL_CREATE, CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT, "rx_process_limit",
	    SYSCTL_DESCR("max number of RX packets to process"),
	    ixgbe_sysctl_rx_process_limit, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT, "tx_process_limit",
	    SYSCTL_DESCR("max number of TX packets to process"),
	    ixgbe_sysctl_tx_process_limit, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READONLY, CTLTYPE_INT,
	    "num_queues", SYSCTL_DESCR("Number of queues"),
	    NULL, 0, &sc->num_queues, 0, CTL_CREATE, CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	/* Sysctls for all devices */
	if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_INT, "fc", SYSCTL_DESCR(IXGBE_SYSCTL_DESC_SET_FC),
	    ixgbe_sysctl_flowcntl, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	sc->enable_aim = ixgbe_enable_aim;
	sc->max_interrupt_rate = ixgbe_max_interrupt_rate;
	if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_BOOL, "enable_aim", SYSCTL_DESCR("Interrupt Moderation"),
	    NULL, 0, &sc->enable_aim, 0, CTL_CREATE, CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "advertise_speed", SYSCTL_DESCR(IXGBE_SYSCTL_DESC_ADV_SPEED),
	    ixgbe_sysctl_advertise, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	/*
	 * If each "que->txrx_use_workqueue" is changed in sysctl handler,
	 * it causesflip-flopping softint/workqueue mode in one deferred
	 * processing. Therefore, preempt_disable()/preempt_enable() are
	 * required in ixgbe_sched_handle_que() to avoid
	 * KASSERT(ixgbe_sched_handle_que()) in softint_schedule().
	 * I think changing "que->txrx_use_workqueue" in interrupt handler
	 * is lighter than doing preempt_disable()/preempt_enable() in every
	 * ixgbe_sched_handle_que().
	 */
	sc->txrx_use_workqueue = ixgbe_txrx_workqueue;
	if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_BOOL, "txrx_workqueue",
	    SYSCTL_DESCR("Use workqueue for packet processing"),
	    NULL, 0, &sc->txrx_use_workqueue, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

#ifdef IXGBE_DEBUG
	/* testing sysctls (for all devices) */
	if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
	    CTLTYPE_INT, "power_state", SYSCTL_DESCR("PCI Power State"),
	    ixgbe_sysctl_power_state, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");

	if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READONLY,
	    CTLTYPE_STRING, "print_rss_config",
	    SYSCTL_DESCR("Prints RSS Configuration"),
	    ixgbe_sysctl_print_rss_config, 0, (void *)sc, 0, CTL_CREATE,
	    CTL_EOL) != 0)
		aprint_error_dev(dev, "could not create sysctl\n");
#endif
	/* for X550 series devices */
	if (hw->mac.type >= ixgbe_mac_X550)
		if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
		    CTLTYPE_INT, "dmac", SYSCTL_DESCR("DMA Coalesce"),
		    ixgbe_sysctl_dmac, 0, (void *)sc, 0, CTL_CREATE,
		    CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");

	/* for WoL-capable devices */
	if (sc->wol_support) {
		if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
		    CTLTYPE_BOOL, "wol_enable",
		    SYSCTL_DESCR("Enable/Disable Wake on LAN"),
		    ixgbe_sysctl_wol_enable, 0, (void *)sc, 0, CTL_CREATE,
		    CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");

		if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
		    CTLTYPE_INT, "wufc",
		    SYSCTL_DESCR("Enable/Disable Wake Up Filters"),
		    ixgbe_sysctl_wufc, 0, (void *)sc, 0, CTL_CREATE,
		    CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");
	}

	/* for X552/X557-AT devices */
	if ((hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T) ||
	    (hw->device_id == IXGBE_DEV_ID_X550EM_A_10G_T)) {
		const struct sysctlnode *phy_node;

		if (sysctl_createv(log, 0, &rnode, &phy_node, 0, CTLTYPE_NODE,
		    "phy", SYSCTL_DESCR("External PHY sysctls"),
		    NULL, 0, NULL, 0, CTL_CREATE, CTL_EOL) != 0) {
			aprint_error_dev(dev, "could not create sysctl\n");
			return;
		}

		if (sysctl_createv(log, 0, &phy_node, &cnode, CTLFLAG_READONLY,
		    CTLTYPE_INT, "temp",
		    SYSCTL_DESCR("Current External PHY Temperature (Celsius)"),
		    ixgbe_sysctl_phy_temp, 0, (void *)sc, 0, CTL_CREATE,
		    CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");

		if (sysctl_createv(log, 0, &phy_node, &cnode, CTLFLAG_READONLY,
		    CTLTYPE_INT, "overtemp_occurred",
		    SYSCTL_DESCR(
			    "External PHY High Temperature Event Occurred"),
		    ixgbe_sysctl_phy_overtemp_occurred, 0, (void *)sc, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");
	}

	if ((hw->mac.type == ixgbe_mac_X550EM_a)
	    && (hw->phy.type == ixgbe_phy_fw))
		if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
		    CTLTYPE_BOOL, "force_10_100_autonego",
		    SYSCTL_DESCR("Force autonego on 10M and 100M"),
		    NULL, 0, &hw->phy.force_10_100_autonego, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");

	if (sc->feat_cap & IXGBE_FEATURE_EEE) {
		if (sysctl_createv(log, 0, &rnode, &cnode, CTLFLAG_READWRITE,
		    CTLTYPE_INT, "eee_state",
		    SYSCTL_DESCR("EEE Power Save State"),
		    ixgbe_sysctl_eee_state, 0, (void *)sc, 0, CTL_CREATE,
		    CTL_EOL) != 0)
			aprint_error_dev(dev, "could not create sysctl\n");
	}
} /* ixgbe_add_device_sysctls */

/************************************************************************
 * ixgbe_allocate_pci_resources
 ************************************************************************/
static int
ixgbe_allocate_pci_resources(struct ixgbe_softc *sc,
    const struct pci_attach_args *pa)
{
	pcireg_t memtype, csr;
	device_t dev = sc->dev;
	bus_addr_t addr;
	int flags;

	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_BAR(0));
	switch (memtype) {
	case PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_32BIT:
	case PCI_MAPREG_TYPE_MEM | PCI_MAPREG_MEM_TYPE_64BIT:
		sc->osdep.mem_bus_space_tag = pa->pa_memt;
		if (pci_mapreg_info(pa->pa_pc, pa->pa_tag, PCI_BAR(0),
		      memtype, &addr, &sc->osdep.mem_size, &flags) != 0)
			goto map_err;
		if ((flags & BUS_SPACE_MAP_PREFETCHABLE) != 0) {
			aprint_normal_dev(dev, "clearing prefetchable bit\n");
			flags &= ~BUS_SPACE_MAP_PREFETCHABLE;
		}
		if (bus_space_map(sc->osdep.mem_bus_space_tag, addr,
		     sc->osdep.mem_size, flags,
		     &sc->osdep.mem_bus_space_handle) != 0) {
map_err:
			sc->osdep.mem_size = 0;
			aprint_error_dev(dev, "unable to map BAR0\n");
			return ENXIO;
		}
		/*
		 * Enable address decoding for memory range in case BIOS or
		 * UEFI don't set it.
		 */
		csr = pci_conf_read(pa->pa_pc, pa->pa_tag,
		    PCI_COMMAND_STATUS_REG);
		csr |= PCI_COMMAND_MEM_ENABLE;
		pci_conf_write(pa->pa_pc, pa->pa_tag, PCI_COMMAND_STATUS_REG,
		    csr);
		break;
	default:
		aprint_error_dev(dev, "unexpected type on BAR0\n");
		return ENXIO;
	}

	return (0);
} /* ixgbe_allocate_pci_resources */

static void
ixgbe_free_deferred_handlers(struct ixgbe_softc *sc)
{
	struct ix_queue *que = sc->queues;
	struct tx_ring *txr = sc->tx_rings;
	int i;

	for (i = 0; i < sc->num_queues; i++, que++, txr++) {
		if (!(sc->feat_en & IXGBE_FEATURE_LEGACY_TX)) {
			if (txr->txr_si != NULL)
				softint_disestablish(txr->txr_si);
		}
		if (que->que_si != NULL)
			softint_disestablish(que->que_si);
	}
	if (sc->txr_wq != NULL)
		workqueue_destroy(sc->txr_wq);
	if (sc->txr_wq_enqueued != NULL)
		percpu_free(sc->txr_wq_enqueued, sizeof(u_int));
	if (sc->que_wq != NULL)
		workqueue_destroy(sc->que_wq);

	if (sc->admin_wq != NULL) {
		workqueue_destroy(sc->admin_wq);
		sc->admin_wq = NULL;
	}
	if (sc->timer_wq != NULL) {
		workqueue_destroy(sc->timer_wq);
		sc->timer_wq = NULL;
	}
	if (sc->recovery_mode_timer_wq != NULL) {
		/*
		 * ixgbe_ifstop() doesn't call the workqueue_wait() for
		 * the recovery_mode_timer workqueue, so call it here.
		 */
		workqueue_wait(sc->recovery_mode_timer_wq,
		    &sc->recovery_mode_timer_wc);
		atomic_store_relaxed(&sc->recovery_mode_timer_pending, 0);
		workqueue_destroy(sc->recovery_mode_timer_wq);
		sc->recovery_mode_timer_wq = NULL;
	}
} /* ixgbe_free_deferred_handlers */

/************************************************************************
 * ixgbe_detach - Device removal routine
 *
 *   Called when the driver is being removed.
 *   Stops the adapter and deallocates all the resources
 *   that were allocated for driver operation.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static int
ixgbe_detach(device_t dev, int flags)
{
	struct ixgbe_softc *sc = device_private(dev);
	struct rx_ring *rxr = sc->rx_rings;
	struct tx_ring *txr = sc->tx_rings;
	struct ixgbe_hw *hw = &sc->hw;
	struct ixgbe_hw_stats *stats = &sc->stats.pf;
	u32	ctrl_ext;
	int i;

	INIT_DEBUGOUT("ixgbe_detach: begin");
	if (sc->osdep.attached == false)
		return 0;

	if (ixgbe_pci_iov_detach(dev) != 0) {
		device_printf(dev, "SR-IOV in use; detach first.\n");
		return (EBUSY);
	}

	if (VLAN_ATTACHED(&sc->osdep.ec) &&
	    (flags & (DETACH_SHUTDOWN | DETACH_FORCE)) == 0) {
		aprint_error_dev(dev, "VLANs in use, detach first\n");
		return (EBUSY);
	}

	ether_ifdetach(sc->ifp);

	sc->osdep.detaching = true;
	/*
	 * Stop the interface. ixgbe_setup_low_power_mode() calls
	 * ixgbe_ifstop(), so it's not required to call ixgbe_ifstop()
	 * directly.
	 */
	ixgbe_setup_low_power_mode(sc);

	callout_halt(&sc->timer, NULL);
	if (sc->feat_en & IXGBE_FEATURE_RECOVERY_MODE)
		callout_halt(&sc->recovery_mode_timer, NULL);

	workqueue_wait(sc->admin_wq, &sc->admin_wc);
	atomic_store_relaxed(&sc->admin_pending, 0);
	workqueue_wait(sc->timer_wq, &sc->timer_wc);
	atomic_store_relaxed(&sc->timer_pending, 0);

	pmf_device_deregister(dev);

	ixgbe_free_deferred_handlers(sc);

	/* let hardware know driver is unloading */
	ctrl_ext = IXGBE_READ_REG(&sc->hw, IXGBE_CTRL_EXT);
	ctrl_ext &= ~IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(&sc->hw, IXGBE_CTRL_EXT, ctrl_ext);

	if (sc->feat_en & IXGBE_FEATURE_NETMAP)
		netmap_detach(sc->ifp);

	ixgbe_free_pci_resources(sc);
#if 0	/* XXX the NetBSD port is probably missing something here */
	bus_generic_detach(dev);
#endif
	if_detach(sc->ifp);
	ifmedia_fini(&sc->media);
	if_percpuq_destroy(sc->ipq);

	sysctl_teardown(&sc->sysctllog);
	evcnt_detach(&sc->efbig_tx_dma_setup);
	evcnt_detach(&sc->mbuf_defrag_failed);
	evcnt_detach(&sc->efbig2_tx_dma_setup);
	evcnt_detach(&sc->einval_tx_dma_setup);
	evcnt_detach(&sc->other_tx_dma_setup);
	evcnt_detach(&sc->eagain_tx_dma_setup);
	evcnt_detach(&sc->enomem_tx_dma_setup);
	evcnt_detach(&sc->watchdog_events);
	evcnt_detach(&sc->tso_err);
	evcnt_detach(&sc->admin_irqev);
	evcnt_detach(&sc->link_workev);
	evcnt_detach(&sc->mod_workev);
	evcnt_detach(&sc->msf_workev);
	evcnt_detach(&sc->phy_workev);

	for (i = 0; i < IXGBE_TC_COUNTER_NUM; i++) {
		if (i < __arraycount(stats->mpc)) {
			evcnt_detach(&stats->mpc[i]);
			if (hw->mac.type == ixgbe_mac_82598EB)
				evcnt_detach(&stats->rnbc[i]);
		}
		if (i < __arraycount(stats->pxontxc)) {
			evcnt_detach(&stats->pxontxc[i]);
			evcnt_detach(&stats->pxonrxc[i]);
			evcnt_detach(&stats->pxofftxc[i]);
			evcnt_detach(&stats->pxoffrxc[i]);
			if (hw->mac.type >= ixgbe_mac_82599EB)
				evcnt_detach(&stats->pxon2offc[i]);
		}
	}

	txr = sc->tx_rings;
	for (i = 0; i < sc->num_queues; i++, rxr++, txr++) {
		evcnt_detach(&sc->queues[i].irqs);
		evcnt_detach(&sc->queues[i].handleq);
		evcnt_detach(&sc->queues[i].req);
		evcnt_detach(&txr->total_packets);
#ifndef IXGBE_LEGACY_TX
		evcnt_detach(&txr->pcq_drops);
#endif
		evcnt_detach(&txr->no_desc_avail);
		evcnt_detach(&txr->tso_tx);

		if (i < __arraycount(stats->qprc)) {
			evcnt_detach(&stats->qprc[i]);
			evcnt_detach(&stats->qptc[i]);
			evcnt_detach(&stats->qbrc[i]);
			evcnt_detach(&stats->qbtc[i]);
			if (hw->mac.type >= ixgbe_mac_82599EB)
				evcnt_detach(&stats->qprdc[i]);
		}

		evcnt_detach(&rxr->rx_packets);
		evcnt_detach(&rxr->rx_bytes);
		evcnt_detach(&rxr->rx_copies);
		evcnt_detach(&rxr->no_mbuf);
		evcnt_detach(&rxr->rx_discarded);
	}
	evcnt_detach(&stats->ipcs);
	evcnt_detach(&stats->l4cs);
	evcnt_detach(&stats->ipcs_bad);
	evcnt_detach(&stats->l4cs_bad);
	evcnt_detach(&stats->intzero);
	evcnt_detach(&stats->legint);
	evcnt_detach(&stats->crcerrs);
	evcnt_detach(&stats->illerrc);
	evcnt_detach(&stats->errbc);
	evcnt_detach(&stats->mspdc);
	if (hw->mac.type >= ixgbe_mac_X550)
		evcnt_detach(&stats->mbsdc);
	evcnt_detach(&stats->mpctotal);
	evcnt_detach(&stats->mlfc);
	evcnt_detach(&stats->mrfc);
	if (hw->mac.type == ixgbe_mac_X550EM_a)
		evcnt_detach(&stats->link_dn_cnt);
	evcnt_detach(&stats->rlec);
	evcnt_detach(&stats->lxontxc);
	evcnt_detach(&stats->lxonrxc);
	evcnt_detach(&stats->lxofftxc);
	evcnt_detach(&stats->lxoffrxc);

	/* Packet Reception Stats */
	evcnt_detach(&stats->tor);
	evcnt_detach(&stats->gorc);
	evcnt_detach(&stats->tpr);
	evcnt_detach(&stats->gprc);
	evcnt_detach(&stats->mprc);
	evcnt_detach(&stats->bprc);
	evcnt_detach(&stats->prc64);
	evcnt_detach(&stats->prc127);
	evcnt_detach(&stats->prc255);
	evcnt_detach(&stats->prc511);
	evcnt_detach(&stats->prc1023);
	evcnt_detach(&stats->prc1522);
	evcnt_detach(&stats->ruc);
	evcnt_detach(&stats->rfc);
	evcnt_detach(&stats->roc);
	evcnt_detach(&stats->rjc);
	evcnt_detach(&stats->mngprc);
	evcnt_detach(&stats->mngpdc);
	evcnt_detach(&stats->xec);

	/* Packet Transmission Stats */
	evcnt_detach(&stats->gotc);
	evcnt_detach(&stats->tpt);
	evcnt_detach(&stats->gptc);
	evcnt_detach(&stats->bptc);
	evcnt_detach(&stats->mptc);
	evcnt_detach(&stats->mngptc);
	evcnt_detach(&stats->ptc64);
	evcnt_detach(&stats->ptc127);
	evcnt_detach(&stats->ptc255);
	evcnt_detach(&stats->ptc511);
	evcnt_detach(&stats->ptc1023);
	evcnt_detach(&stats->ptc1522);

	ixgbe_free_queues(sc);
	free(sc->mta, M_DEVBUF);

	mutex_destroy(&sc->admin_mtx); /* XXX appropriate order? */
	IXGBE_CORE_LOCK_DESTROY(sc);

	return (0);
} /* ixgbe_detach */

/************************************************************************
 * ixgbe_setup_low_power_mode - LPLU/WoL preparation
 *
 *   Prepare the adapter/port for LPLU and/or WoL
 ************************************************************************/
static int
ixgbe_setup_low_power_mode(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	device_t	dev = sc->dev;
	struct ifnet	*ifp = sc->ifp;
	s32		error = 0;

	/* Limit power management flow to X550EM baseT */
	if (hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T &&
	    hw->phy.ops.enter_lplu) {
		/* X550EM baseT adapters need a special LPLU flow */
		hw->phy.reset_disable = true;
		ixgbe_ifstop(ifp, 1);
		error = hw->phy.ops.enter_lplu(hw);
		if (error)
			device_printf(dev,
			    "Error entering LPLU: %d\n", error);
		hw->phy.reset_disable = false;
	} else {
		/* Just stop for other adapters */
		ixgbe_ifstop(ifp, 1);
	}

	IXGBE_CORE_LOCK(sc);

	if (!hw->wol_enabled) {
		ixgbe_set_phy_power(hw, FALSE);
		IXGBE_WRITE_REG(hw, IXGBE_WUFC, 0);
		IXGBE_WRITE_REG(hw, IXGBE_WUC, 0);
	} else {
		/* Turn off support for APM wakeup. (Using ACPI instead) */
		IXGBE_WRITE_REG(hw, IXGBE_GRC_BY_MAC(hw),
		    IXGBE_READ_REG(hw, IXGBE_GRC_BY_MAC(hw)) & ~(u32)2);

		/*
		 * Clear Wake Up Status register to prevent any previous wakeup
		 * events from waking us up immediately after we suspend.
		 */
		IXGBE_WRITE_REG(hw, IXGBE_WUS, 0xffffffff);

		/*
		 * Program the Wakeup Filter Control register with user filter
		 * settings
		 */
		IXGBE_WRITE_REG(hw, IXGBE_WUFC, sc->wufc);

		/* Enable wakeups and power management in Wakeup Control */
		IXGBE_WRITE_REG(hw, IXGBE_WUC,
		    IXGBE_WUC_WKEN | IXGBE_WUC_PME_EN);
	}

	IXGBE_CORE_UNLOCK(sc);

	return error;
} /* ixgbe_setup_low_power_mode */

/************************************************************************
 * ixgbe_shutdown - Shutdown entry point
 ************************************************************************/
#if 0 /* XXX NetBSD ought to register something like this through pmf(9) */
static int
ixgbe_shutdown(device_t dev)
{
	struct ixgbe_softc *sc = device_private(dev);
	int error = 0;

	INIT_DEBUGOUT("ixgbe_shutdown: begin");

	error = ixgbe_setup_low_power_mode(sc);

	return (error);
} /* ixgbe_shutdown */
#endif

/************************************************************************
 * ixgbe_suspend
 *
 *   From D0 to D3
 ************************************************************************/
static bool
ixgbe_suspend(device_t dev, const pmf_qual_t *qual)
{
	struct ixgbe_softc *sc = device_private(dev);
	int	       error = 0;

	INIT_DEBUGOUT("ixgbe_suspend: begin");

	error = ixgbe_setup_low_power_mode(sc);

	return (error);
} /* ixgbe_suspend */

/************************************************************************
 * ixgbe_resume
 *
 *   From D3 to D0
 ************************************************************************/
static bool
ixgbe_resume(device_t dev, const pmf_qual_t *qual)
{
	struct ixgbe_softc *sc = device_private(dev);
	struct ifnet	*ifp = sc->ifp;
	struct ixgbe_hw *hw = &sc->hw;
	u32		wus;

	INIT_DEBUGOUT("ixgbe_resume: begin");

	IXGBE_CORE_LOCK(sc);

	/* Read & clear WUS register */
	wus = IXGBE_READ_REG(hw, IXGBE_WUS);
	if (wus)
		device_printf(dev, "Woken up by (WUS): %#010x\n",
		    IXGBE_READ_REG(hw, IXGBE_WUS));
	IXGBE_WRITE_REG(hw, IXGBE_WUS, 0xffffffff);
	/* And clear WUFC until next low-power transition */
	IXGBE_WRITE_REG(hw, IXGBE_WUFC, 0);

	/*
	 * Required after D3->D0 transition;
	 * will re-advertise all previous advertised speeds
	 */
	if (ifp->if_flags & IFF_UP)
		ixgbe_init_locked(sc);

	IXGBE_CORE_UNLOCK(sc);

	return true;
} /* ixgbe_resume */

/*
 * Set the various hardware offload abilities.
 *
 * This takes the ifnet's if_capenable flags (e.g. set by the user using
 * ifconfig) and indicates to the OS via the ifnet's if_hwassist field what
 * mbuf offload flags the driver will understand.
 */
static void
ixgbe_set_if_hwassist(struct ixgbe_softc *sc)
{
	/* XXX */
}

/************************************************************************
 * ixgbe_init_locked - Init entry point
 *
 *   Used in two ways: It is used by the stack as an init
 *   entry point in network interface structure. It is also
 *   used by the driver as a hw/sw initialization routine to
 *   get to a consistent state.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static void
ixgbe_init_locked(struct ixgbe_softc *sc)
{
	struct ifnet   *ifp = sc->ifp;
	device_t	dev = sc->dev;
	struct ixgbe_hw *hw = &sc->hw;
	struct ix_queue *que;
	struct tx_ring	*txr;
	struct rx_ring	*rxr;
	u32		txdctl, mhadd;
	u32		rxdctl, rxctrl;
	u32		ctrl_ext;
	bool		unsupported_sfp = false;
	int		i, j, error;

	/* XXX check IFF_UP and IFF_RUNNING, power-saving state! */

	KASSERT(mutex_owned(&sc->core_mtx));
	INIT_DEBUGOUT("ixgbe_init_locked: begin");

	hw->need_unsupported_sfp_recovery = false;
	hw->adapter_stopped = FALSE;
	ixgbe_stop_adapter(hw);
	callout_stop(&sc->timer);
	if (sc->feat_en & IXGBE_FEATURE_RECOVERY_MODE)
		callout_stop(&sc->recovery_mode_timer);
	for (i = 0, que = sc->queues; i < sc->num_queues; i++, que++)
		que->disabled_count = 0;

	/* XXX I moved this here from the SIOCSIFMTU case in ixgbe_ioctl(). */
	sc->max_frame_size =
		ifp->if_mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;

	/* Queue indices may change with IOV mode */
	ixgbe_align_all_queue_indices(sc);

	/* reprogram the RAR[0] in case user changed it. */
	ixgbe_set_rar(hw, 0, hw->mac.addr, sc->pool, IXGBE_RAH_AV);

	/* Get the latest mac address, User can use a LAA */
	memcpy(hw->mac.addr, CLLADDR(ifp->if_sadl),
	    IXGBE_ETH_LENGTH_OF_ADDRESS);
	ixgbe_set_rar(hw, 0, hw->mac.addr, sc->pool, 1);
	hw->addr_ctrl.rar_used_count = 1;

	/* Set hardware offload abilities from ifnet flags */
	ixgbe_set_if_hwassist(sc);

	/* Prepare transmit descriptors and buffers */
	if (ixgbe_setup_transmit_structures(sc)) {
		device_printf(dev, "Could not setup transmit structures\n");
		ixgbe_stop_locked(sc);
		return;
	}

	ixgbe_init_hw(hw);

	ixgbe_initialize_iov(sc);

	ixgbe_initialize_transmit_units(sc);

	/* Setup Multicast table */
	ixgbe_set_rxfilter(sc);

	/* Use fixed buffer size, even for jumbo frames */
	sc->rx_mbuf_sz = MCLBYTES;

	/* Prepare receive descriptors and buffers */
	error = ixgbe_setup_receive_structures(sc);
	if (error) {
		device_printf(dev,
		    "Could not setup receive structures (err = %d)\n", error);
		ixgbe_stop_locked(sc);
		return;
	}

	/* Configure RX settings */
	ixgbe_initialize_receive_units(sc);

	/* Initialize variable holding task enqueue requests interrupts */
	sc->task_requests = 0;

	/* Enable SDP & MSI-X interrupts based on adapter */
	ixgbe_config_gpie(sc);

	/* Set MTU size */
	if (ifp->if_mtu > ETHERMTU) {
		/* aka IXGBE_MAXFRS on 82599 and newer */
		mhadd = IXGBE_READ_REG(hw, IXGBE_MHADD);
		mhadd &= ~IXGBE_MHADD_MFS_MASK;
		mhadd |= sc->max_frame_size << IXGBE_MHADD_MFS_SHIFT;
		IXGBE_WRITE_REG(hw, IXGBE_MHADD, mhadd);
	}

	/* Now enable all the queues */
	for (i = 0; i < sc->num_queues; i++) {
		txr = &sc->tx_rings[i];
		txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(txr->me));
		txdctl |= IXGBE_TXDCTL_ENABLE;
		/* Set WTHRESH to 8, burst writeback */
		txdctl &= ~IXGBE_TXDCTL_WTHRESH_MASK;
		txdctl |= IXGBE_TX_WTHRESH << IXGBE_TXDCTL_WTHRESH_SHIFT;
		/*
		 * When the internal queue falls below PTHRESH (32),
		 * start prefetching as long as there are at least
		 * HTHRESH (1) buffers ready. The values are taken
		 * from the Intel linux driver 3.8.21.
		 * Prefetching enables tx line rate even with 1 queue.
		 */
		txdctl |= (32 << 0) | (1 << 8);
		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(txr->me), txdctl);
	}

	for (i = 0; i < sc->num_queues; i++) {
		rxr = &sc->rx_rings[i];
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me));
		if (hw->mac.type == ixgbe_mac_82598EB) {
			/*
			 * PTHRESH = 21
			 * HTHRESH = 4
			 * WTHRESH = 8
			 */
			rxdctl &= ~0x3FFFFF;
			rxdctl |= 0x080420;
		}
		rxdctl |= IXGBE_RXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxr->me), rxdctl);
		for (j = 0; j < 10; j++) {
			if (IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxr->me)) &
			    IXGBE_RXDCTL_ENABLE)
				break;
			else
				msec_delay(1);
		}
		IXGBE_WRITE_BARRIER(hw);

		/*
		 * In netmap mode, we must preserve the buffers made
		 * available to userspace before the if_init()
		 * (this is true by default on the TX side, because
		 * init makes all buffers available to userspace).
		 *
		 * netmap_reset() and the device specific routines
		 * (e.g. ixgbe_setup_receive_rings()) map these
		 * buffers at the end of the NIC ring, so here we
		 * must set the RDT (tail) register to make sure
		 * they are not overwritten.
		 *
		 * In this driver the NIC ring starts at RDH = 0,
		 * RDT points to the last slot available for reception (?),
		 * so RDT = num_rx_desc - 1 means the whole ring is available.
		 */
#ifdef DEV_NETMAP
		if ((sc->feat_en & IXGBE_FEATURE_NETMAP) &&
		    (ifp->if_capenable & IFCAP_NETMAP)) {
			struct netmap_adapter *na = NA(sc->ifp);
			struct netmap_kring *kring = na->rx_rings[i];
			int t = na->num_rx_desc - 1 - nm_kr_rxspace(kring);

			IXGBE_WRITE_REG(hw, IXGBE_RDT(rxr->me), t);
		} else
#endif /* DEV_NETMAP */
			IXGBE_WRITE_REG(hw, IXGBE_RDT(rxr->me),
			    sc->num_rx_desc - 1);
	}

	/* Enable Receive engine */
	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	if (hw->mac.type == ixgbe_mac_82598EB)
		rxctrl |= IXGBE_RXCTRL_DMBYPS;
	rxctrl |= IXGBE_RXCTRL_RXEN;
	ixgbe_enable_rx_dma(hw, rxctrl);

	callout_reset(&sc->timer, hz, ixgbe_local_timer, sc);
	atomic_store_relaxed(&sc->timer_pending, 0);
	if (sc->feat_en & IXGBE_FEATURE_RECOVERY_MODE)
		callout_reset(&sc->recovery_mode_timer, hz,
		    ixgbe_recovery_mode_timer, sc);

	/* Set up MSI/MSI-X routing */
	if (sc->feat_en & IXGBE_FEATURE_MSIX) {
		ixgbe_configure_ivars(sc);
		/* Set up auto-mask */
		if (hw->mac.type == ixgbe_mac_82598EB)
			IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
		else {
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(0), 0xFFFFFFFF);
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(1), 0xFFFFFFFF);
		}
	} else {  /* Simple settings for Legacy/MSI */
		ixgbe_set_ivar(sc, 0, 0, 0);
		ixgbe_set_ivar(sc, 0, 0, 1);
		IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
	}

	ixgbe_init_fdir(sc);

	/*
	 * Check on any SFP devices that
	 * need to be kick-started
	 */
	if (hw->phy.type == ixgbe_phy_none) {
		error = hw->phy.ops.identify(hw);
		if (error == IXGBE_ERR_SFP_NOT_SUPPORTED)
			unsupported_sfp = true;
	} else if (hw->phy.type == ixgbe_phy_sfp_unsupported)
		unsupported_sfp = true;

	if (unsupported_sfp)
		device_printf(dev,
		    "Unsupported SFP+ module type was detected.\n");

	/* Set moderation on the Link interrupt */
	ixgbe_eitr_write(sc, sc->vector, IXGBE_LINK_ITR);

	/* Enable EEE power saving */
	if (sc->feat_cap & IXGBE_FEATURE_EEE)
		hw->mac.ops.setup_eee(hw,
		    sc->feat_en & IXGBE_FEATURE_EEE);

	/* Enable power to the phy. */
	if (!unsupported_sfp) {
		ixgbe_set_phy_power(hw, TRUE);

		/* Config/Enable Link */
		ixgbe_config_link(sc);
	}

	/* Hardware Packet Buffer & Flow Control setup */
	ixgbe_config_delay_values(sc);

	/* Initialize the FC settings */
	ixgbe_start_hw(hw);

	/* Set up VLAN support and filter */
	ixgbe_setup_vlan_hw_support(sc);

	/* Setup DMA Coalescing */
	ixgbe_config_dmac(sc);

	/* OK to schedule workqueues. */
	sc->schedule_wqs_ok = true;

	/* Enable the use of the MBX by the VF's */
	if (sc->feat_en & IXGBE_FEATURE_SRIOV) {
		ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
		ctrl_ext |= IXGBE_CTRL_EXT_PFRSTD;
		IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);
	}

	/* Update saved flags. See ixgbe_ifflags_cb() */
	sc->if_flags = ifp->if_flags;
	sc->ec_capenable = sc->osdep.ec.ec_capenable;

	/* Inform the stack we're ready */
	ifp->if_flags |= IFF_RUNNING;

	/* And now turn on interrupts */
	ixgbe_enable_intr(sc);

	return;
} /* ixgbe_init_locked */

/************************************************************************
 * ixgbe_init
 ************************************************************************/
static int
ixgbe_init(struct ifnet *ifp)
{
	struct ixgbe_softc *sc = ifp->if_softc;

	IXGBE_CORE_LOCK(sc);
	ixgbe_init_locked(sc);
	IXGBE_CORE_UNLOCK(sc);

	return 0;	/* XXX ixgbe_init_locked cannot fail?  really? */
} /* ixgbe_init */

/************************************************************************
 * ixgbe_set_ivar
 *
 *   Setup the correct IVAR register for a particular MSI-X interrupt
 *     (yes this is all very magic and confusing :)
 *    - entry is the register array entry
 *    - vector is the MSI-X vector for this queue
 *    - type is RX/TX/MISC
 ************************************************************************/
static void
ixgbe_set_ivar(struct ixgbe_softc *sc, u8 entry, u8 vector, s8 type)
{
	struct ixgbe_hw *hw = &sc->hw;
	u32 ivar, index;

	vector |= IXGBE_IVAR_ALLOC_VAL;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		if (type == -1)
			entry = IXGBE_IVAR_OTHER_CAUSES_INDEX;
		else
			entry += (type * 64);
		index = (entry >> 2) & 0x1F;
		ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(index));
		ivar &= ~(0xffUL << (8 * (entry & 0x3)));
		ivar |= ((u32)vector << (8 * (entry & 0x3)));
		IXGBE_WRITE_REG(&sc->hw, IXGBE_IVAR(index), ivar);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		if (type == -1) { /* MISC IVAR */
			index = (entry & 1) * 8;
			ivar = IXGBE_READ_REG(hw, IXGBE_IVAR_MISC);
			ivar &= ~(0xffUL << index);
			ivar |= ((u32)vector << index);
			IXGBE_WRITE_REG(hw, IXGBE_IVAR_MISC, ivar);
		} else {	/* RX/TX IVARS */
			index = (16 * (entry & 1)) + (8 * type);
			ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(entry >> 1));
			ivar &= ~(0xffUL << index);
			ivar |= ((u32)vector << index);
			IXGBE_WRITE_REG(hw, IXGBE_IVAR(entry >> 1), ivar);
		}
		break;
	default:
		break;
	}
} /* ixgbe_set_ivar */

/************************************************************************
 * ixgbe_configure_ivars
 ************************************************************************/
static void
ixgbe_configure_ivars(struct ixgbe_softc *sc)
{
	struct ix_queue *que = sc->queues;
	u32		newitr;

	if (sc->max_interrupt_rate > 0)
		newitr = (4000000 / sc->max_interrupt_rate) & 0x0FF8;
	else {
		/*
		 * Disable DMA coalescing if interrupt moderation is
		 * disabled.
		 */
		sc->dmac = 0;
		newitr = 0;
	}

	for (int i = 0; i < sc->num_queues; i++, que++) {
		struct rx_ring *rxr = &sc->rx_rings[i];
		struct tx_ring *txr = &sc->tx_rings[i];
		/* First the RX queue entry */
		ixgbe_set_ivar(sc, rxr->me, que->msix, 0);
		/* ... and the TX */
		ixgbe_set_ivar(sc, txr->me, que->msix, 1);
		/* Set an Initial EITR value */
		ixgbe_eitr_write(sc, que->msix, newitr);
		/*
		 * To eliminate influence of the previous state.
		 * At this point, Tx/Rx interrupt handler
		 * (ixgbe_msix_que()) cannot be called, so  both
		 * IXGBE_TX_LOCK and IXGBE_RX_LOCK are not required.
		 */
		que->eitr_setting = 0;
	}

	/* For the Link interrupt */
	ixgbe_set_ivar(sc, 1, sc->vector, -1);
} /* ixgbe_configure_ivars */

/************************************************************************
 * ixgbe_config_gpie
 ************************************************************************/
static void
ixgbe_config_gpie(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	u32		gpie;

	gpie = IXGBE_READ_REG(hw, IXGBE_GPIE);

	if (sc->feat_en & IXGBE_FEATURE_MSIX) {
		/* Enable Enhanced MSI-X mode */
		gpie |= IXGBE_GPIE_MSIX_MODE
		     |	IXGBE_GPIE_EIAME
		     |	IXGBE_GPIE_PBA_SUPPORT
		     |	IXGBE_GPIE_OCD;
	}

	/* Fan Failure Interrupt */
	if (sc->feat_en & IXGBE_FEATURE_FAN_FAIL)
		gpie |= IXGBE_SDP1_GPIEN;

	/* Thermal Sensor Interrupt */
	if (sc->feat_en & IXGBE_FEATURE_TEMP_SENSOR)
		gpie |= IXGBE_SDP0_GPIEN_X540;

	/* Link detection */
	switch (hw->mac.type) {
	case ixgbe_mac_82599EB:
		gpie |= IXGBE_SDP1_GPIEN | IXGBE_SDP2_GPIEN;
		break;
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		gpie |= IXGBE_SDP0_GPIEN_X540;
		break;
	default:
		break;
	}

	IXGBE_WRITE_REG(hw, IXGBE_GPIE, gpie);

} /* ixgbe_config_gpie */

/************************************************************************
 * ixgbe_config_delay_values
 *
 *   Requires sc->max_frame_size to be set.
 ************************************************************************/
static void
ixgbe_config_delay_values(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	u32		rxpb, frame, size, tmp;

	frame = sc->max_frame_size;

	/* Calculate High Water */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		tmp = IXGBE_DV_X540(frame, frame);
		break;
	default:
		tmp = IXGBE_DV(frame, frame);
		break;
	}
	size = IXGBE_BT2KB(tmp);
	rxpb = IXGBE_READ_REG(hw, IXGBE_RXPBSIZE(0)) >> 10;
	hw->fc.high_water[0] = rxpb - size;

	/* Now calculate Low Water */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		tmp = IXGBE_LOW_DV_X540(frame);
		break;
	default:
		tmp = IXGBE_LOW_DV(frame);
		break;
	}
	hw->fc.low_water[0] = IXGBE_BT2KB(tmp);

	hw->fc.pause_time = IXGBE_FC_PAUSE;
	hw->fc.send_xon = TRUE;
} /* ixgbe_config_delay_values */

/************************************************************************
 * ixgbe_set_rxfilter - Multicast Update
 *
 *   Called whenever multicast address list is updated.
 ************************************************************************/
static void
ixgbe_set_rxfilter(struct ixgbe_softc *sc)
{
	struct ixgbe_mc_addr	*mta;
	struct ifnet		*ifp = sc->ifp;
	u8			*update_ptr;
	int			mcnt = 0;
	u32			fctrl;
	struct ethercom		*ec = &sc->osdep.ec;
	struct ether_multi	*enm;
	struct ether_multistep	step;

	KASSERT(mutex_owned(&sc->core_mtx));
	IOCTL_DEBUGOUT("ixgbe_set_rxfilter: begin");

	mta = sc->mta;
	bzero(mta, sizeof(*mta) * MAX_NUM_MULTICAST_ADDRESSES);

	ETHER_LOCK(ec);
	ec->ec_flags &= ~ETHER_F_ALLMULTI;
	ETHER_FIRST_MULTI(step, ec, enm);
	while (enm != NULL) {
		if ((mcnt == MAX_NUM_MULTICAST_ADDRESSES) ||
		    (memcmp(enm->enm_addrlo, enm->enm_addrhi,
			ETHER_ADDR_LEN) != 0)) {
			ec->ec_flags |= ETHER_F_ALLMULTI;
			break;
		}
		bcopy(enm->enm_addrlo,
		    mta[mcnt].addr, IXGBE_ETH_LENGTH_OF_ADDRESS);
		mta[mcnt].vmdq = sc->pool;
		mcnt++;
		ETHER_NEXT_MULTI(step, enm);
	}

	fctrl = IXGBE_READ_REG(&sc->hw, IXGBE_FCTRL);
	if (ifp->if_flags & IFF_PROMISC)
		fctrl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
	else if (ec->ec_flags & ETHER_F_ALLMULTI) {
		fctrl |= IXGBE_FCTRL_MPE;
		fctrl &= ~IXGBE_FCTRL_UPE;
	} else
		fctrl &= ~(IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);

	/* Update multicast filter entries only when it's not ALLMULTI */
	if ((ec->ec_flags & ETHER_F_ALLMULTI) == 0) {
		ETHER_UNLOCK(ec);
		update_ptr = (u8 *)mta;
		ixgbe_update_mc_addr_list(&sc->hw, update_ptr, mcnt,
		    ixgbe_mc_array_itr, TRUE);
	} else
		ETHER_UNLOCK(ec);

	IXGBE_WRITE_REG(&sc->hw, IXGBE_FCTRL, fctrl);
} /* ixgbe_set_rxfilter */

/************************************************************************
 * ixgbe_mc_array_itr
 *
 *   An iterator function needed by the multicast shared code.
 *   It feeds the shared code routine the addresses in the
 *   array of ixgbe_set_rxfilter() one by one.
 ************************************************************************/
static u8 *
ixgbe_mc_array_itr(struct ixgbe_hw *hw, u8 **update_ptr, u32 *vmdq)
{
	struct ixgbe_mc_addr *mta;

	mta = (struct ixgbe_mc_addr *)*update_ptr;
	*vmdq = mta->vmdq;

	*update_ptr = (u8*)(mta + 1);

	return (mta->addr);
} /* ixgbe_mc_array_itr */

/************************************************************************
 * ixgbe_local_timer - Timer routine
 *
 *   Checks for link status, updates statistics,
 *   and runs the watchdog check.
 ************************************************************************/
static void
ixgbe_local_timer(void *arg)
{
	struct ixgbe_softc *sc = arg;

	if (sc->schedule_wqs_ok) {
		if (atomic_cas_uint(&sc->timer_pending, 0, 1) == 0)
			workqueue_enqueue(sc->timer_wq,
			    &sc->timer_wc, NULL);
	}
}

static void
ixgbe_handle_timer(struct work *wk, void *context)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;
	device_t	dev = sc->dev;
	struct ix_queue	*que = sc->queues;
	u64		queues = 0;
	u64		v0, v1, v2, v3, v4, v5, v6, v7;
	int		hung = 0;
	int		i;

	IXGBE_CORE_LOCK(sc);

	/* Check for pluggable optics */
	if (ixgbe_is_sfp(hw)) {
		bool sched_mod_task = false;

		if (hw->mac.type == ixgbe_mac_82598EB) {
			/*
			 * On 82598EB, SFP+'s MOD_ABS pin is not connected to
			 * any GPIO(SDP). So just schedule TASK_MOD.
			 */
			sched_mod_task = true;
		} else {
			bool was_full, is_full;

			was_full =
			    hw->phy.sfp_type != ixgbe_sfp_type_not_present;
			is_full = ixgbe_sfp_cage_full(hw);

			/* Do probe if cage state changed */
			if (was_full ^ is_full)
				sched_mod_task = true;
		}
		if (sched_mod_task) {
			mutex_enter(&sc->admin_mtx);
			sc->task_requests |= IXGBE_REQUEST_TASK_MOD_WOI;
			ixgbe_schedule_admin_tasklet(sc);
			mutex_exit(&sc->admin_mtx);
		}
	}

	ixgbe_update_link_status(sc);
	ixgbe_update_stats_counters(sc);

	/* Update some event counters */
	v0 = v1 = v2 = v3 = v4 = v5 = v6 = v7 = 0;
	que = sc->queues;
	for (i = 0; i < sc->num_queues; i++, que++) {
		struct tx_ring	*txr = que->txr;

		v0 += txr->q_efbig_tx_dma_setup;
		v1 += txr->q_mbuf_defrag_failed;
		v2 += txr->q_efbig2_tx_dma_setup;
		v3 += txr->q_einval_tx_dma_setup;
		v4 += txr->q_other_tx_dma_setup;
		v5 += txr->q_eagain_tx_dma_setup;
		v6 += txr->q_enomem_tx_dma_setup;
		v7 += txr->q_tso_err;
	}
	IXGBE_EVC_STORE(&sc->efbig_tx_dma_setup, v0);
	IXGBE_EVC_STORE(&sc->mbuf_defrag_failed, v1);
	IXGBE_EVC_STORE(&sc->efbig2_tx_dma_setup, v2);
	IXGBE_EVC_STORE(&sc->einval_tx_dma_setup, v3);
	IXGBE_EVC_STORE(&sc->other_tx_dma_setup, v4);
	IXGBE_EVC_STORE(&sc->eagain_tx_dma_setup, v5);
	IXGBE_EVC_STORE(&sc->enomem_tx_dma_setup, v6);
	IXGBE_EVC_STORE(&sc->tso_err, v7);

	/*
	 * Check the TX queues status
	 *	- mark hung queues so we don't schedule on them
	 *	- watchdog only if all queues show hung
	 */
	que = sc->queues;
	for (i = 0; i < sc->num_queues; i++, que++) {
		/* Keep track of queues with work for soft irq */
		if (que->txr->busy)
			queues |= 1ULL << que->me;
		/*
		 * Each time txeof runs without cleaning, but there
		 * are uncleaned descriptors it increments busy. If
		 * we get to the MAX we declare it hung.
		 */
		if (que->busy == IXGBE_QUEUE_HUNG) {
			++hung;
			/* Mark the queue as inactive */
			sc->active_queues &= ~(1ULL << que->me);
			continue;
		} else {
			/* Check if we've come back from hung */
			if ((sc->active_queues & (1ULL << que->me)) == 0)
				sc->active_queues |= 1ULL << que->me;
		}
		if (que->busy >= IXGBE_MAX_TX_BUSY) {
			device_printf(dev,
			    "Warning queue %d appears to be hung!\n", i);
			que->txr->busy = IXGBE_QUEUE_HUNG;
			++hung;
		}
	}

	/* Only truly watchdog if all queues show hung */
	if (hung == sc->num_queues)
		goto watchdog;
#if 0 /* XXX Avoid unexpectedly disabling interrupt forever (PR#53294) */
	else if (queues != 0) { /* Force an IRQ on queues with work */
		que = sc->queues;
		for (i = 0; i < sc->num_queues; i++, que++) {
			mutex_enter(&que->dc_mtx);
			if (que->disabled_count == 0)
				ixgbe_rearm_queues(sc,
				    queues & ((u64)1 << i));
			mutex_exit(&que->dc_mtx);
		}
	}
#endif

	atomic_store_relaxed(&sc->timer_pending, 0);
	IXGBE_CORE_UNLOCK(sc);
	callout_reset(&sc->timer, hz, ixgbe_local_timer, sc);
	return;

watchdog:
	device_printf(sc->dev, "Watchdog timeout -- resetting\n");
	sc->ifp->if_flags &= ~IFF_RUNNING;
	IXGBE_EVC_ADD(&sc->watchdog_events, 1);
	ixgbe_init_locked(sc);
	IXGBE_CORE_UNLOCK(sc);
} /* ixgbe_handle_timer */

/************************************************************************
 * ixgbe_recovery_mode_timer - Recovery mode timer routine
 ************************************************************************/
static void
ixgbe_recovery_mode_timer(void *arg)
{
	struct ixgbe_softc *sc = arg;

	if (__predict_true(sc->osdep.detaching == false)) {
		if (atomic_cas_uint(&sc->recovery_mode_timer_pending,
			0, 1) == 0) {
			workqueue_enqueue(sc->recovery_mode_timer_wq,
			    &sc->recovery_mode_timer_wc, NULL);
		}
	}
}

static void
ixgbe_handle_recovery_mode_timer(struct work *wk, void *context)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;

	IXGBE_CORE_LOCK(sc);
	if (ixgbe_fw_recovery_mode(hw)) {
		if (atomic_cas_uint(&sc->recovery_mode, 0, 1) == 0) {
			/* Firmware error detected, entering recovery mode */
			device_printf(sc->dev,
			    "Firmware recovery mode detected. Limiting "
			    "functionality. Refer to the Intel(R) Ethernet "
			    "Adapters and Devices User Guide for details on "
			    "firmware recovery mode.\n");

			if (hw->adapter_stopped == FALSE)
				ixgbe_stop_locked(sc);
		}
	} else
		atomic_cas_uint(&sc->recovery_mode, 1, 0);

	atomic_store_relaxed(&sc->recovery_mode_timer_pending, 0);
	callout_reset(&sc->recovery_mode_timer, hz,
	    ixgbe_recovery_mode_timer, sc);
	IXGBE_CORE_UNLOCK(sc);
} /* ixgbe_handle_recovery_mode_timer */

/************************************************************************
 * ixgbe_handle_mod - Tasklet for SFP module interrupts
 * bool int_en: true if it's called when the interrupt is enabled.
 ************************************************************************/
static void
ixgbe_handle_mod(void *context, bool int_en)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;
	device_t	dev = sc->dev;
	enum ixgbe_sfp_type last_sfp_type;
	u32		err;
	bool		last_unsupported_sfp_recovery;

	KASSERT(mutex_owned(&sc->core_mtx));

	last_sfp_type = hw->phy.sfp_type;
	last_unsupported_sfp_recovery = hw->need_unsupported_sfp_recovery;
	IXGBE_EVC_ADD(&sc->mod_workev, 1);
	if (sc->hw.need_crosstalk_fix) {
		if ((hw->mac.type != ixgbe_mac_82598EB) &&
		    !ixgbe_sfp_cage_full(hw))
			goto out;
	}

	err = hw->phy.ops.identify_sfp(hw);
	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		if (last_unsupported_sfp_recovery == false)
			device_printf(dev,
			    "Unsupported SFP+ module type was detected.\n");
		goto out;
	}

	if (hw->need_unsupported_sfp_recovery) {
		device_printf(dev, "Recovering from unsupported SFP\n");
		/*
		 *  We could recover the status by calling setup_sfp(),
		 * setup_link() and some others. It's complex and might not
		 * work correctly on some unknown cases. To avoid such type of
		 * problem, call ixgbe_init_locked(). It's simple and safe
		 * approach.
		 */
		ixgbe_init_locked(sc);
	} else if ((hw->phy.sfp_type != ixgbe_sfp_type_not_present) &&
	    (hw->phy.sfp_type != last_sfp_type)) {
		/* A module is inserted and changed. */

		if (hw->mac.type == ixgbe_mac_82598EB)
			err = hw->phy.ops.reset(hw);
		else {
			err = hw->mac.ops.setup_sfp(hw);
			hw->phy.sfp_setup_needed = FALSE;
		}
		if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
			device_printf(dev,
			    "Setup failure - unsupported SFP+ module type.\n");
			goto out;
		}
	}

out:
	/* get_supported_phy_layer will call hw->phy.ops.identify_sfp() */
	sc->phy_layer = ixgbe_get_supported_physical_layer(hw);

	/* Adjust media types shown in ifconfig */
	IXGBE_CORE_UNLOCK(sc);
	ifmedia_removeall(&sc->media);
	ixgbe_add_media_types(sc);
	ifmedia_set(&sc->media, IFM_ETHER | IFM_AUTO);
	IXGBE_CORE_LOCK(sc);

	/*
	 * Don't schedule MSF event if the chip is 82598. 82598 doesn't support
	 * MSF. At least, calling ixgbe_handle_msf on 82598 DA makes the link
	 * flap because the function calls setup_link().
	 */
	if (hw->mac.type != ixgbe_mac_82598EB) {
		mutex_enter(&sc->admin_mtx);
		if (int_en)
			sc->task_requests |= IXGBE_REQUEST_TASK_MSF;
		else
			sc->task_requests |= IXGBE_REQUEST_TASK_MSF_WOI;
		mutex_exit(&sc->admin_mtx);
	}

	/*
	 * Don't call ixgbe_schedule_admin_tasklet() because we are on
	 * the workqueue now.
	 */
} /* ixgbe_handle_mod */


/************************************************************************
 * ixgbe_handle_msf - Tasklet for MSF (multispeed fiber) interrupts
 ************************************************************************/
static void
ixgbe_handle_msf(void *context)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;
	u32		autoneg;
	bool		negotiate;

	KASSERT(mutex_owned(&sc->core_mtx));

	IXGBE_EVC_ADD(&sc->msf_workev, 1);

	autoneg = hw->phy.autoneg_advertised;
	if ((!autoneg) && (hw->mac.ops.get_link_capabilities))
		hw->mac.ops.get_link_capabilities(hw, &autoneg, &negotiate);
	if (hw->mac.ops.setup_link)
		hw->mac.ops.setup_link(hw, autoneg, TRUE);
} /* ixgbe_handle_msf */

/************************************************************************
 * ixgbe_handle_phy - Tasklet for external PHY interrupts
 ************************************************************************/
static void
ixgbe_handle_phy(void *context)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;
	int error;

	KASSERT(mutex_owned(&sc->core_mtx));

	IXGBE_EVC_ADD(&sc->phy_workev, 1);
	error = hw->phy.ops.handle_lasi(hw);
	if (error == IXGBE_ERR_OVERTEMP)
		device_printf(sc->dev,
		    "CRITICAL: EXTERNAL PHY OVER TEMP!! "
		    " PHY will downshift to lower power state!\n");
	else if (error)
		device_printf(sc->dev,
		    "Error handling LASI interrupt: %d\n", error);
} /* ixgbe_handle_phy */

static void
ixgbe_handle_admin(struct work *wk, void *context)
{
	struct ixgbe_softc *sc = context;
	struct ifnet	*ifp = sc->ifp;
	struct ixgbe_hw *hw = &sc->hw;
	u32		task_requests;
	u32		eims_enable = 0;

	mutex_enter(&sc->admin_mtx);
	sc->admin_pending = 0;
	task_requests = sc->task_requests;
	sc->task_requests = 0;
	mutex_exit(&sc->admin_mtx);

	/*
	 * Hold the IFNET_LOCK across this entire call.  This will
	 * prevent additional changes to sc->phy_layer
	 * and serialize calls to this tasklet.  We cannot hold the
	 * CORE_LOCK while calling into the ifmedia functions as
	 * they call ifmedia_lock() and the lock is CORE_LOCK.
	 */
	IFNET_LOCK(ifp);
	IXGBE_CORE_LOCK(sc);
	if ((task_requests & IXGBE_REQUEST_TASK_LSC) != 0) {
		ixgbe_handle_link(sc);
		eims_enable |= IXGBE_EIMS_LSC;
	}
	if ((task_requests & IXGBE_REQUEST_TASK_MOD_WOI) != 0)
		ixgbe_handle_mod(sc, false);
	if ((task_requests & IXGBE_REQUEST_TASK_MOD) != 0) {
		ixgbe_handle_mod(sc, true);
		if (hw->mac.type >= ixgbe_mac_X540)
			eims_enable |= IXGBE_EICR_GPI_SDP0_X540;
		else
			eims_enable |= IXGBE_EICR_GPI_SDP2_BY_MAC(hw);
	}
	if ((task_requests
	    & (IXGBE_REQUEST_TASK_MSF_WOI | IXGBE_REQUEST_TASK_MSF)) != 0) {
		ixgbe_handle_msf(sc);
		if (((task_requests & IXGBE_REQUEST_TASK_MSF) != 0) &&
		    (hw->mac.type == ixgbe_mac_82599EB))
		    eims_enable |= IXGBE_EIMS_GPI_SDP1_BY_MAC(hw);
	}
	if ((task_requests & IXGBE_REQUEST_TASK_PHY) != 0) {
		ixgbe_handle_phy(sc);
		eims_enable |= IXGBE_EICR_GPI_SDP0_X540;
	}
	if ((task_requests & IXGBE_REQUEST_TASK_FDIR) != 0) {
		ixgbe_reinit_fdir(sc);
		eims_enable |= IXGBE_EIMS_FLOW_DIR;
	}
#if 0 /* notyet */
	if ((task_requests & IXGBE_REQUEST_TASK_MBX) != 0) {
		ixgbe_handle_mbx(sc);
		eims_enable |= IXGBE_EIMS_MAILBOX;
	}
#endif
	IXGBE_WRITE_REG(hw, IXGBE_EIMS, eims_enable);

	IXGBE_CORE_UNLOCK(sc);
	IFNET_UNLOCK(ifp);
} /* ixgbe_handle_admin */

static void
ixgbe_ifstop(struct ifnet *ifp, int disable)
{
	struct ixgbe_softc *sc = ifp->if_softc;

	IXGBE_CORE_LOCK(sc);
	ixgbe_stop_locked(sc);
	IXGBE_CORE_UNLOCK(sc);

	workqueue_wait(sc->timer_wq, &sc->timer_wc);
	atomic_store_relaxed(&sc->timer_pending, 0);
}

/************************************************************************
 * ixgbe_stop_locked - Stop the hardware
 *
 *   Disables all traffic on the adapter by issuing a
 *   global reset on the MAC and deallocates TX/RX buffers.
 ************************************************************************/
static void
ixgbe_stop_locked(void *arg)
{
	struct ifnet	*ifp;
	struct ixgbe_softc *sc = arg;
	struct ixgbe_hw *hw = &sc->hw;

	ifp = sc->ifp;

	KASSERT(mutex_owned(&sc->core_mtx));

	INIT_DEBUGOUT("ixgbe_stop_locked: begin\n");
	ixgbe_disable_intr(sc);
	callout_stop(&sc->timer);

	/* Don't schedule workqueues. */
	sc->schedule_wqs_ok = false;

	/* Let the stack know...*/
	ifp->if_flags &= ~IFF_RUNNING;

	ixgbe_reset_hw(hw);
	hw->adapter_stopped = FALSE;
	ixgbe_stop_adapter(hw);
	if (hw->mac.type == ixgbe_mac_82599EB)
		ixgbe_stop_mac_link_on_d3_82599(hw);
	/* Turn off the laser - noop with no optics */
	ixgbe_disable_tx_laser(hw);

	/* Update the stack */
	sc->link_up = FALSE;
	ixgbe_update_link_status(sc);

	/* reprogram the RAR[0] in case user changed it. */
	ixgbe_set_rar(&sc->hw, 0, sc->hw.mac.addr, 0, IXGBE_RAH_AV);

	return;
} /* ixgbe_stop_locked */

/************************************************************************
 * ixgbe_update_link_status - Update OS on link state
 *
 * Note: Only updates the OS on the cached link state.
 *	 The real check of the hardware only happens with
 *	 a link interrupt.
 ************************************************************************/
static void
ixgbe_update_link_status(struct ixgbe_softc *sc)
{
	struct ifnet	*ifp = sc->ifp;
	device_t	dev = sc->dev;
	struct ixgbe_hw *hw = &sc->hw;

	KASSERT(mutex_owned(&sc->core_mtx));

	if (sc->link_up) {
		if (sc->link_active != LINK_STATE_UP) {
			/*
			 * To eliminate influence of the previous state
			 * in the same way as ixgbe_init_locked().
			 */
			struct ix_queue	*que = sc->queues;
			for (int i = 0; i < sc->num_queues; i++, que++)
				que->eitr_setting = 0;

			if (sc->link_speed == IXGBE_LINK_SPEED_10GB_FULL) {
				/*
				 *  Discard count for both MAC Local Fault and
				 * Remote Fault because those registers are
				 * valid only when the link speed is up and
				 * 10Gbps.
				 */
				IXGBE_READ_REG(hw, IXGBE_MLFC);
				IXGBE_READ_REG(hw, IXGBE_MRFC);
			}

			if (bootverbose) {
				const char *bpsmsg;

				switch (sc->link_speed) {
				case IXGBE_LINK_SPEED_10GB_FULL:
					bpsmsg = "10 Gbps";
					break;
				case IXGBE_LINK_SPEED_5GB_FULL:
					bpsmsg = "5 Gbps";
					break;
				case IXGBE_LINK_SPEED_2_5GB_FULL:
					bpsmsg = "2.5 Gbps";
					break;
				case IXGBE_LINK_SPEED_1GB_FULL:
					bpsmsg = "1 Gbps";
					break;
				case IXGBE_LINK_SPEED_100_FULL:
					bpsmsg = "100 Mbps";
					break;
				case IXGBE_LINK_SPEED_10_FULL:
					bpsmsg = "10 Mbps";
					break;
				default:
					bpsmsg = "unknown speed";
					break;
				}
				device_printf(dev, "Link is up %s %s \n",
				    bpsmsg, "Full Duplex");
			}
			sc->link_active = LINK_STATE_UP;
			/* Update any Flow Control changes */
			ixgbe_fc_enable(&sc->hw);
			/* Update DMA coalescing config */
			ixgbe_config_dmac(sc);
			if_link_state_change(ifp, LINK_STATE_UP);

			if (sc->feat_en & IXGBE_FEATURE_SRIOV)
				ixgbe_ping_all_vfs(sc);
		}
	} else {
		/*
		 * Do it when link active changes to DOWN. i.e.
		 * a) LINK_STATE_UNKNOWN -> LINK_STATE_DOWN
		 * b) LINK_STATE_UP	 -> LINK_STATE_DOWN
		 */
		if (sc->link_active != LINK_STATE_DOWN) {
			if (bootverbose)
				device_printf(dev, "Link is Down\n");
			if_link_state_change(ifp, LINK_STATE_DOWN);
			sc->link_active = LINK_STATE_DOWN;
			if (sc->feat_en & IXGBE_FEATURE_SRIOV)
				ixgbe_ping_all_vfs(sc);
			ixgbe_drain_all(sc);
		}
	}
} /* ixgbe_update_link_status */

/************************************************************************
 * ixgbe_config_dmac - Configure DMA Coalescing
 ************************************************************************/
static void
ixgbe_config_dmac(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	struct ixgbe_dmac_config *dcfg = &hw->mac.dmac_config;

	if (hw->mac.type < ixgbe_mac_X550 || !hw->mac.ops.dmac_config)
		return;

	if (dcfg->watchdog_timer ^ sc->dmac ||
	    dcfg->link_speed ^ sc->link_speed) {
		dcfg->watchdog_timer = sc->dmac;
		dcfg->fcoe_en = false;
		dcfg->link_speed = sc->link_speed;
		dcfg->num_tcs = 1;

		INIT_DEBUGOUT2("dmac settings: watchdog %d, link speed %d\n",
		    dcfg->watchdog_timer, dcfg->link_speed);

		hw->mac.ops.dmac_config(hw);
	}
} /* ixgbe_config_dmac */

/************************************************************************
 * ixgbe_enable_intr
 ************************************************************************/
static void
ixgbe_enable_intr(struct ixgbe_softc *sc)
{
	struct ixgbe_hw	*hw = &sc->hw;
	struct ix_queue	*que = sc->queues;
	u32		mask, fwsm;

	mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);

	switch (sc->hw.mac.type) {
	case ixgbe_mac_82599EB:
		mask |= IXGBE_EIMS_ECC;
		/* Temperature sensor on some adapters */
		mask |= IXGBE_EIMS_GPI_SDP0;
		/* SFP+ (RX_LOS_N & MOD_ABS_N) */
		mask |= IXGBE_EIMS_GPI_SDP1;
		mask |= IXGBE_EIMS_GPI_SDP2;
		break;
	case ixgbe_mac_X540:
		/* Detect if Thermal Sensor is enabled */
		fwsm = IXGBE_READ_REG(hw, IXGBE_FWSM);
		if (fwsm & IXGBE_FWSM_TS_ENABLED)
			mask |= IXGBE_EIMS_TS;
		mask |= IXGBE_EIMS_ECC;
		break;
	case ixgbe_mac_X550:
		/* MAC thermal sensor is automatically enabled */
		mask |= IXGBE_EIMS_TS;
		mask |= IXGBE_EIMS_ECC;
		break;
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		/* Some devices use SDP0 for important information */
		if (hw->device_id == IXGBE_DEV_ID_X550EM_X_SFP ||
		    hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP ||
		    hw->device_id == IXGBE_DEV_ID_X550EM_A_SFP_N ||
		    hw->device_id == IXGBE_DEV_ID_X550EM_X_10G_T)
			mask |= IXGBE_EIMS_GPI_SDP0_BY_MAC(hw);
		if (hw->phy.type == ixgbe_phy_x550em_ext_t)
			mask |= IXGBE_EICR_GPI_SDP0_X540;
		mask |= IXGBE_EIMS_ECC;
		break;
	default:
		break;
	}

	/* Enable Fan Failure detection */
	if (sc->feat_en & IXGBE_FEATURE_FAN_FAIL)
		mask |= IXGBE_EIMS_GPI_SDP1;
	/* Enable SR-IOV */
	if (sc->feat_en & IXGBE_FEATURE_SRIOV)
		mask |= IXGBE_EIMS_MAILBOX;
	/* Enable Flow Director */
	if (sc->feat_en & IXGBE_FEATURE_FDIR)
		mask |= IXGBE_EIMS_FLOW_DIR;

	IXGBE_WRITE_REG(hw, IXGBE_EIMS, mask);

	/* With MSI-X we use auto clear */
	if ((sc->feat_en & IXGBE_FEATURE_MSIX) != 0) {
		/*
		 * We use auto clear for RTX_QUEUE only. Don't use other
		 * interrupts (e.g. link interrupt). BTW, we don't use
		 *  TCP_TIMER interrupt itself.
		 */
		IXGBE_WRITE_REG(hw, IXGBE_EIAC, IXGBE_EIMS_RTX_QUEUE);
	}

	/*
	 * Now enable all queues, this is done separately to
	 * allow for handling the extended (beyond 32) MSI-X
	 * vectors that can be used by 82599
	 */
	for (int i = 0; i < sc->num_queues; i++, que++)
		ixgbe_enable_queue(sc, que->msix);

	IXGBE_WRITE_FLUSH(hw);

} /* ixgbe_enable_intr */

/************************************************************************
 * ixgbe_disable_intr_internal
 ************************************************************************/
static void
ixgbe_disable_intr_internal(struct ixgbe_softc *sc, bool nestok)
{
	struct ix_queue	*que = sc->queues;

	/* disable interrupts other than queues */
	IXGBE_WRITE_REG(&sc->hw, IXGBE_EIMC, ~IXGBE_EIMC_RTX_QUEUE);

	if ((sc->feat_en & IXGBE_FEATURE_MSIX) != 0)
		IXGBE_WRITE_REG(&sc->hw, IXGBE_EIAC, 0);

	for (int i = 0; i < sc->num_queues; i++, que++)
		ixgbe_disable_queue_internal(sc, que->msix, nestok);

	IXGBE_WRITE_FLUSH(&sc->hw);

} /* ixgbe_do_disable_intr_internal */

/************************************************************************
 * ixgbe_disable_intr
 ************************************************************************/
static void
ixgbe_disable_intr(struct ixgbe_softc *sc)
{

	ixgbe_disable_intr_internal(sc, true);
} /* ixgbe_disable_intr */

/************************************************************************
 * ixgbe_ensure_disabled_intr
 ************************************************************************/
void
ixgbe_ensure_disabled_intr(struct ixgbe_softc *sc)
{

	ixgbe_disable_intr_internal(sc, false);
} /* ixgbe_ensure_disabled_intr */

/************************************************************************
 * ixgbe_legacy_irq - Legacy Interrupt Service routine
 ************************************************************************/
static int
ixgbe_legacy_irq(void *arg)
{
	struct ix_queue *que = arg;
	struct ixgbe_softc *sc = que->sc;
	struct ixgbe_hw	*hw = &sc->hw;
	struct ifnet	*ifp = sc->ifp;
	struct tx_ring	*txr = sc->tx_rings;
	u32		eicr;
	u32		eims_orig;
	u32		eims_enable = 0;
	u32		eims_disable = 0;

	eims_orig = IXGBE_READ_REG(hw, IXGBE_EIMS);
	/*
	 * Silicon errata #26 on 82598. Disable all interrupts before reading
	 * EICR.
	 */
	IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_IRQ_CLEAR_MASK);

	/* Read and clear EICR */
	eicr = IXGBE_READ_REG(hw, IXGBE_EICR);

	if (eicr == 0) {
		IXGBE_EVC_ADD(&sc->stats.pf.intzero, 1);
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, eims_orig);
		return 0;
	}
	IXGBE_EVC_ADD(&sc->stats.pf.legint, 1);

	/* Queue (0) intr */
	if (((ifp->if_flags & IFF_RUNNING) != 0) &&
	    (eicr & IXGBE_EIMC_RTX_QUEUE) != 0) {
		IXGBE_EVC_ADD(&que->irqs, 1);

		/*
		 * The same as ixgbe_msix_que() about
		 * "que->txrx_use_workqueue".
		 */
		que->txrx_use_workqueue = sc->txrx_use_workqueue;

		IXGBE_TX_LOCK(txr);
		ixgbe_txeof(txr);
#ifdef notyet
		if (!ixgbe_ring_empty(ifp, txr->br))
			ixgbe_start_locked(ifp, txr);
#endif
		IXGBE_TX_UNLOCK(txr);

		IXGBE_EVC_ADD(&que->req, 1);
		ixgbe_sched_handle_que(sc, que);
		/* Disable queue 0 interrupt */
		eims_disable |= 1UL << 0;
	} else
		eims_enable |= eims_orig & IXGBE_EIMC_RTX_QUEUE;

	ixgbe_intr_admin_common(sc, eicr, &eims_disable);

	/* Re-enable some interrupts */
	IXGBE_WRITE_REG(hw, IXGBE_EIMS,
	    (eims_orig & ~eims_disable) | eims_enable);

	return 1;
} /* ixgbe_legacy_irq */

/************************************************************************
 * ixgbe_free_pciintr_resources
 ************************************************************************/
static void
ixgbe_free_pciintr_resources(struct ixgbe_softc *sc)
{
	struct ix_queue *que = sc->queues;
	int		rid;

	/*
	 * Release all msix queue resources:
	 */
	for (int i = 0; i < sc->num_queues; i++, que++) {
		if (que->res != NULL) {
			pci_intr_disestablish(sc->osdep.pc, sc->osdep.ihs[i]);
			sc->osdep.ihs[i] = NULL;
		}
	}

	/* Clean the Legacy or Link interrupt last */
	if (sc->vector) /* we are doing MSIX */
		rid = sc->vector;
	else
		rid = 0;

	if (sc->osdep.ihs[rid] != NULL) {
		pci_intr_disestablish(sc->osdep.pc, sc->osdep.ihs[rid]);
		sc->osdep.ihs[rid] = NULL;
	}

	if (sc->osdep.intrs != NULL) {
		pci_intr_release(sc->osdep.pc, sc->osdep.intrs,
		    sc->osdep.nintrs);
		sc->osdep.intrs = NULL;
	}
} /* ixgbe_free_pciintr_resources */

/************************************************************************
 * ixgbe_free_pci_resources
 ************************************************************************/
static void
ixgbe_free_pci_resources(struct ixgbe_softc *sc)
{

	ixgbe_free_pciintr_resources(sc);

	if (sc->osdep.mem_size != 0) {
		bus_space_unmap(sc->osdep.mem_bus_space_tag,
		    sc->osdep.mem_bus_space_handle,
		    sc->osdep.mem_size);
	}
} /* ixgbe_free_pci_resources */

/************************************************************************
 * ixgbe_sysctl_flowcntl
 *
 *   SYSCTL wrapper around setting Flow Control
 ************************************************************************/
static int
ixgbe_sysctl_flowcntl(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int error, fc;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	fc = sc->hw.fc.current_mode;
	node.sysctl_data = &fc;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;

	/* Don't bother if it's not changed */
	if (fc == sc->hw.fc.current_mode)
		return (0);

	return ixgbe_set_flowcntl(sc, fc);
} /* ixgbe_sysctl_flowcntl */

/************************************************************************
 * ixgbe_set_flowcntl - Set flow control
 *
 *   Flow control values:
 *     0 - off
 *     1 - rx pause
 *     2 - tx pause
 *     3 - full
 ************************************************************************/
static int
ixgbe_set_flowcntl(struct ixgbe_softc *sc, int fc)
{
	switch (fc) {
		case ixgbe_fc_rx_pause:
		case ixgbe_fc_tx_pause:
		case ixgbe_fc_full:
			sc->hw.fc.requested_mode = fc;
			if (sc->num_queues > 1)
				ixgbe_disable_rx_drop(sc);
			break;
		case ixgbe_fc_none:
			sc->hw.fc.requested_mode = ixgbe_fc_none;
			if (sc->num_queues > 1)
				ixgbe_enable_rx_drop(sc);
			break;
		default:
			return (EINVAL);
	}

#if 0 /* XXX NetBSD */
	/* Don't autoneg if forcing a value */
	sc->hw.fc.disable_fc_autoneg = TRUE;
#endif
	ixgbe_fc_enable(&sc->hw);

	return (0);
} /* ixgbe_set_flowcntl */

/************************************************************************
 * ixgbe_enable_rx_drop
 *
 *   Enable the hardware to drop packets when the buffer is
 *   full. This is useful with multiqueue, so that no single
 *   queue being full stalls the entire RX engine. We only
 *   enable this when Multiqueue is enabled AND Flow Control
 *   is disabled.
 ************************************************************************/
static void
ixgbe_enable_rx_drop(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	struct rx_ring	*rxr;
	u32		srrctl;

	for (int i = 0; i < sc->num_queues; i++) {
		rxr = &sc->rx_rings[i];
		srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(rxr->me));
		srrctl |= IXGBE_SRRCTL_DROP_EN;
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rxr->me), srrctl);
	}

	/* enable drop for each vf */
	for (int i = 0; i < sc->num_vfs; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
		    (IXGBE_QDE_WRITE | (i << IXGBE_QDE_IDX_SHIFT) |
		    IXGBE_QDE_ENABLE));
	}
} /* ixgbe_enable_rx_drop */

/************************************************************************
 * ixgbe_disable_rx_drop
 ************************************************************************/
static void
ixgbe_disable_rx_drop(struct ixgbe_softc *sc)
{
	struct ixgbe_hw *hw = &sc->hw;
	struct rx_ring	*rxr;
	u32		srrctl;

	for (int i = 0; i < sc->num_queues; i++) {
		rxr = &sc->rx_rings[i];
		srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(rxr->me));
		srrctl &= ~IXGBE_SRRCTL_DROP_EN;
		IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rxr->me), srrctl);
	}

	/* disable drop for each vf */
	for (int i = 0; i < sc->num_vfs; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
		    (IXGBE_QDE_WRITE | (i << IXGBE_QDE_IDX_SHIFT)));
	}
} /* ixgbe_disable_rx_drop */

/************************************************************************
 * ixgbe_sysctl_advertise
 *
 *   SYSCTL wrapper around setting advertised speed
 ************************************************************************/
static int
ixgbe_sysctl_advertise(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int	       error = 0, advertise;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	advertise = sc->advertise;
	node.sysctl_data = &advertise;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;

	return ixgbe_set_advertise(sc, advertise);
} /* ixgbe_sysctl_advertise */

/************************************************************************
 * ixgbe_set_advertise - Control advertised link speed
 *
 *   Flags:
 *     0x00 - Default (all capable link speed)
 *     0x1  - advertise 100 Mb
 *     0x2  - advertise 1G
 *     0x4  - advertise 10G
 *     0x8  - advertise 10 Mb (yes, Mb)
 *     0x10 - advertise 2.5G
 *     0x20 - advertise 5G
 ************************************************************************/
static int
ixgbe_set_advertise(struct ixgbe_softc *sc, int advertise)
{
	device_t	 dev;
	struct ixgbe_hw	 *hw;
	ixgbe_link_speed speed = 0;
	ixgbe_link_speed link_caps = 0;
	s32		 err = IXGBE_NOT_IMPLEMENTED;
	bool		 negotiate = FALSE;

	/* Checks to validate new value */
	if (sc->advertise == advertise) /* no change */
		return (0);

	dev = sc->dev;
	hw = &sc->hw;

	/* No speed changes for backplane media */
	if (hw->phy.media_type == ixgbe_media_type_backplane)
		return (ENODEV);

	if (!((hw->phy.media_type == ixgbe_media_type_copper) ||
	    (hw->phy.multispeed_fiber))) {
		device_printf(dev,
		    "Advertised speed can only be set on copper or "
		    "multispeed fiber media types.\n");
		return (EINVAL);
	}

	if (advertise < 0x0 || advertise > 0x3f) {
		device_printf(dev, "Invalid advertised speed; "
		    "valid modes are 0x0 through 0x3f\n");
		return (EINVAL);
	}

	if (hw->mac.ops.get_link_capabilities) {
		err = hw->mac.ops.get_link_capabilities(hw, &link_caps,
		    &negotiate);
		if (err != IXGBE_SUCCESS) {
			device_printf(dev, "Unable to determine supported "
			    "advertise speeds\n");
			return (ENODEV);
		}
	}

	/* Set new value and report new advertised mode */
	if (advertise & 0x1) {
		if (!(link_caps & IXGBE_LINK_SPEED_100_FULL)) {
			device_printf(dev, "Interface does not support 100Mb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_100_FULL;
	}
	if (advertise & 0x2) {
		if (!(link_caps & IXGBE_LINK_SPEED_1GB_FULL)) {
			device_printf(dev, "Interface does not support 1Gb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_1GB_FULL;
	}
	if (advertise & 0x4) {
		if (!(link_caps & IXGBE_LINK_SPEED_10GB_FULL)) {
			device_printf(dev, "Interface does not support 10Gb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_10GB_FULL;
	}
	if (advertise & 0x8) {
		if (!(link_caps & IXGBE_LINK_SPEED_10_FULL)) {
			device_printf(dev, "Interface does not support 10Mb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_10_FULL;
	}
	if (advertise & 0x10) {
		if (!(link_caps & IXGBE_LINK_SPEED_2_5GB_FULL)) {
			device_printf(dev, "Interface does not support 2.5Gb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_2_5GB_FULL;
	}
	if (advertise & 0x20) {
		if (!(link_caps & IXGBE_LINK_SPEED_5GB_FULL)) {
			device_printf(dev, "Interface does not support 5Gb "
			    "advertised speed\n");
			return (EINVAL);
		}
		speed |= IXGBE_LINK_SPEED_5GB_FULL;
	}
	if (advertise == 0)
		speed = link_caps; /* All capable link speed */

	hw->mac.autotry_restart = TRUE;
	hw->mac.ops.setup_link(hw, speed, TRUE);
	sc->advertise = advertise;

	return (0);
} /* ixgbe_set_advertise */

/************************************************************************
 * ixgbe_get_default_advertise - Get default advertised speed settings
 *
 *   Formatted for sysctl usage.
 *   Flags:
 *     0x1  - advertise 100 Mb
 *     0x2  - advertise 1G
 *     0x4  - advertise 10G
 *     0x8  - advertise 10 Mb (yes, Mb)
 *     0x10 - advertise 2.5G
 *     0x20 - advertise 5G
 ************************************************************************/
static int
ixgbe_get_default_advertise(struct ixgbe_softc *sc)
{
	struct ixgbe_hw	 *hw = &sc->hw;
	int		 speed;
	ixgbe_link_speed link_caps = 0;
	s32		 err;
	bool		 negotiate = FALSE;

	/*
	 * Advertised speed means nothing unless it's copper or
	 * multi-speed fiber
	 */
	if (!(hw->phy.media_type == ixgbe_media_type_copper) &&
	    !(hw->phy.multispeed_fiber))
		return (0);

	err = hw->mac.ops.get_link_capabilities(hw, &link_caps, &negotiate);
	if (err != IXGBE_SUCCESS)
		return (0);

	speed =
	    ((link_caps & IXGBE_LINK_SPEED_10GB_FULL)  ? 0x4  : 0) |
	    ((link_caps & IXGBE_LINK_SPEED_5GB_FULL)   ? 0x20 : 0) |
	    ((link_caps & IXGBE_LINK_SPEED_2_5GB_FULL) ? 0x10 : 0) |
	    ((link_caps & IXGBE_LINK_SPEED_1GB_FULL)   ? 0x2  : 0) |
	    ((link_caps & IXGBE_LINK_SPEED_100_FULL)   ? 0x1  : 0) |
	    ((link_caps & IXGBE_LINK_SPEED_10_FULL)    ? 0x8  : 0);

	return speed;
} /* ixgbe_get_default_advertise */

/************************************************************************
 * ixgbe_sysctl_dmac - Manage DMA Coalescing
 *
 *   Control values:
 *     0/1 - off / on (use default value of 1000)
 *
 *     Legal timer values are:
 *     50,100,250,500,1000,2000,5000,10000
 *
 *     Turning off interrupt moderation will also turn this off.
 ************************************************************************/
static int
ixgbe_sysctl_dmac(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ifnet   *ifp = sc->ifp;
	int	       error;
	int	       newval;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	newval = sc->dmac;
	node.sysctl_data = &newval;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);

	switch (newval) {
	case 0:
		/* Disabled */
		sc->dmac = 0;
		break;
	case 1:
		/* Enable and use default */
		sc->dmac = 1000;
		break;
	case 50:
	case 100:
	case 250:
	case 500:
	case 1000:
	case 2000:
	case 5000:
	case 10000:
		/* Legal values - allow */
		sc->dmac = newval;
		break;
	default:
		/* Do nothing, illegal value */
		return (EINVAL);
	}

	/* Re-initialize hardware if it's already running */
	if (ifp->if_flags & IFF_RUNNING)
		if_init(ifp);

	return (0);
}

#ifdef IXGBE_DEBUG
/************************************************************************
 * ixgbe_sysctl_power_state
 *
 *   Sysctl to test power states
 *   Values:
 *     0      - set device to D0
 *     3      - set device to D3
 *     (none) - get current device power state
 ************************************************************************/
static int
ixgbe_sysctl_power_state(SYSCTLFN_ARGS)
{
#ifdef notyet
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	device_t       dev =  sc->dev;
	int	       curr_ps, new_ps, error = 0;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	curr_ps = new_ps = pci_get_powerstate(dev);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (req->newp == NULL))
		return (error);

	if (new_ps == curr_ps)
		return (0);

	if (new_ps == 3 && curr_ps == 0)
		error = DEVICE_SUSPEND(dev);
	else if (new_ps == 0 && curr_ps == 3)
		error = DEVICE_RESUME(dev);
	else
		return (EINVAL);

	device_printf(dev, "New state: %d\n", pci_get_powerstate(dev));

	return (error);
#else
	return 0;
#endif
} /* ixgbe_sysctl_power_state */
#endif

/************************************************************************
 * ixgbe_sysctl_wol_enable
 *
 *   Sysctl to enable/disable the WoL capability,
 *   if supported by the adapter.
 *
 *   Values:
 *     0 - disabled
 *     1 - enabled
 ************************************************************************/
static int
ixgbe_sysctl_wol_enable(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ixgbe_hw *hw = &sc->hw;
	bool		new_wol_enabled;
	int		error = 0;

	/*
	 * It's not required to check recovery mode because this function never
	 * touches hardware.
	 */
	new_wol_enabled = hw->wol_enabled;
	node.sysctl_data = &new_wol_enabled;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);
	if (new_wol_enabled == hw->wol_enabled)
		return (0);

	if (new_wol_enabled && !sc->wol_support)
		return (ENODEV);
	else
		hw->wol_enabled = new_wol_enabled;

	return (0);
} /* ixgbe_sysctl_wol_enable */

/************************************************************************
 * ixgbe_sysctl_wufc - Wake Up Filter Control
 *
 *   Sysctl to enable/disable the types of packets that the
 *   adapter will wake up on upon receipt.
 *   Flags:
 *     0x1  - Link Status Change
 *     0x2  - Magic Packet
 *     0x4  - Direct Exact
 *     0x8  - Directed Multicast
 *     0x10 - Broadcast
 *     0x20 - ARP/IPv4 Request Packet
 *     0x40 - Direct IPv4 Packet
 *     0x80 - Direct IPv6 Packet
 *
 *   Settings not listed above will cause the sysctl to return an error.
 ************************************************************************/
static int
ixgbe_sysctl_wufc(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int error = 0;
	u32 new_wufc;

	/*
	 * It's not required to check recovery mode because this function never
	 * touches hardware.
	 */
	new_wufc = sc->wufc;
	node.sysctl_data = &new_wufc;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);
	if (new_wufc == sc->wufc)
		return (0);

	if (new_wufc & 0xffffff00)
		return (EINVAL);

	new_wufc &= 0xff;
	new_wufc |= (0xffffff & sc->wufc);
	sc->wufc = new_wufc;

	return (0);
} /* ixgbe_sysctl_wufc */

#ifdef IXGBE_DEBUG
/************************************************************************
 * ixgbe_sysctl_print_rss_config
 ************************************************************************/
static int
ixgbe_sysctl_print_rss_config(SYSCTLFN_ARGS)
{
#ifdef notyet
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ixgbe_hw *hw = &sc->hw;
	device_t	dev = sc->dev;
	struct sbuf	*buf;
	int		error = 0, reta_size;
	u32		reg;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	buf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	if (!buf) {
		device_printf(dev, "Could not allocate sbuf for output.\n");
		return (ENOMEM);
	}

	// TODO: use sbufs to make a string to print out
	/* Set multiplier for RETA setup and table size based on MAC */
	switch (sc->hw.mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		reta_size = 128;
		break;
	default:
		reta_size = 32;
		break;
	}

	/* Print out the redirection table */
	sbuf_cat(buf, "\n");
	for (int i = 0; i < reta_size; i++) {
		if (i < 32) {
			reg = IXGBE_READ_REG(hw, IXGBE_RETA(i));
			sbuf_printf(buf, "RETA(%2d): 0x%08x\n", i, reg);
		} else {
			reg = IXGBE_READ_REG(hw, IXGBE_ERETA(i - 32));
			sbuf_printf(buf, "ERETA(%2d): 0x%08x\n", i - 32, reg);
		}
	}

	// TODO: print more config

	error = sbuf_finish(buf);
	if (error)
		device_printf(dev, "Error finishing sbuf: %d\n", error);

	sbuf_delete(buf);
#endif
	return (0);
} /* ixgbe_sysctl_print_rss_config */
#endif /* IXGBE_DEBUG */

/************************************************************************
 * ixgbe_sysctl_phy_temp - Retrieve temperature of PHY
 *
 *   For X552/X557-AT devices using an external PHY
 ************************************************************************/
static int
ixgbe_sysctl_phy_temp(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ixgbe_hw *hw = &sc->hw;
	int val;
	u16 reg;
	int		error;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	if ((hw->device_id != IXGBE_DEV_ID_X550EM_X_10G_T) &&
	    (hw->device_id != IXGBE_DEV_ID_X550EM_A_10G_T)) {
		device_printf(sc->dev,
		    "Device has no supported external thermal sensor.\n");
		return (ENODEV);
	}

	if (hw->phy.ops.read_reg(hw, IXGBE_PHY_CURRENT_TEMP,
		IXGBE_MDIO_VENDOR_SPECIFIC_1_DEV_TYPE, &reg)) {
		device_printf(sc->dev,
		    "Error reading from PHY's current temperature register\n");
		return (EAGAIN);
	}

	node.sysctl_data = &val;

	/* Shift temp for output */
	val = reg >> 8;

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);

	return (0);
} /* ixgbe_sysctl_phy_temp */

/************************************************************************
 * ixgbe_sysctl_phy_overtemp_occurred
 *
 *   Reports (directly from the PHY) whether the current PHY
 *   temperature is over the overtemp threshold.
 ************************************************************************/
static int
ixgbe_sysctl_phy_overtemp_occurred(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ixgbe_hw *hw = &sc->hw;
	int val, error;
	u16 reg;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	if ((hw->device_id != IXGBE_DEV_ID_X550EM_X_10G_T) &&
	    (hw->device_id != IXGBE_DEV_ID_X550EM_A_10G_T)) {
		device_printf(sc->dev,
		    "Device has no supported external thermal sensor.\n");
		return (ENODEV);
	}

	if (hw->phy.ops.read_reg(hw, IXGBE_PHY_OVERTEMP_STATUS,
		IXGBE_MDIO_VENDOR_SPECIFIC_1_DEV_TYPE, &reg)) {
		device_printf(sc->dev,
		    "Error reading from PHY's temperature status register\n");
		return (EAGAIN);
	}

	node.sysctl_data = &val;

	/* Get occurrence bit */
	val = !!(reg & 0x4000);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);

	return (0);
} /* ixgbe_sysctl_phy_overtemp_occurred */

/************************************************************************
 * ixgbe_sysctl_eee_state
 *
 *   Sysctl to set EEE power saving feature
 *   Values:
 *     0      - disable EEE
 *     1      - enable EEE
 *     (none) - get current device EEE state
 ************************************************************************/
static int
ixgbe_sysctl_eee_state(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	struct ifnet   *ifp = sc->ifp;
	device_t       dev = sc->dev;
	int	       curr_eee, new_eee, error = 0;
	s32	       retval;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	curr_eee = new_eee = !!(sc->feat_en & IXGBE_FEATURE_EEE);
	node.sysctl_data = &new_eee;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if ((error) || (newp == NULL))
		return (error);

	/* Nothing to do */
	if (new_eee == curr_eee)
		return (0);

	/* Not supported */
	if (!(sc->feat_cap & IXGBE_FEATURE_EEE))
		return (EINVAL);

	/* Bounds checking */
	if ((new_eee < 0) || (new_eee > 1))
		return (EINVAL);

	retval = ixgbe_setup_eee(&sc->hw, new_eee);
	if (retval) {
		device_printf(dev, "Error in EEE setup: 0x%08X\n", retval);
		return (EINVAL);
	}

	/* Restart auto-neg */
	if_init(ifp);

	device_printf(dev, "New EEE state: %d\n", new_eee);

	/* Cache new value */
	if (new_eee)
		sc->feat_en |= IXGBE_FEATURE_EEE;
	else
		sc->feat_en &= ~IXGBE_FEATURE_EEE;

	return (error);
} /* ixgbe_sysctl_eee_state */

#define PRINTQS(sc, regname)						\
	do {								\
		struct ixgbe_hw	*_hw = &(sc)->hw;			\
		int _i;							\
									\
		printf("%s: %s", device_xname((sc)->dev), #regname);	\
		for (_i = 0; _i < (sc)->num_queues; _i++) {		\
			printf((_i == 0) ? "\t" : " ");			\
			printf("%08x", IXGBE_READ_REG(_hw,		\
				IXGBE_##regname(_i)));			\
		}							\
		printf("\n");						\
	} while (0)

/************************************************************************
 * ixgbe_print_debug_info
 *
 *   Called only when em_display_debug_stats is enabled.
 *   Provides a way to take a look at important statistics
 *   maintained by the driver and hardware.
 ************************************************************************/
static void
ixgbe_print_debug_info(struct ixgbe_softc *sc)
{
	device_t	dev = sc->dev;
	struct ixgbe_hw *hw = &sc->hw;
	int table_size;
	int i;

	switch (sc->hw.mac.type) {
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		table_size = 128;
		break;
	default:
		table_size = 32;
		break;
	}

	device_printf(dev, "[E]RETA:\n");
	for (i = 0; i < table_size; i++) {
		if (i < 32)
			printf("%02x: %08x\n", i, IXGBE_READ_REG(hw,
				IXGBE_RETA(i)));
		else
			printf("%02x: %08x\n", i, IXGBE_READ_REG(hw,
				IXGBE_ERETA(i - 32)));
	}

	device_printf(dev, "queue:");
	for (i = 0; i < sc->num_queues; i++) {
		printf((i == 0) ? "\t" : " ");
		printf("%8d", i);
	}
	printf("\n");
	PRINTQS(sc, RDBAL);
	PRINTQS(sc, RDBAH);
	PRINTQS(sc, RDLEN);
	PRINTQS(sc, SRRCTL);
	PRINTQS(sc, RDH);
	PRINTQS(sc, RDT);
	PRINTQS(sc, RXDCTL);

	device_printf(dev, "RQSMR:");
	for (i = 0; i < sc->num_queues / 4; i++) {
		printf((i == 0) ? "\t" : " ");
		printf("%08x", IXGBE_READ_REG(hw, IXGBE_RQSMR(i)));
	}
	printf("\n");

	device_printf(dev, "disabled_count:");
	for (i = 0; i < sc->num_queues; i++) {
		printf((i == 0) ? "\t" : " ");
		printf("%8d", sc->queues[i].disabled_count);
	}
	printf("\n");

	device_printf(dev, "EIMS:\t%08x\n", IXGBE_READ_REG(hw, IXGBE_EIMS));
	if (hw->mac.type != ixgbe_mac_82598EB) {
		device_printf(dev, "EIMS_EX(0):\t%08x\n",
			      IXGBE_READ_REG(hw, IXGBE_EIMS_EX(0)));
		device_printf(dev, "EIMS_EX(1):\t%08x\n",
			      IXGBE_READ_REG(hw, IXGBE_EIMS_EX(1)));
	}
	device_printf(dev, "EIAM:\t%08x\n", IXGBE_READ_REG(hw, IXGBE_EIAM));
	device_printf(dev, "EIAC:\t%08x\n", IXGBE_READ_REG(hw, IXGBE_EIAC));
} /* ixgbe_print_debug_info */

/************************************************************************
 * ixgbe_sysctl_debug
 ************************************************************************/
static int
ixgbe_sysctl_debug(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int	       error, result = 0;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	node.sysctl_data = &result;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error || newp == NULL)
		return error;

	if (result == 1)
		ixgbe_print_debug_info(sc);

	return 0;
} /* ixgbe_sysctl_debug */

/************************************************************************
 * ixgbe_sysctl_rx_copy_len
 ************************************************************************/
static int
ixgbe_sysctl_rx_copy_len(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int error;
	int result = sc->rx_copy_len;

	node.sysctl_data = &result;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error || newp == NULL)
		return error;

	if ((result < 0) || (result > IXGBE_RX_COPY_LEN_MAX))
		return EINVAL;

	sc->rx_copy_len = result;

	return 0;
} /* ixgbe_sysctl_rx_copy_len */

/************************************************************************
 * ixgbe_sysctl_tx_process_limit
 ************************************************************************/
static int
ixgbe_sysctl_tx_process_limit(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int error;
	int result = sc->tx_process_limit;

	node.sysctl_data = &result;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error || newp == NULL)
		return error;

	if ((result <= 0) || (result > sc->num_tx_desc))
		return EINVAL;

	sc->tx_process_limit = result;

	return 0;
} /* ixgbe_sysctl_tx_process_limit */

/************************************************************************
 * ixgbe_sysctl_rx_process_limit
 ************************************************************************/
static int
ixgbe_sysctl_rx_process_limit(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ixgbe_softc *sc = (struct ixgbe_softc *)node.sysctl_data;
	int error;
	int result = sc->rx_process_limit;

	node.sysctl_data = &result;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));

	if (error || newp == NULL)
		return error;

	if ((result <= 0) || (result > sc->num_rx_desc))
		return EINVAL;

	sc->rx_process_limit = result;

	return 0;
} /* ixgbe_sysctl_rx_process_limit */

/************************************************************************
 * ixgbe_init_device_features
 ************************************************************************/
static void
ixgbe_init_device_features(struct ixgbe_softc *sc)
{
	sc->feat_cap = IXGBE_FEATURE_NETMAP
			  | IXGBE_FEATURE_RSS
			  | IXGBE_FEATURE_MSI
			  | IXGBE_FEATURE_MSIX
			  | IXGBE_FEATURE_LEGACY_IRQ
			  | IXGBE_FEATURE_LEGACY_TX;

	/* Set capabilities first... */
	switch (sc->hw.mac.type) {
	case ixgbe_mac_82598EB:
		if (sc->hw.device_id == IXGBE_DEV_ID_82598AT)
			sc->feat_cap |= IXGBE_FEATURE_FAN_FAIL;
		break;
	case ixgbe_mac_X540:
		sc->feat_cap |= IXGBE_FEATURE_SRIOV;
		sc->feat_cap |= IXGBE_FEATURE_FDIR;
		if ((sc->hw.device_id == IXGBE_DEV_ID_X540_BYPASS) &&
		    (sc->hw.bus.func == 0))
			sc->feat_cap |= IXGBE_FEATURE_BYPASS;
		break;
	case ixgbe_mac_X550:
		/*
		 * IXGBE_FEATURE_RECOVERY_MODE will be set after reading
		 * NVM Image version.
		 */
		sc->feat_cap |= IXGBE_FEATURE_TEMP_SENSOR;
		sc->feat_cap |= IXGBE_FEATURE_SRIOV;
		sc->feat_cap |= IXGBE_FEATURE_FDIR;
		break;
	case ixgbe_mac_X550EM_x:
		/*
		 * IXGBE_FEATURE_RECOVERY_MODE will be set after reading
		 * NVM Image version.
		 */
		sc->feat_cap |= IXGBE_FEATURE_SRIOV;
		sc->feat_cap |= IXGBE_FEATURE_FDIR;
		break;
	case ixgbe_mac_X550EM_a:
		/*
		 * IXGBE_FEATURE_RECOVERY_MODE will be set after reading
		 * NVM Image version.
		 */
		sc->feat_cap |= IXGBE_FEATURE_SRIOV;
		sc->feat_cap |= IXGBE_FEATURE_FDIR;
		sc->feat_cap &= ~IXGBE_FEATURE_LEGACY_IRQ;
		if ((sc->hw.device_id == IXGBE_DEV_ID_X550EM_A_1G_T) ||
		    (sc->hw.device_id == IXGBE_DEV_ID_X550EM_A_1G_T_L)) {
			sc->feat_cap |= IXGBE_FEATURE_TEMP_SENSOR;
			sc->feat_cap |= IXGBE_FEATURE_EEE;
		}
		break;
	case ixgbe_mac_82599EB:
		sc->feat_cap |= IXGBE_FEATURE_SRIOV;
		sc->feat_cap |= IXGBE_FEATURE_FDIR;
		if ((sc->hw.device_id == IXGBE_DEV_ID_82599_BYPASS) &&
		    (sc->hw.bus.func == 0))
			sc->feat_cap |= IXGBE_FEATURE_BYPASS;
		if (sc->hw.device_id == IXGBE_DEV_ID_82599_QSFP_SF_QP)
			sc->feat_cap &= ~IXGBE_FEATURE_LEGACY_IRQ;
		break;
	default:
		break;
	}

	/* Enabled by default... */
	/* Fan failure detection */
	if (sc->feat_cap & IXGBE_FEATURE_FAN_FAIL)
		sc->feat_en |= IXGBE_FEATURE_FAN_FAIL;
	/* Netmap */
	if (sc->feat_cap & IXGBE_FEATURE_NETMAP)
		sc->feat_en |= IXGBE_FEATURE_NETMAP;
	/* EEE */
	if (sc->feat_cap & IXGBE_FEATURE_EEE)
		sc->feat_en |= IXGBE_FEATURE_EEE;
	/* Thermal Sensor */
	if (sc->feat_cap & IXGBE_FEATURE_TEMP_SENSOR)
		sc->feat_en |= IXGBE_FEATURE_TEMP_SENSOR;
	/*
	 * Recovery mode:
	 * NetBSD: IXGBE_FEATURE_RECOVERY_MODE will be controlled after reading
	 * NVM Image version.
	 */

	/* Enabled via global sysctl... */
	/* Flow Director */
	if (ixgbe_enable_fdir) {
		if (sc->feat_cap & IXGBE_FEATURE_FDIR)
			sc->feat_en |= IXGBE_FEATURE_FDIR;
		else
			device_printf(sc->dev, "Device does not support "
			    "Flow Director. Leaving disabled.");
	}
	/* Legacy (single queue) transmit */
	if ((sc->feat_cap & IXGBE_FEATURE_LEGACY_TX) &&
	    ixgbe_enable_legacy_tx)
		sc->feat_en |= IXGBE_FEATURE_LEGACY_TX;
	/*
	 * Message Signal Interrupts - Extended (MSI-X)
	 * Normal MSI is only enabled if MSI-X calls fail.
	 */
	if (!ixgbe_enable_msix)
		sc->feat_cap &= ~IXGBE_FEATURE_MSIX;
	/* Receive-Side Scaling (RSS) */
	if ((sc->feat_cap & IXGBE_FEATURE_RSS) && ixgbe_enable_rss)
		sc->feat_en |= IXGBE_FEATURE_RSS;

	/* Disable features with unmet dependencies... */
	/* No MSI-X */
	if (!(sc->feat_cap & IXGBE_FEATURE_MSIX)) {
		sc->feat_cap &= ~IXGBE_FEATURE_RSS;
		sc->feat_cap &= ~IXGBE_FEATURE_SRIOV;
		sc->feat_en &= ~IXGBE_FEATURE_RSS;
		sc->feat_en &= ~IXGBE_FEATURE_SRIOV;
	}
} /* ixgbe_init_device_features */

/************************************************************************
 * ixgbe_probe - Device identification routine
 *
 *   Determines if the driver should be loaded on
 *   adapter based on its PCI vendor/device ID.
 *
 *   return BUS_PROBE_DEFAULT on success, positive on failure
 ************************************************************************/
static int
ixgbe_probe(device_t dev, cfdata_t cf, void *aux)
{
	const struct pci_attach_args *pa = aux;

	return (ixgbe_lookup(pa) != NULL) ? 1 : 0;
}

static const ixgbe_vendor_info_t *
ixgbe_lookup(const struct pci_attach_args *pa)
{
	const ixgbe_vendor_info_t *ent;
	pcireg_t subid;

	INIT_DEBUGOUT("ixgbe_lookup: begin");

	if (PCI_VENDOR(pa->pa_id) != IXGBE_INTEL_VENDOR_ID)
		return NULL;

	subid = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_SUBSYS_ID_REG);

	for (ent = ixgbe_vendor_info_array; ent->vendor_id != 0; ent++) {
		if ((PCI_VENDOR(pa->pa_id) == ent->vendor_id) &&
		    (PCI_PRODUCT(pa->pa_id) == ent->device_id) &&
		    ((PCI_SUBSYS_VENDOR(subid) == ent->subvendor_id) ||
			(ent->subvendor_id == 0)) &&
		    ((PCI_SUBSYS_ID(subid) == ent->subdevice_id) ||
			(ent->subdevice_id == 0))) {
			return ent;
		}
	}
	return NULL;
}

static int
ixgbe_ifflags_cb(struct ethercom *ec)
{
	struct ifnet *ifp = &ec->ec_if;
	struct ixgbe_softc *sc = ifp->if_softc;
	u_short change;
	int rv = 0;

	IXGBE_CORE_LOCK(sc);

	change = ifp->if_flags ^ sc->if_flags;
	if (change != 0)
		sc->if_flags = ifp->if_flags;

	if ((change & ~(IFF_CANTCHANGE | IFF_DEBUG)) != 0) {
		rv = ENETRESET;
		goto out;
	} else if ((change & IFF_PROMISC) != 0)
		ixgbe_set_rxfilter(sc);

	/* Check for ec_capenable. */
	change = ec->ec_capenable ^ sc->ec_capenable;
	sc->ec_capenable = ec->ec_capenable;
	if ((change & ~(ETHERCAP_VLAN_MTU | ETHERCAP_VLAN_HWTAGGING
	    | ETHERCAP_VLAN_HWFILTER)) != 0) {
		rv = ENETRESET;
		goto out;
	}

	/*
	 * Special handling is not required for ETHERCAP_VLAN_MTU.
	 * MAXFRS(MHADD) does not include the 4bytes of the VLAN header.
	 */

	/* Set up VLAN support and filter */
	if ((change & (ETHERCAP_VLAN_HWTAGGING | ETHERCAP_VLAN_HWFILTER)) != 0)
		ixgbe_setup_vlan_hw_support(sc);

out:
	IXGBE_CORE_UNLOCK(sc);

	return rv;
}

/************************************************************************
 * ixgbe_ioctl - Ioctl entry point
 *
 *   Called when the user wants to configure the interface.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static int
ixgbe_ioctl(struct ifnet *ifp, u_long command, void *data)
{
	struct ixgbe_softc *sc = ifp->if_softc;
	struct ixgbe_hw *hw = &sc->hw;
	struct ifcapreq *ifcr = data;
	struct ifreq	*ifr = data;
	int		error = 0;
	int l4csum_en;
	const int l4csum = IFCAP_CSUM_TCPv4_Rx | IFCAP_CSUM_UDPv4_Rx |
	     IFCAP_CSUM_TCPv6_Rx | IFCAP_CSUM_UDPv6_Rx;

	if (ixgbe_fw_recovery_mode_swflag(sc))
		return (EPERM);

	switch (command) {
	case SIOCSIFFLAGS:
		IOCTL_DEBUGOUT("ioctl: SIOCSIFFLAGS (Set Interface Flags)");
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		IOCTL_DEBUGOUT("ioctl: SIOC(ADD|DEL)MULTI");
		break;
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		IOCTL_DEBUGOUT("ioctl: SIOCxIFMEDIA (Get/Set Interface Media)");
		break;
	case SIOCSIFCAP:
		IOCTL_DEBUGOUT("ioctl: SIOCSIFCAP (Set Capabilities)");
		break;
	case SIOCSIFMTU:
		IOCTL_DEBUGOUT("ioctl: SIOCSIFMTU (Set Interface MTU)");
		break;
#ifdef __NetBSD__
	case SIOCINITIFADDR:
		IOCTL_DEBUGOUT("ioctl: SIOCINITIFADDR");
		break;
	case SIOCGIFFLAGS:
		IOCTL_DEBUGOUT("ioctl: SIOCGIFFLAGS");
		break;
	case SIOCGIFAFLAG_IN:
		IOCTL_DEBUGOUT("ioctl: SIOCGIFAFLAG_IN");
		break;
	case SIOCGIFADDR:
		IOCTL_DEBUGOUT("ioctl: SIOCGIFADDR");
		break;
	case SIOCGIFMTU:
		IOCTL_DEBUGOUT("ioctl: SIOCGIFMTU (Get Interface MTU)");
		break;
	case SIOCGIFCAP:
		IOCTL_DEBUGOUT("ioctl: SIOCGIFCAP (Get IF cap)");
		break;
	case SIOCGETHERCAP:
		IOCTL_DEBUGOUT("ioctl: SIOCGETHERCAP (Get ethercap)");
		break;
	case SIOCGLIFADDR:
		IOCTL_DEBUGOUT("ioctl: SIOCGLIFADDR (Get Interface addr)");
		break;
	case SIOCZIFDATA:
		IOCTL_DEBUGOUT("ioctl: SIOCZIFDATA (Zero counter)");
		hw->mac.ops.clear_hw_cntrs(hw);
		ixgbe_clear_evcnt(sc);
		break;
	case SIOCAIFADDR:
		IOCTL_DEBUGOUT("ioctl: SIOCAIFADDR (add/chg IF alias)");
		break;
#endif
	default:
		IOCTL_DEBUGOUT1("ioctl: UNKNOWN (0x%X)", (int)command);
		break;
	}

	switch (command) {
	case SIOCGI2C:
	{
		struct ixgbe_i2c_req	i2c;

		IOCTL_DEBUGOUT("ioctl: SIOCGI2C (Get I2C Data)");
		error = copyin(ifr->ifr_data, &i2c, sizeof(i2c));
		if (error != 0)
			break;
		if (i2c.dev_addr != 0xA0 && i2c.dev_addr != 0xA2) {
			error = EINVAL;
			break;
		}
		if (i2c.len > sizeof(i2c.data)) {
			error = EINVAL;
			break;
		}

		hw->phy.ops.read_i2c_byte(hw, i2c.offset,
		    i2c.dev_addr, i2c.data);
		error = copyout(&i2c, ifr->ifr_data, sizeof(i2c));
		break;
	}
	case SIOCSIFCAP:
		/* Layer-4 Rx checksum offload has to be turned on and
		 * off as a unit.
		 */
		l4csum_en = ifcr->ifcr_capenable & l4csum;
		if (l4csum_en != l4csum && l4csum_en != 0)
			return EINVAL;
		/*FALLTHROUGH*/
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCSIFFLAGS:
	case SIOCSIFMTU:
	default:
		if ((error = ether_ioctl(ifp, command, data)) != ENETRESET)
			return error;
		if ((ifp->if_flags & IFF_RUNNING) == 0)
			;
		else if (command == SIOCSIFCAP || command == SIOCSIFMTU) {
			IXGBE_CORE_LOCK(sc);
			if ((ifp->if_flags & IFF_RUNNING) != 0)
				ixgbe_init_locked(sc);
			ixgbe_recalculate_max_frame(sc);
			IXGBE_CORE_UNLOCK(sc);
		} else if (command == SIOCADDMULTI || command == SIOCDELMULTI) {
			/*
			 * Multicast list has changed; set the hardware filter
			 * accordingly.
			 */
			IXGBE_CORE_LOCK(sc);
			ixgbe_disable_intr(sc);
			ixgbe_set_rxfilter(sc);
			ixgbe_enable_intr(sc);
			IXGBE_CORE_UNLOCK(sc);
		}
		return 0;
	}

	return error;
} /* ixgbe_ioctl */

/************************************************************************
 * ixgbe_check_fan_failure
 ************************************************************************/
static int
ixgbe_check_fan_failure(struct ixgbe_softc *sc, u32 reg, bool in_interrupt)
{
	u32 mask;

	mask = (in_interrupt) ? IXGBE_EICR_GPI_SDP1_BY_MAC(&sc->hw) :
	    IXGBE_ESDP_SDP1;

	if ((reg & mask) == 0)
		return IXGBE_SUCCESS;

	/*
	 * Use ratecheck() just in case interrupt occur frequently.
	 * When EXPX9501AT's fan stopped, interrupt occurred only once,
	 * an red LED on the board turned on and link never up until
	 * power off.
	 */
	if (ratecheck(&sc->lasterr_time, &ixgbe_errlog_intrvl))
		device_printf(sc->dev,
		    "\nCRITICAL: FAN FAILURE!! REPLACE IMMEDIATELY!!\n");

	return IXGBE_ERR_FAN_FAILURE;
} /* ixgbe_check_fan_failure */

/************************************************************************
 * ixgbe_handle_que
 ************************************************************************/
static void
ixgbe_handle_que(void *context)
{
	struct ix_queue *que = context;
	struct ixgbe_softc *sc = que->sc;
	struct tx_ring	*txr = que->txr;
	struct ifnet	*ifp = sc->ifp;
	bool		more = false;

	IXGBE_EVC_ADD(&que->handleq, 1);

	if (ifp->if_flags & IFF_RUNNING) {
		IXGBE_TX_LOCK(txr);
		more = ixgbe_txeof(txr);
		if (!(sc->feat_en & IXGBE_FEATURE_LEGACY_TX))
			if (!ixgbe_mq_ring_empty(ifp, txr->txr_interq))
				ixgbe_mq_start_locked(ifp, txr);
		/* Only for queue 0 */
		/* NetBSD still needs this for CBQ */
		if ((&sc->queues[0] == que)
		    && (!ixgbe_legacy_ring_empty(ifp, NULL)))
			ixgbe_legacy_start_locked(ifp, txr);
		IXGBE_TX_UNLOCK(txr);
		more |= ixgbe_rxeof(que);
	}

	if (more) {
		IXGBE_EVC_ADD(&que->req, 1);
		ixgbe_sched_handle_que(sc, que);
	} else if (que->res != NULL) {
		/* MSIX: Re-enable this interrupt */
		ixgbe_enable_queue(sc, que->msix);
	} else {
		/* INTx or MSI */
		ixgbe_enable_queue(sc, 0);
	}

	return;
} /* ixgbe_handle_que */

/************************************************************************
 * ixgbe_handle_que_work
 ************************************************************************/
static void
ixgbe_handle_que_work(struct work *wk, void *context)
{
	struct ix_queue *que = container_of(wk, struct ix_queue, wq_cookie);

	/*
	 * "enqueued flag" is not required here.
	 * See ixgbe_msix_que().
	 */
	ixgbe_handle_que(que);
}

/************************************************************************
 * ixgbe_allocate_legacy - Setup the Legacy or MSI Interrupt handler
 ************************************************************************/
static int
ixgbe_allocate_legacy(struct ixgbe_softc *sc,
    const struct pci_attach_args *pa)
{
	device_t	dev = sc->dev;
	struct ix_queue *que = sc->queues;
	struct tx_ring	*txr = sc->tx_rings;
	int		counts[PCI_INTR_TYPE_SIZE];
	pci_intr_type_t intr_type, max_type;
	char		intrbuf[PCI_INTRSTR_LEN];
	char		wqname[MAXCOMLEN];
	const char	*intrstr = NULL;
	int defertx_error = 0, error;

	/* We allocate a single interrupt resource */
	max_type = PCI_INTR_TYPE_MSI;
	counts[PCI_INTR_TYPE_MSIX] = 0;
	counts[PCI_INTR_TYPE_MSI] =
	    (sc->feat_en & IXGBE_FEATURE_MSI) ? 1 : 0;
	/* Check not feat_en but feat_cap to fallback to INTx */
	counts[PCI_INTR_TYPE_INTX] =
	    (sc->feat_cap & IXGBE_FEATURE_LEGACY_IRQ) ? 1 : 0;

alloc_retry:
	if (pci_intr_alloc(pa, &sc->osdep.intrs, counts, max_type) != 0) {
		aprint_error_dev(dev, "couldn't alloc interrupt\n");
		return ENXIO;
	}
	sc->osdep.nintrs = 1;
	intrstr = pci_intr_string(sc->osdep.pc, sc->osdep.intrs[0],
	    intrbuf, sizeof(intrbuf));
	sc->osdep.ihs[0] = pci_intr_establish_xname(sc->osdep.pc,
	    sc->osdep.intrs[0], IPL_NET, ixgbe_legacy_irq, que,
	    device_xname(dev));
	intr_type = pci_intr_type(sc->osdep.pc, sc->osdep.intrs[0]);
	if (sc->osdep.ihs[0] == NULL) {
		aprint_error_dev(dev,"unable to establish %s\n",
		    (intr_type == PCI_INTR_TYPE_MSI) ? "MSI" : "INTx");
		pci_intr_release(sc->osdep.pc, sc->osdep.intrs, 1);
		sc->osdep.intrs = NULL;
		switch (intr_type) {
		case PCI_INTR_TYPE_MSI:
			/* The next try is for INTx: Disable MSI */
			max_type = PCI_INTR_TYPE_INTX;
			counts[PCI_INTR_TYPE_INTX] = 1;
			sc->feat_en &= ~IXGBE_FEATURE_MSI;
			if (sc->feat_cap & IXGBE_FEATURE_LEGACY_IRQ) {
				sc->feat_en |= IXGBE_FEATURE_LEGACY_IRQ;
				goto alloc_retry;
			} else
				break;
		case PCI_INTR_TYPE_INTX:
		default:
			/* See below */
			break;
		}
	}
	if (intr_type == PCI_INTR_TYPE_INTX) {
		sc->feat_en &= ~IXGBE_FEATURE_MSI;
		sc->feat_en |= IXGBE_FEATURE_LEGACY_IRQ;
	}
	if (sc->osdep.ihs[0] == NULL) {
		aprint_error_dev(dev,
		    "couldn't establish interrupt%s%s\n",
		    intrstr ? " at " : "", intrstr ? intrstr : "");
		pci_intr_release(sc->osdep.pc, sc->osdep.intrs, 1);
		sc->osdep.intrs = NULL;
		return ENXIO;
	}
	aprint_normal_dev(dev, "interrupting at %s\n", intrstr);
	/*
	 * Try allocating a fast interrupt and the associated deferred
	 * processing contexts.
	 */
	if (!(sc->feat_en & IXGBE_FEATURE_LEGACY_TX)) {
		txr->txr_si =
		    softint_establish(SOFTINT_NET | SOFTINT_MPSAFE,
			ixgbe_deferred_mq_start, txr);

		snprintf(wqname, sizeof(wqname), "%sdeferTx",
		    device_xname(dev));
		defertx_error = workqueue_create(&sc->txr_wq, wqname,
		    ixgbe_deferred_mq_start_work, sc, IXGBE_WORKQUEUE_PRI,
		    IPL_NET, WQ_PERCPU | WQ_MPSAFE);
		sc->txr_wq_enqueued = percpu_alloc(sizeof(u_int));
	}
	que->que_si = softint_establish(SOFTINT_NET | SOFTINT_MPSAFE,
	    ixgbe_handle_que, que);
	snprintf(wqname, sizeof(wqname), "%sTxRx", device_xname(dev));
	error = workqueue_create(&sc->que_wq, wqname,
	    ixgbe_handle_que_work, sc, IXGBE_WORKQUEUE_PRI, IPL_NET,
	    WQ_PERCPU | WQ_MPSAFE);

	if ((!(sc->feat_en & IXGBE_FEATURE_LEGACY_TX)
		&& ((txr->txr_si == NULL) || defertx_error != 0))
	    || (que->que_si == NULL) || error != 0) {
		aprint_error_dev(dev,
		    "could not establish software interrupts\n");

		return ENXIO;
	}
	/* For simplicity in the handlers */
	sc->active_queues = IXGBE_EIMS_ENABLE_MASK;

	return (0);
} /* ixgbe_allocate_legacy */

/************************************************************************
 * ixgbe_allocate_msix - Setup MSI-X Interrupt resources and handlers
 ************************************************************************/
static int
ixgbe_allocate_msix(struct ixgbe_softc *sc, const struct pci_attach_args *pa)
{
	device_t	dev = sc->dev;
	struct ix_queue	*que = sc->queues;
	struct tx_ring	*txr = sc->tx_rings;
	pci_chipset_tag_t pc;
	char		intrbuf[PCI_INTRSTR_LEN];
	char		intr_xname[32];
	char		wqname[MAXCOMLEN];
	const char	*intrstr = NULL;
	int		error, vector = 0;
	int		cpu_id = 0;
	kcpuset_t	*affinity;
#ifdef RSS
	unsigned int	rss_buckets = 0;
	kcpuset_t	cpu_mask;
#endif

	pc = sc->osdep.pc;
#ifdef	RSS
	/*
	 * If we're doing RSS, the number of queues needs to
	 * match the number of RSS buckets that are configured.
	 *
	 * + If there's more queues than RSS buckets, we'll end
	 *   up with queues that get no traffic.
	 *
	 * + If there's more RSS buckets than queues, we'll end
	 *   up having multiple RSS buckets map to the same queue,
	 *   so there'll be some contention.
	 */
	rss_buckets = rss_getnumbuckets();
	if ((sc->feat_en & IXGBE_FEATURE_RSS) &&
	    (sc->num_queues != rss_buckets)) {
		device_printf(dev,
		    "%s: number of queues (%d) != number of RSS buckets (%d)"
		    "; performance will be impacted.\n",
		    __func__, sc->num_queues, rss_buckets);
	}
#endif

	sc->osdep.nintrs = sc->num_queues + 1;
	if (pci_msix_alloc_exact(pa, &sc->osdep.intrs,
	    sc->osdep.nintrs) != 0) {
		aprint_error_dev(dev,
		    "failed to allocate MSI-X interrupt\n");
		sc->feat_en &= ~IXGBE_FEATURE_MSIX;
		return (ENXIO);
	}

	kcpuset_create(&affinity, false);
	for (int i = 0; i < sc->num_queues; i++, vector++, que++, txr++) {
		snprintf(intr_xname, sizeof(intr_xname), "%s TXRX%d",
		    device_xname(dev), i);
		intrstr = pci_intr_string(pc, sc->osdep.intrs[i], intrbuf,
		    sizeof(intrbuf));
		pci_intr_setattr(pc, &sc->osdep.intrs[i], PCI_INTR_MPSAFE,
		    true);

		/* Set the handler function */
		que->res = sc->osdep.ihs[i] = pci_intr_establish_xname(pc,
		    sc->osdep.intrs[i], IPL_NET, ixgbe_msix_que, que,
		    intr_xname);
		if (que->res == NULL) {
			aprint_error_dev(dev,
			    "Failed to register QUE handler\n");
			error = ENXIO;
			goto err_out;
		}
		que->msix = vector;
		sc->active_queues |= 1ULL << que->msix;

		if (sc->feat_en & IXGBE_FEATURE_RSS) {
#ifdef	RSS
			/*
			 * The queue ID is used as the RSS layer bucket ID.
			 * We look up the queue ID -> RSS CPU ID and select
			 * that.
			 */
			cpu_id = rss_getcpu(i % rss_getnumbuckets());
			CPU_SETOF(cpu_id, &cpu_mask);
#endif
		} else {
			/*
			 * Bind the MSI-X vector, and thus the
			 * rings to the corresponding CPU.
			 *
			 * This just happens to match the default RSS
			 * round-robin bucket -> queue -> CPU allocation.
			 */
			if (sc->num_queues > 1)
				cpu_id = i;
		}
		/* Round-robin affinity */
		kcpuset_zero(affinity);
		kcpuset_set(affinity, cpu_id % ncpu);
		error = interrupt_distribute(sc->osdep.ihs[i], affinity,
		    NULL);
		aprint_normal_dev(dev, "for TX/RX, interrupting at %s",
		    intrstr);
		if (error == 0) {
#if 1 /* def IXGBE_DEBUG */
#ifdef	RSS
			aprint_normal(", bound RSS bucket %d to CPU %d", i,
			    cpu_id % ncpu);
#else
			aprint_normal(", bound queue %d to cpu %d", i,
			    cpu_id % ncpu);
#endif
#endif /* IXGBE_DEBUG */
		}
		aprint_normal("\n");

		if (!(sc->feat_en & IXGBE_FEATURE_LEGACY_TX)) {
			txr->txr_si = softint_establish(
				SOFTINT_NET | SOFTINT_MPSAFE,
				ixgbe_deferred_mq_start, txr);
			if (txr->txr_si == NULL) {
				aprint_error_dev(dev,
				    "couldn't establish software interrupt\n");
				error = ENXIO;
				goto err_out;
			}
		}
		que->que_si
		    = softint_establish(SOFTINT_NET | SOFTINT_MPSAFE,
			ixgbe_handle_que, que);
		if (que->que_si == NULL) {
			aprint_error_dev(dev,
			    "couldn't establish software interrupt\n");
			error = ENXIO;
			goto err_out;
		}
	}
	snprintf(wqname, sizeof(wqname), "%sdeferTx", device_xname(dev));
	error = workqueue_create(&sc->txr_wq, wqname,
	    ixgbe_deferred_mq_start_work, sc, IXGBE_WORKQUEUE_PRI, IPL_NET,
	    WQ_PERCPU | WQ_MPSAFE);
	if (error) {
		aprint_error_dev(dev,
		    "couldn't create workqueue for deferred Tx\n");
		goto err_out;
	}
	sc->txr_wq_enqueued = percpu_alloc(sizeof(u_int));

	snprintf(wqname, sizeof(wqname), "%sTxRx", device_xname(dev));
	error = workqueue_create(&sc->que_wq, wqname,
	    ixgbe_handle_que_work, sc, IXGBE_WORKQUEUE_PRI, IPL_NET,
	    WQ_PERCPU | WQ_MPSAFE);
	if (error) {
		aprint_error_dev(dev, "couldn't create workqueue for Tx/Rx\n");
		goto err_out;
	}

	/* and Link */
	cpu_id++;
	snprintf(intr_xname, sizeof(intr_xname), "%s link", device_xname(dev));
	sc->vector = vector;
	intrstr = pci_intr_string(pc, sc->osdep.intrs[vector], intrbuf,
	    sizeof(intrbuf));
	pci_intr_setattr(pc, &sc->osdep.intrs[vector], PCI_INTR_MPSAFE, true);

	/* Set the link handler function */
	sc->osdep.ihs[vector] = pci_intr_establish_xname(pc,
	    sc->osdep.intrs[vector], IPL_NET, ixgbe_msix_admin, sc,
	    intr_xname);
	if (sc->osdep.ihs[vector] == NULL) {
		aprint_error_dev(dev, "Failed to register LINK handler\n");
		error = ENXIO;
		goto err_out;
	}
	/* Round-robin affinity */
	kcpuset_zero(affinity);
	kcpuset_set(affinity, cpu_id % ncpu);
	error = interrupt_distribute(sc->osdep.ihs[vector], affinity,
	    NULL);

	aprint_normal_dev(dev,
	    "for link, interrupting at %s", intrstr);
	if (error == 0)
		aprint_normal(", affinity to cpu %d\n", cpu_id % ncpu);
	else
		aprint_normal("\n");

	kcpuset_destroy(affinity);
	aprint_normal_dev(dev,
	    "Using MSI-X interrupts with %d vectors\n", vector + 1);

	return (0);

err_out:
	kcpuset_destroy(affinity);
	ixgbe_free_deferred_handlers(sc);
	ixgbe_free_pciintr_resources(sc);
	return (error);
} /* ixgbe_allocate_msix */

/************************************************************************
 * ixgbe_configure_interrupts
 *
 *   Setup MSI-X, MSI, or legacy interrupts (in that order).
 *   This will also depend on user settings.
 ************************************************************************/
static int
ixgbe_configure_interrupts(struct ixgbe_softc *sc)
{
	device_t dev = sc->dev;
	struct ixgbe_mac_info *mac = &sc->hw.mac;
	int want, queues, msgs;

	/* Default to 1 queue if MSI-X setup fails */
	sc->num_queues = 1;

	/* Override by tuneable */
	if (!(sc->feat_cap & IXGBE_FEATURE_MSIX))
		goto msi;

	/*
	 *  NetBSD only: Use single vector MSI when number of CPU is 1 to save
	 * interrupt slot.
	 */
	if (ncpu == 1)
		goto msi;

	/* First try MSI-X */
	msgs = pci_msix_count(sc->osdep.pc, sc->osdep.tag);
	msgs = MIN(msgs, IXG_MAX_NINTR);
	if (msgs < 2)
		goto msi;

	sc->feat_en |= IXGBE_FEATURE_MSIX;

	/* Figure out a reasonable auto config value */
	queues = (ncpu > (msgs - 1)) ? (msgs - 1) : ncpu;

#ifdef	RSS
	/* If we're doing RSS, clamp at the number of RSS buckets */
	if (sc->feat_en & IXGBE_FEATURE_RSS)
		queues = uimin(queues, rss_getnumbuckets());
#endif
	if (ixgbe_num_queues > queues) {
		aprint_error_dev(sc->dev,
		    "ixgbe_num_queues (%d) is too large, "
		    "using reduced amount (%d).\n", ixgbe_num_queues, queues);
		ixgbe_num_queues = queues;
	}

	if (ixgbe_num_queues != 0)
		queues = ixgbe_num_queues;
	else
		queues = uimin(queues,
		    uimin(mac->max_tx_queues, mac->max_rx_queues));

	/*
	 * Want one vector (RX/TX pair) per queue
	 * plus an additional for Link.
	 */
	want = queues + 1;
	if (msgs >= want)
		msgs = want;
	else {
		aprint_error_dev(dev, "MSI-X Configuration Problem, "
		    "%d vectors but %d queues wanted!\n", msgs, want);
		goto msi;
	}
	sc->num_queues = queues;
	sc->feat_en |= IXGBE_FEATURE_MSIX;
	return (0);

	/*
	 * MSI-X allocation failed or provided us with
	 * less vectors than needed. Free MSI-X resources
	 * and we'll try enabling MSI.
	 */
msi:
	/* Without MSI-X, some features are no longer supported */
	sc->feat_cap &= ~IXGBE_FEATURE_RSS;
	sc->feat_en  &= ~IXGBE_FEATURE_RSS;
	sc->feat_cap &= ~IXGBE_FEATURE_SRIOV;
	sc->feat_en  &= ~IXGBE_FEATURE_SRIOV;

	msgs = pci_msi_count(sc->osdep.pc, sc->osdep.tag);
	sc->feat_en &= ~IXGBE_FEATURE_MSIX;
	if (msgs > 1)
		msgs = 1;
	if (msgs != 0) {
		msgs = 1;
		sc->feat_en |= IXGBE_FEATURE_MSI;
		return (0);
	}

	if (!(sc->feat_cap & IXGBE_FEATURE_LEGACY_IRQ)) {
		aprint_error_dev(dev,
		    "Device does not support legacy interrupts.\n");
		return 1;
	}

	sc->feat_en |= IXGBE_FEATURE_LEGACY_IRQ;

	return (0);
} /* ixgbe_configure_interrupts */


/************************************************************************
 * ixgbe_handle_link - Tasklet for MSI-X Link interrupts
 *
 *   Done outside of interrupt context since the driver might sleep
 ************************************************************************/
static void
ixgbe_handle_link(void *context)
{
	struct ixgbe_softc *sc = context;
	struct ixgbe_hw *hw = &sc->hw;

	KASSERT(mutex_owned(&sc->core_mtx));

	IXGBE_EVC_ADD(&sc->link_workev, 1);
	ixgbe_check_link(hw, &sc->link_speed, &sc->link_up, 0);
	ixgbe_update_link_status(sc);

	/* Re-enable link interrupts */
	IXGBE_WRITE_REG(hw, IXGBE_EIMS, IXGBE_EIMS_LSC);
} /* ixgbe_handle_link */

#if 0
/************************************************************************
 * ixgbe_rearm_queues
 ************************************************************************/
static __inline void
ixgbe_rearm_queues(struct ixgbe_softc *sc, u64 queues)
{
	u32 mask;

	switch (sc->hw.mac.type) {
	case ixgbe_mac_82598EB:
		mask = (IXGBE_EIMS_RTX_QUEUE & queues);
		IXGBE_WRITE_REG(&sc->hw, IXGBE_EICS, mask);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
		mask = (queues & 0xFFFFFFFF);
		IXGBE_WRITE_REG(&sc->hw, IXGBE_EICS_EX(0), mask);
		mask = (queues >> 32);
		IXGBE_WRITE_REG(&sc->hw, IXGBE_EICS_EX(1), mask);
		break;
	default:
		break;
	}
} /* ixgbe_rearm_queues */
#endif
