/* $NetBSD: mesong12_clkc.h,v 1.2 2024/02/07 04:20:26 msaitoh Exp $ */

/*
 * Copyright (c) 2021 Ryo Shimizu
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MESONG12_CLKC_H
#define _MESONG12_CLKC_H

/*
 * CLOCK IDs.
 *  The values are matched to those in dt-bindings/clock/g12a-clkc.h ,
 *  but some are only defined locally.
 */
#define MESONG12_CLOCK_SYS_PLL		0
#define MESONG12_CLOCK_FIXED_PLL	1
#define MESONG12_CLOCK_FCLK_DIV2	2
#define MESONG12_CLOCK_FCLK_DIV3	3
#define MESONG12_CLOCK_FCLK_DIV4	4
#define MESONG12_CLOCK_FCLK_DIV5	5
#define MESONG12_CLOCK_FCLK_DIV7	6
#define MESONG12_CLOCK_GP0_PLL		7

#define MESONG12_CLOCK_CLK81		10
#define MESONG12_CLOCK_MPLL0		11
#define MESONG12_CLOCK_MPLL1		12
#define MESONG12_CLOCK_MPLL2		13
#define MESONG12_CLOCK_MPLL3		14
#define MESONG12_CLOCK_DDR		15
#define MESONG12_CLOCK_DOS		16
#define MESONG12_CLOCK_AUDIO_LOCKER	17
#define MESONG12_CLOCK_MIPI_DSI_HOST	18
#define MESONG12_CLOCK_ETH_PHY		19
#define MESONG12_CLOCK_ISA		20
#define MESONG12_CLOCK_PL301		21
#define MESONG12_CLOCK_PERIPHS		22
#define MESONG12_CLOCK_SPICC0		23
#define MESONG12_CLOCK_I2C		24
#define MESONG12_CLOCK_SANA		25
#define MESONG12_CLOCK_SD		26
#define MESONG12_CLOCK_RNG0		27
#define MESONG12_CLOCK_UART0		28
#define MESONG12_CLOCK_SPICC1		29
#define MESONG12_CLOCK_HIU_IFACE	30
#define MESONG12_CLOCK_MIPI_DSI_PHY	31
#define MESONG12_CLOCK_ASSIST_MISC	32
#define MESONG12_CLOCK_SD_EMMC_A	33
#define MESONG12_CLOCK_SD_EMMC_B	34
#define MESONG12_CLOCK_SD_EMMC_C	35
#define MESONG12_CLOCK_AUDIO_CODEC	36
#define MESONG12_CLOCK_AUDIO		37
#define MESONG12_CLOCK_ETH		38
#define MESONG12_CLOCK_DEMUX		39
#define MESONG12_CLOCK_AUDIO_IFIFO	40
#define MESONG12_CLOCK_ADC		41
#define MESONG12_CLOCK_UART1		42
#define MESONG12_CLOCK_G2D		43
#define MESONG12_CLOCK_RESET		44
#define MESONG12_CLOCK_PCIE_COMB	45
#define MESONG12_CLOCK_PARSER		46
#define MESONG12_CLOCK_USB		47
#define MESONG12_CLOCK_PCIE_PHY		48
#define MESONG12_CLOCK_AHB_ARB0		49
#define MESONG12_CLOCK_AHB_DATA_BUS	50
#define MESONG12_CLOCK_AHB_CTRL_BUS	51
#define MESONG12_CLOCK_HTX_HDCP22	52
#define MESONG12_CLOCK_HTX_PCLK		53
#define MESONG12_CLOCK_BT656		54
#define MESONG12_CLOCK_USB1_DDR_BRIDGE	55
#define MESONG12_CLOCK_MMC_PCLK		56
#define MESONG12_CLOCK_UART2		57
#define MESONG12_CLOCK_VPU_INTR		58
#define MESONG12_CLOCK_GIC		59
#define MESONG12_CLOCK_SD_EMMC_A_CLK0	60
#define MESONG12_CLOCK_SD_EMMC_B_CLK0	61
#define MESONG12_CLOCK_SD_EMMC_C_CLK0	62

#define MESONG12_CLOCK_HIFI_PLL		74

#define MESONG12_CLOCK_VCLK2_VENCI0	80
#define MESONG12_CLOCK_VCLK2_VENCI1	81
#define MESONG12_CLOCK_VCLK2_VENCP0	82
#define MESONG12_CLOCK_VCLK2_VENCP1	83
#define MESONG12_CLOCK_VCLK2_VENCT0	84
#define MESONG12_CLOCK_VCLK2_VENCT1	85
#define MESONG12_CLOCK_VCLK2_OTHER	86
#define MESONG12_CLOCK_VCLK2_ENCI	87
#define MESONG12_CLOCK_VCLK2_ENCP	88
#define MESONG12_CLOCK_DAC_CLK		89
#define MESONG12_CLOCK_AOCLK		90
#define MESONG12_CLOCK_IEC958		91
#define MESONG12_CLOCK_ENC480P		92
#define MESONG12_CLOCK_RNG1		93
#define MESONG12_CLOCK_VCLK2_ENCT	94
#define MESONG12_CLOCK_VCLK2_ENCL	95
#define MESONG12_CLOCK_VCLK2_VENCLMMC	96
#define MESONG12_CLOCK_VCLK2_VENCL	97
#define MESONG12_CLOCK_VCLK2_OTHER1	98
#define MESONG12_CLOCK_FCLK_DIV2P5	99

#define MESONG12_CLOCK_DMA		105
#define MESONG12_CLOCK_EFUSE		106
#define MESONG12_CLOCK_ROM_BOOT		107
#define MESONG12_CLOCK_RESET_SEC	108
#define MESONG12_CLOCK_SEC_AHB_APB3	109
#define MESONG12_CLOCK_VPU_0_SEL	110

#define MESONG12_CLOCK_VPU_0		112
#define MESONG12_CLOCK_VPU_1_SEL	113

#define MESONG12_CLOCK_VPU_1		115
#define MESONG12_CLOCK_VPU		116
#define MESONG12_CLOCK_VAPB_0_SEL	117

#define MESONG12_CLOCK_VAPB_0		119
#define MESONG12_CLOCK_VAPB_1_SEL	120

#define MESONG12_CLOCK_VAPB_1		122
#define MESONG12_CLOCK_VAPB_SEL		123
#define MESONG12_CLOCK_VAPB		124

#define MESONG12_CLOCK_HDMI_PLL		128
#define MESONG12_CLOCK_VID_PLL		129

#define MESONG12_CLOCK_VCLK		138
#define MESONG12_CLOCK_VCLK2		139

#define MESONG12_CLOCK_VCLK_DIV1	148
#define MESONG12_CLOCK_VCLK_DIV2	149
#define MESONG12_CLOCK_VCLK_DIV4	150
#define MESONG12_CLOCK_VCLK_DIV6	151
#define MESONG12_CLOCK_VCLK_DIV12	152
#define MESONG12_CLOCK_VCLK2_DIV1	153
#define MESONG12_CLOCK_VCLK2_DIV2	154
#define MESONG12_CLOCK_VCLK2_DIV4	155
#define MESONG12_CLOCK_VCLK2_DIV6	156
#define MESONG12_CLOCK_VCLK2_DIV12	157

#define MESONG12_CLOCK_CTS_ENCI		162
#define MESONG12_CLOCK_CTS_ENCP		163
#define MESONG12_CLOCK_CTS_VDAC		164
#define MESONG12_CLOCK_HDMI_TX		165

#define MESONG12_CLOCK_HDMI		168
#define MESONG12_CLOCK_MALI_0_SEL	169

#define MESONG12_CLOCK_MALI_0		171
#define MESONG12_CLOCK_MALI_1_SEL	172

#define MESONG12_CLOCK_MALI_1		174
#define MESONG12_CLOCK_MALI		175

#define MESONG12_CLOCK_MPLL_50M		177

#define MESONG12_CLOCK_CPU_CLK		187

#define MESONG12_CLOCK_PCIE_PLL		201

#define MESONG12_CLOCK_VDEC_1		204

#define MESONG12_CLOCK_VDEC_HEVC	207

#define MESONG12_CLOCK_VDEC_HEVCF	210

#define MESONG12_CLOCK_TS		212

#define MESONG12_CLOCK_CPUB_CLK		224

#define MESONG12_CLOCK_GP1_PLL		243

#define MESONG12_CLOCK_DSU_CLK		252
#define MESONG12_CLOCK_CPU1_CLK		253
#define MESONG12_CLOCK_CPU2_CLK		254
#define MESONG12_CLOCK_CPU3_CLK		255


/*
 * locally defined
 */
#define MESONG12_CLOCK_MPEG_SEL				8
#define MESONG12_CLOCK_MPEG_DIV				9

#define MESONG12_CLOCK_SD_EMMC_A_CLK0_SEL		63
#define MESONG12_CLOCK_SD_EMMC_A_CLK0_DIV		64
#define MESONG12_CLOCK_SD_EMMC_B_CLK0_SEL		65
#define MESONG12_CLOCK_SD_EMMC_B_CLK0_DIV		66
#define MESONG12_CLOCK_SD_EMMC_C_CLK0_SEL		67
#define MESONG12_CLOCK_SD_EMMC_C_CLK0_DIV		68
#define MESONG12_CLOCK_MPLL0_DIV			69
#define MESONG12_CLOCK_MPLL1_DIV			70
#define MESONG12_CLOCK_MPLL2_DIV			71
#define MESONG12_CLOCK_MPLL3_DIV			72
#define MESONG12_CLOCK_MPLL_PREDIV			73
#define MESONG12_CLOCK_FCLK_DIV2_DIV			75
#define MESONG12_CLOCK_FCLK_DIV3_DIV			76
#define MESONG12_CLOCK_FCLK_DIV4_DIV			77
#define MESONG12_CLOCK_FCLK_DIV5_DIV			78
#define MESONG12_CLOCK_FCLK_DIV7_DIV			79
#define MESONG12_CLOCK_FCLK_DIV2P5_DIV			100
#define MESONG12_CLOCK_FIXED_PLL_DCO			101
#define MESONG12_CLOCK_SYS_PLL_DCO			102
#define MESONG12_CLOCK_GP0_PLL_DCO			103
#define MESONG12_CLOCK_HIFI_PLL_DCO			104
#define MESONG12_CLOCK_VPU_0_DIV			111
#define MESONG12_CLOCK_VPU_1_DIV			114
#define MESONG12_CLOCK_VAPB_0_DIV			118
#define MESONG12_CLOCK_VAPB_1_DIV			121
#define MESONG12_CLOCK_HDMI_PLL_DCO			125
#define MESONG12_CLOCK_HDMI_PLL_OD			126
#define MESONG12_CLOCK_HDMI_PLL_OD2			127
#define MESONG12_CLOCK_VID_PLL_SEL			130
#define MESONG12_CLOCK_VID_PLL_DIV			131
#define MESONG12_CLOCK_VCLK_SEL				132
#define MESONG12_CLOCK_VCLK2_SEL			133
#define MESONG12_CLOCK_VCLK_INPUT			134
#define MESONG12_CLOCK_VCLK2_INPUT			135
#define MESONG12_CLOCK_VCLK_DIV				136
#define MESONG12_CLOCK_VCLK2_DIV			137
#define MESONG12_CLOCK_VCLK_DIV2_EN			140
#define MESONG12_CLOCK_VCLK_DIV4_EN			141
#define MESONG12_CLOCK_VCLK_DIV6_EN			142
#define MESONG12_CLOCK_VCLK_DIV12_EN			143
#define MESONG12_CLOCK_VCLK2_DIV2_EN			144
#define MESONG12_CLOCK_VCLK2_DIV4_EN			145
#define MESONG12_CLOCK_VCLK2_DIV6_EN			146
#define MESONG12_CLOCK_VCLK2_DIV12_EN			147
#define MESONG12_CLOCK_CTS_ENCI_SEL			158
#define MESONG12_CLOCK_CTS_ENCP_SEL			159
#define MESONG12_CLOCK_CTS_VDAC_SEL			160
#define MESONG12_CLOCK_HDMI_TX_SEL			161
#define MESONG12_CLOCK_HDMI_SEL				166
#define MESONG12_CLOCK_HDMI_DIV				167
#define MESONG12_CLOCK_MALI_0_DIV			170
#define MESONG12_CLOCK_MALI_1_DIV			173
#define MESONG12_CLOCK_MPLL_50M_DIV			176
#define MESONG12_CLOCK_SYS_PLL_DIV16_EN			178
#define MESONG12_CLOCK_SYS_PLL_DIV16			179
#define MESONG12_CLOCK_CPU_CLK_DYN0_SEL			180
#define MESONG12_CLOCK_CPU_CLK_DYN0_DIV			181
#define MESONG12_CLOCK_CPU_CLK_DYN0			182
#define MESONG12_CLOCK_CPU_CLK_DYN1_SEL			183
#define MESONG12_CLOCK_CPU_CLK_DYN1_DIV			184
#define MESONG12_CLOCK_CPU_CLK_DYN1			185
#define MESONG12_CLOCK_CPU_CLK_DYN			186
#define MESONG12_CLOCK_CPU_CLK_DIV16_EN			188
#define MESONG12_CLOCK_CPU_CLK_DIV16			189
#define MESONG12_CLOCK_CPU_CLK_APB_DIV			190
#define MESONG12_CLOCK_CPU_CLK_APB			191
#define MESONG12_CLOCK_CPU_CLK_ATB_DIV			192
#define MESONG12_CLOCK_CPU_CLK_ATB			193
#define MESONG12_CLOCK_CPU_CLK_AXI_DIV			194
#define MESONG12_CLOCK_CPU_CLK_AXI			195
#define MESONG12_CLOCK_CPU_CLK_TRACE_DIV		196
#define MESONG12_CLOCK_CPU_CLK_TRACE			197
#define MESONG12_CLOCK_PCIE_PLL_DCO			198
#define MESONG12_CLOCK_PCIE_PLL_DCO_DIV2		199
#define MESONG12_CLOCK_PCIE_PLL_OD			200
#define MESONG12_CLOCK_VDEC_1_SEL			202
#define MESONG12_CLOCK_VDEC_1_DIV			203
#define MESONG12_CLOCK_VDEC_HEVC_SEL			205
#define MESONG12_CLOCK_VDEC_HEVC_DIV			206
#define MESONG12_CLOCK_VDEC_HEVCF_SEL			208
#define MESONG12_CLOCK_VDEC_HEVCF_DIV			209
#define MESONG12_CLOCK_TS_DIV				211
#define MESONG12_CLOCK_SYS1_PLL_DCO			213
#define MESONG12_CLOCK_SYS1_PLL				214
#define MESONG12_CLOCK_SYS1_PLL_DIV16_EN		215
#define MESONG12_CLOCK_SYS1_PLL_DIV16			216
#define MESONG12_CLOCK_CPUB_CLK_DYN0_SEL		217
#define MESONG12_CLOCK_CPUB_CLK_DYN0_DIV		218
#define MESONG12_CLOCK_CPUB_CLK_DYN0			219
#define MESONG12_CLOCK_CPUB_CLK_DYN1_SEL		220
#define MESONG12_CLOCK_CPUB_CLK_DYN1_DIV		221
#define MESONG12_CLOCK_CPUB_CLK_DYN1			222
#define MESONG12_CLOCK_CPUB_CLK_DYN			223
#define MESONG12_CLOCK_CPUB_CLK_DIV16_EN		225
#define MESONG12_CLOCK_CPUB_CLK_DIV16			226
#define MESONG12_CLOCK_CPUB_CLK_DIV2			227
#define MESONG12_CLOCK_CPUB_CLK_DIV3			228
#define MESONG12_CLOCK_CPUB_CLK_DIV4			229
#define MESONG12_CLOCK_CPUB_CLK_DIV5			230
#define MESONG12_CLOCK_CPUB_CLK_DIV6			231
#define MESONG12_CLOCK_CPUB_CLK_DIV7			232
#define MESONG12_CLOCK_CPUB_CLK_DIV8			233
#define MESONG12_CLOCK_CPUB_CLK_APB_SEL			234
#define MESONG12_CLOCK_CPUB_CLK_APB			235
#define MESONG12_CLOCK_CPUB_CLK_ATB_SEL			236
#define MESONG12_CLOCK_CPUB_CLK_ATB			237
#define MESONG12_CLOCK_CPUB_CLK_AXI_SEL			238
#define MESONG12_CLOCK_CPUB_CLK_AXI			239
#define MESONG12_CLOCK_CPUB_CLK_TRACE_SEL		240
#define MESONG12_CLOCK_CPUB_CLK_TRACE			241
#define MESONG12_CLOCK_GP1_PLL_DCO			242
#define MESONG12_CLOCK_DSU_CLK_DYN0_SEL			244
#define MESONG12_CLOCK_DSU_CLK_DYN0_DIV			245
#define MESONG12_CLOCK_DSU_CLK_DYN0			246
#define MESONG12_CLOCK_DSU_CLK_DYN1_SEL			247
#define MESONG12_CLOCK_DSU_CLK_DYN1_DIV			248
#define MESONG12_CLOCK_DSU_CLK_DYN1			249
#define MESONG12_CLOCK_DSU_CLK_DYN			250
#define MESONG12_CLOCK_DSU_CLK_FINAL			251
#define MESONG12_CLOCK_SPICC0_SCLK_SEL			256
#define MESONG12_CLOCK_SPICC0_SCLK_DIV			257
#define MESONG12_CLOCK_SPICC1_SCLK_SEL			259
#define MESONG12_CLOCK_SPICC1_SCLK_DIV			260
#define MESONG12_CLOCK_NNA_AXI_CLK_SEL			262
#define MESONG12_CLOCK_NNA_AXI_CLK_DIV			263
#define MESONG12_CLOCK_NNA_CORE_CLK_SEL			265
#define MESONG12_CLOCK_NNA_CORE_CLK_DIV			266


#endif /* _MESONG12_CLKC_H */
