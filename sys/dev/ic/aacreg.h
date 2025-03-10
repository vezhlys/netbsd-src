/*	$NetBSD: aacreg.h,v 1.15 2024/02/02 22:19:13 andvar Exp $	*/

/*-
 * Copyright (c) 2002, 2007 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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

/*-
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2000-2001 Scott Long
 * Copyright (c) 2000 BSDi
 * Copyright (c) 2000 Niklas Hallqvist
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from FreeBSD: aacreg.h,v 1.1 2000/09/13 03:20:34 msmith Exp
 * via OpenBSD: aacreg.h,v 1.3 2001/06/12 15:40:29 niklas Exp
 * incorporating some of: aacreg.h,v 1.23 2005/10/14 16:22:45 scottl Exp
 */

/*
 * Data structures defining the interface between the driver and the Adaptec
 * 'FSA' adapters.  Note that many field names and comments here are taken
 * verbatim from the Adaptec driver source in order to make comparing the
 * two slightly easier.
 */

#ifndef _PCI_AACREG_H_
#define	_PCI_AACREG_H_

/*
 * Misc. magic numbers.
 */
#define	AAC_MAX_CONTAINERS	64
#define	AAC_BLOCK_SIZE		512

/*
 * Communications interface.
 *
 * Where datastructure layouts are closely parallel to the Adaptec sample code,
 * retain their naming conventions (for now) to aid in cross-referencing.
 */

/*
 * We establish 4 command queues and matching response queues.  Queues must
 * be 16-byte aligned, and are sized as follows:
 */
#define	AAC_HOST_NORM_CMD_ENTRIES	8	/* cmd adapter->host, normal pri */
#define	AAC_HOST_HIGH_CMD_ENTRIES	4	/* cmd adapter->host, high pri */
#define	AAC_ADAP_NORM_CMD_ENTRIES	512	/* cmd host->adapter, normal pri */
#define	AAC_ADAP_HIGH_CMD_ENTRIES	4	/* cmd host->adapter, high pri */
#define	AAC_HOST_NORM_RESP_ENTRIES	512	/* resp, adapter->host, normal pri */
#define	AAC_HOST_HIGH_RESP_ENTRIES	4	/* resp, adapter->host, high pri */
#define	AAC_ADAP_NORM_RESP_ENTRIES	8	/* resp, host->adapter, normal pri */
#define	AAC_ADAP_HIGH_RESP_ENTRIES	4	/* resp, host->adapter, high pri */

#define	AAC_TOTALQ_LENGTH \
    (AAC_HOST_HIGH_CMD_ENTRIES + AAC_HOST_NORM_CMD_ENTRIES + \
    AAC_ADAP_HIGH_CMD_ENTRIES +	AAC_ADAP_NORM_CMD_ENTRIES + \
    AAC_HOST_HIGH_RESP_ENTRIES + AAC_HOST_NORM_RESP_ENTRIES + \
    AAC_ADAP_HIGH_RESP_ENTRIES + AAC_ADAP_NORM_RESP_ENTRIES)

#define	AAC_QUEUE_COUNT		8
#define	AAC_QUEUE_ALIGN		16

struct aac_queue_entry {
	u_int32_t aq_fib_size;		/* FIB size in bytes */
	u_int32_t aq_fib_addr;		/* receiver-space address of the FIB */
} __packed;

#define	AAC_PRODUCER_INDEX	0
#define	AAC_CONSUMER_INDEX	1

/*
 * Table of queue indices and queues used to communicate with the
 * controller.  This structure must be aligned to AAC_QUEUE_ALIGN
 */
struct aac_queue_table {
	/* queue consumer/producer indexes (layout mandated by adapter) */
	u_int32_t qt_qindex[AAC_QUEUE_COUNT][2];

	/* queue entry structures (layout mandated by adapter) */
	struct aac_queue_entry qt_HostNormCmdQueue[AAC_HOST_NORM_CMD_ENTRIES];
	struct aac_queue_entry qt_HostHighCmdQueue[AAC_HOST_HIGH_CMD_ENTRIES];
	struct aac_queue_entry qt_AdapNormCmdQueue[AAC_ADAP_NORM_CMD_ENTRIES];
	struct aac_queue_entry qt_AdapHighCmdQueue[AAC_ADAP_HIGH_CMD_ENTRIES];
	struct aac_queue_entry
	    qt_HostNormRespQueue[AAC_HOST_NORM_RESP_ENTRIES];
	struct aac_queue_entry
	    qt_HostHighRespQueue[AAC_HOST_HIGH_RESP_ENTRIES];
	struct aac_queue_entry
	    qt_AdapNormRespQueue[AAC_ADAP_NORM_RESP_ENTRIES];
	struct aac_queue_entry
	    qt_AdapHighRespQueue[AAC_ADAP_HIGH_RESP_ENTRIES];
} __packed;

/*
 * Adapter Init Structure: this is passed to the adapter with the
 * AAC_MONKER_INITSTRUCT command to point it at our control structures.
 */
struct aac_adapter_init {
	u_int32_t InitStructRevision;
	u_int32_t MiniPortRevision;
	u_int32_t FilesystemRevision;
	u_int32_t CommHeaderAddress;
	u_int32_t FastIoCommAreaAddress;
	u_int32_t AdapterFibsPhysicalAddress;
	u_int32_t AdapterFibsVirtualAddress;
	u_int32_t AdapterFibsSize;
	u_int32_t AdapterFibAlign;
	u_int32_t PrintfBufferAddress;
	u_int32_t PrintfBufferSize;
	u_int32_t HostPhysMemPages;
	u_int32_t HostElapsedSeconds;
	/* ADAPTER_INIT_STRUCT_REVISION_4 begins here */
	u_int32_t InitFlags;		/* flags for supported features */
	u_int32_t MaxIoCommands;	/* max outstanding commands */
	u_int32_t MaxIoSize;		/* largest I/O command */
	u_int32_t MaxFibSize;		/* largest FIB to adapter */
} __packed;

#define	AAC_INIT_STRUCT_REVISION		3
#define	AAC_INIT_STRUCT_REVISION_4		4
#define	AAC_INIT_STRUCT_MINIPORT_REVISION	1
#define AAC_INITFLAGS_NEW_COMM_SUPPORTED	1
#define AAC_PAGE_SIZE		4096	/* Used to set HostPhysMemPages */

/*
 * Shared data types
 */

/*
 * Container types
 */
#define	CT_NONE			0
#define	CT_VOLUME		1
#define	CT_MIRROR		2
#define	CT_STRIPE		3
#define	CT_RAID5		4
#define	CT_SSRW			5
#define	CT_SSRO			6
#define	CT_MORPH		7
#define	CT_PASSTHRU		8
#define	CT_RAID4		9
#define	CT_RAID10		10	/* stripe of mirror */
#define	CT_RAID00		11	/* stripe of stripe */
#define	CT_VOLUME_OF_MIRRORS	12	/* volume of mirror */
#define	CT_PSEUDO_RAID3		13	/* really raid4 */
#define	CT_RAID50		14	/* stripe of raid5 */
#define	CT_RAID5D		15	/* raid5 distributed hot-sparing */
#define	CT_RAID5D0		16
#define	CT_RAID1E		17	/* extended raid1 mirroring */
#define	CT_RAID6		18
#define	CT_RAID60		19

/*
 * Host-addressable object types
 */
#define	FT_REG			1	/* regular file */
#define	FT_DIR			2	/* directory */
#define	FT_BLK			3	/* "block" device - reserved */
#define	FT_CHR			4	/* "character special" device - reserved */
#define	FT_LNK			5	/* symbolic link */
#define	FT_SOCK			6	/* socket */
#define	FT_FIFO			7	/* fifo */
#define	FT_FILESYS		8	/* ADAPTEC's "FSA"(tm) filesystem */
#define	FT_DRIVE		9	/* phys disk - addressable in scsi by bus/target/lun */
#define	FT_SLICE		10	/* virtual disk - raw volume - slice */
#define	FT_PARTITION		11	/* FSA part, inside slice, container building block */
#define	FT_VOLUME		12	/* Container - Volume Set */
#define	FT_STRIPE		13	/* Container - Stripe Set */
#define	FT_MIRROR		14	/* Container - Mirror Set */
#define	FT_RAID5		15	/* Container - Raid 5 Set */
#define	FT_DATABASE		16	/* Storage object with "foreign" content manager */

/*
 * Host-side scatter/gather list for raw commands.
 */
struct aac_sg_entryraw {
	u_int32_t Next;		/* reserved for FW use */
	u_int32_t Prev;		/* reserved for FW use */
	u_int64_t SgAddress;
	u_int32_t SgByteCount;
	u_int32_t Flags;	/* reserved for FW use */
} __packed;

struct aac_sg_tableraw {
	u_int32_t SgCount;
	struct aac_sg_entryraw SgEntryRaw[0];
} __packed;

/*
 * Host-side scatter/gather list for 32-bit commands.
 */
struct aac_sg_entry {
	u_int32_t SgAddress;
	u_int32_t SgByteCount;
} __packed;

struct aac_sg_table {
	u_int32_t SgCount;
	struct aac_sg_entry SgEntry[0];
} __packed;

/*
 * Host-side scatter/gather list for 64-bit commands.
 */
struct aac_sg_entry64 {
	u_int64_t SgAddress;
	u_int32_t SgByteCount;
} __packed;

struct aac_sg_table64 {
	u_int32_t SgCount;
	struct aac_sg_entry64	SgEntry64[0];
} __packed;

/*
 * Container creation data
 */
struct aac_container_creation {
	u_int8_t ViaBuildNumber;
	u_int8_t MicroSecond;
	u_int8_t Via;			/* 1 = FSU, 2 = API, etc. */
	u_int8_t YearsSince1900;
	u_int32_t Month:4;		/* 1-12 */
	u_int32_t Day:6;		/* 1-32 */
	u_int32_t Hour:6;		/* 0-23 */
	u_int32_t Minute:6;		/* 0-59 */
	u_int32_t Second:6;		/* 0-59 */
	u_int64_t ViaAdapterSerialNumber;
} __packed;

typedef enum {
	RevApplication = 1,
	RevDkiCli,
	RevNetService,
	RevApi,
	RevFileSysDriver,
	RevMiniportDriver,
	RevAdapterSW,
	RevMonitor,
	RevRemoteApi,
} RevComponent;

struct FsaRevision {
	union {
        	struct {
			u_int8_t dash;
			u_int8_t type;
			u_int8_t minor;
			u_int8_t major;
	        } comp;
	        u_int32_t ul;
	} external;
	u_int32_t buildNumber;
} __packed;

/*
 * Adapter Information
 */

#define	CPU_NTSIM		1
#define	CPU_I960		2
#define	CPU_ARM			3
#define	CPU_SPARC		4
#define	CPU_POWERPC		5
#define	CPU_ALPHA		6
#define	CPU_P7			7
#define	CPU_I960_RX		8
#define	CPU__last		9

#define	CPUI960_JX		1
#define	CPUI960_CX		2
#define	CPUI960_HX		3
#define	CPUI960_RX		4
#define	CPUARM_SA110		5
#define	CPUARM_xxx		6
#define	CPUPPC_603e		7
#define	CPUPPC_xxx		8
#define	CPUI80303		9
#define	CPU_XSCALE_80321	10
#define	CPU_MIPS_4KC		11
#define	CPU_MIPS_5KC		12
#define	CPUSUBTYPE__last	13

#define	PLAT_NTSIM		1
#define	PLAT_V3ADU		2
#define	PLAT_CYCLONE		3
#define	PLAT_CYCLONE_HD		4
#define	PLAT_BATBOARD		5
#define	PLAT_BATBOARD_HD	6
#define	PLAT_YOLO		7
#define	PLAT_COBRA		8
#define	PLAT_ANAHEIM		9
#define	PLAT_JALAPENO		10
#define	PLAT_QUEENS		11
#define	PLAT_JALAPENO_DELL	12
#define	PLAT_POBLANO		13
#define	PLAT_POBLANO_OPAL	14
#define	PLAT_POBLANO_SL0	15
#define	PLAT_POBLANO_SL1	16
#define	PLAT_POBLANO_SL2	17
#define	PLAT_POBLANO_XXX	18
#define	PLAT_JALAPENO_P2	19
#define	PLAT_HABANERO		20
#define	PLAT_VULCAN		21
#define	PLAT_CRUSADER		22
#define	PLAT_LANCER		23
#define	PLAT_HARRIER		24
#define	PLAT_TERMINATOR		25
#define	PLAT_SKYHAWK		26
#define	PLAT_CORSAIR		27
#define	PLAT_JAGUAR		28
#define	PLAT_SATAHAWK		29
#define	PLAT_SATANATOR		30
#define	PLAT_PROWLER		31
#define	PLAT_BLACKBIRD		32
#define	PLAT_SABREEXPRESS	33
#define	PLAT_INTRUDER		34
#define	PLAT__last		35

#define	OEM_FLAVOR_ADAPTEC	1
#define	OEM_FLAVOR_DELL		2
#define	OEM_FLAVOR_HP		3
#define	OEM_FLAVOR_IBM		4
#define	OEM_FLAVOR_CPQ		5
#define	OEM_FLAVOR_FSC		6
#define	OEM_FLAVOR_DWS		7
#define	OEM_FLAVOR_BRAND_Z	8
#define	OEM_FLAVOR_LEGEND	9
#define	OEM_FLAVOR_HITACHI	10
#define	OEM_FLAVOR_ESG		11
#define	OEM_FLAVOR_ICP		12
#define	OEM_FLAVOR_SCM		13
#define	OEM_FLAVOR__last	14

/*
 * XXX the aac-2622 with no battery present reports PLATFORM_BAT_OPT_PRESENT
 */
#define	PLATFORM_BAT_REQ_PRESENT	1	/* BATTERY REQUIRED AND PRESENT */
#define	PLATFORM_BAT_REQ_NOTPRESENT	2	/* BATTERY REQUIRED AND NOT PRESENT */
#define	PLATFORM_BAT_OPT_PRESENT	3	/* BATTERY OPTIONAL AND PRESENT */
#define	PLATFORM_BAT_OPT_NOTPRESENT	4	/* BATTERY OPTIONAL AND NOT PRESENT */
#define	PLATFORM_BAT_NOT_SUPPORTED	5	/* BATTERY NOT SUPPORTED */

/* 
 * options supported by this board
 * there has to be a one to one mapping of these defines and the ones in 
 * fsaapi.h, search for FSA_SUPPORT_SNAPSHOT
 */
#define AAC_SUPPORTED_SNAPSHOT		0x01
#define AAC_SUPPORTED_CLUSTERS		0x02
#define AAC_SUPPORTED_WRITE_CACHE	0x04
#define AAC_SUPPORTED_64BIT_DATA	0x08
#define AAC_SUPPORTED_HOST_TIME_FIB	0x10
#define AAC_SUPPORTED_RAID50		0x20
#define AAC_SUPPORTED_4GB_WINDOW	0x40
#define AAC_SUPPORTED_SCSI_UPGRADEABLE	0x80
#define AAC_SUPPORTED_SOFT_ERR_REPORT	0x100
#define AAC_SUPPORTED_NOT_RECONDITION	0x200
#define AAC_SUPPORTED_SGMAP_HOST64	0x400
#define AAC_SUPPORTED_ALARM		0x800
#define AAC_SUPPORTED_NONDASD		0x1000
#define AAC_SUPPORTED_SCSI_MANAGED	0x2000	
#define AAC_SUPPORTED_RAID_SCSI_MODE	0x4000	
#define AAC_SUPPORTED_SUPPLEMENT_ADAPTER_INFO	0x10000
#define AAC_SUPPORTED_NEW_COMM		0x20000
#define AAC_SUPPORTED_64BIT_ARRAYSIZE	0x40000
#define AAC_SUPPORTED_HEAT_SENSOR	0x80000

/*
 * Structure used to respond to a RequestAdapterInfo fib.
 */
struct aac_adapter_info {
	u_int32_t PlatformBase;		/* adapter type */
	u_int32_t CpuArchitecture;	/* adapter CPU type */
	u_int32_t CpuVariant;		/* adapter CPU subtype */
	u_int32_t ClockSpeed;		/* adapter CPU clockspeed */
	u_int32_t ExecutionMem;		/* adapter Execution Memory size */
	u_int32_t BufferMem;		/* adapter Data Memory */
	u_int32_t TotalMem;		/* adapter Total Memory */
	struct FsaRevision KernelRevision; /* adapter Kernel SW Revision */
	struct FsaRevision MonitorRevision; /* adapter Monitor/Diag SW Rev */
	struct FsaRevision HardwareRevision; /* TDB */
	struct FsaRevision BIOSRevision; /* adapter BIOS Revision */
	u_int32_t ClusteringEnabled;
	u_int32_t ClusterChannelMask;
	u_int64_t SerialNumber;
	u_int32_t batteryPlatform;
	u_int32_t SupportedOptions;	/* supported features of this ctrlr */
	u_int32_t OemVariant;
} __packed;

/*
 * Monitor/Kernel interface.
 */

/*
 * Synchronous commands to the monitor/kernel.
 */
#define	AAC_MONKER_BREAKPOINT	0x04
#define	AAC_MONKER_INITSTRUCT	0x05
#define	AAC_MONKER_SYNCFIB	0x0c
#define	AAC_MONKER_GETKERNVER	0x11
#define	AAC_MONKER_POSTRESULTS	0x14
#define	AAC_MONKER_GETINFO	0x19
#define	AAC_MONKER_GETDRVPROP	0x23
#define	AAC_MONKER_RCVTEMP	0x25
#define	AAC_MONKER_GETCOMMPREF	0x26
#define	AAC_MONKER_REINIT	0xee

/*
 * Command status values
 */
#define	ST_OK			0
#define	ST_PERM			1
#define	ST_NOENT		2
#define	ST_IO			5
#define	ST_NXIO			6
#define	ST_E2BIG		7
#define	ST_ACCES		13
#define	ST_EXIST		17
#define	ST_XDEV			18
#define	ST_NODEV		19
#define	ST_NOTDIR		20
#define	ST_ISDIR		21
#define	ST_INVAL		22
#define	ST_FBIG			27
#define	ST_NOSPC		28
#define	ST_ROFS			30
#define	ST_MLINK		31
#define	ST_WOULDBLOCK		35
#define	ST_NAMETOOLONG		63
#define	ST_NOTEMPTY		66
#define	ST_DQUOT		69
#define	ST_STALE		70
#define	ST_REMOTE		71
#define	ST_BADHANDLE		10001
#define	ST_NOT_SYNC		10002
#define	ST_BAD_COOKIE		10003
#define	ST_NOTSUPP		10004
#define	ST_TOOSMALL		10005
#define	ST_SERVERFAULT		10006
#define	ST_BADTYPE		10007
#define	ST_JUKEBOX		10008
#define	ST_NOTMOUNTED		10009
#define	ST_MAINTMODE		10010
#define	ST_STALEACL		10011

/*
 * Volume manager commands
 */
#define	VM_Null			0
#define	VM_NameServe		1
#define	VM_ContainerConfig	2
#define	VM_Ioctl		3
#define	VM_FilesystemIoctl	4
#define	VM_CloseAll		5
#define	VM_CtBlockRead		6
#define	VM_CtBlockWrite		7
#define	VM_SliceBlockRead	8	/* raw access to configured "storage objects" */
#define	VM_SliceBlockWrite	9
#define	VM_DriveBlockRead	10	/* raw access to physical devices */
#define	VM_DriveBlockWrite	11
#define	VM_EnclosureMgt		12	/* enclosure management */
#define	VM_Unused		13	/* used to be diskset management */
#define	VM_CtBlockVerify	14
#define	VM_CtPerf		15	/* performance test */
#define	VM_CtBlockRead64	16
#define	VM_CtBlockWrite64	17
#define	VM_CtBlockVerify64	18
#define	VM_CtHostRead64		19
#define	VM_CtHostWrite64	20
#define	VM_DrvErrTblLog		21	/* drive error table/log type of command */
#define	VM_NameServe64		22

/*
 * "Mountable object"
 */
struct aac_mntobj {
	u_int32_t ObjectId;
	char	FileSystemName[16];
	struct aac_container_creation CreateInfo;
	u_int32_t Capacity;
	u_int32_t VolType;
	u_int32_t ObjType;
	u_int32_t ContentState;
#define	AAC_FSCS_READONLY 0x0002 /* XXX need more information than this */
	union {
		u_int32_t pad[8];
	} ObjExtension;
	u_int32_t AlterEgoId;
	u_int32_t CapacityHigh; /* Only if VM_NameServe64 */
} __packed;

struct aac_mntinfo {
	u_int32_t Command;
	u_int32_t MntType;
	u_int32_t MntCount;
} __packed;

struct aac_mntinforesponse {
	u_int32_t Status;
	u_int32_t MntType;
	u_int32_t MntRespCount;
	struct aac_mntobj MntTable[1];
} __packed;

/*
 * Container shutdown command.
 */
struct aac_closecommand {
	u_int32_t	Command;
	u_int32_t	ContainerId;
} __packed;

/*
 * Container Config Command
 */
#define CT_GET_SCSI_METHOD	64
struct aac_ctcfg {
	u_int32_t		Command;
	u_int32_t		cmd;
	u_int32_t		param;
} __packed;

struct aac_ctcfg_resp {
	u_int32_t		Status;
	u_int32_t		resp;
	u_int32_t		param;
} __packed;

/*
 * 'Ioctl' commands
 */
#define AAC_SCSI_MAX_PORTS	10
#define AAC_BUS_NO_EXIST	0
#define AAC_BUS_VALID		1
#define AAC_BUS_FAULTED		2
#define AAC_BUS_DISABLED	3
#define GetBusInfo		0x9

struct aac_getbusinf {
	u_int32_t		ProbeComplete;
	u_int32_t		BusCount;
	u_int32_t		TargetsPerBus;
	u_int8_t		InitiatorBusId[AAC_SCSI_MAX_PORTS];
	u_int8_t		BusValid[AAC_SCSI_MAX_PORTS];
} __packed;

struct aac_vmioctl {
	u_int32_t		Command;
	u_int32_t		ObjType;
	u_int32_t		MethId;
	u_int32_t		ObjId;
	u_int32_t		IoctlCmd;
	u_int32_t		IoctlBuf[1];	/* Placeholder? */
} __packed;

struct aac_vmi_businf_resp {
	u_int32_t		Status;
	u_int32_t		ObjType;
	u_int32_t		MethId;
	u_int32_t		ObjId;
	u_int32_t		IoctlCmd;
	struct aac_getbusinf	BusInf;
} __packed;

#if 0
#define AAC_BTL_TO_HANDLE(b, t, l) \
    (((b & 0x3f) << 7) | ((l & 0x7) << 4) | (t & 0xf))
#else
#define AAC_BTL_TO_HANDLE(b, t, l) \
    ((((u_int32_t)b & 0x0f) << 24) | \
     (((u_int32_t)l & 0xff) << 16) | \
     ((u_int32_t)t & 0xffff))
#endif
#define GetDeviceProbeInfo 0x5

struct aac_vmi_devinfo_resp {
	u_int32_t		Status;
	u_int32_t		ObjType;
	u_int32_t		MethId;
	u_int32_t		ObjId;
	u_int32_t		IoctlCmd;
	u_int8_t		VendorId[8];
	u_int8_t		ProductId[16];
	u_int8_t		ProductRev[4];
	u_int32_t		Inquiry7;
	u_int32_t		align1;
	u_int32_t		Inquiry0;
	u_int32_t		align2;
	u_int32_t		Inquiry1;
	u_int32_t		align3;
	u_int32_t		reserved[2];
	u_int8_t		VendorSpecific[20];
	u_int32_t		Smart:1;
	u_int32_t		AAC_Managed:1;
	u_int32_t		align4;
	u_int32_t		reserved2:6;
	u_int32_t		Bus;
	u_int32_t		Target;
	u_int32_t		Lun;
	u_int32_t		ultraEnable:1,
				disconnectEnable:1,
				fast20EnabledW:1,
				scamDevice:1,
				scamTolerant:1,
				setForSync:1,
				setForWide:1,
				syncDevice:1,
				wideDevice:1,
				reserved1:7,
				ScsiRate:8,
				ScsiOffset:8;
}; /* Do not pack */

#define ResetBus 0x16
struct aac_resetbus {
	u_int32_t		BusNumber;
};

/*
 * Write 'stability' options.
 */
#define	CSTABLE			1
#define	CUNSTABLE		2

/*
 * Commit level response for a write request.
 */
#define	CMFILE_SYNC_NVRAM	1
#define	CMDATA_SYNC_NVRAM	2
#define	CMFILE_SYNC		3
#define	CMDATA_SYNC		4
#define	CMUNSTABLE		5

/*
 * Block read/write operations.  These structures are packed into the 'data'
 * area in the FIB.
 */
struct aac_blockread {
	u_int32_t Command;		/* not FSACommand! */
	u_int32_t ContainerId;
	u_int32_t BlockNumber;
	u_int32_t ByteCount;
	struct aac_sg_table SgMap;	/* variable size */
} __packed;

struct aac_blockread64 {
	u_int32_t Command;	/* not FSACommand! */
	u_int16_t ContainerId;
	u_int16_t SectorCount;
	u_int32_t BlockNumber;
	u_int16_t Pad;
	u_int16_t Flags;
	struct aac_sg_table64 SgMap64;	/* variable size */
} __packed;

struct aac_blockread_response {
	u_int32_t Status;
	u_int32_t ByteCount;
} __packed;

struct aac_blockwrite {
	u_int32_t Command;	/* not FSACommand! */
	u_int32_t ContainerId;
	u_int32_t BlockNumber;
	u_int32_t ByteCount;
	u_int32_t Stable;
	struct aac_sg_table SgMap;	/* variable size */
} __packed;

struct aac_blockwrite64 {
	u_int32_t Command;	/* not FSACommand! */
	u_int16_t ContainerId;
	u_int16_t SectorCount;
	u_int32_t BlockNumber;
	u_int16_t Pad;
	u_int16_t Flags;
	struct aac_sg_table64 SgMap64;	/* variable size */
} __packed;

struct aac_blockwrite_response {
	u_int32_t Status;
	u_int32_t ByteCount;
	u_int32_t Committed;
} __packed;

struct aac_raw_io {
	u_int64_t		BlockNumber;
	u_int32_t		ByteCount;
	u_int16_t		ContainerId;
	u_int16_t		Flags;				/* 0: W, 1: R */
	u_int16_t		BpTotal;			/* reserved for FW use */
	u_int16_t		BpComplete;			/* reserved for FW use */
	struct aac_sg_tableraw	SgMapRaw;	/* variable size */
} __packed;

struct aac_close_command {
	u_int32_t	Command;
	u_int32_t	ContainerId;
} __packed;

/*
 * SCSI Passthrough structures
 */
struct aac_srb32 {
	u_int32_t		function;
	u_int32_t		bus;
	u_int32_t		target;
	u_int32_t		lun;
	u_int32_t		timeout;
	u_int32_t		flags;
	u_int32_t		data_len;
	u_int32_t		retry_limit;
	u_int32_t		cdb_len;
	u_int8_t		cdb[16];
	struct aac_sg_table	sg_map32;
};

#define AAC_SRB_FUNC_EXECUTE_SCSI	0x00
#define AAC_SRB_FUNC_CLAIM_DEVICE	0x01
#define AAC_SRB_FUNC_IO_CONTROL		0x02
#define AAC_SRB_FUNC_RECEIVE_EVENT	0x03
#define AAC_SRB_FUNC_RELEASE_QUEUE	0x04
#define AAC_SRB_FUNC_ATTACH_DEVICE	0x05
#define AAC_SRB_FUNC_RELEASE_DEVICE	0x06
#define AAC_SRB_FUNC_SHUTDOWN		0x07
#define AAC_SRB_FUNC_FLUSH		0x08
#define AAC_SRB_FUNC_ABORT_COMMAND	0x10
#define AAC_SRB_FUNC_RELEASE_RECOVERY	0x11
#define AAC_SRB_FUNC_RESET_BUS		0x12
#define AAC_SRB_FUNC_RESET_DEVICE	0x13
#define AAC_SRB_FUNC_TERMINATE_IO	0x14
#define AAC_SRB_FUNC_FLUSH_QUEUE	0x15
#define AAC_SRB_FUNC_REMOVE_DEVICE	0x16
#define AAC_SRB_FUNC_DOMAIN_VALIDATION	0x17

#define AAC_SRB_FLAGS_NO_DATA_XFER		0x0000
#define	AAC_SRB_FLAGS_DISABLE_DISCONNECT	0x0004
#define	AAC_SRB_FLAGS_DISABLE_SYNC_TRANSFER	0x0008
#define AAC_SRB_FLAGS_BYPASS_FROZEN_QUEUE	0x0010
#define	AAC_SRB_FLAGS_DISABLE_AUTOSENSE		0x0020
#define	AAC_SRB_FLAGS_DATA_IN			0x0040
#define AAC_SRB_FLAGS_DATA_OUT			0x0080
#define	AAC_SRB_FLAGS_UNSPECIFIED_DIRECTION \
			(AAC_SRB_FLAGS_DATA_IN | AAC_SRB_FLAGS_DATA_OUT)

#define AAC_HOST_SENSE_DATA_MAX			30

struct aac_srb_response {
	u_int32_t	fib_status;
	u_int32_t	srb_status;
	u_int32_t	scsi_status;
	u_int32_t	data_len;
	u_int32_t	sense_len;
	u_int8_t	sense[AAC_HOST_SENSE_DATA_MAX];
};

/*
 * Status codes for SCSI passthrough commands.  Since they are based on ASPI,
 * they also exactly match CAM status codes in both enumeration and meaning.
 * They seem to also be used as status codes for synchronous FIBs.
 */
#define AAC_SRB_STS_PENDING			0x00
#define AAC_SRB_STS_SUCCESS			0x01
#define AAC_SRB_STS_ABORTED			0x02
#define AAC_SRB_STS_ABORT_FAILED		0x03
#define AAC_SRB_STS_ERROR			0x04
#define AAC_SRB_STS_BUSY			0x05
#define AAC_SRB_STS_INVALID_REQUEST		0x06
#define AAC_SRB_STS_INVALID_PATH_ID		0x07
#define AAC_SRB_STS_NO_DEVICE			0x08
#define AAC_SRB_STS_TIMEOUT			0x09
#define AAC_SRB_STS_SELECTION_TIMEOUT		0x0a
#define AAC_SRB_STS_COMMAND_TIMEOUT		0x0b
#define AAC_SRB_STS_MESSAGE_REJECTED		0x0d
#define AAC_SRB_STS_BUS_RESET			0x0e
#define AAC_SRB_STS_PARITY_ERROR		0x0f
#define AAC_SRB_STS_REQUEST_SENSE_FAILED	0x10
#define AAC_SRB_STS_NO_HBA			0x11
#define AAC_SRB_STS_DATA_OVERRUN		0x12
#define AAC_SRB_STS_UNEXPECTED_BUS_FREE		0x13
#define AAC_SRB_STS_PHASE_SEQUENCE_FAILURE	0x14
#define AAC_SRB_STS_BAD_SRB_BLOCK_LENGTH	0x15
#define AAC_SRB_STS_REQUEST_FLUSHED		0x16
#define AAC_SRB_STS_INVALID_LUN			0x20
#define AAC_SRB_STS_INVALID_TARGET_ID		0x21
#define AAC_SRB_STS_BAD_FUNCTION		0x22
#define AAC_SRB_STS_ERROR_RECOVER		0x23

/*
 * Register set for adapters based on the Falcon bridge and PPC core
 */

#define AAC_FA_DOORBELL0_CLEAR		0x00
#define AAC_FA_DOORBELL1_CLEAR		0x02
#define AAC_FA_DOORBELL0		0x04
#define AAC_FA_DOORBELL1		0x06
#define AAC_FA_MASK0_CLEAR		0x08
#define AAC_FA_MASK1_CLEAR		0x0a
#define	AAC_FA_MASK0			0x0c
#define AAC_FA_MASK1			0x0e
#define AAC_FA_MAILBOX			0x10
#define	AAC_FA_FWSTATUS			0x2c	/* Mailbox 7 */
#define	AAC_FA_INTSRC			0x900

#define AAC_FA_HACK(sc)	(void)AAC_GETREG4(sc, AAC_FA_INTSRC)

/*
 * Register definitions for the Adaptec AAC-364 'Jalapeno I/II' adapters, based
 * on the SA110 'StrongArm'.
 */

#define	AAC_REGSIZE		0x100

/* doorbell 0 (adapter->host) */
#define	AAC_SA_DOORBELL0_CLEAR	0x98
#define	AAC_SA_DOORBELL0_SET	0x9c
#define	AAC_SA_DOORBELL0	0x9c
#define	AAC_SA_MASK0_CLEAR	0xa0
#define	AAC_SA_MASK0_SET	0xa4

/* doorbell 1 (host->adapter) */
#define	AAC_SA_DOORBELL1_CLEAR	0x9a
#define	AAC_SA_DOORBELL1_SET	0x9e
#define	AAC_SA_MASK1_CLEAR	0xa2
#define	AAC_SA_MASK1_SET	0xa6

/* mailbox (20 bytes) */
#define	AAC_SA_MAILBOX		0xa8
#define	AAC_SA_FWSTATUS		0xc4

/*
 * Register definitions for the Adaptec 'Pablano' adapters, based on the
 * i960Rx, and other related adapters.
 */

#define	AAC_RX_IDBR		0x20	/* inbound doorbell */
#define	AAC_RX_IISR		0x24	/* inbound interrupt status */
#define	AAC_RX_IIMR		0x28	/* inbound interrupt mask */
#define	AAC_RX_ODBR		0x2c	/* outbound doorbell */
#define	AAC_RX_OISR		0x30	/* outbound interrupt status */
#define	AAC_RX_OIMR		0x34	/* outbound interrupt mask */
#define	AAC_RX_IQUE		0x40	/* inbound queue */
#define	AAC_RX_OQUE		0x44	/* outbound queue */

#define	AAC_RX_MAILBOX		0x50	/* mailbox (20 bytes) */
#define	AAC_RX_FWSTATUS		0x6c

/*
 * Register definitions for the Adaptec 'Rocket' RAID-On-Chip adapters.
 * Unsurprisingly, it's quite similar to the i960!
 */

#define AAC_RKT_IDBR		0x20	/* inbound doorbell register */
#define AAC_RKT_IISR		0x24	/* inbound interrupt status register */
#define AAC_RKT_IIMR		0x28	/* inbound interrupt mask register */
#define AAC_RKT_ODBR		0x2c	/* outbound doorbell register */
#define AAC_RKT_OISR		0x30	/* outbound interrupt status register */
#define AAC_RKT_OIMR		0x34	/* outbound interrupt mask register */
#define AAC_RKT_IQUE		0x40	/* inbound queue */
#define AAC_RKT_OQUE		0x44	/* outbound queue */

#define AAC_RKT_MAILBOX		0x1000	/* mailbox */
#define AAC_RKT_FWSTATUS	0x101c	/* Firmware Status (mailbox 7) */

/*
 * Common bit definitions for the doorbell registers.
 */

/*
 * Status bits in the doorbell registers.
 */
#define	AAC_DB_SYNC_COMMAND	(1<<0)	/* send/completed synchronous FIB */
#define	AAC_DB_COMMAND_READY	(1<<1)	/* posted one or more commands */
#define	AAC_DB_RESPONSE_READY	(1<<2)	/* one or more commands complete */
#define	AAC_DB_COMMAND_NOT_FULL	(1<<3)	/* command queue not full */
#define	AAC_DB_RESPONSE_NOT_FULL (1<<4)	/* response queue not full */

/*
 * The adapter can request the host print a message by setting the
 * DB_PRINTF flag in DOORBELL0.  The driver responds by collecting the
 * message from the printf buffer, clearing the DB_PRINTF flag in
 * DOORBELL0 and setting it in DOORBELL1.
 * (ODBR and IDBR respectively for the i960Rx adapters)
 */
#define	AAC_DB_PRINTF		(1<<5)	/* adapter requests host printf */
#define	AAC_PRINTF_DONE		(1<<5)	/* host completed printf processing */

/*
 * Mask containing the interrupt bits we care about.  We don't anticipate
 * (or want) interrupts not in this mask.
 */
#define	AAC_DB_INTERRUPTS \
	(AAC_DB_COMMAND_READY | AAC_DB_RESPONSE_READY | AAC_DB_PRINTF)
#define AAC_DB_INT_NEW_COMM		0x08

/*
 * Queue names
 *
 * Note that we base these at 0 in order to use them as array indices.  Adaptec
 * used base 1 for some unknown reason, and sorted them in a different order.
 */
#define	AAC_HOST_NORM_CMD_QUEUE		0
#define	AAC_HOST_HIGH_CMD_QUEUE		1
#define	AAC_ADAP_NORM_CMD_QUEUE		2
#define	AAC_ADAP_HIGH_CMD_QUEUE		3
#define	AAC_HOST_NORM_RESP_QUEUE	4
#define	AAC_HOST_HIGH_RESP_QUEUE	5
#define	AAC_ADAP_NORM_RESP_QUEUE	6
#define	AAC_ADAP_HIGH_RESP_QUEUE	7

/*
 * List structure used to chain FIBs (used by the adapter - we hang FIBs off
 * our private command structure and don't touch these)
 */
struct aac_fib_list_entry {
	u_int32_t	Flink;
	u_int32_t	Blink;
} __packed;

/*
 * FIB (FSA Interface Block?); this is the datastructure passed between the
 * host and adapter.
 */
struct aac_fib_header {
	u_int32_t XferState;
	u_int16_t Command;
	u_int8_t StructType;
	u_int8_t Flags;
	u_int16_t Size;
	u_int16_t SenderSize;
	u_int32_t SenderFibAddress;
	u_int32_t ReceiverFibAddress;
	u_int32_t SenderData;
	union {
		struct {
			u_int32_t ReceiverTimeStart;
			u_int32_t ReceiverTimeDone;
		} _s;
		struct aac_fib_list_entry FibLinks;
	} _u;
} __packed;

#define	AAC_FIB_DATASIZE (512 - sizeof(struct aac_fib_header))

struct aac_fib {
	struct aac_fib_header Header;
	u_int8_t data[AAC_FIB_DATASIZE];
} __packed;

/*
 * FIB commands
 */
#define	TestCommandResponse		1
#define	TestAdapterCommand		2

/* Lowlevel and comm commands */
#define	LastTestCommand			100
#define	ReinitHostNormCommandQueue	101
#define	ReinitHostHighCommandQueue	102
#define	ReinitHostHighRespQueue		103
#define	ReinitHostNormRespQueue		104
#define	ReinitAdapNormCommandQueue	105
#define	ReinitAdapHighCommandQueue	107
#define	ReinitAdapHighRespQueue		108
#define	ReinitAdapNormRespQueue		109
#define	InterfaceShutdown		110
#define	DmaCommandFib			120
#define	StartProfile			121
#define	TermProfile			122
#define	SpeedTest			123
#define	TakeABreakPt			124
#define	RequestPerfData			125
#define	SetInterruptDefTimer		126
#define	SetInterruptDefCount		127
#define	GetInterruptDefStatus		128
#define	LastCommCommand			129

/* filesystem commands */
#define	NuFileSystem			300
#define	UFS				301
#define	HostFileSystem			302
#define	LastFileSystemCommand		303

/* Container Commands */
#define	ContainerCommand		500
#define	ContainerCommand64		501
#define	RawIo				502

/* Cluster Commands */
#define	ClusterCommand			550

/* Scsi Port commands (scsi passthrough) */
#define	ScsiPortCommand			600
#define	ScsiPortCommandU64		601
#define	SataPortCommandU64		602
#define	SasSmpPassThrough		603
#define	SasRequestPhyInfo		612

/* Misc house keeping and generic adapter initiated commands */
#define	AifRequest			700
#define	CheckRevision			701
#define	FsaHostShutdown			702
#define	RequestAdapterInfo		703
#define	IsAdapterPaused			704
#define	SendHostTime			705
#define	RequestSupplementAdapterInfo	706	/* Supp. Info for set in UCC
						 * use only if supported
						 * (RequestAdapterInfo first) */
#define	LastMiscCommand			707

#define	OnLineDiagnostic		800
#define	FduAdapterTest			801
#define	RequestCompatibilityId		802
#define	AdapterEnvironmentInfo		803	/* temp. sensors */

#define	NvsramEventLog			900
#define	ResetNvsramEventLogPointers	901
#define	EnableEventLog			902
#define	DisableEventLog			903
#define	EncryptedKeyTransportFIB	904
#define	KeyableFeaturesFIB		905

/*
 * FIB types
 */
#define	AAC_FIBTYPE_TFIB		1
#define	AAC_FIBTYPE_TQE			2
#define	AAC_FIBTYPE_TCTPERF		3

/*
 * FIB transfer state
 */
#define	AAC_FIBSTATE_HOSTOWNED		(1<<0)	/* owned by the host */
#define	AAC_FIBSTATE_ADAPTEROWNED	(1<<1)	/* owned by the adapter */
#define	AAC_FIBSTATE_INITIALISED	(1<<2)	/* initialised */
#define	AAC_FIBSTATE_EMPTY		(1<<3)	/* empty */
#define	AAC_FIBSTATE_FROMPOOL		(1<<4)	/* allocated from pool */
#define	AAC_FIBSTATE_FROMHOST		(1<<5)	/* sent from the host */
#define	AAC_FIBSTATE_FROMADAP		(1<<6)	/* sent from the adapter */
#define	AAC_FIBSTATE_REXPECTED		(1<<7)	/* response is expected */
#define	AAC_FIBSTATE_RNOTEXPECTED	(1<<8)	/* response is not expected */
#define	AAC_FIBSTATE_DONEADAP		(1<<9)	/* processed by the adapter */
#define	AAC_FIBSTATE_DONEHOST		(1<<10)	/* processed by the host */
#define	AAC_FIBSTATE_HIGH		(1<<11)	/* high priority */
#define	AAC_FIBSTATE_NORM		(1<<12)	/* normal priority */
#define	AAC_FIBSTATE_ASYNC		(1<<13)
#define	AAC_FIBSTATE_ASYNCIO		(1<<13)	/* to be removed */
#define	AAC_FIBSTATE_PAGEFILEIO		(1<<14)	/* to be removed */
#define	AAC_FIBSTATE_SHUTDOWN		(1<<15)
#define	AAC_FIBSTATE_LAZYWRITE		(1<<16)	/* to be removed */
#define	AAC_FIBSTATE_ADAPMICROFIB	(1<<17)
#define	AAC_FIBSTATE_BIOSFIB		(1<<18)
#define	AAC_FIBSTATE_FAST_RESPONSE	(1<<19)	/* fast response capable */
#define	AAC_FIBSTATE_APIFIB		(1<<20)

/*
 * FIB error values
 */
#define	AAC_ERROR_NORMAL			0x00
#define	AAC_ERROR_PENDING			0x01
#define	AAC_ERROR_FATAL				0x02
#define	AAC_ERROR_INVALID_QUEUE			0x03
#define	AAC_ERROR_NOENTRIES			0x04
#define	AAC_ERROR_SENDFAILED			0x05
#define	AAC_ERROR_INVALID_QUEUE_PRIORITY	0x06
#define	AAC_ERROR_FIB_ALLOCATION_FAILED		0x07
#define	AAC_ERROR_FIB_DEALLOCATION_FAILED	0x08

/*
 *  Adapter Status Register
 *
 *  Phase Status mailbox is 32bits:
 *  <31:16> = Phase Status
 *  <15:0>  = Phase
 *
 *  The adapter reports its present state through the phase.  Only
 *  a single phase should be ever be set.  Each phase can have multiple
 *  phase status bits to provide more detailed information about the
 *  state of the adapter.
 */
#define	AAC_SELF_TEST_FAILED	0x00000004
#define	AAC_MONITOR_PANIC	0x00000020
#define	AAC_UP_AND_RUNNING	0x00000080
#define	AAC_KERNEL_PANIC	0x00000100

/*
 * Data types relating to control and monitoring of the NVRAM/WriteCache 
 * subsystem.
 */

#define AAC_NFILESYS	24	/* maximum number of filesystems */

/*
 * NVRAM/Write Cache subsystem states
 */
typedef enum {
	NVSTATUS_DISABLED = 0,	/* present, clean, not being used */
	NVSTATUS_ENABLED,	/* present, possibly dirty, ready for use */
	NVSTATUS_ERROR,		/* present, dirty, contains dirty data */
	NVSTATUS_BATTERY,	/* present, bad or low battery, may contain
				 * dirty data */
	NVSTATUS_UNKNOWN	/* for bad/missing device */
} AAC_NVSTATUS;

/*
 * NVRAM/Write Cache subsystem battery component states
 *
 */
typedef enum {
	NVBATTSTATUS_NONE = 0,	/* battery has no power or is not present */
	NVBATTSTATUS_LOW,	/* battery is low on power */
	NVBATTSTATUS_OK,	/* battery is okay - normal operation possible
				 * only in this state */
	NVBATTSTATUS_RECONDITIONING	/* no battery present - reconditioning
					 * in process */
} AAC_NVBATTSTATUS;

/*
 * Battery transition type
 */
typedef enum {
	NVBATT_TRANSITION_NONE = 0,	/* battery now has no power or is not
					 * present */
	NVBATT_TRANSITION_LOW,		/* battery is now low on power */
	NVBATT_TRANSITION_OK		/* battery is now okay - normal
					 * operation possible only in this
					 * state */
} AAC_NVBATT_TRANSITION;

/*
 * NVRAM Info structure returned for NVRAM_GetInfo call
 */
struct aac_nvramdevinfo {
	u_int32_t	NV_Enabled;	/* write caching enabled */
	u_int32_t	NV_Error;	/* device in error state */
	u_int32_t	NV_NDirty;	/* count of dirty NVRAM buffers */
	u_int32_t	NV_NActive;	/* count of NVRAM buffers being
					 * written */
} __packed;

struct aac_nvraminfo {
	AAC_NVSTATUS		NV_Status;	/* nvram subsystem status */
	AAC_NVBATTSTATUS	NV_BattStatus;	/* battery status */
	u_int32_t		NV_Size;	/* size of WriteCache NVRAM in
						 * bytes */
	u_int32_t		NV_BufSize;	/* size of NVRAM buffers in
						 * bytes */
	u_int32_t		NV_NBufs;	/* number of NVRAM buffers */
	u_int32_t		NV_NDirty;	/* Num dirty NVRAM buffers */
	u_int32_t		NV_NClean;	/* Num clean NVRAM buffers */
	u_int32_t		NV_NActive;	/* Num NVRAM buffers being
						 * written */
	u_int32_t		NV_NBrokered;	/* Num brokered NVRAM buffers */
	struct aac_nvramdevinfo	NV_DevInfo[AAC_NFILESYS];	/* per device
								 * info */
	u_int32_t		NV_BattNeedsReconditioning;	/* boolean */
	u_int32_t		NV_TotalSize;	/* size of all non-volatile
						 * memories in bytes */
} __packed;

/*
 * Data types relating to adapter-initiated FIBs
 *
 * Based on types and structures in <aifstruc.h>
 */

/*
 * Progress Reports
 */
typedef enum {
	AifJobStsSuccess = 1,
	AifJobStsFinished,
	AifJobStsAborted,
	AifJobStsFailed,
	AifJobStsLastReportMarker = 100,	/* All prior mean last report */
	AifJobStsSuspended,
	AifJobStsRunning
} AAC_AifJobStatus;

typedef enum {
	AifJobScsiMin = 1,		/* Minimum value for Scsi operation */
	AifJobScsiZero,			/* SCSI device clear operation */
	AifJobScsiVerify,		/* SCSI device Verify operation NO
					 * REPAIR */
	AifJobScsiExercise,		/* SCSI device Exercise operation */
	AifJobScsiVerifyRepair,		/* SCSI device Verify operation WITH
					 * repair */
	AifJobScsiWritePattern,		/* write pattern */
	AifJobScsiMax = 99,		/* Max Scsi value */
	AifJobCtrMin,			/* Min Ctr op value */
	AifJobCtrZero,			/* Container clear operation */
	AifJobCtrCopy,			/* Container copy operation */
	AifJobCtrCreateMirror,		/* Container Create Mirror operation */
	AifJobCtrMergeMirror,		/* Container Merge Mirror operation */
	AifJobCtrScrubMirror,		/* Container Scrub Mirror operation */
	AifJobCtrRebuildRaid5,		/* Container Rebuild Raid5 operation */
	AifJobCtrScrubRaid5,		/* Container Scrub Raid5 operation */
	AifJobCtrMorph,			/* Container morph operation */
	AifJobCtrPartCopy,		/* Container Partition copy operation */
	AifJobCtrRebuildMirror,		/* Container Rebuild Mirror operation */
	AifJobCtrCrazyCache,		/* crazy cache */
	AifJobCtrCopyback,		/* Container Copyback operation */
	AifJobCtrCompactRaid5D,		/* Container Compaction operation */
	AifJobCtrExpandRaid5D,		/* Container Expansion operation */
	AifJobCtrRebuildRaid6,		/* Container Rebuild Raid6 operation */
	AifJobCtrScrubRaid6,		/* Container Scrub Raid6 operation */
	AifJobCtrSSBackup,		/* Container snapshot backup task */
	AifJobCtrMax = 199,		/* Max Ctr type operation */
	AifJobFsMin,			/* Min Fs type operation */
	AifJobFsCreate,			/* File System Create operation */
	AifJobFsVerify,			/* File System Verify operation */
	AifJobFsExtend,			/* File System Extend operation */
	AifJobFsMax = 299,		/* Max Fs type operation */
	AifJobApiFormatNTFS,		/* Format a drive to NTFS */
	AifJobApiFormatFAT,		/* Format a drive to FAT */
	AifJobApiUpdateSnapshot,	/* update the read/write half of a
					 * snapshot */
	AifJobApiFormatFAT32,		/* Format a drive to FAT32 */
	AifJobApiMax = 399,		/* Max API type operation */
	AifJobCtlContinuousCtrVerify,	/* Adapter operation */
	AifJobCtlMax = 499		/* Max Adapter type operation */
} AAC_AifJobType;

struct aac_AifContainers {
	u_int32_t	src;		/* from/master */
	u_int32_t	dst;		/* to/slave */
} __packed;

union aac_AifJobClient {
	struct aac_AifContainers	container;	/* For Container and
							 * filesystem progress
							 * ops; */
	int32_t				scsi_dh;	/* For SCSI progress
							 * ops */
};

struct aac_AifJobDesc {
	u_int32_t		jobID;		/* DO NOT FILL IN! Will be
						 * filled in by AIF */
	AAC_AifJobType		type;		/* Operation that is being
						 * performed */
	union aac_AifJobClient	client;		/* Details */
} __packed;

struct aac_AifJobProgressReport {
	struct aac_AifJobDesc	jd;
	AAC_AifJobStatus	status;
	u_int32_t		finalTick;
	u_int32_t		currentTick;
	u_int32_t		jobSpecificData1;
	u_int32_t		jobSpecificData2;
} __packed;

/*
 * Event Notification
 */
typedef enum {
	/* General application notifies start here */
	AifEnGeneric = 1,		/* Generic notification */
	AifEnTaskComplete,		/* Task has completed */
	AifEnConfigChange,		/* Adapter config change occurred */
	AifEnContainerChange,		/* Adapter specific container 
					 * configuration change */
	AifEnDeviceFailure,		/* SCSI device failed */
	AifEnMirrorFailover,		/* Mirror failover started */
	AifEnContainerEvent,		/* Significant container event */
	AifEnFileSystemChange,		/* File system changed */
	AifEnConfigPause,		/* Container pause event */
	AifEnConfigResume,		/* Container resume event */
	AifEnFailoverChange,		/* Failover space assignment changed */
	AifEnRAID5RebuildDone,		/* RAID5 rebuild finished */
	AifEnEnclosureManagement,	/* Enclosure management event */
	AifEnBatteryEvent,		/* Significant NV battery event */
	AifEnAddContainer,		/* A new container was created. */
	AifEnDeleteContainer,		/* A container was deleted. */
	AifEnSMARTEvent, 	       	/* SMART Event */
	AifEnBatteryNeedsRecond,	/* The battery needs reconditioning */
	AifEnClusterEvent,		/* Some cluster event */
	AifEnDiskSetEvent,		/* A disk set event occurred. */
	AifDriverNotifyStart=199,	/* Notifies for host driver go here */
	/* Host driver notifications start here */
	AifDenMorphComplete, 		/* A morph operation completed */
	AifDenVolumeExtendComplete 	/* Volume expand operation completed */
} AAC_AifEventNotifyType;

struct aac_AifEnsGeneric {
	char	text[132];		/* Generic text */
} __packed;

struct aac_AifEnsDeviceFailure {
	u_int32_t	deviceHandle;	/* SCSI device handle */
} __packed;

struct aac_AifEnsMirrorFailover {
	u_int32_t	container;	/* Container with failed element */
	u_int32_t	failedSlice;	/* Old slice which failed */
	u_int32_t	creatingSlice;	/* New slice used for auto-create */
} __packed;

struct aac_AifEnsContainerChange {
	u_int32_t	container[2];	/* container that changed, -1 if no
					 * container */
} __packed;

struct aac_AifEnsContainerEvent {
	u_int32_t	container;	/* container number  */
	u_int32_t	eventType;	/* event type */
} __packed;

struct aac_AifEnsEnclosureEvent {
	u_int32_t	empID;		/* enclosure management proc number  */
	u_int32_t	unitID;		/* unitId, fan id, power supply id,
					 * slot id, tempsensor id.  */
	u_int32_t	eventType;	/* event type */
} __packed;

struct aac_AifEnsBatteryEvent {
	AAC_NVBATT_TRANSITION	transition_type;	/* eg from low to ok */
	AAC_NVBATTSTATUS	current_state;		/* current batt state */
	AAC_NVBATTSTATUS	prior_state;		/* prev batt state */
} __packed;

struct aac_AifEnsDiskSetEvent {
	u_int32_t	eventType;
	u_int64_t	DsNum;
	u_int64_t	CreatorId;
} __packed;

typedef enum {
	CLUSTER_NULL_EVENT = 0,
	CLUSTER_PARTNER_NAME_EVENT,	/* change in partner hostname or
					 * adaptername from NULL to non-NULL */
	/* (partner's agent may be up) */
	CLUSTER_PARTNER_NULL_NAME_EVENT	/* change in partner hostname or
					 * adaptername from non-null to NULL */
	/* (partner has rebooted) */
} AAC_ClusterAifEvent;

struct aac_AifEnsClusterEvent {
	AAC_ClusterAifEvent	eventType;
} __packed;

struct aac_AifEventNotify {
	AAC_AifEventNotifyType	type;
	union {
		struct aac_AifEnsGeneric		EG;
		struct aac_AifEnsDeviceFailure		EDF;
		struct aac_AifEnsMirrorFailover		EMF;
		struct aac_AifEnsContainerChange	ECC;
		struct aac_AifEnsContainerEvent		ECE;
		struct aac_AifEnsEnclosureEvent		EEE;
		struct aac_AifEnsBatteryEvent		EBE;
		struct aac_AifEnsDiskSetEvent		EDS;
/*		struct aac_AifEnsSMARTEvent		ES;*/
		struct aac_AifEnsClusterEvent		ECLE;
	} data;
} __packed;

/*
 * Adapter Initiated FIB command structures. Start with the adapter
 * initiated FIBs that really come from the adapter, and get responded
 * to by the host. 
 */
#define AAC_AIF_REPORT_MAX_SIZE 64

typedef enum {
	AifCmdEventNotify = 1,	/* Notify of event */
	AifCmdJobProgress,	/* Progress report */
	AifCmdAPIReport,	/* Report from other user of API */
	AifCmdDriverNotify,	/* Notify host driver of event */
	AifReqJobList = 100,	/* Gets back complete job list */
	AifReqJobsForCtr,	/* Gets back jobs for specific container */
	AifReqJobsForScsi,	/* Gets back jobs for specific SCSI device */
	AifReqJobReport,	/* Gets back a specific job report or list */
	AifReqTerminateJob,	/* Terminates job */
	AifReqSuspendJob,	/* Suspends a job */
	AifReqResumeJob,	/* Resumes a job */
	AifReqSendAPIReport,	/* API generic report requests */
	AifReqAPIJobStart,	/* Start a job from the API */
	AifReqAPIJobUpdate,	/* Update a job report from the API */
	AifReqAPIJobFinish	/* Finish a job from the API */
} AAC_AifCommand;

struct aac_aif_command {
	AAC_AifCommand	command;	/* Tell host what type of
					 * notify this is */
	u_int32_t	seqNumber;	/* To allow ordering of
					 * reports (if necessary) */
	union {
		struct aac_AifEventNotify	EN;	/* Event notify */
		struct aac_AifJobProgressReport	PR[1];	/* Progress report */
		u_int8_t			AR[AAC_AIF_REPORT_MAX_SIZE];
		u_int8_t			data[AAC_FIB_DATASIZE - 8];
	} data;
} __packed;

#endif	/* !_PCI_AACREG_H_ */
