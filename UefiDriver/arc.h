#pragma once

//
// Bullshit thats not defined in EFI library
//
typedef union _LARGE_INTEGER
{
	struct
	{
		UINT32 LowPart;
		INT32 HighPart;
	};
	struct
	{
		UINT32 LowPart;
		INT32 HighPart;
	} u;
	UINT64 QuadPart;
} LARGE_INTEGER;

typedef union _ULARGE_INTEGER
{
	struct
	{
		UINT32 LowPart;
		UINT32 HighPart;
	};
	struct
	{
		UINT32 LowPart;
		UINT32 HighPart;
	} u;
	UINT64 QuadPart;
} ULARGE_INTEGER;

typedef struct _UNICODE_STRING
{
	UINT16 Length;
	UINT16 MaximumLength;
	CHAR16*   Buffer;
} UNICODE_STRING;

//
// Calculate the address of the base of the structure given its type, and an
// address of a field within the structure.
//
#define CONTAINING_RECORD(address, type, field) ((type *)((CHAR8*)(address) - (UINT64)(&((type *)0)->field)))

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks; // 0x0
	VOID* ExceptionTable; // 0x10
	UINT32 ExceptionTableSize; // 0x18
	// ULONG padding on IA64
	VOID* GpValue; // 0x20
	VOID* NonPagedDebugInfo; // 0x28
	VOID* ImageBase; // 0x30
	VOID* EntryPoint; // 0x38
	UINT32 SizeOfImage; // 0x40
	struct _UNICODE_STRING FullImageName; // 0x48
	struct _UNICODE_STRING BaseImageName; // 0x58
	UINT32 Flags; // 0x68
	UINT16 LoadCount; // 0x6C
	UINT16 u1; // 0x6E
	VOID* SectionPointer; // 0x70
	UINT32 CheckSum; // 0x78
	UINT32 CoverageSectionSize; // 0x7C
	VOID* CoverageSection; // 0x80
	VOID* LoadedImports; // 0x88
	VOID* Spare; // 0x90
	UINT32 SizeOfImageNotRounded; // 0x98
	UINT32 TimeDateStamp; // 0x9C
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

//
// Define DEVICE_FLAGS
//

typedef struct _DEVICE_FLAGS
{
	UINT32 Failed : 1;
	UINT32 ReadOnly : 1;
	UINT32 Removable : 1;
	UINT32 ConsoleIn : 1;
	UINT32 ConsoleOut : 1;
	UINT32 Input : 1;
	UINT32 Output : 1;
} DEVICE_FLAGS, *PDEVICE_FLAGS;

//
// Define configuration routine types.
//
// Configuration information.
//

typedef enum _CONFIGURATION_TYPE
{
	ArcSystem,
	CentralProcessor,
	FloatingPointProcessor,
	PrimaryIcache,
	PrimaryDcache,
	SecondaryIcache,
	SecondaryDcache,
	SecondaryCache,
	EisaAdapter,
	TcAdapter,
	ScsiAdapter,
	DtiAdapter,
	MultiFunctionAdapter,
	DiskController,
	TapeController,
	CdromController,
	WormController,
	SerialController,
	NetworkController,
	DisplayController,
	ParallelController,
	PointerController,
	KeyboardController,
	AudioController,
	OtherController,
	DiskPeripheral,
	FloppyDiskPeripheral,
	TapePeripheral,
	ModemPeripheral,
	MonitorPeripheral,
	PrinterPeripheral,
	PointerPeripheral,
	KeyboardPeripheral,
	TerminalPeripheral,
	OtherPeripheral,
	LinePeripheral,
	NetworkPeripheral,
	SystemMemory,
	DockingInformation,
	RealModeIrqRoutingTable,
	RealModePCIEnumeration,
	MaximumType
} CONFIGURATION_TYPE, *PCONFIGURATION_TYPE;

typedef enum _CONFIGURATION_CLASS
{
	SystemClass,
	ProcessorClass,
	CacheClass,
	AdapterClass,
	ControllerClass,
	PeripheralClass,
	MemoryClass,
	MaximumClass
} CONFIGURATION_CLASS, *PCONFIGURATION_CLASS;

typedef struct _CONFIGURATION_COMPONENT
{
	CONFIGURATION_CLASS Class;
	CONFIGURATION_TYPE Type;
	DEVICE_FLAGS Flags;
	UINT16 Version;
	UINT16 Revision;
	UINT32 Key;
	union
	{
		UINT32 AffinityMask;
		struct
		{
			UINT16 Group;
			UINT16 GroupIndex;
		};
	};
	UINT32 ConfigurationDataLength;
	UINT32 IdentifierLength;
	INT8* Identifier;
} CONFIGURATION_COMPONENT, *PCONFIGURATION_COMPONENT;

//
// Define configuration data structure used in all systems.
//
typedef struct _CONFIGURATION_COMPONENT_DATA
{
	struct _CONFIGURATION_COMPONENT_DATA *Parent;
	struct _CONFIGURATION_COMPONENT_DATA *Child;
	struct _CONFIGURATION_COMPONENT_DATA *Sibling;
	CONFIGURATION_COMPONENT ComponentEntry;
	VOID* ConfigurationData;
} CONFIGURATION_COMPONENT_DATA, *PCONFIGURATION_COMPONENT_DATA;



typedef struct _NLS_DATA_BLOCK
{
	VOID* AnsiCodePageData;
	VOID* OemCodePageData;
	VOID* UnicodeCaseTableData;
} NLS_DATA_BLOCK, *PNLS_DATA_BLOCK;

typedef struct _VHD_DISK_SIGNATURE
{
	UINT32 ParentPartitionNumber;
	UINT8 BootDevice[1];
} VHD_DISK_SIGNATURE, *PVHD_DISK_SIGNATURE;

typedef struct _ARC_DISK_SIGNATURE
{
	LIST_ENTRY ListEntry;
	UINT32   Signature;
	CHAR8*   ArcName;
	UINT32   CheckSum;
	BOOLEAN ValidPartitionTable;
	BOOLEAN xInt13;
	BOOLEAN IsGpt;
	UINT8 Reserved;
	UINT8 GptSignature[16];
	PVHD_DISK_SIGNATURE VhdSignature;
} ARC_DISK_SIGNATURE, *PARC_DISK_SIGNATURE;

typedef struct _ARC_DISK_INFORMATION
{
	LIST_ENTRY DiskSignatures;
} ARC_DISK_INFORMATION, *PARC_DISK_INFORMATION;

typedef struct _I386_LOADER_BLOCK
{
	VOID* CommonDataArea;
	UINT32 MachineType;      // Temporary only
	UINT32 VirtualBias;
} I386_LOADER_BLOCK, *PI386_LOADER_BLOCK;

typedef struct _ARM_LOADER_BLOCK
{
	UINT64 VirtualBias;
	VOID* KdCpuBuffer;
} ARM_LOADER_BLOCK, *PARM_LOADER_BLOCK;

typedef struct _VIRTUAL_EFI_RUNTIME_SERVICES
{
	//
	//  (Virtual) Entry points to each of the EFI Runtime services.
	//
	EFI_GET_TIME GetTime;
	EFI_SET_TIME SetTime;
	EFI_GET_WAKEUP_TIME GetWakeupTime;
	EFI_SET_WAKEUP_TIME SetWakeupTime;
	EFI_SET_VIRTUAL_ADDRESS_MAP SetVirtualAddressMap;
	EFI_CONVERT_POINTER ConvertPointer;
	EFI_GET_VARIABLE GetVariable;
	EFI_GET_NEXT_VARIABLE_NAME GetNextVariableName;
	EFI_SET_VARIABLE SetVariable;
	EFI_GET_NEXT_HIGH_MONO_COUNT GetNextHighMonotonicCount;
	EFI_RESET_SYSTEM ResetSystem;
	EFI_UPDATE_CAPSULE UpdateCapsule;
	EFI_QUERY_CAPSULE_CAPABILITIES QueryCapsuleCapabilities;
	EFI_QUERY_VARIABLE_INFO QueryVariableInfo;
} VIRTUAL_EFI_RUNTIME_SERVICES, *PVIRTUAL_EFI_RUNTIME_SERVICES;

typedef struct _EFI_FIRMWARE_INFORMATION
{
	UINT32 FirmwareVersion;
	PVIRTUAL_EFI_RUNTIME_SERVICES VirtualEfiRuntimeServices;

	//
	// The return value from SetVirtualAddressMap call.
	//
	EFI_STATUS SetVirtualAddressMapStatus;

	//
	// Number of mappings missed if any due to change in firmware
	// runtime memory map (for debugging).
	//
	UINT32 MissedMappingsCount;

	//
	// The firmware resource list identifies firmware components that can
	// be updated via WU.
	//
	LIST_ENTRY FirmwareResourceList;

	//
	// The EFI memory map.
	//
	VOID* EfiMemoryMap;
	UINT32 EfiMemoryMapSize;
	UINT32 EfiMemoryMapDescriptorSize;

} EFI_FIRMWARE_INFORMATION, *PEFI_FIRMWARE_INFORMATION;

typedef struct _PCAT_FIRMWARE_INFORMATION
{
	UINT32 PlaceHolder;
} PCAT_FIRMWARE_INFORMATION, *PPCAT_FIRMWARE_INFORMATION;

typedef struct _FIRMWARE_INFORMATION_LOADER_BLOCK
{
	struct
	{
		//
		// If set to TRUE, indicates that the system is running on EFI firmware.
		//
		UINT32 FirmwareTypeEfi : 1;

		//
		// A flag indicating whether EFI runtime service calls must be routed through IUM.
		//
		UINT32 EfiRuntimeUseIum : 1;

		//
		// A flag indicating whether EFI runtime code and data pages are
		// separate and protected with RW or RX protections.
		//
		UINT32 EfiRuntimePageProtectionEnabled : 1;

		//
		// A flag indicating whether the firmware supports code and data page
		// separation with restricted protections.
		//
		UINT32 EfiRuntimePageProtectionSupported : 1;

		#if defined (_ARM64_) || defined(_WIN64)
		//
		// If set to TRUE, indicates that the system EFI was started in EL2
		// and therefore has something running there (hypervisor/microvisor).
		// Also, this is where APs will start (EL2), and need to be directed
		// to EL1 properly before they can start in the HLOS.
		//
		UINT32 FirmwareStartedInEL2 : 1;
		UINT32 Reserved : 27;
		#else
		UINT32 Reserved : 28;
		#endif

	};

	union
	{
		EFI_FIRMWARE_INFORMATION EfiInformation;
		PCAT_FIRMWARE_INFORMATION PcatInformation;
	} u;

} FIRMWARE_INFORMATION_LOADER_BLOCK, *PFIRMWARE_INFORMATION_LOADER_BLOCK;

//
// Internal boot flags definitions.
//
#define INTERNAL_BOOT_FLAGS_NONE               0x00000000
#define INTERNAL_BOOT_FLAGS_UTC_BOOT_TIME      0x00000001
#define INTERNAL_BOOT_FLAGS_RTC_BOOT_TIME      0x00000002
#define INTERNAL_BOOT_FLAGS_NO_LEGACY_SERVICES 0x00000004

typedef struct _PROFILE_PARAMETER_BLOCK
{
	UINT16  Status;
	UINT16  Reserved;
	UINT16  DockingState;
	UINT16  Capabilities;
	UINT32   DockID;
	UINT32   SerialNumber;
} PROFILE_PARAMETER_BLOCK;

typedef struct _LOADER_PERFORMANCE_DATA
{
	UINT64 StartTime;
	UINT64 EndTime;
} LOADER_PERFORMANCE_DATA, *PLOADER_PERFORMANCE_DATA;

//
// The SORTPP tool can't handle array sizes expressed in terms of enums
// This hack can be removed when the tool is fixed
//
#define BOOT_ENTROPY_SOURCE_DATA_SIZE    (64)
#define BOOT_RNG_BYTES_FOR_NTOSKRNL      (1024)
#define BOOT_SEED_BYTES_FOR_CNG          (48)

//
// Entropy result codes and source IDs
// for Boot entropy sources are defined both in arc.h and
// ntexapi.h. These two copies must be kept identical.
//
typedef enum _BOOT_ENTROPY_SOURCE_RESULT_CODE
{
	BootEntropySourceStructureUninitialized = 0,
	BootEntropySourceDisabledByPolicy = 1,
	BootEntropySourceNotPresent = 2,
	BootEntropySourceError = 3,
	BootEntropySourceSuccess = 4,
} BOOT_ENTROPY_SOURCE_RESULT_CODE, *PBOOT_ENTROPY_SOURCE_RESULT_CODE;

typedef enum _BOOT_ENTROPY_SOURCE_ID
{
	BootEntropySourceNone = 0,
	BootEntropySourceSeedfile = 1,
	BootEntropySourceExternal = 2,
	BootEntropySourceTpm = 3,
	BootEntropySourceRdrand = 4,
	BootEntropySourceTime = 5,
	BootEntropySourceAcpiOem0 = 6,
	BootEntropySourceUefi = 7,
	BootEntropySourceCng = 8,
	BootMaxEntropySources = 8,
} BOOT_ENTROPY_SOURCE_ID;

//
// Boot entropy information
// This is the data that Boot passes to NT that contains the
// entropy & RNG information.
// These are the Boot versions of these structures.
// The name contains the string 'LDR' to distinguish it from the
// OS loader equivalents in ntexapi_h.w
//

typedef struct _BOOT_ENTROPY_SOURCE_LDR_RESULT
{
	BOOT_ENTROPY_SOURCE_ID SourceId;
	UINT64 Policy;
	BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
	EFI_STATUS ResultStatus;
	UINT64 Time; // in BlArchGetPerformanceCounter() units
	UINT32 EntropyLength;
	UINT8 EntropyData[BOOT_ENTROPY_SOURCE_DATA_SIZE];
} BOOT_ENTROPY_SOURCE_LDR_RESULT, *PBOOT_ENTROPY_SOURCE_LDR_RESULT;

//
// The constant BootMaxEntropySources is defined both in arc.w and ntexapi_h.w.
// If these ever get out of sync, different components will disagree on the value,
// and thus on the size of the array below.
// To help detect this type of bug we add a field with this constant so that the
// CHKed builds can assert on it.
//
typedef struct _BOOT_ENTROPY_LDR_RESULT
{
	UINT32 maxEntropySources;
	BOOT_ENTROPY_SOURCE_LDR_RESULT EntropySourceResult[BootMaxEntropySources];
	UINT8 SeedBytesForCng[BOOT_SEED_BYTES_FOR_CNG];
	UINT8 RngBytesForNtoskrnl[BOOT_RNG_BYTES_FOR_NTOSKRNL];
} BOOT_ENTROPY_LDR_RESULT, *PBOOT_ENTROPY_LDR_RESULT;

//
// Hypervisor specific loader parameters.
//
typedef struct _LOADER_PARAMETER_HYPERVISOR_EXTENSION
{
	//
	// Hypervisor crashdump pages if present.
	//
	UINT32 HypervisorCrashdumpAreaPageCount;
	UINT64 HypervisorCrashdumpAreaSpa;
	//
	// Hypervisor launch status.
	//
	UINT64 HypervisorLaunchStatus;
	UINT64 HypervisorLaunchStatusArg1;
	UINT64 HypervisorLaunchStatusArg2;
	UINT64 HypervisorLaunchStatusArg3;
	UINT64 HypervisorLaunchStatusArg4;
} LOADER_PARAMETER_HYPERVISOR_EXTENSION, *PLOADER_PARAMETER_HYPERVISOR_EXTENSION;

typedef struct _LOADER_BUGCHECK_PARAMETERS
{
	//
	// Bugcheck parameters passed to the kernel.
	//
	UINT32 BugcheckCode;
	UINT64 BugcheckParameter1;
	UINT64 BugcheckParameter2;
	UINT64 BugcheckParameter3;
	UINT64 BugcheckParameter4;
} LOADER_BUGCHECK_PARAMETERS, *PLOADER_BUGCHECK_PARAMETERS;

//
// EFI Offline crashdump configuration table definition.
//
#define OFFLINE_CRASHDUMP_VERSION_1 1
#define OFFLINE_CRASHDUMP_VERSION_2 2
#define OFFLINE_CRASHDUMP_VERSION_MAX OFFLINE_CRASHDUMP_VERSION_2

typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
{
	UINT32 Version;
	UINT32 AbnormalResetOccurred;
	UINT32 OfflineMemoryDumpCapable;
	//
	// Version_2 additional members.
	//
	PHYSICAL_ADDRESS ResetDataAddress;
	UINT32 ResetDataSize;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2;

//
// Original first version definition. Now only used in winload.efi when interfacing with firmware, and in
// sysinfo.c when interfacing with higher level sw above the kernel, to maintain backward compatibility.
//
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1
{
	UINT32 Version;
	UINT32 AbnormalResetOccurred;
	UINT32 OfflineMemoryDumpCapable;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1;

typedef OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 OFFLINE_CRASHDUMP_CONFIGURATION_TABLE;
typedef POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 POFFLINE_CRASHDUMP_CONFIGURATION_TABLE;

//
// Code Integrity specific loader paramets.
//
typedef struct _LOADER_PARAMETER_CI_EXTENSION
{
	//
	// Offset and size of various serialized data.
	//
	UINT32 RevocationListOffset;
	UINT32 RevocationListSize;
	UINT8 SerializedData[1];
} LOADER_PARAMETER_CI_EXTENSION, *PLOADER_PARAMETER_CI_EXTENSION;

typedef struct _LOADER_HIVE_RECOVERY_INFO
{
	struct
	{
		//
		// 1 if the hive was recovered by the boot loader, 0 otherwise.
		//
		UINT32 Recovered : 1;
		//
		// 1 if recovery from a legacy log file was performed, 0 otherwise.
		//
		UINT32 LegacyRecovery : 1;
		//
		// 1 if this hive was loaded as part of a soft reboot and encountered
		// a sharing violation during the load (causing it to be loaded from
		// a copy). 0 otherwise.
		//
		UINT32 SoftRebootConflict : 1;
		//
		// The most recent log from which recovery was performed as an 
		// HFILE_TYPE.
		//
		//      i.e. For legacy recovery the individual log file recovery was
		//           performed from, otherwise the log from which the highest
		//           sequence numbered entry was from.
		//
		UINT32 MostRecentLog : 3;
		UINT32 Spare : ((sizeof( UINT32 ) * 8) - 5);
	};

	//
	// The sequence number that should be used for the next log entry.
	//
	UINT32 LogNextSequence;
	//
	// The minimum sequence number in the most recent log.
	//
	UINT32 LogMinimumSequence;
	//
	// The file offset at which the next log entry should be written in the
	// most recent log.
	//
	UINT32 LogCurrentOffset;
} LOADER_HIVE_RECOVERY_INFO, *PLOADER_HIVE_RECOVERY_INFO;

typedef struct _LOADER_PARAMETER_EXTENSION
{
	UINT32   Size; // set to sizeof (struct _LOADER_PARAMETER_EXTENSION)
	PROFILE_PARAMETER_BLOCK Profile;

	//
	// Errata Manager inf file.
	//
	VOID*   EmInfFileImage;
	UINT32   EmInfFileSize;

	//
	// Pointer to the triage block, if present.
	//
	VOID* TriageDumpBlock;

	struct _HEADLESS_LOADER_BLOCK *HeadlessLoaderBlock;

	struct _SMBIOS3_TABLE_HEADER *SMBiosEPSHeader;

	VOID*   DrvDBImage;   // Database used to identify "broken" drivers.
	UINT32   DrvDBSize;

	// If booting from the Network (PXE) then we will
	// save the Network boot params in this loader block
	struct _NETWORK_LOADER_BLOCK *NetworkLoaderBlock;

	#if defined(_X86_)
	//
	// Pointers to IRQL translation tables that reside in the HAL
	// and are exposed to the kernel for use in the "inlined IRQL"
	// build
	//
	PUCHAR HalpIRQLToTPR;
	PUCHAR HalpVectorToIRQL;
	#endif

	//
	// Firmware Location
	//
	LIST_ENTRY  FirmwareDescriptorListHead;

	//
	// Pointer to the in-memory copy of override ACPI tables.  The override
	// table file is a simple binary file with one or more ACPI tables laid
	// out one after another.
	//
	VOID*   AcpiTable;

	//
	// Size of override ACPI tables in bytes.
	//
	UINT32   AcpiTableSize;

	//
	// Various informational flags passed to OS via OS Loader.
	//
	struct
	{
		//
		// Variables describing the success of the previous boot - whether
		// booting into the OS was successful, and whether the arc from boot to
		// runtime to shutdown was successful.  Various types of system crashes
		// will cause one or both of these to be FALSE.
		//
		UINT32 LastBootSucceeded : 1;
		UINT32 LastBootShutdown : 1;

		//
		// A flag indicating whether the platform supports access to IO ports.
		//
		UINT32 IoPortAccessSupported : 1;

		//
		// A flag indicating whether or not the boot debugger persisted
		// through kernel initialization.
		//
		UINT32 BootDebuggerActive : 1;

		//
		// A flag indicating whether the system must enforce strong code
		// guarantees.
		//
		UINT32 StrongCodeGuarantees : 1;

		//
		// A flag indicating whether the system must enforce hard strong code
		// guarantees.
		//
		UINT32 HardStrongCodeGuarantees : 1;

		//
		// A flag indicating whether SID sharing disabled.
		//
		UINT32 SidSharingDisabled : 1;

		//
		// A flag indicating whether TPM was intialized successfully or not
		// by the OS loader during boot.
		//
		UINT32 TpmInitialized : 1;

		//
		// A flag indicating whether the VSM code page has been configured and
		// is usable.
		//
		UINT32 VsmConfigured : 1;

		//
		// A flag indicating whether IUM is enabled.
		//
		UINT32 IumEnabled : 1;

		//
		// A flag indicating whether we're booting from SMB
		//
		UINT32 IsSmbboot : 1;

		//
		// The remainder of the bits are reserved.
		//
		UINT32 Reserved : 21;
	};

	//
	// Loader runtime performance data.
	//
	PLOADER_PERFORMANCE_DATA LoaderPerformanceData;

	//
	// Boot application persistent data.
	//
	LIST_ENTRY BootApplicationPersistentData;

	//
	// Windows Memory Diagnostic Test Results.
	//
	VOID* WmdTestResult;

	//
	// Boot entry identifier.
	//
	GUID BootIdentifier;

	//
	// The number of pages to reserve for the resume application to use as
	// scratch space.  This should correspond to the boot environment's memory
	// footprint.
	//
	UINT32 ResumePages;

	//
	// The crash dump header, if present.
	//
	VOID* DumpHeader;

	//
	// Boot graphics context.
	//
	VOID* BgContext;

	//
	// NUMA node locality information and group assignment data.
	//
	VOID* NumaLocalityInfo;
	VOID* NumaGroupAssignment;

	//
	// List of hives attached by loader
	//
	LIST_ENTRY AttachedHives;

	//
	// Number of entries in the MemoryCachingRequirements map.
	//
	UINT32 MemoryCachingRequirementsCount;

	//
	// List of MEMORY_CACHING_REQUIREMENTS for the system.
	//
	VOID* MemoryCachingRequirements;

	//
	// Result of the Boot entropy gathering.
	//
	BOOT_ENTROPY_LDR_RESULT BootEntropyResult;

	//
	// Computed ITC/TSC frequency of the BSP in hertz.
	//
	UINT64 ProcessorCounterFrequency;

	//
	// Hypervisor specific information.
	//
	LOADER_PARAMETER_HYPERVISOR_EXTENSION HypervisorExtension;

	//
	// Hardware configuration ID used to uniquelly identify the system.
	//
	GUID HardwareConfigurationId;

	//
	// List of HAL_EXTENSION_MODULE_ENTRY structures.
	//
	LIST_ENTRY HalExtensionModuleList;

	//
	// Contains most recent time from firmware, bootstat.dat and ntos build time.
	//
	LARGE_INTEGER SystemTime;

	//
	// Contains cycle counter timestamp at the time SystemTime value was read.
	//
	UINT64 TimeStampAtSystemTimeRead;

	//
	// Boot Flags that are passed to the SystemBootEnvironmentInformation class.
	//
	UINT64 BootFlags;

	//
	// Internal only flags that are passed to the kernel.
	//
	UINT64 InternalBootFlags;

	//
	// Pointer to the in-memory copy of the Wfs FP data.
	//
	VOID*   WfsFPData;

	//
	// Size of Wfs FP data in bytes.
	//
	UINT32   WfsFPDataSize;

	//
	// Loader bugcheck parameters for the kernel or extensions to act upon
	//
	LOADER_BUGCHECK_PARAMETERS BugcheckParameters;

	//
	// API set schema data.
	//
	VOID* ApiSetSchema;
	UINT32 ApiSetSchemaSize;
	LIST_ENTRY ApiSetSchemaExtensions;

	//
	// The system's firmware version according to ACPI's FADT,
	// SMBIOS's BIOS information table, and EFI's system table respectively.
	//
	UNICODE_STRING AcpiBiosVersion;
	UNICODE_STRING SmbiosVersion;
	UNICODE_STRING EfiVersion;

	//
	// Debugger Descriptor
	//
	struct _DEBUG_DEVICE_DESCRIPTOR *KdDebugDevice;

	//
	// EFI Offline crashdump configuration table.
	//
	OFFLINE_CRASHDUMP_CONFIGURATION_TABLE OfflineCrashdumpConfigurationTable;

	//
	// Manufacturing mode profile name.
	//
	UNICODE_STRING ManufacturingProfile;

	//
	// BBT Buffer to enable precise event based sampling.
	//
	VOID* BbtBuffer;

	//
	// Registry values to be passed to the kernel for calculation of Xsave Buffer Size on Intel platforms
	//
	#if defined(_X86_) || defined (_AMD64_) || defined (_WIN64)
	UINT64 XsaveAllowedFeatures;
	UINT32 XsaveFlags;
	#endif

	//
	// Boot options used by the OS loader.
	//
	VOID* BootOptions;

	//
	// Boot sequence tracking for reliability reporting.
	//
	UINT32 BootId;

	//
	// Code Integrity configuration.
	//
	PLOADER_PARAMETER_CI_EXTENSION CodeIntegrityData;
	UINT32 CodeIntegrityDataSize;

	LOADER_HIVE_RECOVERY_INFO SystemHiveRecoveryInfo;
} LOADER_PARAMETER_EXTENSION, *PLOADER_PARAMETER_EXTENSION;

typedef struct _LOADER_PARAMETER_BLOCK
{
	UINT32 OsMajorVersion;
	UINT32 OsMinorVersion;
	UINT32 Size;
	UINT32 OsLoaderSecurityVersion;
	LIST_ENTRY LoadOrderListHead;
	LIST_ENTRY MemoryDescriptorListHead;
	//
	// Define the Core, TPM Core and Core Extensions driver lists. The
	// lists are organized as follows:
	//
	//  1. Core Drivers: This list consists of drivers that ELAM drivers and
	//         3rd party Core Extensions depend upon (e.g. WDF, CNG.sys). All
	//         drivers in this group should be MS-supplied and thus MS-signed.
	//
	//  2. ELAM drivers. This list consists of 3rd party ELAM drivers. These
	//         drivers need to be signed with ELAM certificate.
	//
	//  3. Core Extensions: This list consists of 3rd party drivers (viz.
	//         Platform Extensions and Tree drivers) that TPM Core drivers
	//         depend upon. These drivers need to be signed with Core Extension
	//         certificate.
	//
	//  4. TPM Core: This list consists of TPM driver and bus drivers (e.g.
	//         ACPI, PCI) that are necessary to enumerate TPM. All drivers in
	//         this group should be MS-supplied and thus MS-signed.
	//
	//  5. Boot Driver: This list contains the rest of the boot drivers.
	//
	LIST_ENTRY BootDriverListHead;
	LIST_ENTRY EarlyLaunchListHead;
	LIST_ENTRY CoreDriverListHead;
	LIST_ENTRY CoreExtensionsDriverListHead;
	LIST_ENTRY TpmCoreDriverListHead;
	UINT64 KernelStack;
	UINT64 Prcb;
	UINT64 Process;
	UINT64 Thread;
	UINT32 KernelStackSize;
	UINT32 RegistryLength;
	VOID* RegistryBase;
	PCONFIGURATION_COMPONENT_DATA ConfigurationRoot;
	UINT8* ArcBootDeviceName;
	UINT8* ArcHalDeviceName;
	UINT8* NtBootPathName;
	UINT8* NtHalPathName;
	UINT8* LoadOptions;
	PNLS_DATA_BLOCK NlsData;
	PARC_DISK_INFORMATION ArcDiskInformation;
	PLOADER_PARAMETER_EXTENSION Extension;
	union
	{
		I386_LOADER_BLOCK I386;
		ARM_LOADER_BLOCK Arm;
	} u;
	FIRMWARE_INFORMATION_LOADER_BLOCK FirmwareInformation;
} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;