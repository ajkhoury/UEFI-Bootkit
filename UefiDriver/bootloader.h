#pragma once

#include <Protocol/GraphicsOutput.h>
#include "arc.h"

typedef UINTN BLSTATUS;
#define BLAPI __stdcall

#define BOOT_APPLICATION_SIGNATURE_1                    'TOOB'
#define BOOT_APPLICATION_SIGNATURE_2                    ' PPA'

#define BOOT_MEMORY_TRANSLATION_TYPE_PHYSICAL           0
#define BOOT_MEMORY_TRANSLATION_TYPE_VIRTUAL            1

#define BOOT_APPLICATION_VERSION                        2
#define BL_MEMORY_DATA_VERSION                          1
#define BL_RETURN_ARGUMENTS_VERSION                     1
#define BL_FIRMWARE_DESCRIPTOR_VERSION                  2

#define BL_RETURN_ARGUMENTS_NO_PAE_FLAG                 0x40

#define BL_APPLICATION_ENTRY_FLAG_NO_GUID               0x01
#define BL_APPLICATION_ENTRY_BCD_OPTIONS_INTERNAL       0x02
#define BL_APPLICATION_ENTRY_WINLOAD                    0x04
#define BL_APPLICATION_ENTRY_STARTUP                    0x08
#define BL_APPLICATION_ENTRY_REBOOT_ON_ERROR            0x20
#define BL_APPLICATION_ENTRY_NTLDR                      0x40
#define BL_APPLICATION_ENTRY_BCD_OPTIONS_EXTERNAL       0x80
#define BL_APPLICATION_ENTRY_WINRESUME                  0x100
#define BL_APPLICATION_ENTRY_SETUPLDR                   0x200
#define BL_APPLICATION_ENTRY_BOOTSECTOR                 0x400
#define BL_APPLICATION_ENTRY_BOOTMGR                    0x1000
#define BL_APPLICATION_ENTRY_DISPLAY_ORDER              0x800000
#define BL_APPLICATION_ENTRY_FIXED_SEQUENCE             0x20000000
#define BL_APPLICATION_ENTRY_RECOVERY                   0x40000000

#define BL_LIBRARY_FLAG_NO_DISPLAY                      0x01
#define BL_LIBRARY_FLAG_REINITIALIZE                    0x02
#define BL_LIBRARY_FLAG_REINITIALIZE_ALL                0x04
#define BL_LIBRARY_FLAG_ZERO_HEAP_ALLOCATIONS_ON_FREE   0x10
#define BL_LIBRARY_FLAG_INITIALIZATION_COMPLETED        0x20
#define BL_LIBRARY_FLAG_NO_GRAPHICS_CONSOLE             0x800

#define BL_DISPLAY_GRAPHICS_FORCED_VIDEO_MODE_FLAG      0x01
#define BL_DISPLAY_GRAPHICS_FORCED_HIGH_RES_MODE_FLAG   0x02

typedef enum _BL_MEMORY_TYPE
{
	// Loader Memory
	BlLoaderMemory = 0xD0000002,
	BlLoaderDeviceMemory = 0xD0000004,
	BlLoaderHeap = 0xD0000005,
	BlLoaderPageDirectory = 0xD0000006,
	BlLoaderReferencePage = 0xD0000007,
	BlLoaderRamDisk = 0xD0000008,
	BlLoaderData = 0xD000000A,
	BlLoaderRegistry = 0xD000000B,
	BlLoaderBlockMemory = 0xD000000C,
	BlLoaderSelfMap = 0xD000000F,
	// Application Memory
	BlApplicationReserved = 0xE0000001,
	BlApplicationData = 0xE0000004,
	// System Memory
	BlConventionalMemory = 0xF0000001,
	BlUnusableMemory = 0xF0000002,
	BlReservedMemory = 0xF0000003,
	BlEfiBootMemory = 0xF0000004,
	BlEfiRuntimeMemory = 0xF0000006,
	BlAcpiReclaimMemory = 0xF0000008,
	BlAcpiNvsMemory = 0xF0000009,
	BlDeviceIoMemory = 0xF000000A,
	BlDevicePortMemory = 0xF000000B,
	BlPalMemory = 0xF000000C,
} BL_MEMORY_TYPE;

typedef struct _BL_LIBRARY_PARAMETERS
{
	UINT32 LibraryFlags;
	UINT32 TranslationType;
	UINT32 MinimumAllocationCount;
	UINT32 MinimumHeapSize;
	UINT32 HeapAllocationAttributes;
	CHAR16* ApplicationBaseDirectory;
	UINT32 DescriptorCount;
	CHAR16* FontBaseDirectory;
} BL_LIBRARY_PARAMETERS, *PBL_LIBRARY_PARAMETERS;

typedef struct _BOOT_APPLICATION_PARAMETER_BLOCK
{
	/* This header tells the library what image we're dealing with */
	UINT32 Signature[2]; // 0x00
	UINT32 Version; // 0x08
	UINT32 Size; // 0xC
	UINT32 ImageType; // 0x10
	UINT32 MemoryTranslationType; // 0x14
	UINT64 ImageBase; // 0x18
	UINT32 ImageSize; // 0x20
					  /* Offset to BL_MEMORY_DATA */
	UINT32 MemoryDataOffset; // 0x24
							 /* Offset to BL_APPLICATION_ENTRY */
	UINT32 AppEntryOffset; // 0x28
						   /* Offset to BL_DEVICE_DESCRPIPTOR */
	UINT32 BootDeviceOffset; // 0x2C
							 /* Offset to BL_FIRMWARE_DESCRIPTOR */
	UINT32 FirmwareParametersOffset; // 0x30
									 /* Offset to BL_RETURN_ARGUMENTS */
	UINT32 ReturnArgumentsOffset; // 0x34
} BOOT_APPLICATION_PARAMETER_BLOCK, *PBOOT_APPLICATION_PARAMETER_BLOCK;

typedef struct _BL_MEMORY_DATA
{
	UINT32 Version;
	UINT32 MdListOffset;
	UINT32 DescriptorCount;
	UINT32 DescriptorSize;
	UINT32 DescriptorOffset;
} BL_MEMORY_DATA, *PBL_MEMORY_DATA;

typedef struct _BL_FIRMWARE_DESCRIPTOR
{
	UINT32 Version;
	UINT32 Unknown;
	EFI_HANDLE ImageHandle;
	EFI_SYSTEM_TABLE* SystemTable;
} BL_FIRMWARE_DESCRIPTOR, *PBL_FIRMWARE_DESCRIPTOR;

typedef struct _BL_RETURN_ARGUMENTS
{
	UINT32 Version; // 0x00
	UINT32 Status; // 0x04
	UINT32 Flags; // 0x08
	UINT64 DataSize; // 0x10
	UINT64 DataPage; // 0x18
} BL_RETURN_ARGUMENTS, *PBL_RETURN_ARGUMENTS;

typedef struct _BL_MEMORY_DESCRIPTOR
{
	LIST_ENTRY ListEntry;
	union
	{
		struct
		{
			UINT64 BasePage;
			UINT64 VirtualPage;
		};
		struct
		{
			UINT64 BaseAddress;
			UINT64 VirtualAddress;
		};
	};
	UINT64 PageCount;
	UINT32 Flags;
	BL_MEMORY_TYPE Type;
} BL_MEMORY_DESCRIPTOR, *PBL_MEMORY_DESCRIPTOR;

typedef struct _BL_BCD_OPTION
{
	UINT32 Type;
	UINT32 DataOffset;
	UINT32 DataSize;
	UINT32 ListOffset;
	UINT32 NextEntryOffset;
	UINT32 Empty;
} BL_BCD_OPTION, *PBL_BCD_OPTION;

typedef struct _BL_APPLICATION_ENTRY
{
	CHAR8 Signature[8];
	UINT32 Flags;
	EFI_GUID Guid;
	UINT32 Unknown[4];
	BL_BCD_OPTION BcdData;
} BL_APPLICATION_ENTRY, *PBL_APPLICATION_ENTRY;

typedef struct _BL_LOADED_APPLICATION_ENTRY
{
	UINT32 Flags;
	EFI_GUID Guid;
	PBL_BCD_OPTION BcdData;
} BL_LOADED_APPLICATION_ENTRY, *PBL_LOADED_APPLICATION_ENTRY;


//
// Console Stuff
//
struct _BL_TEXT_CONSOLE;
struct _BL_DISPLAY_STATE;
struct _BL_DISPLAY_MODE;
struct _BL_INPUT_CONSOLE;
struct _BL_REMOTE_CONSOLE;
struct _BL_GRAPHICS_CONSOLE;
typedef
VOID
( *PCONSOLE_DESTRUCT ) (
	IN struct _BL_TEXT_CONSOLE* Console
	);

typedef
EFI_STATUS
( *PCONSOLE_REINITIALIZE ) (
	IN struct _BL_TEXT_CONSOLE* Console
	);

typedef
EFI_STATUS
( *PCONSOLE_GET_TEXT_STATE ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	OUT struct _BL_DISPLAY_STATE* TextState
	);

typedef
EFI_STATUS
( *PCONSOLE_SET_TEXT_STATE ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	IN UINT32 Flags,
	IN struct _BL_DISPLAY_STATE* TextState
	);

typedef
EFI_STATUS
( *PCONSOLE_GET_TEXT_RESOLUTION ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	OUT UINT32* TextResolution
	);

typedef
EFI_STATUS
( *PCONSOLE_SET_TEXT_RESOLUTION ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	IN UINT32 NewTextResolution,
	OUT UINT32* OldTextResolution
	);

typedef
EFI_STATUS
( *PCONSOLE_CLEAR_TEXT ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	IN BOOLEAN LineOnly
	);

typedef
BOOLEAN
( *PCONSOLE_IS_ENABLED ) (
	IN struct _BL_GRAPHICS_CONSOLE* Console
	);

typedef
EFI_STATUS
( *PCONSOLE_GET_GRAPHICAL_RESOLUTION ) (
	IN struct _BL_GRAPHICS_CONSOLE* Console,
	OUT struct _BL_DISPLAY_MODE* DisplayMode
	);

typedef
EFI_STATUS
( *PCONSOLE_SET_GRAPHICAL_RESOLUTION ) (
	IN struct _BL_GRAPHICS_CONSOLE* Console,
	IN struct _BL_DISPLAY_MODE DisplayMode
	);

typedef
EFI_STATUS
( *PCONSOLE_ENABLE ) (
	IN struct _BL_GRAPHICS_CONSOLE* Console,
	IN BOOLEAN Enable
	);

typedef
EFI_STATUS
( *PCONSOLE_WRITE_TEXT ) (
	IN struct _BL_TEXT_CONSOLE* Console,
	IN CHAR8* Text,
	IN UINT32 Attribute
	);

typedef struct _BL_DISPLAY_STATE
{
	UINT32 BgColor;
	UINT32 FgColor;
	UINT32 XPos;
	UINT32 YPos;
	UINT32 CursorVisible;
} BL_DISPLAY_STATE, *PBL_DISPLAY_STATE;

typedef struct _BL_DISPLAY_MODE
{
	UINT32 HRes;
	UINT32 VRes;
	UINT32 HRes2;
} BL_DISPLAY_MODE, *PBL_DISPLAY_MODE;

typedef struct _BL_TEXT_CONSOLE_VTABLE
{
	PCONSOLE_DESTRUCT Destruct;
	PCONSOLE_REINITIALIZE Reinitialize;
	PCONSOLE_GET_TEXT_STATE GetTextState;
	PCONSOLE_SET_TEXT_STATE SetTextState;
	PCONSOLE_GET_TEXT_RESOLUTION GetTextResolution;
	PCONSOLE_SET_TEXT_RESOLUTION SetTextResolution;
	PCONSOLE_CLEAR_TEXT ClearText;
	PCONSOLE_WRITE_TEXT WriteText;
} BL_TEXT_CONSOLE_VTABLE, *PBL_TEXT_CONSOLE_VTABLE;

typedef struct _BL_GRAPHICS_CONSOLE_VTABLE
{
	BL_TEXT_CONSOLE_VTABLE Text;
	PCONSOLE_IS_ENABLED IsEnabled;
	PCONSOLE_ENABLE Enable;
	VOID* GetConsoleResolution;
	PCONSOLE_GET_GRAPHICAL_RESOLUTION GetGraphicalResolution;
	PCONSOLE_GET_GRAPHICAL_RESOLUTION GetOriginalResolution;
	PCONSOLE_SET_GRAPHICAL_RESOLUTION SetOriginalResolution;
} BL_GRAPHICS_CONSOLE_VTABLE, *PBL_GRAPHICS_CONSOLE_VTABLE;

typedef struct _BL_TEXT_CONSOLE
{
	PBL_TEXT_CONSOLE_VTABLE Callbacks;
	BL_DISPLAY_STATE State;
	BL_DISPLAY_MODE DisplayMode;
	BOOLEAN Active;
	EFI_GUID* Protocol;
	UINT32 Mode;
	EFI_SIMPLE_TEXT_OUTPUT_MODE OldMode;
} BL_TEXT_CONSOLE, *PBL_TEXT_CONSOLE;

typedef struct _BL_INPUT_CONSOLE_VTABLE
{
	PCONSOLE_DESTRUCT Destruct;
	PCONSOLE_REINITIALIZE Reinitialize;
	//PCONSOLE_IS_KEY_PENDING IsKeyPending;
	//PCONSOLE_READ_INPUT ReadInput;
	//PCONSOLE_ERASE_BUFFER EraseBuffer;
	//PCONSOLE_FILL_BUFFER FillBuffer;
} BL_INPUT_CONSOLE_VTABLE, *PBL_INPUT_CONSOLE_VTABLE;

typedef struct _BL_INPUT_CONSOLE
{
	PBL_INPUT_CONSOLE_VTABLE Callbacks;
	UINT32* Buffer;
	UINT32* DataStart;
	UINT32* DataEnd;
	UINT32* EndBuffer;
} BL_INPUT_CONSOLE, *PBL_INPUT_CONSOLE;

typedef enum _BL_GRAPHICS_CONSOLE_TYPE
{
	BlGopConsole,
	BlUgaConsole
} BL_GRAPHICS_CONSOLE_TYPE;

typedef struct _BL_GRAPHICS_CONSOLE
{
	BL_TEXT_CONSOLE TextConsole;
	BL_DISPLAY_MODE DisplayMode;
	UINT32 PixelDepth;
	UINT32 FgColor;
	UINT32 BgColor;
	BL_DISPLAY_MODE OldDisplayMode;
	UINT32 OldPixelDepth;
	EFI_HANDLE Handle;
	BL_GRAPHICS_CONSOLE_TYPE Type;
	EFI_GRAPHICS_OUTPUT_PROTOCOL* Protocol;
	VOID* FrameBuffer;
	UINT32 FrameBufferSize;
	UINT32 PixelsPerScanLine;
	UINT32 Mode;
	UINT32 OldMode;
} BL_GRAPHICS_CONSOLE, *PBL_GRAPHICS_CONSOLE;

typedef struct _BL_REMOTE_CONSOLE
{
	BL_TEXT_CONSOLE TextConsole;
} BL_REMOTE_CONSOLE, *PBL_REMOTE_CONSOLE;
