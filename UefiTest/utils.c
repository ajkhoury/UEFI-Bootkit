#include "utils.h"

// Libraries
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
// Protocols
#include <Protocol/SimpleFileSystem.h>

VOID UtilPrintLoadedImageInfo( IN EFI_LOADED_IMAGE *ImageInfo )
{
	Print( L"\r\n[+] %s\r\n", ConvertDevicePathToText( ImageInfo->FilePath, TRUE, TRUE ) );
	Print( L"     ->ImageBase = %lx\r\n", ImageInfo->ImageBase );
	Print( L"     ->ImageSize = %lx\r\n", ImageInfo->ImageSize );
}

VOID UtilWaitForKey( VOID )
{
	UINTN index = 0;
	EFI_INPUT_KEY key = { 0 };
	gBS->WaitForEvent( 1, &gST->ConIn->WaitForKey, &index );
	gST->ConIn->ReadKeyStroke( gST->ConIn, &key );
}

EFI_STATUS UtilLocateFile( IN CHAR16* ImagePath, OUT EFI_DEVICE_PATH** DevicePath )
{
	EFI_FILE_IO_INTERFACE *ioDevice;
	EFI_FILE_HANDLE handleRoots, bootFile;
	EFI_HANDLE* handleArray;
	UINTN nbHandles, i;
	EFI_STATUS efistatus;

	*DevicePath = (EFI_DEVICE_PATH *)NULL;
	efistatus = gBS->LocateHandleBuffer( ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &nbHandles, &handleArray );
	if (EFI_ERROR( efistatus ))
		return efistatus;

	Print( L"\r\nNumber of UEFI Filesystem Devices: %d\r\n", nbHandles );

	for (i = 0; i < nbHandles; i++)
	{
		efistatus = gBS->HandleProtocol( handleArray[i], &gEfiSimpleFileSystemProtocolGuid, &ioDevice );
		if (EFI_ERROR( efistatus ))
			continue;

		efistatus = ioDevice->OpenVolume( ioDevice, &handleRoots );
		if (EFI_ERROR( efistatus ))
			continue;

		efistatus = handleRoots->Open( handleRoots, &bootFile, ImagePath, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY );
		if (!EFI_ERROR( efistatus ))
		{
			handleRoots->Close( bootFile );
			*DevicePath = FileDevicePath( handleArray[i], ImagePath );
			break;
		}
	}

	return efistatus;
}

EFI_STATUS UtilFindPattern( IN UINT8* Pattern, IN UINT8 Wildcard, IN UINT32 PatternLength, VOID* Base, UINT32 Size, OUT VOID ** Found )
{
	if (Found == NULL || Pattern == NULL || Base == NULL)
		return EFI_INVALID_PARAMETER;

	for (UINT64 i = 0; i < Size - PatternLength; i++)
	{
		BOOLEAN found = TRUE;
		for (UINT64 j = 0; j < PatternLength; j++)
		{
			if (Pattern[j] != Wildcard && Pattern[j] != ((UINT8*)Base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*Found = (UINT8*)Base + i;
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}

VOID* UtilCallAddress( IN VOID* CallAddress )
{
	UINT32 RelativeCallOffset = *(UINT32*)((UINT8*)CallAddress + 1);
	return (VOID*)((UINT8*)CallAddress + RelativeCallOffset + 1 + sizeof( UINT32 ));
}

UINT32 UtilCalcRelativeCallOffset( IN VOID* CallAddress, IN VOID* TargetAddress )
{
	return (UINT32)(((UINT64)TargetAddress) - ((UINT64)CallAddress + 1 + sizeof( UINT32 )));
}