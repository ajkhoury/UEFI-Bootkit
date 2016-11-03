#include "utils.h"
#include "udis86/udis86.h"

// Libraries
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>

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

UINT32 UtilCodeSize( IN UINT8* CodeStart )
{
	for (int i = 1; i <= 1000; i++)
	{
		if (CodeStart[i - 1] == 0xCC)
			return i - 1;
	}
	return 1000;
}

VOID UtilDisassembleCode( IN UINT8* CodeStart, IN VOID* VirtualAddress, IN UINT32 Length )
{
	ud_t u;
	UINT32 codeSize = 0;
	codeSize = Length;//UtilCodeSize( CodeStart );
	ud_init( &u );
	ud_set_input_buffer( &u, CodeStart, codeSize );
	ud_set_pc( &u, (UINT64)VirtualAddress );
	ud_set_mode( &u, 64 );
	ud_set_syntax( &u, UD_SYN_INTEL );

	while (ud_disassemble( &u ))
	{
		//int len = ud_insn_len(&u);
		CHAR16 wcHex[256] = { 0 };
		CHAR16 wcAsm[256] = { 0 };
		uint64_t offset = ud_insn_off( &u );
		const CHAR8* szHex = ud_insn_hex( &u );
		const CHAR8* szAsm = ud_insn_asm( &u );
		AsciiStrToUnicodeStr( szHex, (CHAR16*)wcHex );
		AsciiStrToUnicodeStr( szAsm, (CHAR16*)wcAsm );
		Print( L"  %lx  %-20s%-48s\n", offset, wcHex, wcAsm );
	}
}

//for (int i = 1; i <= 64; i++)
//	Print( (i % 16 == 0) ? L"%02x\r\n" : (i % 8 == 0) ? L"%02x   " : L"%02x ", ((UINT8*)oOslLoadImage)[i - 1] );