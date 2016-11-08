#include "pe.h"

PIMAGE_DOS_HEADER ImageDosHeader( IN VOID* ImageBase )
{
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)(ImageBase);
	if (!ImageDosHeader)
		return NULL;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	return ImageDosHeader;
}

PIMAGE_NT_HEADERS ImageNtHeader( IN VOID* ImageBase )
{
	PIMAGE_DOS_HEADER ImageDosHdr;
	PIMAGE_NT_HEADERS ImageNtHdr;
	ImageDosHdr = ImageDosHeader( ImageBase );
	if (!ImageDosHdr)
		return NULL;
	ImageNtHdr = (PIMAGE_NT_HEADERS)((UINT8*)ImageBase + ImageDosHdr->e_lfanew);
	if (ImageNtHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	return ImageNtHdr;
}