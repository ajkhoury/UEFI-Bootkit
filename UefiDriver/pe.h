#pragma once

#include "pestructs.h"

#define IMAGE32(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define IMAGE_SIZE(hdr) (IMAGE64(hdr) ? ((PIMAGE_NT_HEADERS64)hdr)->OptionalHeader.SizeOfImage : ((PIMAGE_NT_HEADERS32)hdr)->OptionalHeader.SizeOfImage)

#define HEADER_VAL_T(hdr, val) (IMAGE64(hdr) ? ((PIMAGE_NT_HEADERS64)hdr)->OptionalHeader.val : ((PIMAGE_NT_HEADERS32)hdr)->OptionalHeader.val)
#define THUNK_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_THUNK_DATA64)ptr)->val : ((PIMAGE_THUNK_DATA32)ptr)->val)
#define DATA_DIRECTORY(hdr, idx) (IMAGE64(hdr) ? &(((PIMAGE_OPTIONAL_HEADER64)&(hdr->OptionalHeader))->DataDirectory[idx]) : &(((PIMAGE_OPTIONAL_HEADER32)&(hdr->OptionalHeader))->DataDirectory[idx]))

PIMAGE_DOS_HEADER ImageDosHeader( IN VOID* ImageBase );

PIMAGE_NT_HEADERS ImageNtHeader( IN VOID* ImageBase );