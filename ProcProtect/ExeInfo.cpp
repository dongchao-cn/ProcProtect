#include <ntifs.h>
#include <ntintsafe.h>
//#include <ntddk.h>
//#include <winnt.h>
#include "ExeInfo.h"
#include "MD5.h"

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;


void GetDosHeader(HANDLE hFile,PIMAGE_DOS_HEADER pImageDosHeader)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iostatus;
	FILE_POSITION_INFORMATION fpi;
	fpi.CurrentByteOffset.QuadPart = 0;
	status = ZwSetInformationFile(hFile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(NT_SUCCESS(status));

	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pImageDosHeader,
		sizeof(IMAGE_DOS_HEADER),
		0,
		NULL);
	ASSERT(NT_SUCCESS(status));
}

void GetPEHeader(HANDLE hFile,PIMAGE_NT_HEADERS pImagePEHeader)
{
	IMAGE_DOS_HEADER ImageDosHeader;
	GetDosHeader(hFile,&ImageDosHeader);

	NTSTATUS status;
	IO_STATUS_BLOCK iostatus;
	FILE_POSITION_INFORMATION fpi;
	fpi.CurrentByteOffset.QuadPart = ImageDosHeader.e_lfanew;
	status = ZwSetInformationFile(hFile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(NT_SUCCESS(status));

	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pImagePEHeader,
		sizeof(IMAGE_NT_HEADERS),
		0,
		NULL);
	ASSERT(NT_SUCCESS(status));
}


void GetSectionTable(HANDLE hFile,PIMAGE_SECTION_HEADER pImageSectionHeader,WORD &ImageSectionNum)
{
	IMAGE_NT_HEADERS ImagePEHeader;
	GetPEHeader(hFile,&ImagePEHeader);
	ImageSectionNum = ImagePEHeader.FileHeader.NumberOfSections;

	if (pImageSectionHeader == NULL)
	{
		// 通过ImageSectionNum返回需要的大小
		return;
	}

	IMAGE_DOS_HEADER ImageDosHeader;
	GetDosHeader(hFile,&ImageDosHeader);

	NTSTATUS status;
	IO_STATUS_BLOCK iostatus;
	FILE_POSITION_INFORMATION fpi;
	fpi.CurrentByteOffset.QuadPart = ImageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
	status = ZwSetInformationFile(hFile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(NT_SUCCESS(status));

	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pImageSectionHeader,
		sizeof(IMAGE_SECTION_HEADER)*ImageSectionNum,
		0,
		NULL);
	ASSERT(NT_SUCCESS(status));
}

WORD FindRVASection(HANDLE hFile,ULONG RVA)
{
	PIMAGE_SECTION_HEADER pImageSectionHeader;
	WORD ImageSectionNum;
	GetSectionTable(hFile,NULL,ImageSectionNum);
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)ExAllocatePool(NonPagedPool,sizeof(IMAGE_SECTION_HEADER)*ImageSectionNum);
	GetSectionTable(hFile,pImageSectionHeader,ImageSectionNum);


	WORD SectionNum = 0;
	for (;SectionNum < ImageSectionNum;SectionNum++)
	{
		if (RVA >= pImageSectionHeader[SectionNum].VirtualAddress
			&& RVA < pImageSectionHeader[SectionNum].VirtualAddress + pImageSectionHeader[SectionNum].Misc.VirtualSize)
		{
			break;
		}
	}
	ExFreePool(pImageSectionHeader);
	return SectionNum;
}


ULONG RVA2FileOffset(HANDLE hFile,ULONG RVA)
{
	PIMAGE_SECTION_HEADER pImageSectionHeader;
	WORD ImageSectionNum;
	GetSectionTable(hFile,NULL,ImageSectionNum);
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)ExAllocatePool(NonPagedPool,sizeof(IMAGE_SECTION_HEADER)*ImageSectionNum);
	GetSectionTable(hFile,pImageSectionHeader,ImageSectionNum);
	
	WORD SectionNum = FindRVASection(hFile,RVA);

	ULONG FileOffset = RVA - (pImageSectionHeader[SectionNum].VirtualAddress - pImageSectionHeader[SectionNum].PointerToRawData);
	ExFreePool(pImageSectionHeader);
	return FileOffset;
}

void GetImportDescriptor(HANDLE hFile,PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor,ULONG &ImportDescriptorNum)
{
	IMAGE_NT_HEADERS ImagePEHeader;
	GetPEHeader(hFile,&ImagePEHeader);

	ULONG ImportTableFileOffset = RVA2FileOffset(hFile,ImagePEHeader.OptionalHeader.DataDirectory[1].VirtualAddress);
	ImportDescriptorNum = 0;
	IMAGE_IMPORT_DESCRIPTOR tpImportDesc;

	NTSTATUS status;
	IO_STATUS_BLOCK iostatus;
	FILE_POSITION_INFORMATION fpi;
	fpi.CurrentByteOffset.QuadPart = ImportTableFileOffset;
	status = ZwSetInformationFile(hFile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(NT_SUCCESS(status));

	while(1)
	{
		status = ZwReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&iostatus,
			&tpImportDesc,
			sizeof(IMAGE_IMPORT_DESCRIPTOR),
			0,
			NULL);
		ASSERT(NT_SUCCESS(status));

		if (tpImportDesc.Characteristics == 0)
			break;
		ImportDescriptorNum++;
	}

	if (pImageImportDescriptor == NULL)
	{
		// 通过ImportDescriptorNum返回需要的大小
		return;
	}

	fpi.CurrentByteOffset.QuadPart = ImportTableFileOffset;
	status = ZwSetInformationFile(hFile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(NT_SUCCESS(status));

	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pImageImportDescriptor,
		sizeof(IMAGE_IMPORT_DESCRIPTOR)*ImportDescriptorNum,
		0,
		NULL);
	ASSERT(NT_SUCCESS(status));
}

void GetDllName(HANDLE hFile,char *DllName[],ULONG &DllNum)
{
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	ULONG ImportDescriptorNum;
	GetImportDescriptor(hFile,NULL,ImportDescriptorNum);
	DllNum = ImportDescriptorNum;
	if (DllName == NULL)
	{
		// 通过DllNum返回需要的大小
		return;
	}
	pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ExAllocatePool(NonPagedPool,sizeof(IMAGE_IMPORT_DESCRIPTOR)*ImportDescriptorNum);
	GetImportDescriptor(hFile,pImageImportDescriptor,ImportDescriptorNum);
	ULONG i;
	for (i = 0;i < ImportDescriptorNum;i++)
	{

		ULONG NameFileOffset = RVA2FileOffset(hFile,pImageImportDescriptor[i].Name);
		char tpName[256];

		NTSTATUS status;
		IO_STATUS_BLOCK iostatus;
		FILE_POSITION_INFORMATION fpi;
		fpi.CurrentByteOffset.QuadPart = NameFileOffset;
		status = ZwSetInformationFile(hFile,
			&iostatus,
			&fpi,
			sizeof(FILE_POSITION_INFORMATION),
			FilePositionInformation);
		ASSERT(NT_SUCCESS(status));

		status = ZwReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&iostatus,
			tpName,
			256,
			0,
			NULL);
		ASSERT(NT_SUCCESS(status));
		strcpy(DllName[i],tpName);
	}
	ExFreePool(pImageImportDescriptor);
}

// 内存均有外部分配
void GetFullDllPath(
					OUT PUNICODE_STRING pusDllPath,
					IN PUNICODE_STRING pusExePath,
					IN PUNICODE_STRING pusDllName,
					IN ULONG Method
					)
{
	// 清空pusDllPath
	memset(pusDllPath->Buffer,0,pusDllPath->MaximumLength);
	pusDllPath->Length = 0;

	NTSTATUS status;
	ULONG i;
	// Method:
	// 1:windows系统目录
	// 2:包含可执行文件的目录
	// 3:16位系统目录 即windows下的system目录
	// 4:windows目录
	switch (Method)
	{
	case 1:
		memcpy(pusDllPath->Buffer,L"\\SystemRoot\\system32\\",sizeof(L"\\SystemRoot\\system32\\"));
		pusDllPath->Length = sizeof(L"\\SystemRoot\\system32\\") - 2;
		break;
	case 2:
		RtlCopyUnicodeString(pusDllPath,pusExePath);
		for (i = pusExePath->Length/2;i > 0;i--)
		{
			if (memcmp(&pusDllPath->Buffer[i],L"\\",2) == 0)
				break;
		}
		pusDllPath->Length = (i+1)*2;
		break;
	case 3:
		memcpy(pusDllPath->Buffer,L"\\SystemRoot\\system\\",sizeof(L"\\SystemRoot\\system\\"));
		pusDllPath->Length = sizeof(L"\\SystemRoot\\system\\")-2;
		break;
	case 4:
		memcpy(pusDllPath->Buffer,L"\\SystemRoot\\",sizeof(L"\\SystemRoot\\"));
		pusDllPath->Length = sizeof(L"\\SystemRoot\\") - 2;
		break;
	default:
		break;
	}
	status = RtlAppendUnicodeStringToString(pusDllPath,pusDllName);
	ASSERT(NT_SUCCESS(status));
}

// pusFile需要全名\\??\\C:\\windows\\notepad.exe
void SetSafeExe(PUNICODE_STRING pusFile)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAtr;
	InitializeObjectAttributes(&objAtr,
		pusFile,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	IO_STATUS_BLOCK iostatus;
	HANDLE hFile;
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&objAtr,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	ASSERT(NT_SUCCESS(status));
	ULONG DllNum;
	GetDllName(hFile,NULL,DllNum);
	char **DllName = (char **)ExAllocatePool(NonPagedPool,DllNum);
	int i;
	for (i = 0;i < DllNum;i++)
		*(DllName+i) = (char*)ExAllocatePool(NonPagedPool,256);
	GetDllName(hFile,DllName,DllNum);

	// 处理得到的DLL
	for (i = 0;i < DllNum;i++)
	{
	//	KdPrint(("%s\n",DllName[i]));
		ANSI_STRING asDllName;
		RtlInitAnsiString(&asDllName,DllName[i]);
		UNICODE_STRING usDllName;
		WCHAR usDllNameBuf[256];
		RtlInitEmptyUnicodeString(&usDllName,usDllNameBuf,sizeof(usDllNameBuf));
		RtlAnsiStringToUnicodeString(&usDllName,&asDllName,FALSE);

		UNICODE_STRING usDllPath;
		WCHAR usDllPathBuf[0x200];
		RtlInitEmptyUnicodeString(&usDllPath,usDllPathBuf,sizeof(usDllPathBuf));

		int j;
		for (j = 1;j <= 4;j++)
		{
			GetFullDllPath(&usDllPath,pusFile,&usDllName,j);

			UNICODE_STRING usFileMD5;
			WCHAR usFileMD5Buf[0x200];
			RtlInitEmptyUnicodeString(&usFileMD5,usFileMD5Buf,sizeof(usFileMD5Buf));
			status = MD5File(&usDllPath,&usFileMD5);
			if (NT_SUCCESS(status))
			{
				KdPrint(("DllName = %s,Method = %d,DllPath = %wZ,usFileMD5 = %wZ\n",
					DllName[i],j,&usDllPath,&usFileMD5));
				break;
			}
		}
		if (j == 5)
		{
			// 未获得路径
		//	KdPrint(("DllName = %s，Can't Find\n",DllName[i]));
		}
	}
	for (i = 0;i < DllNum;i++)
		ExFreePool(*(DllName+i));
//	ExFreePool(DllName);
}

