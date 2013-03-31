#ifndef _EXE_INFO_H
#define _EXE_INFO_H

void GetDllName(HANDLE hFile,char *DllName[],ULONG &DllNum);
void SetSafeExe(PUNICODE_STRING pusFile);

#endif