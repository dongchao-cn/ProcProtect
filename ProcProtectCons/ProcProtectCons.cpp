// ProcProtectCons.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include "..\ProcProtect\IOCTL.h"

#define SymLinkName "\\\\.\\ProcProtect"

int _tmain(int argc, _TCHAR* argv[])
{
	char buf[0x200];
	GetWindowsDirectory(buf,0x200);
	printf("%s",buf);
	system("pause");
	/*
	FILE* pFile = fopen("notepad.exe","rb");
	char **DllName;
	ULONG DllNum;
	GetDllName(pFile,NULL,DllNum);
	DllName = new char*[DllNum];
	ULONG i;
	for (i = 0;i < DllNum;i++)
		*(DllName+i) = new char[256];
	GetDllName(pFile,DllName,DllNum);
	for (i = 0;i < DllNum;i++)
		printf("%s\n",DllName[i]);
	for (i = 0;i < DllNum;i++)
		delete[] *(DllName+i);
	delete[] DllName;

	system("pause");
	*/
	
	/*
	// 这里调用驱动
	HANDLE hDevice = 
		CreateFile(SymLinkName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL );

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile Failed GetLastError = %d\n", GetLastError());
		system("pause");
		return 1;
	}

	int iPID = GetCurrentProcessId();
//	printf("PID = ");
//	scanf("%d",&iPID);

	printf("Press AnyKey To IOCTL_Install_SSDTHook\n");
	system("pause");

	BOOL bRet;
	DWORD dwOutput;
	bRet = DeviceIoControl(hDevice, IOCTL_Install_SSDTHook,
		NULL,0,
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		printf("IOCTL_Install_SSDTHook Failed");
		system("pause");
		return 1;
	}

	bRet = DeviceIoControl(hDevice, IOCTL_AddPortectProc,
		&iPID,sizeof(iPID),
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		printf("IOCTL_AddPortectProc Failed");
		system("pause");
		return 1;
	}

	// 启动notepad
	STARTUPINFO si; //一些必备参数设置
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi; //必备参数设置结束

	bRet = CreateProcess(NULL,"notepad.exe",NULL,NULL,FALSE,0,NULL,NULL,&si,&pi);
	
	
	printf("Press AnyKey To IOCTL_UnInstall_SSDTHook\n");
	system("pause");
	bRet = DeviceIoControl(hDevice, IOCTL_UnInstall_SSDTHook,
		NULL, 0, 
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		printf("IOCTL_UnInstall_SSDTHook Failed");
		system("pause");
		return 1;
	}
	*/
	return 0;
}