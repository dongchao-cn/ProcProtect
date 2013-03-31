#include <ntifs.h>
#include "BaseFun.h"
#include "SSDTHook.h"
#include "MD5.h"
#include "ProcList.h"

// 保存原始的SSDT及SSDTShadow表内容
ULONG ulOldSSDTTable[MAX_SSDT_ITEM_NUM];
ULONG ulOldSSDTShadowTable[MAX_SSDT_ITEM_NUM];

// 存放SSDT及SSDTShadow表地址
extern "C" PSSDT KeServiceDescriptorTable;
PSSDT KeServiceDescriptorTableShadow;

// SSDT及SSDTShadow表内存MDL
PMDL pSSDTMdl = NULL;
PMDL pSSDTShadowMdl = NULL;

// MDL映射出来的SSDT及SSDTShadow表地址
SSDT SSDTMdlEntry;
SSDT SSDTShadowMdlEntry;

// 保存需要被保护的PID
extern LIST_ENTRY SafeProcHead;

extern "C" NTSTATUS ZwQueryInformationProcess(
	__in       HANDLE ProcessHandle,
	__in       PROCESSINFOCLASS ProcessInformationClass,
	__out      PVOID ProcessInformation,
	__in       ULONG ProcessInformationLength,
	__out_opt  PULONG ReturnLength
	);


/***********************************************************************
* 函数名称:InstallSDDTHook 
* 函数描述:安装SSDTHook
* 参数列表:
*		空
* 返回值:状态值
* 注:
***********************************************************************/
NTSTATUS
InstallSDDTHook()
{
//	KdPrint(("InstallSDDTHook\n"));
	// 使SSDT表可写
	// 创建MDL
	pSSDTMdl = MmCreateMdl(NULL,
		KeServiceDescriptorTable->pvSSDTBase,
		KeServiceDescriptorTable->ulNumberOfServices * 4);
	if(!pSSDTMdl)
	{
		KdPrint(("[InstallSDDTHook] MmCreateMdl pSSDTMdl Failed\n"));
		return STATUS_UNSUCCESSFUL;
	}
	// 创建非分页内存块
	MmBuildMdlForNonPagedPool(pSSDTMdl);
	// 设置为可写
	pSSDTMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
	// 拷贝旧的SSDT结构体
	memcpy(&SSDTMdlEntry,
		KeServiceDescriptorTable,
		sizeof(SSDT));
	// 锁定这块内存，更新新的SSDT结构体地址
	SSDTMdlEntry.pvSSDTBase = (ULONG*)MmMapLockedPages(pSSDTMdl,
		KernelMode);


	// 使SSDTShadow表可写
	// 查找SSDTShadow地址
	KeServiceDescriptorTableShadow = FindSSDTShadow();
	if (!KeServiceDescriptorTableShadow)
	{
		KdPrint(("[InstallSDDTHook] FindSSDTShadow Failed\n"));
		return STATUS_UNSUCCESSFUL;
	}
	// 创建MDL
	pSSDTShadowMdl = MmCreateMdl(NULL,
		KeServiceDescriptorTableShadow->pvSSDTBase,
		KeServiceDescriptorTableShadow->ulNumberOfServices*4);
	if(!pSSDTShadowMdl)
	{
		KdPrint(("[InstallSDDTHook] MmCreateMdl pSSDTShadowMdl Failed\n"));
		return STATUS_UNSUCCESSFUL;
	}
	// 创建非分页内存块
	MmBuildMdlForNonPagedPool(pSSDTShadowMdl);
	// 设置为可写
	pSSDTShadowMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
	// 拷贝旧的SSDT结构体
	memcpy(&SSDTShadowMdlEntry,
		KeServiceDescriptorTableShadow,
		sizeof(SSDT));
	// 锁定这块内存，更新新的SSDT结构体地址
	SSDTShadowMdlEntry.pvSSDTBase = (ULONG*)MmMapLockedPages(pSSDTShadowMdl,
		KernelMode);

	// 保存原始表
	SaveSSDTTable(&SSDTMdlEntry,ulOldSSDTTable);
	SaveSSDTTable(&SSDTShadowMdlEntry,ulOldSSDTShadowTable);

	// 添加SSDT钩子
	/*
	InstallSSDTHookByIndex(&SSDTMdlEntry,
		nt_NtOpenProcess, 
		(ULONG)HookNtOpenProcess);
	*/
	/*
	InstallSSDTHookByIndex(&SSDTMdlEntry,
		nt_NtCreateThread, 
		(ULONG)HookNtCreateThread);
	*/
	/*
	InstallSSDTHookByIndex(&SSDTMdlEntry,
		nt_NtCreateProcessEx, 
		(ULONG)HookNtCreateProcessEx);
	*/
	/*
	InstallSSDTHookByIndex(&SSDTMdlEntry,
		nt_NtCreateSection, 
		(ULONG)HookNtCreateSection);
	*/
	/*
	InstallSSDTHookByIndex(&SSDTMdlEntry,
		nt_NtMapViewOfSection, 
		(ULONG)HookNtMapViewOfSection);
	*/
	// 添加SSDTShadow钩子
	
	InstallSSDTHookByIndex(&SSDTShadowMdlEntry,
		win32k_NtUserSetWindowsHookEx,
		(ULONG)HookNtUserSetWindowsHookEx);
	/*
	InstallSSDTHookByIndex(&SSDTShadowMdlEntry,
		win32k_NtUserMessageCall,
		(ULONG)HookNtUserMessageCall);
	*/
	return STATUS_SUCCESS;
}

/***********************************************************************
* 函数名称:UnInstallSDDTHook 
* 函数描述:卸载SSDTHook
* 参数列表:
*		空
* 返回值:VOID
* 注:
***********************************************************************/
VOID
UnInstallSDDTHook()
{
//	KdPrint(("UnInstallSDDTHook\n"));

	// 释放进程保护列表
	// 恢复原始的SSDT及SSDTShadow表内容
	LoadSSDTTable(&SSDTMdlEntry,ulOldSSDTTable);
	LoadSSDTTable(&SSDTShadowMdlEntry,ulOldSSDTShadowTable);

	// 解锁MDL块
	MmUnmapLockedPages(SSDTMdlEntry.pvSSDTBase,pSSDTMdl);
	MmUnmapLockedPages(SSDTShadowMdlEntry.pvSSDTBase,pSSDTShadowMdl);

	// 释放MDL
	IoFreeMdl(pSSDTMdl);
	IoFreeMdl(pSSDTShadowMdl);
}

/***********************************************************************
* 函数名称:FindSSDTShadow 
* 函数描述:扫内存查找KeServiceDescriptorTableShadow地址，范围为+-SSDTSHADOW_MAX_SEARCH_LENGTH * sizeof(SSDT)
* 参数列表:
*		空
* 返回值:KeServiceDescriptorTableShadow地址
* 注:
*	http://bbs.pediy.com/showthread.php?p=898895
***********************************************************************/
PSSDT
FindSSDTShadow()
{
	PSSDT KeServiceDescriptorTableShadow = KeServiceDescriptorTable - SSDTSHADOW_MAX_SEARCH_LENGTH * sizeof(SSDT);

	// 扫内存
	while(KeServiceDescriptorTableShadow <= KeServiceDescriptorTable + SSDTSHADOW_MAX_SEARCH_LENGTH * sizeof(SSDT))
	{
		if (RtlCompareMemory(KeServiceDescriptorTable,
			KeServiceDescriptorTableShadow,
			sizeof(SSDT)) == sizeof(SSDT))
		{
			// 找到了KeServiceDescriptorTable
			KeServiceDescriptorTableShadow++;
			break;
		}
		KeServiceDescriptorTableShadow++;
	}

	// 判断是否找到
	if (KeServiceDescriptorTableShadow > KeServiceDescriptorTable + SSDTSHADOW_MAX_SEARCH_LENGTH * sizeof(SSDT))
	{
		// 未找到
		return NULL;
	}

	return KeServiceDescriptorTableShadow;
}

/***********************************************************************
* 函数名称:SaveSSDTTable 
* 函数描述:保存SSDT中的函数地址
* 参数列表:
*		pSSDT:读取位置
*		SSDTTable:存放SSDT的数组
* 返回值:空
***********************************************************************/
VOID
SaveSSDTTable(IN PSSDT pSSDT,
			  OUT ULONG SSDTTable[MAX_SSDT_ITEM_NUM])
{
	PULONG pAddr = pSSDT->pvSSDTBase;
	for (ULONG i = 0; i < pSSDT->ulNumberOfServices;i++,pAddr++)
		SSDTTable[i] = *pAddr;
}

/***********************************************************************
* 函数名称:LoadOldSSDTTable 
* 函数描述:恢复SSDT中的函数地址
* 参数列表:
*		pSSDT:恢复到位置
*		SSDTTable:存放SSDT的数组
* 返回值:空
***********************************************************************/
VOID
LoadSSDTTable(IN PSSDT pSSDT,
			  IN ULONG SSDTTable[MAX_SSDT_ITEM_NUM])
{
	PULONG pAddr = pSSDT->pvSSDTBase;
	for (ULONG i = 0; i < pSSDT->ulNumberOfServices;i++,pAddr++)
		*pAddr = SSDTTable[i];
}

/***********************************************************************
* 函数名称:InstallSSDTHookByIndex
* 函数描述:通过服务号添加SSDT HOOK
* 参数列表:
*		pSSDT:表地址
*		ulServerNum:服务号
*		pNewService:hook函数地址
* 返回值:
***********************************************************************/
VOID
InstallSSDTHookByIndex(PSSDT pSSDT,
					   ULONG ulServerNum,
					   ULONG pNewService)
{
	pSSDT->pvSSDTBase[ulServerNum] = pNewService;
	return;
}

/***********************************************************************
* 函数名称:UnInstallSSDTHookByIndex
* 函数描述:通过服务号卸载SSDT HOOK
* 参数列表:
*		pSSDT:表地址
*		ulServerNum:服务号
*		ulSSDTTable:原始表
* 返回值:
***********************************************************************/
VOID
UnInstallSSDTHookByIndex(PSSDT pSSDT,
						 ULONG ulServerNum,
						 ULONG ulSSDTTable[MAX_SSDT_ITEM_NUM])
{
	pSSDT->pvSSDTBase[ulServerNum] = ulSSDTTable[ulServerNum];
	return;
}


/***********************************************************************
* 函数名称:HookNtOpenProcess
* 函数描述:NtOpenProcess的HOOK
* 参数列表:
*		...
* 返回值:空
* 注:
*	
***********************************************************************/
// 创建原始函数指针
typedef NTSTATUS (*NtOpenProcessType) (__out PHANDLE,
									   __in ACCESS_MASK,
									   __in POBJECT_ATTRIBUTES,
									   __in_opt PCLIENT_ID);
NtOpenProcessType pOldNtOpenProcess = NULL;

NTSTATUS
HookNtOpenProcess (
				   __out PHANDLE  ProcessHandle,
				   __in ACCESS_MASK  DesiredAccess,
				   __in POBJECT_ATTRIBUTES  ObjectAttributes,
				   __in_opt PCLIENT_ID  ClientId
				   )
{
	if (IsSafeProc(ClientId->UniqueProcess)
		&& !IsSafeProc(PsGetCurrentProcessId())
		)
	{
		KdPrint(("[HookNtOpenProcess] CurrentPID = %d ,ClientId->UniqueProcess = %d\n",
			PsGetCurrentProcessId(),ClientId->UniqueProcess));
		return STATUS_ACCESS_DENIED;
	}

	if (pOldNtOpenProcess == NULL)
	{
		// 读取原始SSDT指向的函数
		pOldNtOpenProcess = (NtOpenProcessType)ulOldSSDTTable[nt_NtOpenProcess];
	}
	// 调用原函数
	return pOldNtOpenProcess(ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}


/***********************************************************************
* 函数名称:HookNtCreateThread
* 函数描述:NtCreateThread的HOOK
* 参数列表:
*		...
* 返回值:空
* 注:
*	
***********************************************************************/
typedef NTSTATUS (*NtCreateThreadType)(
									   __out PHANDLE ThreadHandle,
									   __in ACCESS_MASK DesiredAccess,
									   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
									   __in HANDLE ProcessHandle,
									   __out PCLIENT_ID ClientId,
									   __in PCONTEXT ThreadContext,
									   __in PVOID InitialTeb,
									   __in BOOLEAN CreateSuspended
									   );
NtCreateThreadType pOldNtCreateThread = NULL;

NTSTATUS HookNtCreateThread(
							__out PHANDLE ThreadHandle,
							__in ACCESS_MASK DesiredAccess,
							__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							__in HANDLE ProcessHandle,
							__out PCLIENT_ID ClientId,
							__in PCONTEXT ThreadContext,
							__in PVOID InitialTeb,
							__in BOOLEAN CreateSuspended
							)
{

	NTSTATUS status;
	// 查询进程信息
	PROCESS_BASIC_INFORMATION pbi;
	status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, 
		(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[HookNtCreateThread] ZwQueryInformationProcess Failed\n"));
		return pOldNtCreateThread(
			ThreadHandle,
			DesiredAccess,
			ObjectAttributes,
			ProcessHandle,
			ClientId,
			ThreadContext,
			InitialTeb,
			CreateSuspended
			);
	}

	// 拿到PID
	ULONG CurrentPID = (ULONG)PsGetCurrentProcessId();
	ULONG TargetPID = pbi.UniqueProcessId;

	if ( IsSafeProc((HANDLE)TargetPID) 
		&& !IsSafeProc((HANDLE)CurrentPID) 
		)
	{
		// 需要被保护的进程
		if (CurrentPID != TargetPID)
		{
			// 不是自己创建线程，是远线程
			KdPrint(("[HookNtCreateThread] CurrentPID = %d,TargetPID = %d Stoped",
				CurrentPID,TargetPID));
			return STATUS_ACCESS_DENIED;
		}
	}

	if (pOldNtCreateThread == NULL)
	{
		pOldNtCreateThread = (NtCreateThreadType)ulOldSSDTTable[nt_NtCreateThread];
	}

	return pOldNtCreateThread(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		InitialTeb,
		CreateSuspended
		);
}



/***********************************************************************
* 函数名称:HookNtUserSetWindowsHookEx
* 函数描述:NtUserSetWindowsHookEx的HOOK
* 参数列表:
*		...
* 返回值:空
* 注:
*	
***********************************************************************/
typedef HHOOK (*NtUserSetWindowsHookExType)(
	HINSTANCE Mod, 
	PUNICODE_STRING UnsafeModuleName, 
	DWORD ThreadId, 
	int HookId, 
	PVOID HookProc, 
	BOOL Ansi);

NtUserSetWindowsHookExType pOldNtUserSetWindowsHookEx = NULL;

HHOOK HookNtUserSetWindowsHookEx(
								 HINSTANCE Mod, 
								 PUNICODE_STRING UnsafeModuleName, 
								 DWORD ThreadId, 
								 int HookId, 
								 PVOID HookProc,
								 BOOL Ansi)
{
	// 查询线程所属进程
	// http://www.osronline.com/showThread.cfm?link=3172
	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD pEThread = NULL;
	status = PsLookupThreadByThreadId((HANDLE)ThreadId,&pEThread);
	if(!NT_SUCCESS(status))
	{
		return NULL;
	}
	ULONG TargetPID = *(ULONG *)((UCHAR *)pEThread + 0x1ec);
	ObDereferenceObject(pEThread);

//	KdPrint(("[HookNtUserSetWindowsHookEx] UnsafeModuleName = %wZ,TargetThreadId = 0x%x,CurrentPID = %d,TargetPID = %d\n",
//		UnsafeModuleName,ThreadId,PsGetCurrentProcessId(),TargetPID));
	KdPrint(("检测到SetWindowsHookEx函数调用 PID = %d\n",TargetPID));
	ULONG CurrentPID = (ULONG)PsGetCurrentProcessId();
	if ( IsSafeProc((HANDLE)TargetPID) && TargetPID != CurrentPID)
	{
		// 被挂钩的进是我们保护的进程，并且不是自己挂钩
		return NULL;
	}

	if (pOldNtUserSetWindowsHookEx == NULL)
	{
		pOldNtUserSetWindowsHookEx = (NtUserSetWindowsHookExType)ulOldSSDTShadowTable[win32k_NtUserSetWindowsHookEx];
	}
	return pOldNtUserSetWindowsHookEx(
		Mod, 
		UnsafeModuleName, 
		ThreadId, 
		HookId, 
		HookProc, 
		Ansi);
}


/***********************************************************************
* 函数名称:NtUserSetWindowsHookExType
* 函数描述:NtUserMessageCall的HOOK
* 参数列表:
*		...
* 返回值:空
* 注:
*	
***********************************************************************/
typedef BOOL (*NtUserMessageCallType)(
									  HWND hWnd,
									  UINT Msg,
									  WPARAM wParam,
									  LPARAM lParam,
									  ULONG_PTR ResultInfo,
									  DWORD dwType,
									  BOOL Ansi);
NtUserMessageCallType pOldNtUserMessageCall = NULL;

typedef DWORD (*NtUserQueryWindowType)(
									   HWND hWnd,
									   DWORD Index	// QUERY_WINDOW_
									   );
NtUserQueryWindowType pOldNtUserQueryWindow = NULL;

BOOL HookNtUserMessageCall(
						   HWND hWnd,
						   UINT Msg,
						   WPARAM wParam,
						   LPARAM lParam,
						   ULONG_PTR ResultInfo,
						   DWORD dwType,
						   BOOL Ansi)
{
	if (pOldNtUserQueryWindow == NULL)
	{
		pOldNtUserQueryWindow = (NtUserQueryWindowType)ulOldSSDTShadowTable[win32k_NtUserQueryWindow];
	}
	HANDLE TargetPID = (HANDLE)pOldNtUserQueryWindow(hWnd,QUERY_WINDOW_UNIQUE_PROCESS_ID);

	if (PsGetCurrentProcessId() != TargetPID && IsSafeProc(TargetPID))
	{
		KdPrint(("[HookNtUserMessageCall] CurrentPID = %d, TargetPID = %d\n",
			PsGetCurrentProcessId(),TargetPID));
		return FALSE;
	}
	if (pOldNtUserMessageCall == NULL)
	{
		pOldNtUserMessageCall = (NtUserMessageCallType)ulOldSSDTShadowTable[win32k_NtUserMessageCall];
	}
	return pOldNtUserMessageCall(
		hWnd,
		Msg,
		wParam,
		lParam,
		ResultInfo,
		dwType,
		Ansi);
}


/***********************************************************************
* 函数名称:HookNtCreateProcessExType
* 函数描述:NtCreateProcessExType的HOOK
* 参数列表:
*		...
* 返回值:空
* 注:
*	
***********************************************************************/
typedef NTSTATUS (*NtCreateProcessExType)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ParentProcess,
	__in ULONG Flags,
	__in_opt HANDLE SectionHandle,
	__in_opt HANDLE DebugPort,
	__in_opt HANDLE ExceptionPort,
	__in ULONG JobMemberLevel
	);

NtCreateProcessExType pOldNtCreateProcessEx = NULL;

NTSTATUS HookNtCreateProcessEx(
							   __out PHANDLE ProcessHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							   __in HANDLE ParentProcess,
							   __in ULONG Flags,
							   __in_opt HANDLE SectionHandle,
							   __in_opt HANDLE DebugPort,
							   __in_opt HANDLE ExceptionPort,
							   __in ULONG JobMemberLevel
							   )
{
	NTSTATUS retStatus;
	if (pOldNtCreateProcessEx == NULL)
	{
		pOldNtCreateProcessEx = (NtCreateProcessExType)ulOldSSDTTable[nt_NtCreateProcessEx];
	}
	retStatus = pOldNtCreateProcessEx(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ParentProcess,
		Flags,
		SectionHandle,
		DebugPort,
		ExceptionPort,
		JobMemberLevel
		);

	// 获得文件名
	// SectionHandle->pSection->pSegment->pControlArea->pFileObject
	// 具体定义参考wrk
	// struct _SECTION
	PVOID pSection = NULL;
	NTSTATUS status = ObReferenceObjectByHandle(SectionHandle,
		NULL,
		NULL,
		KernelMode,
		&pSection,
		NULL
		);
	if (!NT_SUCCESS(status))
	{
		return retStatus;
	}
	PVOID pSegment = (PVOID)*(ULONG*)((char*)pSection + 20);
	PVOID pControlArea = (PVOID)*(ULONG*)pSegment;
	PVOID pFileObject = (PVOID)*(ULONG*)((char*)pControlArea + 36);
	UNICODE_STRING usFullName;
	WCHAR wFullNameBuf[0x200];
	RtlInitEmptyUnicodeString(&usFullName,
		wFullNameBuf,
		sizeof(wFullNameBuf));
	GetFullPathNameFromFileObject((PFILE_OBJECT)pFileObject,
		&usFullName);
	ObDereferenceObject(pSection);

	// 在这里判断这次被启动的进程是否是我们的主程序EXE
	UNICODE_STRING usCorrectMD5;
	RtlInitUnicodeString(&usCorrectMD5,MAINEXE_MD5);
	UNICODE_STRING usTargetMD5;
	WCHAR wTargetMD5Buf[0x200];
	RtlInitEmptyUnicodeString(&usTargetMD5,wTargetMD5Buf,sizeof(wTargetMD5Buf));
	status = MD5File(&usFullName,&usTargetMD5);

	if (RtlCompareUnicodeString(&usCorrectMD5,&usTargetMD5,TRUE) == 0)
	{
		// 新建进程是我们的主程序EXE
		// 这里的*ProcessHandle是进程句柄，不是PID
		// 查询进程信息
		PROCESS_BASIC_INFORMATION pbi;
		ZwQueryInformationProcess(*ProcessHandle, ProcessBasicInformation, 
			(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		KdPrint(("[HookNtCreateProcessEx] MainEXE Started!PID = %d\n",pbi.UniqueProcessId));
		AddToSafeProcList((HANDLE)pbi.UniqueProcessId);
		return retStatus;
	}

	if (IsSafeProc(PsGetCurrentProcessId()))
	{
		// 父进程是合法进程
		// 这里的*ProcessHandle是进程句柄，不是PID
		// 查询进程信息
		PROCESS_BASIC_INFORMATION pbi;
		ZwQueryInformationProcess(*ProcessHandle, ProcessBasicInformation, 
			(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		KdPrint(("[HookNtCreateProcessEx]  MainExe Create New Safe Proc,PID = %d\n",pbi.UniqueProcessId));
		AddToSafeProcList((HANDLE)pbi.UniqueProcessId);
	}
	return retStatus;
}

typedef NTSTATUS (*NtCreateSectionType)(
										__out PHANDLE SectionHandle,
										__in ACCESS_MASK DesiredAccess,
										__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
										__in_opt PLARGE_INTEGER MaximumSize,
										__in ULONG SectionPageProtection,
										__in ULONG AllocationAttributes,
										__in_opt HANDLE FileHandle
										);
NtCreateSectionType pOldNtCreateSection = NULL;
NTSTATUS HookNtCreateSection(
							 __out PHANDLE SectionHandle,
							 __in ACCESS_MASK DesiredAccess,
							 __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							 __in_opt PLARGE_INTEGER MaximumSize,
							 __in ULONG SectionPageProtection,
							 __in ULONG AllocationAttributes,
							 __in_opt HANDLE FileHandle
							 )
{
	if (pOldNtCreateSection == NULL)
	{
		pOldNtCreateSection = (NtCreateSectionType)ulOldSSDTTable[nt_NtCreateSection];
	}

	if (IsSafeProc(PsGetCurrentProcessId()))
	{
		if (ObjectAttributes != NULL)
		{
			KdPrint(("[HookNtCreateSection] PID = %d ,ObjName = %wZ\n",PsGetCurrentProcessId(),ObjectAttributes->ObjectName));
		}
		else if(FileHandle != NULL)
		{
			PVOID pFileObj = NULL;
			NTSTATUS status = ObReferenceObjectByHandle(FileHandle,
				NULL,
				*IoFileObjectType,
				KernelMode,
				&pFileObj,
				NULL
				);
			if (!NT_SUCCESS(status))
			{
				goto END;
			}
			UNICODE_STRING usFullName;
			WCHAR wFullNameBuf[0x200];
			RtlInitEmptyUnicodeString(&usFullName,wFullNameBuf,sizeof(wFullNameBuf));
			GetFullPathNameFromFileObject((PFILE_OBJECT)pFileObj,
				&usFullName);
			ObDereferenceObject(pFileObj);
			KdPrint(("[HookNtCreateSection] PID = %d ,ObjName = %wZ\n",PsGetCurrentProcessId(),&usFullName));
		}
	}
END:
	NTSTATUS retStatus;
	retStatus = pOldNtCreateSection(
		SectionHandle,
		DesiredAccess,
		ObjectAttributes,
		MaximumSize,
		SectionPageProtection,
		AllocationAttributes,
		FileHandle
		);

	return retStatus;
}

typedef NTSTATUS (*NtMapViewOfSectionType)(
				   __in HANDLE SectionHandle,
				   __in HANDLE ProcessHandle,
				   __inout PVOID *BaseAddress,
				   __in ULONG_PTR ZeroBits,
				   __in SIZE_T CommitSize,
				   __inout_opt PLARGE_INTEGER SectionOffset,
				   __inout PSIZE_T ViewSize,
				   __in SECTION_INHERIT InheritDisposition,
				   __in ULONG AllocationType,
				   __in WIN32_PROTECTION_MASK Win32Protect
				   );
NtMapViewOfSectionType pOldNtMapViewOfSection = NULL;

NTSTATUS HookNtMapViewOfSection(
								__in HANDLE SectionHandle,
								__in HANDLE ProcessHandle,
								__inout PVOID *BaseAddress,
								__in ULONG_PTR ZeroBits,
								__in SIZE_T CommitSize,
								__inout_opt PLARGE_INTEGER SectionOffset,
								__inout PSIZE_T ViewSize,
								__in SECTION_INHERIT InheritDisposition,
								__in ULONG AllocationType,
								__in WIN32_PROTECTION_MASK Win32Protect
								)
{
	// 查询进程信息
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, 
		(PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
//	ASSERT(NT_SUCCESS(status));

	// 拿到PID
	HANDLE CurrentPID = PsGetCurrentProcessId();
	HANDLE TargetPID = (HANDLE)pbi.UniqueProcessId;

	if (IsSafeProc(TargetPID))
	{
		// 获得文件名
		// SectionHandle->pSection->pSegment->pControlArea->pFileObject
		// 具体定义参考wrk
		// struct _SECTION
		PVOID pSection = NULL;
		status = ObReferenceObjectByHandle(SectionHandle,
			NULL,
			NULL,
			KernelMode,
			&pSection,
			NULL
			);
		ASSERT(NT_SUCCESS(status));

		PVOID pSegment = (PVOID)*(ULONG*)((char*)pSection + 20);
		if(pSegment == NULL)
		{
			KdPrint(("pSegment == NULL"));
			ObDereferenceObject(pSection);
			goto END;
		}
		PVOID pControlArea = (PVOID)*(ULONG*)pSegment;
		if(pControlArea == NULL)
		{
			KdPrint(("pControlArea == NULL"));
			ObDereferenceObject(pSection);
			goto END;
		}
		PVOID pFileObject = (PVOID)*(ULONG*)((char*)pControlArea + 36);
		if(pFileObject == NULL)
		{
			KdPrint(("pFileObject == NULL,Win32Protect = 0x%x\n",Win32Protect));
			ObDereferenceObject(pSection);
			goto END;
		}
		UNICODE_STRING usFullName;
		WCHAR wFullNameBuf[0x200];
		RtlInitEmptyUnicodeString(&usFullName,
			wFullNameBuf,
			sizeof(wFullNameBuf));
		GetFullPathNameFromFileObject((PFILE_OBJECT)pFileObject,
			&usFullName);
		KdPrint(("[HookNtMapViewOfSection] CurrentPID = %d,TargetPID = %d,SectionName = %wZ,Win32Protect = 0x%x\n",
			CurrentPID,TargetPID,&usFullName,Win32Protect));
		ObDereferenceObject(pSection);
	}
END:
	if (pOldNtMapViewOfSection == NULL)
	{
		pOldNtMapViewOfSection = (NtMapViewOfSectionType)ulOldSSDTTable[nt_NtMapViewOfSection];
	}
	return pOldNtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Win32Protect
		);
}