#include <ntifs.h>
#include "ProcList.h"

// 保存需要被保护的PID
LIST_ENTRY SafeProcHead;

/***********************************************************************
* 函数名称:InitSafeProcList 
* 函数描述:初始化SafeProcList
* 参数列表:
* 返回值:
***********************************************************************/
VOID 
InitSafeProcList()
{
	InitializeListHead(&SafeProcHead);
}

/***********************************************************************
* 函数名称:AddToSafeProcList 
* 函数描述:将进程ID添加到合法进程表中
* 参数列表:
*		PID:进程ID
* 返回值:NTSTATUS
***********************************************************************/
NTSTATUS
AddToSafeProcList(IN const HANDLE PID)
{
	PSAFEPROC pData;
	pData = (PSAFEPROC)ExAllocatePool(NonPagedPool,
		sizeof(SAFEPROC));
	if (pData == NULL)
	{
	//	KdPrint(("[AddToSafeProcList] ExAllocatePool Failed\n"));
		return STATUS_UNSUCCESSFUL;
	}
	pData->PID = PID;
	InsertTailList(&SafeProcHead,&pData->ListEntry);
//	KdPrint(("[AddToSafeProcList] Add %d\n",PID));
	return TRUE;
}

/***********************************************************************
* 函数名称:DelFromSafeProcList 
* 函数描述:将进程ID从合法进程表中删除
* 参数列表:
*		PID:进程ID
* 返回值:
***********************************************************************/
VOID
DelFromSafeProcList(IN const HANDLE PID)
{
	PSAFEPROC pData;
	pData = (PSAFEPROC)SafeProcHead.Flink;
	while(pData != (PSAFEPROC)&SafeProcHead)
	{
		if (pData->PID == PID)
		{
			// 删除这个PID
			pData->ListEntry.Blink->Flink = pData->ListEntry.Flink;
			pData->ListEntry.Flink->Blink = pData->ListEntry.Blink;
		//	KdPrint(("[DelFromSafeProcList] Del %d\n",PID));
			ExFreePool(pData);
			break;
		}
		pData = (PSAFEPROC)pData->ListEntry.Flink;
	}
	return;
}

/***********************************************************************
* 函数名称:IsSafeProc 
* 函数描述:查询是否是合法进程
* 参数列表:
*		PID:进程的PID
* 返回值:BOOLEAN
***********************************************************************/
BOOLEAN
IsSafeProc(IN const HANDLE PID)
{
	PSAFEPROC pData;
	pData = (PSAFEPROC)SafeProcHead.Flink;
	while(pData != (PSAFEPROC)&SafeProcHead)
	{
		if (pData->PID == PID)
		{
			// 这个PID是合法进程
		//	KdPrint(("[IsSafeProc] Get %d\n",PID));
			return TRUE;
		}
		pData = (PSAFEPROC)pData->ListEntry.Flink;
	}
	return FALSE;
}

/***********************************************************************
* 函数名称:ClearSafeProcList 
* 函数描述:
* 参数列表:
*		PID:进程ID
* 返回值:
***********************************************************************/
VOID
ReleaseSafeProcList()
{
	while (!IsListEmpty(&SafeProcHead))
	{
		PLIST_ENTRY pEntry = RemoveTailList(&SafeProcHead);
		PSAFEPROC pData = (PSAFEPROC)pEntry;
	//	KdPrint(("[ReleaseSafeProcList] Del %d\n",pData->PID));
		KdPrint(("进程PID = %d被取消保护进程\n",pData->PID));
		ExFreePool(pData);
	}
	return;
}