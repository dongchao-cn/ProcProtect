#include <ntifs.h>
#include "IOCTL.h"
#include "BaseFun.h"
#include "ProcProtect.h"
#include "SSDTHook.h"
#include "ProcList.h"
#include "MD5.h"
#include "ExeInfo.h"

// 驱动名定义
#define DeviceName L"\\Device\\ProcProtect"
#define SymLinkName L"\\??\\ProcProtect"

// 保存需要被保护的PID
extern LIST_ENTRY SafeProcHead;

/***********************************************************************
* 函数名称:DriverEntry
* 函数描述:驱动入口函数
* 参数列表:
*		pDriverObject:驱动对象指针
*		pRegistryPath:注册表路径
* 返回值:NTSTATUS
* 注:
***********************************************************************/
extern "C" NTSTATUS DriverEntry (IN PDRIVER_OBJECT pDriverObject,
								 IN PUNICODE_STRING pRegistryPath)
{
//	KdPrint(("Enter ProcProtectDriverEntry\n"));
	NTSTATUS status = STATUS_SUCCESS;
/*
#ifdef DBG
	__asm int 3
#endif
*/
	// 注册其他驱动调用函数入口
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		pDriverObject->MajorFunction[i] = ProcProtectDispatchRoutin;
	pDriverObject->DriverUnload = ProcProtectUnload;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcProtectDeviceIOControl;

	//创建设备
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING usDevName;
	RtlInitUnicodeString(&usDevName,DeviceName);
	status = IoCreateDevice(pDriverObject,
		0 ,
		&usDevName,
		FILE_DEVICE_UNKNOWN,
		0, TRUE,
		&pDevObj );
	if (!NT_SUCCESS(status))
		return status;

	// 设置读写模式为缓冲区设备
	pDevObj->Flags |= DO_BUFFERED_IO;

	//创建符号链接
	UNICODE_STRING usSymLinkName;
	RtlInitUnicodeString(&usSymLinkName,SymLinkName);
	status = IoCreateSymbolicLink(&usSymLinkName,
		&usDevName);
	if (!NT_SUCCESS(status)) 
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	
	return status;
}

/***********************************************************************
* 函数名称:ProcMonDispatchRoutin
* 函数描述:其他操作派遣函数
* 参数列表:
*		pDevObj:设备对象指针
*		pIrp:Irp指针
* 返回值:NTSTATUS
* 注:
***********************************************************************/
NTSTATUS ProcProtectDispatchRoutin(IN PDEVICE_OBJECT pDevObj,
							   IN PIRP pIrp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	NTSTATUS status = STATUS_SUCCESS;

	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );

	return status;
}

/***********************************************************************
* 函数名称:ProcMonDeviceIOControl
* 函数描述:DeviceIOControl派遣函数
* 参数列表:
*		pDevObj:设备对象指针
*		pIrp:Irp指针
* 返回值:NTSTATUS
* 注:
***********************************************************************/
NTSTATUS ProcProtectDeviceIOControl(IN PDEVICE_OBJECT pDevObj,
								IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG info = 0;

	//得到当前堆栈
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	//得到IOCTL码
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
/*
#ifdef DBG
	__asm int 3
#endif
*/
	HANDLE PID;
	switch (code)
	{
	case IOCTL_Install_SSDTHook:
		status = InstallSDDTHook();
		InitSafeProcList();
		break;
	case IOCTL_UnInstall_SSDTHook:
		UnInstallSDDTHook();
		ReleaseSafeProcList();
		break;
	case IOCTL_AddPortectProc:
		PID = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
		AddToSafeProcList(PID);
		KdPrint(("进程PID = %d被设置为保护进程\n",PID));
		break;
	case IOCTL_DelPortectProc:
		PID = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
		DelFromSafeProcList(PID);
	//	KdPrint(("进程PID = %d被取消保护进程\n",PID));
		break;
	case IOCTL_SetSafeExe:
		WCHAR wcExePath[0x200];
		memset(wcExePath,0,0x200);
		memcpy(wcExePath,L"\\??\\",8);
		memcpy(wcExePath+4,pIrp->AssociatedIrp.SystemBuffer,0x190);
		UNICODE_STRING usExePath;
		RtlInitUnicodeString(&usExePath,wcExePath);
		SetSafeExe(&usExePath);
		break;
	default:
		status = STATUS_INVALID_VARIANT;
	}

	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = info;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}

/***********************************************************************
* 函数名称:ProcMonUnload
* 函数描述:驱动卸载函数
* 参数列表:
*		pDriverObject:设备驱动对象
* 返回值:VOID
* 注:
***********************************************************************/
VOID ProcProtectUnload (IN PDRIVER_OBJECT pDriverObject)
{
	
	UNICODE_STRING usSymLinkName;
	RtlInitUnicodeString(&usSymLinkName,SymLinkName);
	IoDeleteSymbolicLink(&usSymLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);
//	KdPrint(("ProcMonUnload!\n"));
}
