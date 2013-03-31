#include <ntifs.h>
#include "BaseFun.h"


/***********************************************************************
* 函数名称:GetFullPathNameFromFileObject 
* 函数描述:通过FILE_OBJECT获得文件全路径名
* 参数列表:
*		FileObj:文件对象
*		pStrFullName:路径名
* 返回值:空
* 注:pStrFullName的内存空间应在函数外申请
***********************************************************************/
VOID 
GetFullPathNameFromFileObject(
							  IN PFILE_OBJECT FileObj,
							  OUT PUNICODE_STRING pStrFullName
							  )
{
	NTSTATUS status;
	CHAR nibuf[0x200];	//分配一块连续的内存即可
	POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)nibuf;
	ULONG retLength;
	ASSERT(FileObj->DeviceObject != NULL);
	status = ObQueryNameString(FileObj->DeviceObject,
		nameInfo,
		sizeof(nibuf),
		&retLength);
	pStrFullName->Length = 0;
	if (NT_SUCCESS(status))
	{
		RtlCopyUnicodeString(pStrFullName, &nameInfo->Name);
	}
	RtlAppendUnicodeStringToString(pStrFullName, &FileObj->FileName); 
}