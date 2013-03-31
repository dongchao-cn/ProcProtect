#ifndef _MD5_H
#define _MD5_H

/***********************************************************************
* 函数名称:MD5File 
* 函数描述:计算文件的MD5值
* 参数列表:
*		pStrFileName:文件名
*		pStrFileMD5:得到的MD5
* 返回值:NTSTATUS
* 注:
*	pStrFileName应该为完整的路径，需使用符号链接或者设备名
*	例如 "C:\\1.txt" 应该为 "\\??\\C:\\1.txt" 或者 "\\Device\\HarddiskVolume1\\1.txt"
*	pStrFileMD5内存由外部负责分配
***********************************************************************/
NTSTATUS
MD5File(IN PUNICODE_STRING pStrFileName,OUT PUNICODE_STRING pStrFileMD5);

/***********************************************************************
* 函数名称:MD5String 
* 函数描述:计算字符串的MD5值
* 参数列表:
*		pStr:字符串
*		pStrMD5:计算得到的MD5
* 返回值:NTSTATUS
*	pStrFileMD5内存由外部负责分配
***********************************************************************/
NTSTATUS
MD5String(IN PUNICODE_STRING pStr,OUT PUNICODE_STRING pStrMD5);


#endif

