#include <NTDDK.h>
#include <Ntstrsafe.h>
#include "MD5.h"

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define RL(x, y) (((x) << (y)) | ((x) >> (32 - (y))))  //x向左循环移y位

#define PP(x) (x<<24)|((x<<8)&0xff0000)|((x>>8)&0xff00)|(x>>24)  //将x高低位互换,例如PP(aabbccdd)=ddccbbaa

#define FF(a, b, c, d, x, s, ac) a = b + (RL((a + F(b,c,d) + x + ac),s))
#define GG(a, b, c, d, x, s, ac) a = b + (RL((a + G(b,c,d) + x + ac),s))
#define HH(a, b, c, d, x, s, ac) a = b + (RL((a + H(b,c,d) + x + ac),s))
#define II(a, b, c, d, x, s, ac) a = b + (RL((a + I(b,c,d) + x + ac),s))

unsigned int A,B,C,D,x[16];
/***********************************************************************
* 函数名称:MD5Calc 
* 函数描述:MD5核心算法,供64轮
* 参数列表:空
* 返回值:空
***********************************************************************/
void MD5Calc(){
	unsigned a,b,c,d;
	a=A,b=B,c=C,d=D;
	/* Round 1 */
	FF (a, b, c, d, x[ 0],  7, 0xd76aa478); /* 1 */
	FF (d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
	FF (b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, x[ 4],  7, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
	FF (b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
	FF (a, b, c, d, x[ 8],  7, 0x698098d8); /* 9 */
	FF (d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
	FF (a, b, c, d, x[12],  7, 0x6b901122); /* 13 */
	FF (d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
	FF (c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
	FF (b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, x[ 1],  5, 0xf61e2562); /* 17 */
	GG (d, a, b, c, x[ 6],  9, 0xc040b340); /* 18 */
	GG (c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
	GG (b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d, x[ 5],  5, 0xd62f105d); /* 21 */
	GG (d, a, b, c, x[10],  9, 0x02441453); /* 22 */
	GG (c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
	GG (b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d, x[ 9],  5, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, x[14],  9, 0xc33707d6); /* 26 */
	GG (c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
	GG (b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
	GG (a, b, c, d, x[13],  5, 0xa9e3e905); /* 29 */
	GG (d, a, b, c, x[ 2],  9, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
	GG (b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, x[ 5],  4, 0xfffa3942); /* 33 */
	HH (d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
	HH (c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
	HH (a, b, c, d, x[ 1],  4, 0xa4beea44); /* 37 */
	HH (d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, x[13],  4, 0x289b7ec6); /* 41 */
	HH (d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
	HH (c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
	HH (b, c, d, a, x[ 6], 23, 0x04881d05); /* 44 */
	HH (a, b, c, d, x[ 9],  4, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d, x[ 0],  6, 0xf4292244); /* 49 */
	II (d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
	II (c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
	II (b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
	II (a, b, c, d, x[12],  6, 0x655b59c3); /* 53 */
	II (d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
	II (b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
	II (a, b, c, d, x[ 8],  6, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
	II (b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
	II (a, b, c, d, x[ 4],  6, 0xf7537e82); /* 61 */
	II (d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
	II (c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
	A += a;
	B += b;
	C += c;
	D += d;
}

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
MD5File(IN PUNICODE_STRING pStrFileName,OUT PUNICODE_STRING pStrFileMD5)
{
	// 确保pStrFileMD5空间足够大，并且清0
	if(pStrFileMD5->MaximumLength < 32 * 2)
		return STATUS_BUFFER_TOO_SMALL;
	pStrFileMD5->Length = 0;
	memset(pStrFileMD5->Buffer,0,pStrFileMD5->MaximumLength);

	// 首先判断文件是否存在
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttributes;
	IO_STATUS_BLOCK ioStatus;
	InitializeObjectAttributes(&objAttributes,
		pStrFileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&objAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(status))
	{
		// 文件不存在
	//	KdPrint(("MD5File - File \"%wZ\" DONT Exist\n",pStrFileName));
		return status;
	}

	// 读取文件长度
	unsigned int i,len,flen[2];   //i临时变量,len文件长,flen[2]为64位二进制表示的文件初始长度
	FILE_STANDARD_INFORMATION fsi;
	status = ZwQueryInformationFile(hFile,
		&ioStatus,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		// 获取文件长度失败
	//	KdPrint(("MD5File - GetFileLength \"%wZ\" Error\n",pStrFileName));
		return status;
	}
	len = fsi.EndOfFile.LowPart;
	flen[1]=len/0x20000000;     //flen单位是bit
	flen[0]=(len%0x20000000)*8;
	
	// 设置文件指针为起点
	FILE_POSITION_INFORMATION fpi;
	fpi.CurrentByteOffset.QuadPart = 0i64;
	status = ZwSetInformationFile(hFile,
		&ioStatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);
	ASSERT(status == STATUS_SUCCESS);

	// 读取文件并计算MD5
	A = 0x67452301,B = 0xefcdab89,C = 0x98badcfe,D = 0x10325476; //初始化链接变量
	RtlFillMemory(&x,64,0);
	ZwReadFile(hFile,NULL,NULL,NULL,&ioStatus,&x,64,NULL,NULL);
	for( i = 0; i < len / 64; i++)
	{	//循环运算直至文件结束
		MD5Calc();
		RtlFillMemory(&x,64,0);
		ZwReadFile(hFile,NULL,NULL,NULL,&ioStatus,&x,64,NULL,NULL);
	}
	((char*)x)[len%64]=0x80;  //文件结束补1,补0操作,0x80二进制即10000000
	if(len % 64 > 55) 
	{
		MD5Calc();
		RtlFillMemory(&x,64,0);
	}
	RtlCopyMemory(x+14,flen,8);//文件末尾加入原文件的bit长度 
	MD5Calc();

	// 写入strMD5
//	KdPrint(("MD5File - File \"%wZ\" MD5 Code:%08x%08x%08x%08x\n",pStrFileName,PP(A),PP(B),PP(C),PP(D))); 
	status = RtlStringCchPrintfW(pStrFileMD5->Buffer,33,L"%08x%08x%08x%08x",PP(A),PP(B),PP(C),PP(D));	//高低位逆反输出
	ASSERT(status == STATUS_SUCCESS);
	pStrFileMD5->Length = 32 * 2;

	// 关闭文件
	ZwClose(hFile);

	return status;
}

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
MD5String(IN PUNICODE_STRING pStr,OUT PUNICODE_STRING pStrMD5)
{
	// 确保pStrFileMD5空间足够大，并且清0
	if(pStrMD5->MaximumLength < 32 * 2)
		return STATUS_BUFFER_TOO_SMALL;
	pStrMD5->Length = 0;
	memset(pStrMD5->Buffer,0,pStrMD5->MaximumLength);

	// 存储MD5
//	UNICODE_STRING strMD5;
//	WCHAR strMD5Buf[33];
//	RtlInitEmptyUnicodeString(&strMD5,strMD5Buf,sizeof(strMD5Buf));
	unsigned int i,len,flen[2];   //i临时变量,len字符串长,flen[2]为64位二进制表示的初始长度
	len = pStr->Length;
	flen[1]=len/0x20000000;     //flen单位是bit
	flen[0]=(len%0x20000000)*8;

	// 读取文件并计算MD5
	A = 0x67452301,B = 0xefcdab89,C = 0x98badcfe,D = 0x10325476; //初始化链接变量
	RtlFillMemory(&x,64,0);
	RtlCopyMemory(x,pStr->Buffer,64);

	for( i = 0; i < len / 64; i++)
	{	//循环运算直至文件结束
		MD5Calc();
		RtlFillMemory(&x,64,0);
		RtlCopyMemory(x,pStr->Buffer,64);
	}
	((char*)x)[len%64]=0x80;  //文件结束补1,补0操作,0x80二进制即10000000
	if(len % 64 > 55)
	{
		MD5Calc();
		RtlFillMemory(&x,64,0);
	}
	RtlCopyMemory(x+14,flen,8);//文件末尾加入原文件的bit长度 
	MD5Calc();

	// 写入strMD5
//	KdPrint(("MD5String - String \"%wZ\" MD5 Code:%08x%08x%08x%08x\n",pStr,PP(A),PP(B),PP(C),PP(D))); 
	RtlStringCchPrintfW(pStrMD5->Buffer,33,L"%08x%08x%08x%08x",PP(A),PP(B),PP(C),PP(D));	//高低位逆反输出
	pStrMD5->Length = 32 * 2;

	return STATUS_SUCCESS;
}
