#ifndef _PROC_LIST
#define _PROC_LIST

#define MAINEXE_MD5 L"C9F225F98574759E377BCE6D87958C9C"

typedef struct _SAFEPROC
{
	LIST_ENTRY ListEntry;
	HANDLE PID;
}SAFEPROC,*PSAFEPROC;

NTSTATUS
AddToSafeProcList(IN const HANDLE PID);

VOID
DelFromSafeProcList(IN const HANDLE PID);

VOID
ReleaseSafeProcList();

VOID
InitSafeProcList();

BOOLEAN
IsSafeProc(IN const HANDLE PID);

#endif

