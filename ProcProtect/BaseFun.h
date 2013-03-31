#ifndef _BASE_FUN
#define _BASE_FUN

VOID 
GetFullPathNameFromFileObject(
							  IN PFILE_OBJECT FileObj,
							  OUT PUNICODE_STRING pStrFullName
							  );

#endif