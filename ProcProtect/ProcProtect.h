#ifndef _PROC_PROTECT_H
#define _PROC_PROTECT_H

// º¯ÊýÉùÃ÷
NTSTATUS ProcProtectDispatchRoutin(IN PDEVICE_OBJECT pDevObj,
							   IN PIRP pIrp);
NTSTATUS ProcProtectDeviceIOControl(IN PDEVICE_OBJECT pDevObj,
								IN PIRP pIrp);
VOID ProcProtectUnload (IN PDRIVER_OBJECT pDriverObject);


#endif