/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    sioctl.c

Abstract:

    Purpose of this driver is to demonstrate how the four different types
    of IOCTLs can be used, and how the I/O manager handles the user I/O
    buffers in each case. This sample also helps to understand the usage of
    some of the memory manager functions.

Environment:

    Kernel mode only.

--*/


//
// Include files.
//

#include <ntddk.h>          // various NT definitions
#include <string.h>

#include "sioctl.h"

typedef unsigned int DWORD;


#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"


#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif



// Windows 10 19041 x64
#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
QWORD FindProcessEPROC(
    _In_ int nPID
)
{
    QWORD eproc = 0x00000000;
    int currentPID = 0;
    int startPID = 0;
    int iCount = 0;
    PLIST_ENTRY plistActiveProcs;

    eproc = (QWORD)PsGetCurrentProcess();
    startPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
    currentPID = startPID;
    for (;;)
    {
        if (nPID == currentPID)
        {
            return eproc;// found
        }
        else if ((iCount >= 1) && (startPID == currentPID))
        {
            break;
        }
        else {
            plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
            eproc = (QWORD)plistActiveProcs->Flink - PS_ACTIVE_OFFSET;
            currentPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
            iCount++;
        }
    }

    return 0;
}

#define DTB_OFFSET 0x028
QWORD GetProcessDirBase(QWORD eproc)
{
    QWORD   directoryTableBase;

    if (eproc == 0x0) {
        return 0x0;
    }

    directoryTableBase = *(QWORD*)(eproc + DTB_OFFSET);
    directoryTableBase = directoryTableBase & 0xfffffffff000;

    return directoryTableBase;
}

#define PFN_MASK(pe)        ((QWORD)((pe) & 0x0000FFFFFFFFF000UL))
#define PFN_SETZERO(pe)    ((QWORD)((pe) & 0xFFFF000000000FFFUL))

NTSTATUS MmReadPhysical(PVOID targetAddress, ULONG64 sourceAddress, size_t size, size_t* bytesRead)
{
    PHYSICAL_ADDRESS address = { 0 };
    MM_COPY_ADDRESS copyInfo = { 0 };
    address.QuadPart = (LONGLONG)sourceAddress;
    copyInfo.PhysicalAddress = address;
    return MmCopyMemory(targetAddress, copyInfo, size, MM_COPY_MEMORY_PHYSICAL, bytesRead);
}


static HANDLE hPhysicalhandle = NULL;

NTSTATUS GetPhysicalHandle()
{
    NTSTATUS status;
    UNICODE_STRING PhysicalMemoryString;
    OBJECT_ATTRIBUTES attributes;

    WCHAR PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
    RtlInitUnicodeString(&PhysicalMemoryString, PhysicalMemoryName);
    InitializeObjectAttributes(&attributes, &PhysicalMemoryString, 0, NULL, NULL);
    status = ZwOpenSection(&hPhysicalhandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);

    return status;
}
NTSTATUS WritePhysicalMemory2(DWORD64 PhysicalAddress, DWORD32 WriteData)
{
    NTSTATUS status;
    PVOID BaseAddress = NULL;
    DWORD32 offset;
    LARGE_INTEGER SectionOffset;
    SIZE_T size = 0x2000;

    status = GetPhysicalHandle();
    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    offset = PhysicalAddress & 0xFFF;

    SectionOffset.QuadPart = (ULONGLONG)(PhysicalAddress);

    status = ZwMapViewOfSection(
        hPhysicalhandle,
        NtCurrentProcess(),
        (PVOID*)&BaseAddress,
        0,
        size,
        &SectionOffset,
        &size,
        ViewShare,
        MEM_TOP_DOWN,
        PAGE_READWRITE);

    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    memmove_s((PVOID)((DWORD64)BaseAddress + offset), sizeof(DWORD32), &WriteData, sizeof(DWORD32));

    status = ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

    if (status < 0)
    {
        status = FALSE;
    }

Leave:
    if (hPhysicalhandle != NULL)
    {
        ZwClose(hPhysicalhandle);
    }

    return status;
}

QWORD EditOptionBitWalkingCr3(ULONG64 cr3, QWORD virtual_addr)
{
    size_t dummy;

    QWORD pml4_start = 0;
    QWORD* ppml4 = NULL;
    QWORD pml4_entry = 0;


    QWORD   pdpt_real = 0;
    QWORD   pdpt_start = 0;
    QWORD   pdpt_new = 0;
    QWORD* ppdpt = NULL;
    QWORD pdpt_entry = 0;

    QWORD   pd_real = 0;
    QWORD   pd_start = 0;
    QWORD   pd_new = 0;
    QWORD* ppd = NULL;
    QWORD pd_entry = 0;

    QWORD   pt_real = 0;
    QWORD   pt_start = 0;
    QWORD   pt_new = 0;
    QWORD* ppt = NULL;
    QWORD pt_entry = 0;


    QWORD   pfn_real = 0;
    QWORD   pfn_start = 0;
    QWORD   pfn_new = 0;

    virt_addr_t a;
    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    //    Int3();
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);



    //copy pml4
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    pml4_start = cr3; //cr3 value is pml4_start_address
    MmReadPhysical(buffer, cr3, copySize, &dummy);


    ppml4 = (PQWORD)buffer;
    pml4_entry = pml4_start + 8 * a.a.pml4_index;
    pdpt_real = ppml4[a.a.pml4_index];
    pdpt_start = PFN_MASK(pdpt_real);
    pdpt_new = pdpt_real | 0x4;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d] == pdpt_start :%p\r\n", a.a.pml4_index, pdpt_start);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pdpt_real :%p\r\n", pdpt_real);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pdpt_new :%p\r\n", pdpt_new);
    PHYSICAL_ADDRESS val_pml4 = { 0, };
    val_pml4.QuadPart = pdpt_new;
    WritePhysicalMemory2(pml4_entry, val_pml4.LowPart);
    WritePhysicalMemory2(pml4_entry + 4, val_pml4.HighPart);
    MmReadPhysical(buffer, pdpt_start, copySize, &dummy);


    ppdpt = (PQWORD)buffer;
    pdpt_entry = pdpt_start + 8 * a.a.pdpt_index;
    pd_real = ppdpt[a.a.pdpt_index];
    pd_start = PFN_MASK(pd_real);
    pd_new = pd_real | 0x4;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d] == pd_start :%p\r\n", a.a.pdpt_index, pd_start);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pd_real :%p\r\n", pd_real);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pd_new :%p\r\n", pd_new);
    PHYSICAL_ADDRESS val_pdpt = { 0, };
    val_pdpt.QuadPart = pd_new;
    WritePhysicalMemory2(pdpt_entry, val_pdpt.LowPart);
    WritePhysicalMemory2(pdpt_entry + 4, val_pdpt.HighPart);
    MmReadPhysical(buffer, pd_start, copySize, &dummy);



    ppd = (PQWORD)buffer;
    pd_entry= pd_start+ 8 * a.a.pd_index;
    pt_real = ppd[a.a.pd_index];
    pt_start = PFN_MASK(pt_real);
    pt_new = pt_real | 0x04;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d] == pt_start :%p\r\n", a.a.pd_index, pt_start);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pt_real :%p\r\n", pt_real);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pt_new :%p\r\n", pt_new);
    PHYSICAL_ADDRESS val_pd = { 0, };
    val_pd.QuadPart = pt_new;
    WritePhysicalMemory2(pd_entry, val_pd.LowPart);
    WritePhysicalMemory2(pd_entry + 4, val_pd.HighPart);
    MmReadPhysical(buffer, pt_start, copySize, &dummy);



    ppt = (PQWORD)buffer;
    pt_entry = pt_start + 8 * a.a.pt_index;
    pfn_real = ppt[a.a.pt_index];
    pfn_start = PFN_MASK(pfn_real);
    pfn_new = pfn_real | 0x04;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].pfn:%p\r\n", a.a.pt_index, pfn_start);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pfn_real :%p\r\n", pfn_real);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "pfn_new :%p\r\n", pfn_new);
    PHYSICAL_ADDRESS val_pt = { 0, };
    val_pt.QuadPart = pfn_new;
    WritePhysicalMemory2(pt_entry, val_pt.LowPart);
    WritePhysicalMemory2(pt_entry + 4, val_pt.HighPart);

    ExFreePool(buffer);

    return pfn_start;
}

//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
);
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreateClose)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
)
/*++

Routine Description:
    This routine is called by the Operating System to initialize the driver.

    It creates the device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:
    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:
    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\SIOCTL"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\IoctlTest"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject);                // Returned ptr to Device Object

    if (!NT_SUCCESS(ntStatus))
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    //
    // Initialize a Unicode String containing the Win32 name
    // for our device.
    //

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);

    //
    // Create a symbolic link between our device name  and the Win32 name
    //

    ntStatus = IoCreateSymbolicLink(
        &ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(ntStatus))
    {
        //
        // Delete everything that this routine has allocated.
        //
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice(deviceObject);
    }


    return ntStatus;
}


NTSTATUS
SioctlCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
/*++

Routine Description:

    This routine is called by the I/O system when the SIOCTL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

    This routine is called by the I/O system to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    //
    // Create counted string version of our Win32 device name.
    //

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);


    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }



}

QWORD test[4] = { 0x41,0x42,0x43,0x44 };

NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    ULONG               outBufLength; // Output buffer length
    PCHAR               inBuf, outBuf; // pointer to Input and output buffer

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {

    case IOCTL_SIOCTL_GET_KERVA:
        inBuf = Irp->AssociatedIrp.SystemBuffer;

        // 전역 변수 test의 커널 주소를 출력함
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Kernel Virtual Address : %llx\n", &test);

        // 전역 변수 test의 커널 주소값을 res에 저장함
        QWORD res1 = (QWORD)&test;  // 여기서 dereference 하지 않고 주소 자체를 사용함

        outBuf = Irp->AssociatedIrp.SystemBuffer;
        RtlCopyBytes(outBuf, &res1, sizeof(res1)); // 주소값을 유저모드로 복사함
        Irp->IoStatus.Information = sizeof(res1);
        break;

    case IOCTL_SIOCTL_ACCESS_KERVA:
        inBuf = Irp->AssociatedIrp.SystemBuffer;

        DWORD userPid = *(DWORD*) inBuf;
        // 전역 변수 test의 커널 주소를 출력함
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Kernel Virtual Address : %llx\n", &test);

        // 전역 변수 test의 커널 주소값을 res에 저장함
        QWORD res2 = (QWORD)&test;  // 여기서 dereference 하지 않고 주소 자체를 사용함


        QWORD eproc_my = 0;
        eproc_my = FindProcessEPROC(userPid);
        QWORD qwCr3_my = 0;
        qwCr3_my = GetProcessDirBase(eproc_my);

        QWORD check = 0;
        check = EditOptionBitWalkingCr3(qwCr3_my, res2);


        outBuf = Irp->AssociatedIrp.SystemBuffer;
        RtlCopyBytes(outBuf, &res2, sizeof(res2)); // 주소값을 유저모드로 복사함
        Irp->IoStatus.Information = sizeof(res2);
        break;

    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
)
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                && *BufferAddress != 127) {

                KdPrint(("%c", *BufferAddress));

            }
            else {

                KdPrint(("."));

            }
            BufferAddress++;
        }
        KdPrint(("\n"));
    }
    return;
}


