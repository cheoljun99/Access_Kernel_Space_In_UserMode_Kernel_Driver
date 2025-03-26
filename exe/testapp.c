/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    testapp.c

Abstract:

Environment:

    Win32 console multi-threaded application

--*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys\sioctl.h>



BOOLEAN
ManageDriver(
    _In_ LPCTSTR  DriverName,
    _In_ LPCTSTR  ServiceName,
    _In_ USHORT   Function
);

BOOLEAN
SetupDriverName(
    _Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
    _In_ ULONG BufferLength
);

char OutputBuffer[100];
char InputBuffer[100];



VOID __cdecl
main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
)
{
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // open the device

    if ((hDevice = CreateFile("\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed : %d\n", errNum);

            return;
        }

        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {

            return;
        }

        if (!ManageDriver(DRIVER_NAME,
            driverLocation,
            DRIVER_FUNC_INSTALL
        )) {

            printf("Unable to install driver.\n");

            // Error - remove driver.

            ManageDriver(DRIVER_NAME,
                driverLocation,
                DRIVER_FUNC_REMOVE
            );

            return;
        }

        hDevice = CreateFile("\\\\.\\IoctlTest",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Error: CreatFile Failed : %d\n", GetLastError());
            return;
        }

    }

    // Printing Input & Output buffer pointers and size

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
        sizeof(InputBuffer));
    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
        sizeof(OutputBuffer));

    // Performing METHOD_BUFFERED

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        "This String is from User Application; using METHOD_BUFFERED");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

    char cInput;
    unsigned __int64 un64KerVa = 0;
   
  
    while (1) {
        cInput = (char)getchar();
        switch (cInput)
        {
            case '1':
            {
                DWORD temp = GetCurrentProcessId();// DeviceIoControl �Լ��� ���� ���� ������ ����� ��� �������� �Է¹ޱ� ������ �̸� �����ֱ� ���ؼ� ����
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_GET_KERVA,
                    &temp,
                    (DWORD)sizeof(temp),
                    &un64KerVa,
                    sizeof(un64KerVa),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;

                }
                printf("�������� �����Ϸ��� Ŀ�� �޸� ���� un64KerVa: %llx\n", un64KerVa);
                printf("�������� ������ �Ұ����մϴ�. 3�� ���� Ȯ���� �� �� �ֽ��ϴ�.\n");
                break;
            }
            case '2':
            {
                DWORD pid = GetCurrentProcessId();
                bRc = DeviceIoControl(hDevice,
                    (DWORD)IOCTL_SIOCTL_ACCESS_KERVA,
                    &pid,
                    (DWORD)sizeof(pid),
                    &un64KerVa,
                    sizeof(un64KerVa),
                    &bytesReturned,
                    NULL
                );
                if (!bRc)
                {
                    printf("Error in DeviceIoControl : %d", GetLastError());
                    return;

                }
                printf("Ŀ�� �޸� ���� un64KerVa: %llx �� ���ؼ� �������� ���ٰ����ϵ��� �����Ͽ����ϴ�.\n3�� ���� Ȯ���� �� �� �ֽ��ϴ�.\n", un64KerVa);
                break;
            }
            case '3':
            {
                DWORD dwPid = GetCurrentProcessId();
                int i = 0;
                printf("10�� ���� �������� Ŀ�� �ּ� ������ �����մϴ�.\n");
                while (i<10)
                {
                    __try {
                        virt_addr_t kerVaStruct;
                        char* p = (char*)un64KerVa;
                        kerVaStruct.value = (QWORD)p;
                        printf("(4kb page size) Ŀ�� �ּ� ���� : %p \n PML4T index : %lld \n PDPT index : %lld \n PD index : %lld \n PT index : %lld \n Offset : %lld \n",
                            p, kerVaStruct.a.pml4_index,
                            kerVaStruct.a.pdpt_index,
                            kerVaStruct.a.pd_index,
                            kerVaStruct.a.pt_index, 
                            kerVaStruct.a.offset_4kb);
                       
                        size_t length = sizeof(char);

                        // Attempt to access the memory
                        char value;
                        // Use memcpy to attempt to read memory
                        memcpy(&value, p, length);
                        // Print the value if no exception was thrown
                        printf("Ŀ�� �ּ� ������ �������� �� : %c\n", (unsigned char)value);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // Handle exceptions
                        fprintf(stderr, "%lu : Access violation or segmentation fault detected!\n", dwPid);
                    }
                    Sleep(1000);
                    i++;
                }
                break;
            }
            case '4':
            {
                DWORD dwPid = GetCurrentProcessId();
                int i = 0;
                printf("10�� ���� �������� Ŀ�� �ּ� ������ �����մϴ�.\n");
                while (i < 10)
                {
                    __try {
                        virt_addr_t kerVaStruct;
                        char* p = (char*)un64KerVa;
                        kerVaStruct.value = (QWORD)p;
                        printf("(4kb page size) Ŀ�� �ּ� ���� : %p \n PML4T index : %lld \n PDPT index : %lld \n PD index : %lld \n PT index : %lld \n Offset : %lld \n",
                            p, kerVaStruct.a.pml4_index,
                            kerVaStruct.a.pdpt_index,
                            kerVaStruct.a.pd_index,
                            kerVaStruct.a.pt_index,
                            kerVaStruct.a.offset_4kb);

                        size_t length = sizeof(char);
                        *p += 1;
                        // Attempt to access the memory
                        char value;
                        // Use memcpy to attempt to read memory
                        memcpy(&value, p, length);
                        // Print the value if no exception was thrown
                        printf("Ŀ�� �ּ� ������ �������� ���� +1�Ͽ� ������ �� : %c\n", (unsigned char)value);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // Handle exceptions
                        fprintf(stderr, "%lu : Access violation or segmentation fault detected!\n", dwPid);
                    }
                    Sleep(1000);
                    i++;
                }
                break;
            }
            case 'x':
                break;
        }
    }
    CloseHandle(hDevice);
    // Unload the driver.  Ignore any errors.
    ManageDriver(DRIVER_NAME,
        driverLocation,
        DRIVER_FUNC_REMOVE
    );
    // close the handle to the device.
}

