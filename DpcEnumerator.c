#include <ntddk.h>

// Define the KDPC_DATA structure for Windows versions >= 8.1.
typedef struct _KDPC_DATA_2 {
    KDPC_LIST DpcList;
    KSPIN_LOCK DpcLock;
    LONG DpcQueueDepth;
    ULONG DpcCount;
    PKDPC ActiveDpc;
} KDPC_DATA_2, *PKDPC_DATA_2;

// Define the KDPC_DATA structure for Windows versions < 8.1.
typedef struct _KDPC_DATA_1 {
    LIST_ENTRY DpcListHead;
    KSPIN_LOCK DpcLock;
    LONG DpcQueueDepth;
    ULONG DpcCount;
} KDPC_DATA_1, *PKDPC_DATA_1;

// Define the KPRCB structure.
typedef struct _KPRCB {
    // ...
    KDPC_DATA_2 DpcData[2];  // For Windows versions >= 8.1.
    KDPC_DATA_1 DpcData[2];  // For Windows versions < 8.1.
    // ...
} KPRCB, *PKPRCB;

// Function to enumerate all DPCs on the system.
NTSTATUS EnumerateDpcs()
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS systemProcess = NULL;
    PVOID systemPeb = NULL;
    PKSYSINFO sysInfo = NULL;
    PKPRCB prcb = NULL;
    PKDPC_DATA_2 dpcData2 = NULL;
    PKDPC_DATA_1 dpcData1 = NULL;
    ULONG numProcessors = KeQueryActiveProcessorCount(NULL);

    // Get a handle to the system process.
    status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Get a pointer to the PEB of the system process.
    systemPeb = PsGetProcessPeb(systemProcess);
    if (systemPeb == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Get a pointer to the KSYSINFO structure.
    sysInfo = *(PKSYSINFO*)((PCHAR)systemPeb + 0x30);
    if (sysInfo == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Iterate over each processor in the system and query its DPC queue.
    for (ULONG i = 0; i < numProcessors; i++)
    {
        prcb = sysInfo->KiProcessorBlock[i];
        if (prcb == NULL)
        {
            continue;
        }

        // Get a pointer to the DPC queue for this processor.
        #if (NTDDI_VERSION >= NTDDI_WINBLUE)
        dpcData2 = &prcb->DpcData[i];
        #else
        dpcData1 = &prcb->DpcData[i];
        #endif

        // Query the DPC queue.
        KIRQL oldIrql;
        KeAcquireSpinLock(&dpcData->DpcLock, &oldIrql);
        PLIST_ENTRY entry = dpcData->DpcList.ListHead.Next;
        while (entry != &dpcData->DpcList.ListHead)
        {
            PKDPC dpc = CONTAINING_RECORD(entry, KDPC, DpcListEntry);
            // TODO: do something with the DPC here
            entry = entry->Next;
        }
        KeReleaseSpinLock(&dpcData->DpcLock, oldIrql);
    }

Cleanup:
    if (systemProcess != NULL)
    {
        ObDereferenceObject(systemProcess);
    }
    return status;
}

// DriverEntry function.
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    // Register the device object.
    // ...

    // Enumerate all DPCs on the system.
    NTSTATUS status = EnumerateDpcs();
    if (!NT_SUCCESS(status))
    {
        // Handle the error.
        // ...
    }

    return status;
}
