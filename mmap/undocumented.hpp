#pragma once
#include <Windows.h>
#include <winternl.h>

//from https://github.com/x64dbg/x64dbg/blob/development/src/dbg/ntdll/ntdll.h
#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

namespace undocumented {
    namespace ntdll {

        typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
        typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
        typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

        typedef struct _PEB
        {
            BOOLEAN InheritedAddressSpace;
            BOOLEAN ReadImageFileExecOptions;
            BOOLEAN BeingDebugged;
            union
            {
                BOOLEAN BitField;
                struct
                {
                    BOOLEAN ImageUsesLargePages : 1;
                    BOOLEAN IsProtectedProcess : 1;
                    BOOLEAN IsImageDynamicallyRelocated : 1;
                    BOOLEAN SkipPatchingUser32Forwarders : 1;
                    BOOLEAN IsPackagedProcess : 1;
                    BOOLEAN IsAppContainer : 1;
                    BOOLEAN IsProtectedProcessLight : 1;
                    BOOLEAN IsLongPathAwareProcess : 1;
                } s1;
            } u1;

            HANDLE Mutant;

            PVOID ImageBaseAddress;
            PPEB_LDR_DATA Ldr;
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
            PVOID SubSystemData;
            PVOID ProcessHeap;
            PRTL_CRITICAL_SECTION FastPebLock;
            PVOID AtlThunkSListPtr;
            PVOID IFEOKey;
            union
            {
                ULONG CrossProcessFlags;
                struct
                {
                    ULONG ProcessInJob : 1;
                    ULONG ProcessInitializing : 1;
                    ULONG ProcessUsingVEH : 1;
                    ULONG ProcessUsingVCH : 1;
                    ULONG ProcessUsingFTH : 1;
                    ULONG ProcessPreviouslyThrottled : 1;
                    ULONG ProcessCurrentlyThrottled : 1;
                    ULONG ReservedBits0 : 25;
                } s2;
            } u2;
            union
            {
                PVOID KernelCallbackTable;
                PVOID UserSharedInfoPtr;
            } u3;
            ULONG SystemReserved[1];
            ULONG AtlThunkSListPtr32;
            PVOID ApiSetMap;
            ULONG TlsExpansionCounter;
            PVOID TlsBitmap;
            ULONG TlsBitmapBits[2];

            PVOID ReadOnlySharedMemoryBase;
            PVOID SharedData; // HotpatchInformation
            PVOID* ReadOnlyStaticServerData;

            PVOID AnsiCodePageData; // PCPTABLEINFO
            PVOID OemCodePageData; // PCPTABLEINFO
            PVOID UnicodeCaseTableData; // PNLSTABLEINFO

            ULONG NumberOfProcessors;
            ULONG NtGlobalFlag;

            LARGE_INTEGER CriticalSectionTimeout;
            SIZE_T HeapSegmentReserve;
            SIZE_T HeapSegmentCommit;
            SIZE_T HeapDeCommitTotalFreeThreshold;
            SIZE_T HeapDeCommitFreeBlockThreshold;

            ULONG NumberOfHeaps;
            ULONG MaximumNumberOfHeaps;
            PVOID* ProcessHeaps; // PHEAP

            PVOID GdiSharedHandleTable;
            PVOID ProcessStarterHelper;
            ULONG GdiDCAttributeList;

            PRTL_CRITICAL_SECTION LoaderLock;

            ULONG OSMajorVersion;
            ULONG OSMinorVersion;
            USHORT OSBuildNumber;
            USHORT OSCSDVersion;
            ULONG OSPlatformId;
            ULONG ImageSubsystem;
            ULONG ImageSubsystemMajorVersion;
            ULONG ImageSubsystemMinorVersion;
            ULONG_PTR ActiveProcessAffinityMask;
            GDI_HANDLE_BUFFER GdiHandleBuffer;
            PVOID PostProcessInitRoutine;

            PVOID TlsExpansionBitmap;
            ULONG TlsExpansionBitmapBits[32];

            ULONG SessionId;

            ULARGE_INTEGER AppCompatFlags;
            ULARGE_INTEGER AppCompatFlagsUser;
            PVOID pShimData;
            PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

            UNICODE_STRING CSDVersion;

            PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
            PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
            PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
            PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

            SIZE_T MinimumStackCommit;

            PVOID* FlsCallback;
            LIST_ENTRY FlsListHead;
            PVOID FlsBitmap;
            ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
            ULONG FlsHighIndex;

            PVOID WerRegistrationData;
            PVOID WerShipAssertPtr;
            PVOID pUnused; // pContextData
            PVOID pImageHeaderHash;
            union
            {
                ULONG TracingFlags;
                struct
                {
                    ULONG HeapTracingEnabled : 1;
                    ULONG CritSecTracingEnabled : 1;
                    ULONG LibLoaderTracingEnabled : 1;
                    ULONG SpareTracingBits : 29;
                } s3;
            } u4;
            ULONGLONG CsrServerReadOnlySharedMemoryBase;
            PVOID TppWorkerpListLock;
            LIST_ENTRY TppWorkerpList;
            PVOID WaitOnAddressHashTable[128];
            PVOID TelemetryCoverageHeader; // REDSTONE3
            ULONG CloudFileFlags;
        } PEB, * PPEB;
    }
}