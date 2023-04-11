#pragma once
#include <evntrace.h>

typedef enum CKCL_TRACE_OPERATION
{
	CKCL_START_TRACE = 1,
	CKCL_STOP_TRACE = 2,
	CKCL_QUERY_TRACE = 3,
	CKCL_UPDATE_TRACE = 4,
	CKCL_FLUSH_TRACE = 5
}CKCL_TRACE_OPERATION;

using CustomInvokeCall = void(*)();

class EtwHook
{
	using SyscallHookFn = void(*)(u32 SystemCallIndex, _Inout_ PVOID* SystemCallFunction);

private:
	//u8* PerfGlobalGroupMask = 0;
	u8* EtwpDebuggerData = 0;
	pv CkclWmiLoggerContext = 0;
	pv SystemCallEntryPage = 0;
	pv NtBase = 0;

	//HalpPerformanceCounter
	u64 HalpStallCounter = 0;

	u64 GetCpuClock = 0;
	u64 OldGetCpuClock = 0;
	SyscallHookFn HkSyscall = 0;
	CustomInvokeCall CustomFilterRoutine = 0;
	bool bIsInit = false;
	u64 StopWatchDog = false;
	KEVENT WatchDogEvent;

	static ULONG64 HookInternalGetCpuClock();

	static ULONG64 HookHalQueryCounter();

	bool InitOffset();
	
	static VOID WatchDogThread(PVOID Param);

public:

	static NTSTATUS ModifyTraceSettings(CKCL_TRACE_OPERATION Operation, ULONG TraceWhat = EVENT_TRACE_FLAG_SYSTEMCALL);
	
	static pv GetSyscallEntry();

	NTSTATUS Init(SyscallHookFn SyscallHookRoutine = 0, CustomInvokeCall CustomFilter = 0, ULONG HkEvent = EVENT_TRACE_FLAG_SYSTEMCALL);

	NTSTATUS UnInit();

	void InvokeSysCall();

	void DefaultSyscallHandler(u32 SystemCallIndex, PVOID* SystemCallFunction);
};

extern class EtwHook EtwHook;
