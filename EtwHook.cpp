#include "global.h"
#include "ia32.h"
#include "hde/hde64.h"

#include "EtwHook.h"

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER Wnode;
	ULONG BufferSize;
	ULONG MinimumBuffers;
	ULONG MaximumBuffers;
	ULONG MaximumFileSize;
	ULONG LogFileMode;
	ULONG FlushTimer;
	ULONG EnableFlags;
	union {
		LONG AgeLimit;
		LONG FlushThreshold;
	} DUMMYUNIONNAME;
	ULONG NumberOfBuffers;
	ULONG FreeBuffers;
	ULONG EventsLost;
	ULONG BuffersWritten;
	ULONG LogBuffersLost;
	ULONG RealTimeBuffersLost;
	HANDLE LoggerThreadId;
	ULONG LogFileNameOffset;
	ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64 Unknown[3];
	UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

//#define EtwpStartTrace		1
//#define EtwpStopTrace			2
//#define EtwpQueryTrace		3
//#define EtwpUpdateTrace		4
//#define EtwpFlushTrace		5

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls


#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

using HalQueryCounterFn = u64(*)();
HalQueryCounterFn OldHalQueryCounter = 0;

ULONG64 EtwHook::HookInternalGetCpuClock()
{
	if (::EtwHook.CustomFilterRoutine)
		::EtwHook.CustomFilterRoutine();
	else
		::EtwHook.InvokeSysCall();

	return __rdtsc();
}

ULONG64 EtwHook::HookHalQueryCounter()
{
	HookInternalGetCpuClock();
	return OldHalQueryCounter();
}

//TraceWhat = EVENT_TRACE_FLAG_SYSTEMCALL 
NTSTATUS EtwHook::ModifyTraceSettings(CKCL_TRACE_OPERATION Operation, ULONG TraceWhat)
{	
	//auto SetPreviousMode = [](KPROCESSOR_MODE NewMode, u64 thread = __readgsqword(0x188)) -> KPROCESSOR_MODE
	//{
	//	auto prvmodeOff = 0x232;//*(u32*)((u64)ImpGetFunAddr(ExGetPreviousMode) + 12);
	//	auto ret = *(u8*)(thread + prvmodeOff);
	//	*(u8*)(thread + prvmodeOff) = NewMode;
	//	return ret;
	//};

	CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)KAlloc(PAGE_SIZE);

	wchar_t* provider_name = (wchar_t*)KAlloc(256 * sizeof(wchar_t));

	RtlZeroMemory(property, PAGE_SIZE);
	RtlZeroMemory(provider_name, 256 * sizeof(wchar_t));

	RtlCopyMemory(provider_name, E(L"Circular Kernel Context Logger"), sizeof(L"Circular Kernel Context Logger"));
	ImpCall(RtlInitUnicodeString, &property->ProviderName, (const wchar_t*)provider_name);

	property->Wnode.BufferSize = PAGE_SIZE;
	property->Wnode.Flags = 0x00020000;
	property->Wnode.Guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
	property->Wnode.ClientContext = 3;
	property->BufferSize = sizeof(unsigned long);
	property->MinimumBuffers = 2;
	property->MaximumBuffers = 2;
	property->LogFileMode = 0x00000400;

	unsigned long length = 0;
	if (Operation == CKCL_UPDATE_TRACE) 
		property->EnableFlags = TraceWhat; // 0x00000080; EVENT_TRACE_FLAG_SYSTEMCALL  

	//auto OrigMode = ImpCall(ExGetPreviousMode);
	//if (OrigMode == UserMode)
	//{
	//	SetPreviousMode(KernelMode);
	//}

	NTSTATUS status = ImpCall(ZwTraceControl, Operation, property, PAGE_SIZE, property, PAGE_SIZE, &length);

	//SetPreviousMode(OrigMode);

	KFree(provider_name);
	KFree(property);

	return status;
}

bool EtwHook::InitOffset()
{
	getKernelModuleByName(E("ntoskrnl.exe"), &NtBase, 0);

	//if (!PerfGlobalGroupMask)
	//{
	//	PerfGlobalGroupMask = FindPatternRange(ImpGetFunAddr(KeReleaseSpinLock), 0x30, E("F6 05"));
	//	if (PerfGlobalGroupMask)
	//		PerfGlobalGroupMask = PerfGlobalGroupMask + *(INT*)(PerfGlobalGroupMask + 2) + 7 - 6;
	//
	//	if (!PerfGlobalGroupMask)
	//	{
	//		PerfGlobalGroupMask = FindPatternRange(ImpGetFunAddr(KeReleaseSpinLock), 0x30, E("F7 05"));
	//		if (PerfGlobalGroupMask)
	//			PerfGlobalGroupMask = PerfGlobalGroupMask + *(INT*)(PerfGlobalGroupMask + 2) + 10 - 4;
	//	}
	//	if (!PerfGlobalGroupMask)
	//	{
	//		PerfGlobalGroupMask = FindPatternRange(ImpGetFunAddr(KeReleaseSpinLock), 0x30, E("0F BA"));
	//		if (PerfGlobalGroupMask)
	//			PerfGlobalGroupMask = PerfGlobalGroupMask + *(INT*)(PerfGlobalGroupMask + 3) + 8 - 4;
	//	}
	//
	//	if (!PerfGlobalGroupMask)
	//	{
	//		__db();
	//		ImpCall(DbgPrintEx, 0, 0, E("PerfGlobalGroupMask Not Found!\n"));
	//		return FALSE;
	//	}
	//}

	if (!EtwpDebuggerData)
	{
		do
		{
			EtwpDebuggerData = FindPatternSect(NtBase, E(".data"), E("2c 08 04 38 0c"));
			if (EtwpDebuggerData)
				break;

			EtwpDebuggerData = FindPatternSect(NtBase, E(".rdata"), E("2c 08 04 38 0c"));
			if (EtwpDebuggerData)
				break;

			EtwpDebuggerData = FindPatternSect(NtBase, E(".text"), E("2c 08 04 38 0c"));
			if (EtwpDebuggerData)
				break;

			__db();
		} while (false);
		EtwpDebuggerData -= 2;
	}
	
	pv* EtwpDebuggerDataSilo = *(pv**)(EtwpDebuggerData + 0x10);
	CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];

	if (GetWinVer() <= 7601 || GetWinVer() >= 22000)
	{
		GetCpuClock = ((u64)CkclWmiLoggerContext + 0x18);
	}
	else
	{
		GetCpuClock = ((u64)CkclWmiLoggerContext + 0x28);
	}


	if (!SystemCallEntryPage)
	{
		SystemCallEntryPage = PAGE_ALIGN(GetSyscallEntry());
	}

	return EtwpDebuggerData && SystemCallEntryPage;
}

pv EtwHook::GetSyscallEntry()
{
	PVOID SyscallEntry = (PVOID)__readmsr(IA32_LSTAR);

	ULONG SizeOfSection = 0;
	PVOID SectionBase = FindSection(EPtr(::NtBase), E("KVASCODE"), &SizeOfSection);
	if (!SectionBase)
		return SyscallEntry;

	// Is the value within this KVA shadow region? If not, we're done.
	if (!(SyscallEntry >= SectionBase && SyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection)))
		return SyscallEntry;

	// This is KiSystemCall64Shadow.
	hde64s HDE;
	for (PCHAR KiSystemServiceUser = (PCHAR)SyscallEntry; /* */; KiSystemServiceUser += HDE.len)
	{
		// Disassemble every instruction till the first near jmp (E9).
		if (!hde64_disasm(KiSystemServiceUser, &HDE))
			break;

		if (HDE.opcode != OPCODE_JMP_NEAR)
			continue;

		// Ignore jmps within the KVA shadow region.
		PVOID PossibleSyscallEntry = (PVOID)((u64)KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32);
		if (PossibleSyscallEntry >= SectionBase && PossibleSyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection))
			continue;

		// Found KiSystemServiceUser.
		SyscallEntry = PossibleSyscallEntry;
		break;
	}

	return SyscallEntry;
}

VOID EtwHook::WatchDogThread(PVOID Param) {

	while (!::EtwHook.StopWatchDog)
	{
		if (GetWinVer() <= 18363)
		{
			if (*(u64*)::EtwHook.GetCpuClock != (u64)HookInternalGetCpuClock)
			{
				__dbgdb();
				*(u64*)::EtwHook.GetCpuClock = (u64)HookInternalGetCpuClock;
			}
		}
		else
		{
			if (*(HalQueryCounterFn*)(::EtwHook.HalpStallCounter + 0x70) != HookHalQueryCounter)
			{
				__dbgdb();
				*(HalQueryCounterFn*)(::EtwHook.HalpStallCounter + 0x70) = HookHalQueryCounter;
			}
		}

		KSleep(50);
	}

	ImpCall(KeSetEvent, &::EtwHook.WatchDogEvent, IO_KEYBOARD_INCREMENT, FALSE);
	ImpCall(PsTerminateSystemThread, STATUS_SUCCESS);
}

NTSTATUS EtwHook::Init(SyscallHookFn SyscallHookRoutine, CustomInvokeCall CustomFilter, ULONG HkEvent)
{
	//Turn off etw to prevent other hook 
	ModifyTraceSettings(CKCL_STOP_TRACE);

	if (!InitOffset())
		return STATUS_NOT_SUPPORTED;

	NTSTATUS Status = ModifyTraceSettings(CKCL_UPDATE_TRACE, HkEvent );
	if (Status != 0)
	{
		Status = ModifyTraceSettings(CKCL_START_TRACE);
		if (Status != 0) {
			return Status;
		}

		Status = ModifyTraceSettings(CKCL_UPDATE_TRACE, HkEvent);
		if (Status != 0) {
			return Status;
		}
	}

	//need to re-get cpuclock due to close and open etw
	if (!InitOffset())
		return STATUS_NOT_SUPPORTED;

	HkSyscall = SyscallHookRoutine;

	CustomFilterRoutine = CustomFilter;

	OldGetCpuClock = *(u64*)GetCpuClock;

	if (GetWinVer() <= 18363)
	{		
		*(u64*)GetCpuClock = (u64)HookInternalGetCpuClock;
	}
	else 
	{
		if (!HalpStallCounter)
		{
			pv KeQueryPerformanceCounter = GetProcAddress(this->NtBase, E("KeQueryPerformanceCounter"));
			if (!KeQueryPerformanceCounter)
				__db();

			// mov rdi, cs:HalpPerformanceCounter 
			auto rva = FindPatternRange(KeQueryPerformanceCounter, 0x100, E("48 8B 3D"));

			// mov rsi, cs:HalpPerformanceCounter win11
			if (!rva)
				rva = FindPatternRange(KeQueryPerformanceCounter, 0x100, E("48 8B 35"));

			//u poi(poi(nt!HalpStallCounter) + 70)
			HalpStallCounter = *(u64*)RVA2(rva, 7, 3);
		}

		if (!OldHalQueryCounter)
			OldHalQueryCounter = *(HalQueryCounterFn*)(HalpStallCounter + 0x70);
				
		*(u64*)GetCpuClock = 1;
		*(HalQueryCounterFn*)(HalpStallCounter + 0x70) = HookHalQueryCounter;
	}

	bIsInit = true;

	ImpCall(KeInitializeEvent, &WatchDogEvent, NotificationEvent, FALSE);
	HANDLE hSysThread = NULL;
	ImpCall(PsCreateSystemThread, &hSysThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WatchDogThread, NULL);
	if (hSysThread)
		ImpCall(ZwClose, hSysThread);

	return STATUS_SUCCESS;
}

NTSTATUS EtwHook::UnInit()
{
	if (!bIsInit)
		return 0;

	::EtwHook.StopWatchDog = true;
	ImpCall(KeWaitForSingleObject, &WatchDogEvent, Executive, KernelMode, FALSE, NULL);

	if (GetCpuClock)
		*(u64*)GetCpuClock = OldGetCpuClock;

	if (OldHalQueryCounter && HalpStallCounter) 
		*(u64*)(HalpStallCounter + 0x70) = (u64)OldHalQueryCounter;
	
	if (NT_SUCCESS(ModifyTraceSettings(CKCL_STOP_TRACE)))
	{
		ModifyTraceSettings(CKCL_START_TRACE);
	}

	bIsInit = false;

	//wait for syscall hook routine
	KSleep(100);
	return STATUS_SUCCESS;
}

#include "EtwHide.h"

void EtwHook::InvokeSysCall()
{
	if (ImpCall(KeGetCurrentIrql) > 0 || ImpCall(ExGetPreviousMode) == KernelMode)
		return;

	//increase speed
	if (!EtwHide.bIsInit || EtwHide.m_HiderProcess == ImpCall(IoGetCurrentProcess))
	{
		return;
	}


	auto CurrentThread = __readgsqword(0x188);
	u32 SystemCallIndex = *(u32*)(CurrentThread + 0x80);

	auto StackMax = __readgsqword(0x1A8);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();
	UINT Offset = 0;
	// First walk backwards on the stack to find the 2 magic values.
	for (pv* StackCurrent = (pv*)StackMax; StackCurrent > StackFrame; --StackCurrent)
	{
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != INFINITYHOOK_MAGIC_1)
		{
			continue;
		}
		// If the first magic is set, check for the second magic.
		--StackCurrent;

		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != INFINITYHOOK_MAGIC_2)
		{
			continue;
		}

		// Now we reverse the direction of the stack walk.
		for (;
			(u64)StackCurrent < StackMax;
			++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;
			if (!(PAGE_ALIGN(*AsUlonglong) >= SystemCallEntryPage &&
				PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2))))
			{
				continue;
			}
			Offset = (u64)StackCurrent - (u64)StackFrame;

			break;
		}

		break;
	}
	
	if (Offset) {
		PVOID* StackCurrent = (pv*)((u64)StackFrame + Offset);
		if (*(u64*)StackCurrent >= (u64)SystemCallEntryPage &&
			*(u64*)StackCurrent < ((u64)SystemCallEntryPage + (PAGE_SIZE * 2)))
		{
			void** SystemCallFunction = &StackCurrent[9];
			if (HkSyscall)
			{
				HkSyscall(SystemCallIndex, SystemCallFunction);
			}
			else
			{
				DefaultSyscallHandler(SystemCallIndex, SystemCallFunction);
			}
		}
	}
}

void EtwHook::DefaultSyscallHandler(u32 SystemCallIndex, PVOID* SystemCallFunction)
{
	__dbgdb();
	return;
}

class EtwHook EtwHook;

