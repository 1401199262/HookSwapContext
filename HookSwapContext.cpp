#include "global.h"
#include "EtwHook.h"

#include "HookSwapContext.h"

void HkSwapContext()
{
	__db();
	//DbgPrintEx(0, 0, "Cur ThId %llx\n", PsGetCurrentThreadId());
	return;
}


void Workkk()
{
	// it is getcpuclock, safe for debugging.
	//if (GetWinVer() <= 18363)
	//	__db();


	auto CurrentThread = __readgsqword(0x188);
	auto StackMax = __readgsqword(0x1A8);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

	if ((u64)StackMax - (u64)StackFrame > 0x6000 || (u64)StackFrame > StackMax)
	{
		__db();
		return;
	}

	int FoundFlag = 0;
	for (pv* StackCurrent = (pv*)StackFrame; (u64)StackCurrent < StackMax; StackCurrent++)
	{
		if (FoundFlag == 0)
		{
			if (*(u32*)StackCurrent == 0x28)			
				FoundFlag++;
			continue;
		}

		if (FoundFlag == 1)
		{
			if (*(u32*)StackCurrent == 0x405A04)
			{
				HkSwapContext();
				break;
			}
		}
	}
}



void HookSwapContext()
{
	EtwHook.Init(0, Workkk, EVENT_TRACE_FLAG_CSWITCH);
}

