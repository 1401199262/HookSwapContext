#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <windef.h>
#include <stdint.h>
#pragma comment(lib,"Ksecdd.lib")

#include "DriverConfig.h"

#include "random.h"
#include "Crt.h"
#include "Define.h"
#include "Crypt.h"
#include "Import.h"

//eptred var
extern PVOID NtBase;
extern PDRIVER_OBJECT g_DriverObject;
extern "C" int _fltused;
extern std::_Prhand std::_Raise_handler;
void atexit();

#include "util.h"



//#define OPT_OFF #pragma optimize("", off)
//#define OPT_ON #pragma optimize("", on)


