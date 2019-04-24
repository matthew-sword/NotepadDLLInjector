// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <tchar.h>

HMODULE g_hMod = NULL;

extern DWORD WINAPI peeper(LPVOID pDllHandle);


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HANDLE hThread = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		//start
		hThread = CreateThread(NULL, 0, peeper, &hModule, 0, NULL);
		CloseHandle(hThread);
		break;
		//end
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

