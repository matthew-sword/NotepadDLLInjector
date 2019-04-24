// peeperDLL.cpp : 定义 DLL 应用程序的导出函数。
#include "stdafx.h"
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <fcntl.h>
#include <io.h>

//定义WriteFile函数指针 WINAPI stccall 标准调用约定  被调用者清理栈
typedef BOOL(WINAPI* pHookedWriteFile) (
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

//定义Readfile函数指针
typedef _Must_inspect_result_ BOOL(WINAPI* pHookedReadFile) (
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);


static FILE* g_consoleFile = 0;
static pHookedWriteFile g_pOrgWriteFile = 0;
static pHookedReadFile g_pOrgReadFile = 0;
static HMODULE* hSelf = 0;

//for test
FILE* fp = NULL;

BOOL MsgTrans(char* pMsg);

BOOL GetMsg(LPVOID PDllHandle);

int LockLibIntoProcMem(HMODULE DllHandle, HMODULE* LocalDllHandle);

BOOL HookIAT(LPCSTR szDllName, PROC pFuncOrg, PROC pFuncHook);

BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,	//文件指针
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, //字符串缓存指针
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped);

_Must_inspect_result_ BOOL WINAPI HookedReadFile(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped);


DWORD WINAPI peeper(LPVOID pDllHandle)
{	
	//for test
	fp = fopen("d:\\peeperMsg.txt", "a+");
	if (!fp)
		printf("open file failed\n");
	
	//获取要钩取的API地址
	g_pOrgReadFile = (pHookedReadFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
	g_pOrgWriteFile = (pHookedWriteFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
	//fprintf(fp, "peeper:GetProcAddress of Readfile WriteFile\n");

	fprintf(fp, "peeper:execute HookIAT\n");
	if (g_pOrgReadFile &&
		g_pOrgWriteFile &&
		HookIAT("kernel32.dll", (PROC)g_pOrgReadFile, (PROC)HookedReadFile) &&
		HookIAT("kernel32.dll", (PROC)g_pOrgWriteFile, (PROC)HookedWriteFile))
	{
		fprintf(fp,"peeper:Attach Success\n");
	}
	else
		fprintf(fp,"peeper:Attach Failed\n");

	fclose(fp);
	return 0;
}

BOOL MsgTrans(char* pMsg)
{
	//检查管道是否打开
	char  PipeName[] = { "\\\\.\\pipe\\peeper" };
	BOOL b = WaitNamedPipeA(PipeName, 0);	

	//打开管道
	HANDLE hFile = CreateFileA(PipeName, 
								GENERIC_READ | GENERIC_WRITE,
								0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( !b || (hFile == INVALID_HANDLE_VALUE) )
	{
		printf("connected faild\n");
		return FALSE;
	}
		
	//进行通信
	char buf[1024];
	ZeroMemory(buf, 1024);
	DWORD dwRead;
	char msg[] = ">>>\nmsg from peeper such as notepad buffer\n>>>\n";
	//WriteFile(hFile, msg, strlen(msg), &dwRead, NULL);
	WriteFile(hFile, pMsg, strlen(pMsg), &dwRead, NULL);
	CloseHandle(hFile);

	return TRUE;
}


//防止DLL被加载其得进程卸载
/*

int LockLibIntoProcMem(HMODULE DllHandle, HMODULE* LocalDllHandle)
{
	if (NULL == LocalDllHandle)
		return ERROR_INVALID_PARAMETER;

	*LocalDllHandle = NULL;
	TCHAR moduleName[1024];

	//获取peeperDll路径
	if (0 == GetModuleFileName(DllHandle, moduleName, sizeof(moduleName) / sizeof(TCHAR)))
		return GetLastError();
	//加载该dll

	*LocalDllHandle = LoadLibrary(moduleName);

	if (NULL == *LocalDllHandle)
		return GetLastError();

	return NO_ERROR;
}
*/

//hook IAT
//szDllName 被钩取的Dll kernel32.dll
BOOL HookIAT(LPCSTR szDllName, PROC pFuncOrg, PROC pFuncHook)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(NULL);	//返回notepad.exe的在内存中的基地址
	pAddr = (PBYTE)hMod;

	//pAddr = VA to PE Signature
	pAddr += *((DWORD*)&pAddr[0x3c]);
	//dwRVA = RVA to PIMAGE_IMPORT_DESCRIPTOR
	dwRVA = *((DWORD*)&pAddr[0x80]);
	//pImportDesc = baseAddr + RVA
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImportDesc->Name; pImportDesc++)
	{
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);

		if (!_stricmp(szLibName, szDllName))
		{
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
			for (; pThunk->u1.Function; pThunk++)
			{
				if (pThunk->u1.Function == (DWORD)pFuncOrg)
				{
					DWORD dwOrgProtect;
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOrgProtect);
					pThunk->u1.Function = (DWORD)pFuncHook;
					VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwOrgProtect, &dwOrgProtect);
					return TRUE;
				}
			}
		}
	}
	fprintf(fp, "peeper:Hook Failed\n");
	return FALSE;
}


//hook WriteFile
BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,	//文件指针
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, //字符串缓存指针
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	printf("\n<writeFile>:\n%.*s\n", (int)nNumberOfBytesToWrite, (char*)lpBuffer);

	if (MsgTrans((char*)lpBuffer))
		fprintf(fp,"peeper:Msg Trans success\n");

	return (*g_pOrgWriteFile)(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}


//hook ReadFile
_Must_inspect_result_ BOOL WINAPI HookedReadFile(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	int statusCode = (*g_pOrgReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	printf("\n<readFile>:\n%.*s\n", *((int*)lpNumberOfBytesRead), (char*)lpBuffer);

	if (MsgTrans((char*)lpBuffer))
		fprintf(fp,"peeper:Msg Trans success\n");

	return statusCode;
}


