#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <tlhelp32.h>	//工具帮助库
#include <string.h>
#include <tchar.h>



DWORD GetPidByName(const char* pName);

BOOL InjectDll(DWORD pid, LPCTSTR DllPath);

BOOL Connector();

int main(int argc, char * argv[])
{
	char pName[] = "notepad.exe";
	char DllPath[] = "d:\\peeperDLL.dll";	//DLL文件路径

	DWORD pid = 0;
	BOOL InjectRet = FALSE;

	printf("injecting to %s\n", pName);
	//获取notepad pid
	pid = GetPidByName(pName);
	if (!pid)
	{
		printf("notepad not execute!\n");
		goto EXIT;
	}
	printf("pid is %-6d\n",pid);
	

	//注入DLL
	if (argc == 1)	//使用默认DLL地址
		InjectRet = InjectDll(pid, DllPath);
	else 
		InjectRet = InjectDll(pid, argv[1]);

	if (InjectRet)
		printf("Inject DLL Success!\n");
	else	
		printf("Inject DLL Failed!\n");

	//建立命名管道
	Connector();

EXIT:
	system("pause");
	return 0;
}

DWORD GetPidByName(const char* pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	//获取所有进程快照
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (strcmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
		//printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
	}
	CloseHandle(hSnapshot);
	return 0;


}

BOOL InjectDll(DWORD pid, LPCTSTR DllPath)
{
	DWORD dwBufSize = (DWORD)(_tcslen(DllPath) + 1) * sizeof(TCHAR);
	HANDLE hProcess = NULL;	//notepad进程句柄, LoadLibraryW函数
	HMODULE hMod = NULL;
	HANDLE hThread = NULL;
	LPTHREAD_START_ROUTINE pThreadProc;
	LPVOID pRemoteBuf = NULL;


	//获取notepad 进程句柄
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		printf("open process failed! pid %d\n", pid);
		return FALSE;
	}

	//printf("hProcess : %d\n", hProcess);

	//分配虚拟内存
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	//printf("RemoteBufAddr : %d\nBufSize : %d\n", pRemoteBuf, dwBufSize);

	//将dll路径写入内存
	int ret = WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)DllPath, dwBufSize, NULL);
	//printf("Dll path : %s\nret : %d\n", DllPath, ret);

	//获取LoadLibrary地址
	//hMod = GetModuleHandle("kernel32.dll");
	hMod = LoadLibrary("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	//printf("hMod : %d\n", hMod);
	//printf("pThreadProc : %d\n", pThreadProc);

	//在notepad中运行远程线程
	hThread = CreateRemoteThread(
		hProcess,	//notepad进程句柄
		NULL,
		0,
		pThreadProc,	//LoadLibraryW句柄
		pRemoteBuf,	//需要注入的DLL文件路径
		0,
		NULL);

	//printf("LastError Code : %d \n", GetLastError());
	//printf("hThread : %d\n", hThread);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	//printf("LastError Code : %d\n", GetLastError());

	return TRUE;
}

BOOL Connector()
{
	
	char  PipeName[] = { "\\\\.\\pipe\\peeper" };
	//服务端创建管道
	HANDLE hNamePipe = CreateNamedPipeA(PipeName,
										PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 
										PIPE_TYPE_BYTE, 1, 1024, 1024, 0, NULL);
	if (hNamePipe == INVALID_HANDLE_VALUE)
	{
		printf("create NamedPipe failed\n error code : %d\n", GetLastError());
		return FALSE;
	}
	printf("create NamedPipe success\n");

	//等待客户端进行连接
	printf("wating for client pipe connection\n");
	BOOL b = ConnectNamedPipe(hNamePipe, NULL);
	
	/*
	//创建异步事件
	OVERLAPPED op;	//异步事件句柄
	ZeroMemory(&op, sizeof(OVERLAPPED));
	op.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	//当有客户端进行连接时，事件变成有信号的状态
	printf("WaitForSingleObject\n");
	DWORD evt = WaitForSingleObject(op.hEvent, INFINITE);

	if ( evt == 0 )
		printf("Client pipe connect success\n");
	else
		printf("Client pipe connect falied\n");
	*/

	//利用管道进行通信读写
	char buf[1024];
	DWORD cbWrite;
	ZeroMemory(buf, 1024);

	printf("reading file from pipe\n");
	ReadFile(hNamePipe, buf, 1024, &cbWrite, NULL);
	printf("read file finished\n");

	DisconnectNamedPipe(hNamePipe);
	CloseHandle(hNamePipe);
	
	printf("msg:\n%s",buf);

	return TRUE;
}