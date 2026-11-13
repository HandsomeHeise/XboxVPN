#pragma once

#include <xtl.h>
#include <stddef.h>

// The XDK import libraries include these entry points. The public SDK headers
// expose only the title-facing networking wrappers.
typedef LONG NTSTATUS;
#define NT_SUCCESS(status) (static_cast<NTSTATUS>(status) >= 0)

struct ANSI_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
};

struct XBOX_KRNL_VERSION
{
    WORD Major;
    WORD Minor;
    WORD Build;
    WORD Qfe;
};

// Prefix of the native module entry used to check the loaded XAM build.
struct LDR_DATA_TABLE_ENTRY
{
    BYTE BeforeImageBase[0x1C];
    PVOID ImageBase;
    BYTE BeforeSizeOfFullImage[0x18];
    DWORD SizeOfFullImage;
    BYTE BeforeTimeDateStamp[0x14];
    DWORD TimeDateStamp;
};

static_assert(offsetof(LDR_DATA_TABLE_ENTRY, ImageBase) == 0x1C, "XEX loader image base layout");
static_assert(offsetof(LDR_DATA_TABLE_ENTRY, SizeOfFullImage) == 0x38, "XEX loader image size layout");
static_assert(offsetof(LDR_DATA_TABLE_ENTRY, TimeDateStamp) == 0x50, "XEX loader timestamp layout");

enum XNCALLER_TYPE
{
    XNCALLER_SYSAPP = 2
};

typedef int (*EthernetInterceptCallback)(PVOID context, const BYTE *frame, DWORD bytes);

extern "C"
{
    extern const XBOX_KRNL_VERSION *XboxKrnlVersion;

    ULONG __cdecl DbgPrint(LPCSTR format, ...);
    NTSTATUS NTAPI ExCreateThread(PHANDLE thread, DWORD stackSize, LPDWORD threadId,
                                  PVOID startup, LPTHREAD_START_ROUTINE routine, PVOID context, DWORD flags);
    VOID XapiThreadStartup(VOID (__cdecl *routine)(VOID *), PVOID context, DWORD exitCode);
    BYTE NTAPI KfAcquireSpinLock(PDWORD lock);
    VOID NTAPI KfReleaseSpinLock(PDWORD lock, BYTE previousIrql);
    BOOL NTAPI MmIsAddressValid(PVOID address);
    VOID NTAPI XeCryptRandom(PBYTE buffer, DWORD bytes);
    NTSTATUS NTAPI XexGetModuleHandle(LPCSTR moduleName, PHANDLE module);
    NTSTATUS NTAPI XexGetProcedureAddress(HANDLE module, DWORD ordinal, PVOID addressOut);
    VOID NTAPI RtlInitAnsiString(ANSI_STRING *destination, LPCSTR source);
    NTSTATUS NTAPI ObCreateSymbolicLink(ANSI_STRING *name, ANSI_STRING *device);
    NTSTATUS NTAPI ObDeleteSymbolicLink(ANSI_STRING *name);
    VOID NTAPI HalSendSMCMessage(PVOID command, PVOID response);

    int NTAPI NetDll_XNetStartup(XNCALLER_TYPE caller, const XNetStartupParams *params);
    int NTAPI NetDll_XNetStartupEx(XNCALLER_TYPE caller, const XNetStartupParams *params, DWORD version);
    int NTAPI NetDll_XNetCleanup(XNCALLER_TYPE caller);
    DWORD NTAPI NetDll_XNetGetTitleXnAddr(XNCALLER_TYPE caller, XNADDR *address);
    int NTAPI NetDll_WSAStartup(XNCALLER_TYPE caller, WORD version, LPWSADATA data);
    int NTAPI NetDll_WSAStartupEx(XNCALLER_TYPE caller, WORD version, LPWSADATA data, DWORD xdkVersion);
    int NTAPI NetDll_WSACleanup(XNCALLER_TYPE caller);
    int NTAPI NetDll_WSAGetLastError();

    SOCKET NTAPI NetDll_socket(XNCALLER_TYPE caller, int family, int type, int protocol);
    int NTAPI NetDll_closesocket(XNCALLER_TYPE caller, SOCKET socket);
    int NTAPI NetDll_setsockopt(XNCALLER_TYPE caller, SOCKET socket, int level, int option,
                               const char *value, int size);
    int NTAPI NetDll_ioctlsocket(XNCALLER_TYPE caller, SOCKET socket, long command, u_long *value);
    int NTAPI NetDll_bind(XNCALLER_TYPE caller, SOCKET socket, const sockaddr *address, int size);
    int NTAPI NetDll_getsockname(XNCALLER_TYPE caller, SOCKET socket, sockaddr *address, int *size);
    int NTAPI NetDll_sendto(XNCALLER_TYPE caller, SOCKET socket, const VOID *buffer, int size, int flags,
                            const sockaddr *address, int addressSize);
    int NTAPI NetDll_recvfrom(XNCALLER_TYPE caller, SOCKET socket, char *buffer, int size, int flags,
                              sockaddr *address, int *addressSize);

    int NTAPI NetDll_XnpEthernetInterceptSetCallbacks(XNCALLER_TYPE caller, EthernetInterceptCallback transmit,
                                                      EthernetInterceptCallback receive, PVOID context, DWORD flags);
    int NTAPI NetDll_XnpEthernetInterceptXmit(XNCALLER_TYPE caller, PBYTE frame, DWORD bytes);
    VOID NTAPI NetDll_XnpEthernetInterceptRecv(XNCALLER_TYPE caller, PBYTE frame, DWORD bytes);
}
