#include "Platform.h"

DWORD WINAPI RunXboxVpn(void *);

BOOL APIENTRY DllMain(HANDLE, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    BYTE command[16] = {0x0A}, response[16] = {};
    HalSendSMCMessage(command, response);
    const unsigned tray = response[1] & 15;
    if (response[0] == command[0] && (tray == 0 || tray == 3))
    {
        DbgPrint("[XboxVPN] Open-tray boot: VPN skipped\n");
        return TRUE;
    }

    HANDLE thread = 0;
    DWORD id = 0;
    const DWORD result = ExCreateThread(&thread, 0x10000, &id, reinterpret_cast<PVOID>(XapiThreadStartup),
                                         RunXboxVpn, 0, 2);
    if (static_cast<LONG>(result) < 0 || !thread)
    {
        DbgPrint("[XboxVPN] Could not start worker (0x%08X)\n", result);
        return FALSE;
    }
    CloseHandle(thread);
    return TRUE;
}
