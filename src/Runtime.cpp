#include "Platform.h"
#include "Engine.h"
#include "MullvadDns.h"
#include "Route.h"
#include "VpnConfig.h"

extern "C" uint32_t wireguard_sys_now() { return GetTickCount(); }
extern "C" void wireguard_random_bytes(void *data, size_t bytes) { XeCryptRandom(static_cast<BYTE *>(data), bytes); }
extern "C" bool wireguard_is_under_load() { return false; }
extern "C" void wireguard_tai64n_now(uint8_t *bytes)
{
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    const uint64_t ticks = (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    const uint64_t unixTicks = ticks - 116444736000000000ULL;
    const uint64_t seconds = 0x400000000000000AULL + unixTicks / 10000000;
    for (unsigned i = 0; i < 8; ++i)
        bytes[i] = BYTE(seconds >> ((7 - i) * 8));
    XboxVpn::Write32(bytes + 8, uint32_t(unixTicks % 10000000) * 100);
}

namespace XboxVpn
{
namespace
{
const char ConfigPath[] = "XboxVpnHdd:\\VPN.ini";
const char SystemLink[] = "\\System??\\XboxVpnHdd:";
const char ProcessLink[] = "\\??\\XboxVpnHdd:";
const char DiskName[] = "\\Device\\Harddisk0\\Partition1";

class HddConfiguration
{
    bool systemMounted, processMounted;

    static bool MakeLink(const char *path, ANSI_STRING &target)
    {
        ANSI_STRING alias;
        RtlInitAnsiString(&alias, path);
        return NT_SUCCESS(ObCreateSymbolicLink(&alias, &target));
    }

    static void RemoveLink(const char *path)
    {
        ANSI_STRING alias;
        RtlInitAnsiString(&alias, path);
        ObDeleteSymbolicLink(&alias);
    }

  public:
    HddConfiguration() : systemMounted(false), processMounted(false) {}

    bool Mount()
    {
        ANSI_STRING target;
        RtlInitAnsiString(&target, DiskName);
        systemMounted = MakeLink(SystemLink, target);
        processMounted = MakeLink(ProcessLink, target);
        return systemMounted || processMounted;
    }

    void Unmount()
    {
        if (processMounted)
            RemoveLink(ProcessLink);
        if (systemMounted)
            RemoveLink(SystemLink);
    }

    ConfigReadStatus Read(char *buffer, size_t capacity, size_t &length)
    {
        length = 0;
        HANDLE file = CreateFileA(ConfigPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (file == INVALID_HANDLE_VALUE)
            return GetLastError() == ERROR_FILE_NOT_FOUND ? ConfigReadMissing : ConfigReadUnavailable;
        DWORD high = 0;
        const DWORD size = GetFileSize(file, &high);
        ConfigReadStatus status = ConfigReadUnavailable;
        if (size != INVALID_FILE_SIZE)
        {
            if (high || size > capacity)
                status = ConfigReadTooLarge;
            else
            {
                DWORD read = 0;
                if (ReadFile(file, buffer, size, &read, 0) && read == size)
                {
                    length = size;
                    status = ConfigReadOk;
                }
            }
        }
        CloseHandle(file);
        return status;
    }

    bool CreateExclusive(const char *text, size_t length)
    {
        HANDLE file = CreateFileA(ConfigPath, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        DWORD written = 0;
        const bool saved = WriteFile(file, text, static_cast<DWORD>(length), &written, 0) &&
                           written == length && FlushFileBuffers(file);
        CloseHandle(file);
        return saved;
    }
};

bool ReadLocalAddress(XNADDR &address)
{
    const DWORD flags = NetDll_XNetGetTitleXnAddr(XNCALLER_SYSAPP, &address);
    return address.ina.s_addr && (flags & XNET_GET_XNADDR_GATEWAY) && !(flags & XNET_GET_XNADDR_PPPOE);
}

template <unsigned Count>
bool MatchesXamCode(DWORD address, const DWORD (&expected)[Count])
{
    return MmIsAddressValid(reinterpret_cast<PVOID>(address)) &&
           MmIsAddressValid(reinterpret_cast<PVOID>(address + sizeof(expected) - 1)) &&
           memcmp(reinterpret_cast<const void *>(address), expected, sizeof(expected)) == 0;
}

const char *RebuildLiveGateway(const void *context)
{
    // These addresses and instructions are specific to retail XAM 17559.
    // Use the same association teardown as a link change, with XAM's own lock.
    const DWORD xamBase = 0x815F0000, stackPointer = 0x81AC7C04, lockAddress = 0x81AC7C00;
    const DWORD acquireAddress = 0x81763388, releaseAddress = 0x81763410, teardownAddress = 0x8174F4D0;
    static const DWORD acquireCode[] = {0x7D8802A6, 0x4BFCA039, 0x9421FF80, 0x7C7B1B78, 0x83ED0100, 0x38600002};
    static const DWORD releaseCode[] = {0x7D8802A6, 0x4BFC9FB9, 0x9421FF90, 0x3D6081AC, 0x7C7E1B78, 0x396B7C00};
    static const DWORD teardownCode[] = {0x7D8802A6, 0x4BFDDEED, 0x9421FF70, 0x89650002, 0x7C7D1B78, 0x7CBF2B78, 0x7CDA3378};
    HANDLE xam = 0;
    char module[] = "xam.xex";
    if (static_cast<LONG>(XexGetModuleHandle(module, &xam)) < 0 || !xam)
        return "XAM unavailable";
    const LDR_DATA_TABLE_ENTRY *image = reinterpret_cast<const LDR_DATA_TABLE_ENTRY *>(xam);
    if (reinterpret_cast<DWORD>(image->ImageBase) != xamBase ||
        image->SizeOfFullImage < stackPointer - xamBase + sizeof(DWORD) || image->TimeDateStamp != 0x5DAA92A1 ||
        !MmIsAddressValid(reinterpret_cast<PVOID>(stackPointer)) || !MatchesXamCode(acquireAddress, acquireCode) ||
        !MatchesXamCode(releaseAddress, releaseCode) || !MatchesXamCode(teardownAddress, teardownCode))
        return "unsupported XAM image";

    typedef BYTE (*Acquire)(DWORD *);
    typedef void (*Release)(DWORD *, BYTE);
    typedef void (*Teardown)(BYTE *, unsigned, BYTE *, DWORD);
    DWORD *const lock = reinterpret_cast<DWORD *>(lockAddress);
    const BYTE irql = reinterpret_cast<Acquire>(acquireAddress)(lock);
    const char *result = "native adapter changed";
    BYTE *const stack = *reinterpret_cast<BYTE **>(stackPointer);
    if (stack && *reinterpret_cast<const void **>(stack + 0x104) == context &&
        *reinterpret_cast<const DWORD *>(stack + 0x108) == XNCALLER_SYSAPP)
    {
        const DWORD primary = *reinterpret_cast<const DWORD *>(stack + 0x1564);
        result = primary ? "primary association not in owner table" : "no primary association";
        for (unsigned owner = 1; primary && owner <= 4; ++owner)
        {
            const BYTE *const table = stack + 0x7EC + (owner - 1) * 0x80;
            const DWORD first = *reinterpret_cast<const DWORD *>(table);
            const unsigned entrySize = 0x138;
            if (!first || primary < first || (primary - first) % entrySize || (primary - first) / entrySize >= table[0xA])
                continue;
            BYTE *const association = reinterpret_cast<BYTE *>(primary);
            result = "primary association already down";
            const WORD flags = *reinterpret_cast<const WORD *>(association);
            if (association[2] > 1 && (flags & 5) == 4)
            {
                reinterpret_cast<Teardown>(teardownAddress)(stack, owner, association, 0x05000000);
                result = "primary association reset";
            }
            break;
        }
    }
    reinterpret_cast<Release>(releaseAddress)(lock, irql);
    return result;
}

class TunnelSession
{
    Engine protocol;
    MullvadDns dns;
    LanFragments fragments;
    PacketQueue<64> outgoing;
    DWORD queueLock, local, tunnelAddress, resolver, remote, lastAttempt, lastSend, keepalive, lastAddressCheck;
    DWORD localPort, remotePort, mtu;
    BYTE mac[6], gateway[6];
    bool haveGateway, wasReady, gatewayHandled;
    SOCKET socket;
    sockaddr_in endpoint;
    BYTE frame[MaximumFrame], plain[MaximumFrame], wire[MaximumFrame], injectFrame[MaximumFrame];

    static int Transmit(void *context, const BYTE *frame, DWORD bytes)
    {
        TunnelSession &session = *static_cast<TunnelSession *>(context);
        const BYTE irql = KfAcquireSpinLock(&session.queueLock);
        const Route route = Classify(frame, bytes, true, session.remote, session.remotePort, session.local, session.localPort);
        if (route == Direct && bytes >= 42 && Read16(frame + 12) == 0x0800 && Read32(frame + 30) == session.remote)
        {
            memcpy(session.gateway, frame, 6);
            session.haveGateway = true;
        }
        if (route == Tunnel)
            session.outgoing.Push(frame, bytes);
        KfReleaseSpinLock(&session.queueLock, irql);
        return route == Direct ? 0 : 1;
    }

    static int Receive(void *context, const BYTE *frame, DWORD bytes)
    {
        TunnelSession &session = *static_cast<TunnelSession *>(context);
        const BYTE irql = KfAcquireSpinLock(&session.queueLock);
        const Route route = Classify(frame, bytes, false, session.remote, session.remotePort, session.local, session.localPort);
        KfReleaseSpinLock(&session.queueLock, irql);
        return route == Direct ? 0 : 1;
    }

    bool Send(const BYTE *packet, unsigned size)
    {
        if (NetDll_sendto(XNCALLER_SYSAPP, socket, packet, size, 0,
                          reinterpret_cast<const sockaddr *>(&endpoint), sizeof(endpoint)) != static_cast<int>(size))
            return false;
        lastSend = GetTickCount();
        return true;
    }

    void Inject(const BYTE *ip, unsigned size)
    {
        if (size > sizeof(injectFrame) - 14)
            return;
        const BYTE irql = KfAcquireSpinLock(&queueLock);
        const bool ready = haveGateway;
        memcpy(injectFrame + 6, gateway, 6);
        KfReleaseSpinLock(&queueLock, irql);
        if (!ready)
            return;
        memcpy(injectFrame, mac, 6);
        Write16(injectFrame + 12, 0x0800);
        memcpy(injectFrame + 14, ip, size);
        NetDll_XnpEthernetInterceptRecv(XNCALLER_SYSAPP, injectFrame, size + 14);
    }

    void DrainOutgoing(bool ready, DWORD now)
    {
        for (unsigned count = 0; count < 32; ++count)
        {
            unsigned bytes;
            const BYTE irql = KfAcquireSpinLock(&queueLock);
            const bool queued = outgoing.Pop(frame, sizeof(frame), bytes);
            KfReleaseSpinLock(&queueLock, irql);
            if (!queued)
                break;
            BYTE *const ip = frame + 14;
            unsigned header, size;
            if (bytes < 14 || !ValidateIp(ip, bytes - 14, header, size) || !RepairChecksums(ip, size))
                continue;
            const Route route = fragments.Decide(ip, size, now);
            if (route == Direct)
            {
                NetDll_XnpEthernetInterceptXmit(XNCALLER_SYSAPP, frame, bytes);
                continue;
            }
            if (route == Drop || !ready)
                continue;
            if (size > mtu && ((Read16(ip + 6) & 0x4000) || header != 20))
            {
                unsigned replySize;
                if (MtuReply(ip, size, plain, replySize, mtu))
                    Inject(plain, replySize);
                continue;
            }
            if (!dns.Rewrite(ip, size, resolver, true, now) || !Translate(ip, size, local, tunnelAddress, true))
                continue;
            unsigned cursor = 0, partSize, wireSize;
            while (Fragment(ip, size, cursor, plain, partSize, mtu))
                if (!protocol.Encrypt(plain, partSize, wire, wireSize) || !Send(wire, wireSize))
                    break;
        }
    }

    void RefreshLocalAddress(DWORD now)
    {
        if (now - lastAddressCheck < 250)
            return;
        lastAddressCheck = now;
        XNADDR address = {};
        if (!ReadLocalAddress(address))
            return;
        const DWORD updated = Read32(reinterpret_cast<const BYTE *>(&address.ina.s_addr));
        if (updated == local && memcmp(mac, address.abEnet, sizeof(mac)) == 0)
            return;

        const BYTE irql = KfAcquireSpinLock(&queueLock);
        local = updated;
        memcpy(mac, address.abEnet, sizeof(mac));
        haveGateway = false;
        outgoing.Clear();
        KfReleaseSpinLock(&queueLock, irql);
        fragments = LanFragments();
        dns = MullvadDns();
        // Refresh the relay's outer UDP route and relearn the next-hop MAC.
        unsigned size;
        if (protocol.Ready() && protocol.Encrypt(0, 0, wire, size))
            Send(wire, size);
        else
            lastAttempt = now - 5500;
    }

  public:
    TunnelSession() : queueLock(0), local(0), tunnelAddress(0), resolver(0), remote(0), lastAttempt(0), lastSend(0),
                      keepalive(0), lastAddressCheck(0), localPort(0), remotePort(0), mtu(0), haveGateway(false), wasReady(false),
                      gatewayHandled(false), socket(INVALID_SOCKET)
    {
        memset(gateway, 0, sizeof(gateway));
        memset(&endpoint, 0, sizeof(endpoint));
    }

    bool Start(const MullvadProfile &profile, const XNADDR &address)
    {
        if (!protocol.Initialize(profile.PrivateKey) || !protocol.SetPeer(profile.PublicKey))
            return false;
        local = Read32(reinterpret_cast<const BYTE *>(&address.ina.s_addr));
        memcpy(mac, address.abEnet, 6);
        tunnelAddress = profile.Address;
        remote = profile.Endpoint;
        remotePort = profile.Port;
        resolver = profile.Dns;
        mtu = profile.Mtu;
        keepalive = profile.KeepaliveSeconds * 1000;
        endpoint.sin_family = AF_INET;
        Write32(reinterpret_cast<BYTE *>(&endpoint.sin_addr.s_addr), remote);
        endpoint.sin_port = htons(static_cast<WORD>(remotePort));

        socket = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        BOOL insecure = TRUE;
        u_long nonblocking = 1;
        sockaddr_in bound = {};
        bound.sin_family = AF_INET;
        int boundSize = sizeof(bound);
        if (socket == INVALID_SOCKET ||
            NetDll_setsockopt(XNCALLER_SYSAPP, socket, SOL_SOCKET, 0x5801, reinterpret_cast<const char *>(&insecure), sizeof(insecure)) ||
            NetDll_ioctlsocket(XNCALLER_SYSAPP, socket, FIONBIO, &nonblocking) ||
            NetDll_bind(XNCALLER_SYSAPP, socket, reinterpret_cast<const sockaddr *>(&bound), sizeof(bound)) ||
            NetDll_getsockname(XNCALLER_SYSAPP, socket, reinterpret_cast<sockaddr *>(&bound), &boundSize) ||
            boundSize != sizeof(bound) || !bound.sin_port)
        {
            DbgPrint("[XboxVPN] Could not open WireGuard UDP socket\n");
            return false;
        }
        localPort = ntohs(bound.sin_port);
        const int result = NetDll_XnpEthernetInterceptSetCallbacks(XNCALLER_SYSAPP, Transmit, Receive, this, 0);
        if (result)
        {
            DbgPrint("[XboxVPN] Could not install Ethernet interceptor (%d)\n", result);
            return false;
        }
        lastAttempt = GetTickCount() - 5500;
        DbgPrint("[XboxVPN] Connecting to Mullvad; Internet IPv4 blocked until handshake\n");
        return true;
    }

    void ClearFailedStart()
    {
        if (socket != INVALID_SOCKET)
            NetDll_closesocket(XNCALLER_SYSAPP, socket);
        socket = INVALID_SOCKET;
        protocol.Clear();
    }

    void Pump()
    {
        const DWORD now = GetTickCount();
        RefreshLocalAddress(now);
        if (protocol.NeedsHandshake() && now - lastAttempt >= 5500)
        {
            unsigned size;
            lastAttempt = now;
            if (protocol.Initiate(wire, size))
                Send(wire, size);
        }
        for (unsigned count = 0; count < 32; ++count)
        {
            sockaddr_in from = {};
            int fromSize = sizeof(from);
            const int bytes = NetDll_recvfrom(XNCALLER_SYSAPP, socket, reinterpret_cast<char *>(wire), sizeof(wire), 0,
                                               reinterpret_cast<sockaddr *>(&from), &fromSize);
            if (bytes <= 0)
                break;
            if (fromSize != sizeof(from) || from.sin_addr.s_addr != endpoint.sin_addr.s_addr || from.sin_port != endpoint.sin_port)
                continue;
            unsigned size, replySize;
            if (!protocol.Receive(wire, bytes, plain, size, frame, replySize))
                continue;
            if (replySize)
                Send(frame, replySize);
            if (size && protocol.Ready() && Translate(plain, size, local, tunnelAddress, false) &&
                dns.Rewrite(plain, size, resolver, false, now))
                Inject(plain, size);
        }
        const bool ready = protocol.Ready();
        if (ready && !gatewayHandled)
        {
            gatewayHandled = true;
            DbgPrint("[XboxVPN] Live gateway: %s\n", RebuildLiveGateway(this));
        }
        if (ready != wasReady)
        {
            wasReady = ready;
            DbgPrint(ready ? "[XboxVPN] Mullvad connected\n" : "[XboxVPN] Tunnel unavailable; reconnecting with Internet blocked\n");
        }
        DrainOutgoing(ready, now);
        if (ready && keepalive && GetTickCount() - lastSend >= keepalive)
        {
            unsigned size;
            if (protocol.Encrypt(0, 0, wire, size))
                Send(wire, size);
        }
    }
};

TunnelSession session;
} // namespace
} // namespace XboxVpn

DWORD WINAPI RunXboxVpn(void *)
{
    using namespace XboxVpn;
    if (!XboxKrnlVersion || XboxKrnlVersion->Build != 17559)
    {
        DbgPrint("[XboxVPN] Retail kernel 17559 required\n");
        return 0;
    }

    HddConfiguration storage;
    while (!storage.Mount())
        Sleep(3000);

    MullvadProfile profile = {};
    ConfigResult last = ConfigLoaded;
    for (;;)
    {
        const ConfigResult result = ReadConfiguration(storage, profile);
        if (result == ConfigLoaded)
            break;
        if (last != result)
        {
            if (result == ConfigMissingCreated)
                DbgPrint("[XboxVPN] Created Hdd:\\VPN.ini. Waiting for a Mullvad WireGuard profile.\n");
            else if (result == ConfigInvalid)
                DbgPrint("[XboxVPN] Hdd:\\VPN.ini needs a valid Mullvad WireGuard profile.\n");
            else
                DbgPrint("[XboxVPN] Waiting for access to Hdd:\\VPN.ini\n");
        }
        last = result;
        Sleep(3000);
    }
    storage.Unmount();

    const DWORD sdkVersion = 0x20530800;
    XNetStartupParams params = {};
    params.cfgSizeOfStruct = sizeof(params);
    while (NetDll_XNetStartupEx(XNCALLER_SYSAPP, &params, sdkVersion))
        Sleep(3000);
    WSADATA winsock = {};
    while (NetDll_WSAStartupEx(XNCALLER_SYSAPP, 0x0202, &winsock, sdkVersion))
        Sleep(3000);

    XNADDR address = {};
    DbgPrint("[XboxVPN] Waiting for an Ethernet IPv4 address\n");
    while (!ReadLocalAddress(address))
        Sleep(250);

    const bool started = session.Start(profile, address);
    crypto_zero(&profile, sizeof(profile));
    if (!started)
    {
        session.ClearFailedStart();
        NetDll_WSACleanup(XNCALLER_SYSAPP);
        NetDll_XNetCleanup(XNCALLER_SYSAPP);
        return 0;
    }
    for (;;)
    {
        session.Pump();
        Sleep(2);
    }
}
