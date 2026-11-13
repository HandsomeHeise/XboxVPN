#pragma once
#include "Packet.h"

namespace XboxVpn
{
enum Route
{
    Direct,
    Tunnel,
    Drop
};

// This function runs in XAM's Ethernet callbacks. It only inspects bounded
// bytes: no allocation, logging, crypto, native networking or waiting here.
inline Route Classify(const unsigned char *frame, unsigned bytes, bool outbound, uint32_t endpoint,
                      unsigned port, uint32_t local, unsigned localPort = 0)
{
    if (!frame || bytes < 14)
        return Drop;
    const unsigned type = Read16(frame + 12);
    // Both HomePlug AV and Gigle/Mediaxtream discovery are local Powerline
    // management. Neither is an Internet IP packet or belongs in WireGuard.
    if (type == 0x0806 || type == 0x88E1 || type == 0x8912)
        return Direct;
    if (type != 0x0800)
        return Drop; // Includes IPv6: no silent IPv6 bypass.
    const unsigned char *ip = frame + 14;
    unsigned h, n;
    if (!ValidateIp(ip, bytes - 14, h, n))
        return Drop;
    const unsigned fragment = Read16(ip + 6) & 0x3FFF;
    const uint32_t source = Read32(ip + 12), destination = Read32(ip + 16);
    if (ip[9] == 17 && !fragment && n >= h + 8)
    {
        const unsigned from = Read16(ip + h), to = Read16(ip + h + 2);
        if (localPort && (outbound ? source == local && from == localPort && destination == endpoint && to == port :
                                    destination == local && to == localPort && source == endpoint && from == port))
            return Direct; // Only the exact outer WireGuard endpoint.
        if ((outbound && from == 68 && to == 67 && destination == 0xFFFFFFFF) ||
            (!outbound && from == 67 && to == 68 && (destination == local || destination == 0xFFFFFFFF)))
            return Direct;
    }
    if (outbound && source != local)
        return Drop;
    // DNS uses the tunnel's resolver even when the console sends it to a LAN address.
    if (outbound && !fragment && (ip[9] == 17 || ip[9] == 6) && n >= h + 4 && Read16(ip + h + 2) == 53)
        return Tunnel;
    const uint32_t remote = outbound ? destination : source;
    if (IsLocalAddress(remote, local, 0))
    {
        // The worker tracks first-fragment routing before forwarding later
        // fragments. This keeps fragmented DNS inside and other LAN flows local.
        if (outbound && fragment)
            return Tunnel;
        return Direct;
    }
    return outbound ? Tunnel : Drop;
}

class LanFragments
{
    struct Entry
    {
        uint32_t Destination, Tick;
        uint16_t Id;
        unsigned char Protocol;
        Route Decision;
        bool Used;
    } Entries[64];
    unsigned Next;

  public:
    LanFragments() : Next(0)
    {
        memset(Entries, 0, sizeof(Entries));
    }
    Route Decide(const unsigned char *ip, unsigned size, uint32_t now)
    {
        unsigned h, n;
        if (!ValidateIp(ip, size, h, n))
            return Drop;
        const unsigned fragment = Read16(ip + 6) & 0x3FFF;
        const uint32_t destination = Read32(ip + 16);
        if (!fragment || !IsLocalAddress(destination, 0, 0))
            return Tunnel;
        const uint16_t id = Read16(ip + 4);
        if (!(fragment & 0x1FFF))
        {
            if ((ip[9] == 17 || ip[9] == 6) && n < h + 4)
                return Drop;
            Route decision = (ip[9] == 17 || ip[9] == 6) && Read16(ip + h + 2) == 53 ? Tunnel : Direct;
            unsigned slot = 64;
            for (unsigned i = 0; i < 64; ++i)
            {
                const Entry &entry = Entries[i];
                if (entry.Used && entry.Id == id && entry.Destination == destination &&
                    entry.Protocol == ip[9])
                {
                    slot = i;
                    // IP ID reuse cannot make an outstanding DNS tail look
                    // like LAN data. Conflicting decisions stay blocked.
                    if (now - entry.Tick < 30000 && entry.Decision != decision)
                        decision = Drop;
                    break;
                }
            }
            if (slot == 64)
                slot = Next++ % 64;
            Entry &entry = Entries[slot];
            entry.Destination = destination;
            entry.Id = id;
            entry.Protocol = ip[9];
            entry.Tick = now;
            entry.Decision = decision;
            entry.Used = true;
            return decision;
        }
        for (unsigned i = 0; i < 64; ++i)
        {
            const Entry &entry = Entries[i];
            if (entry.Used && entry.Id == id && entry.Destination == destination && entry.Protocol == ip[9] &&
                now - entry.Tick < 30000)
                return entry.Decision;
        }
        return Drop;
    }
};
} // namespace XboxVpn
