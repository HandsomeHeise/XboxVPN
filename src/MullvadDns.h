#pragma once
#include "Packet.h"

namespace XboxVpn
{
// Owned by one tunnel worker. Keep the resolver address the native stack
// expects while sending its DNS queries to the profile's in-tunnel resolver.
class MullvadDns
{
    struct Flow
    {
        uint32_t Address, Tick;
        uint16_t Port;
        unsigned char Protocol;
    } Flows[64];

    struct FragmentRoute
    {
        uint32_t Address, Replacement, Tick;
        uint16_t Id, SourcePort, DestinationPort;
        unsigned char Protocol;
        bool Outbound, Used, Blocked;
    } Fragments[64];

    Flow *FindFlow(unsigned protocol, uint16_t port, uint32_t now, bool outbound)
    {
        Flow *available = 0;
        for (unsigned i = 0; i < sizeof(Flows) / sizeof(Flows[0]); ++i)
        {
            Flow &flow = Flows[i];
            if (now - flow.Tick >= (flow.Protocol == 6 ? 300000u : 30000u))
                flow.Port = 0;
            if (flow.Port == port && flow.Protocol == protocol)
                return &flow;
            if (!flow.Port && !available)
                available = &flow;
        }
        return outbound ? available : 0;
    }

    FragmentRoute *FindFragment(uint32_t address, uint16_t id, unsigned protocol, bool outbound,
                                uint32_t now, uint32_t replacement, bool first)
    {
        FragmentRoute *available = 0;
        for (unsigned i = 0; i < sizeof(Fragments) / sizeof(Fragments[0]); ++i)
        {
            FragmentRoute &route = Fragments[i];
            if (now - route.Tick >= 30000u)
                route.Used = false;
            if (!route.Used)
            {
                if (!available)
                    available = &route;
                continue;
            }
            if (route.Id != id || route.Protocol != protocol || route.Outbound != outbound)
                continue;
            if (route.Address == address)
                return &route;
            // After destination translation the receiver cannot distinguish
            // two fragmented datagrams that share an IPv4 ID and protocol.
            if (first && outbound && route.Replacement == replacement)
                return 0;
        }
        return first ? available : 0;
    }

    static bool RewriteAddress(unsigned char *ip, unsigned size, uint32_t address, uint32_t replacement,
                               bool outbound)
    {
        if (address == replacement)
            return true;
        // Translate's inbound form changes the destination and its outbound
        // form changes the source. DNS redirection changes the opposite side.
        return outbound ? Translate(ip, size, replacement, address, false)
                        : Translate(ip, size, address, replacement, true);
    }

  public:
    MullvadDns()
    {
        memset(Flows, 0, sizeof(Flows));
        memset(Fragments, 0, sizeof(Fragments));
    }

    bool Rewrite(unsigned char *ip, unsigned size, uint32_t resolver, bool outbound, uint32_t now)
    {
        if (!resolver)
            return true;
        unsigned header, length;
        if (!ValidateIp(ip, size, header, length))
            return false;
        const unsigned char protocol = ip[9];
        if (protocol != 6 && protocol != 17)
            return true;
        const uint32_t address = Read32(ip + (outbound ? 16 : 12));
        if (!outbound && address != resolver)
            return true;

        const unsigned fragment = Read16(ip + 6);
        const uint16_t id = Read16(ip + 4);
        if (fragment & 0x1FFF)
        {
            // Only the leading fragment identifies the DNS ports.
            const FragmentRoute *route = FindFragment(address, id, protocol, outbound, now, 0, false);
            return route && !route->Blocked && RewriteAddress(ip, size, address, route->Replacement, outbound);
        }
        if (length - header < 4)
            return false;
        const uint16_t sourcePort = Read16(ip + header), destinationPort = Read16(ip + header + 2);
        uint32_t replacement = address;
        Flow *flow = 0;
        const bool dns = (outbound ? destinationPort : sourcePort) == 53;
        if (dns)
        {
            const uint16_t port = outbound ? sourcePort : destinationPort;
            if (port)
                flow = FindFlow(protocol, port, now, outbound);
            if (flow && outbound && flow->Port && flow->Address != address)
                flow = 0;
            replacement = outbound ? resolver : (flow ? flow->Address : address);
        }

        FragmentRoute *route = 0;
        if (fragment & 0x2000)
        {
            route = FindFragment(address, id, protocol, outbound, now, replacement, true);
            if (!route || route->Blocked)
                return false;
            if (route->Used && ((dns && !flow) || route->Replacement != replacement ||
                                route->SourcePort != sourcePort || route->DestinationPort != destinationPort))
            {
                route->Blocked = true;
                return false;
            }
        }
        if (dns && !flow)
            return false;
        if (!RewriteAddress(ip, size, address, replacement, outbound))
            return false;
        if (flow)
        {
            flow->Address = outbound ? address : replacement;
            flow->Protocol = protocol;
            flow->Port = outbound ? sourcePort : destinationPort;
            flow->Tick = now;
        }
        if (route)
        {
            route->Address = address;
            route->Replacement = replacement;
            route->Tick = now;
            route->Id = id;
            route->SourcePort = sourcePort;
            route->DestinationPort = destinationPort;
            route->Protocol = protocol;
            route->Outbound = outbound;
            route->Used = true;
        }
        return true;
    }
};
} // namespace XboxVpn
