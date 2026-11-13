#pragma once
#include <stdint.h>
#include <string.h>

namespace XboxVpn
{
enum
{
    MaximumFrame = 1600,
    MinimumMtu = 1280,
    // 1420-byte inner packets fit below a 1500-byte outer IPv4 MTU, including
    // WireGuard padding/authentication and UDP/IP headers. The profile may lower it.
    TunnelMtu = 1420
};
inline bool HasKey(const unsigned char *key)
{
    unsigned value = 0;
    for (unsigned i = 0; i < 32; ++i)
        value |= key[i];
    return value != 0;
}
inline uint16_t Read16(const unsigned char *p)
{
    return uint16_t(p[0] << 8 | p[1]);
}
inline uint32_t Read32(const unsigned char *p)
{
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
inline void Write16(unsigned char *p, unsigned value)
{
    p[0] = value >> 8;
    p[1] = value;
}
inline void Write32(unsigned char *p, uint32_t value)
{
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}
uint16_t Checksum(const unsigned char *bytes, unsigned size, uint32_t seed = 0);
bool ValidateIp(const unsigned char *packet, unsigned size, unsigned &header, unsigned &length);
bool RepairChecksums(unsigned char *packet, unsigned size);
bool Translate(unsigned char *packet, unsigned size, uint32_t local, uint32_t tunnel, bool outbound);
bool IsLocalAddress(uint32_t address, uint32_t local, uint32_t mask);
bool Fragment(const unsigned char *packet, unsigned size, unsigned &cursor, unsigned char *part,
              unsigned &partSize, unsigned mtu = TunnelMtu);
bool MtuReply(const unsigned char *packet, unsigned size, unsigned char *reply, unsigned &replySize,
              unsigned mtu = TunnelMtu);

// Synchronization belongs to the platform adapter. Native callbacks are serialized
// by XAM; worker access uses the same small interrupt-safe queue lock.
template <unsigned Capacity> class PacketQueue
{
    struct Slot
    {
        unsigned Size;
        unsigned char Bytes[MaximumFrame];
    } Slots[Capacity];
    unsigned Head, Tail, Count;

  public:
    PacketQueue() : Head(0), Tail(0), Count(0) {}
    bool Push(const unsigned char *bytes, unsigned size)
    {
        if (!bytes || !size || size > MaximumFrame || Count == Capacity)
            return false;
        Slots[Tail].Size = size;
        memcpy(Slots[Tail].Bytes, bytes, size);
        Tail = (Tail + 1) % Capacity;
        ++Count;
        return true;
    }
    bool Pop(unsigned char *bytes, unsigned capacity, unsigned &size)
    {
        size = 0;
        if (!Count || capacity < Slots[Head].Size)
            return false;
        size = Slots[Head].Size;
        memcpy(bytes, Slots[Head].Bytes, size);
        Head = (Head + 1) % Capacity;
        --Count;
        return true;
    }
    void Clear()
    {
        Head = Tail = Count = 0;
    }
};

} // namespace XboxVpn
