#include "Packet.h"

namespace XboxVpn
{
uint16_t Checksum(const unsigned char *bytes, unsigned size, uint32_t sum)
{
    while (size >= 2)
    {
        sum += Read16(bytes);
        bytes += 2;
        size -= 2;
    }
    if (size)
        sum += unsigned(*bytes) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return uint16_t(~sum);
}
bool ValidateIp(const unsigned char *p, unsigned size, unsigned &header, unsigned &length)
{
    if (!p || size < 20 || p[0] >> 4 != 4)
        return false;
    header = (p[0] & 15) * 4;
    length = Read16(p + 2);
    return header >= 20 && header <= size && length >= header && length <= size;
}
bool RepairChecksums(unsigned char *p, unsigned size)
{
    unsigned h, n;
    if (!ValidateIp(p, size, h, n))
        return false;
    const unsigned flags = Read16(p + 6), length = n - h;
    if (!(flags & 0x3FFF))
    {
        unsigned offset = 0;
        if (p[9] == 17)
        {
            if (length < 8 || Read16(p + h + 4) != length)
                return false;
            offset = 6;
        }
        else if (p[9] == 6)
        {
            if (length < 20 || (p[h + 12] >> 4) * 4u < 20 || (p[h + 12] >> 4) * 4u > length)
                return false;
            offset = 16;
        }
        else if (p[9] == 1)
        {
            if (length < 8)
                return false;
            Write16(p + h + 2, 0);
            Write16(p + h + 2, Checksum(p + h, length));
        }
        if (offset)
        {
            Write16(p + h + offset, 0);
            uint32_t sum = Read16(p + 12) + Read16(p + 14) + Read16(p + 16) + Read16(p + 18) + p[9] + length;
            uint16_t value = Checksum(p + h, length, sum);
            Write16(p + h + offset, value ? value : 0xFFFF);
        }
    }
    Write16(p + 10, 0);
    Write16(p + 10, Checksum(p, h));
    return true;
}
static void Adjust(unsigned char *checksum, uint32_t before, uint32_t after)
{
    uint32_t sum = uint16_t(~Read16(checksum));
    sum += uint16_t(~(before >> 16)) + uint16_t(~before) + (after >> 16) + (after & 0xFFFF);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    Write16(checksum, uint16_t(~sum));
}
bool Translate(unsigned char *p, unsigned size, uint32_t local, uint32_t tunnel, bool out)
{
    unsigned h, n;
    if (!ValidateIp(p, size, h, n))
        return false;
    const unsigned address = out ? 12 : 16;
    const uint32_t before = out ? local : tunnel, after = out ? tunnel : local;
    if (Read32(p + address) != before)
        return false;
    const unsigned fragment = Read16(p + 6);
    // The first fragment carries the transport checksum. Later fragments only
    // need the IPv4 checksum; never interpret arbitrary fragment bytes as TCP.
    if (!(fragment & 0x1FFF))
    {
        if (p[9] == 6 || p[9] == 17)
        {
            const unsigned offset = p[9] == 6 ? 16 : 6;
            if (n - h < offset + 2)
                return false;
            if (Read16(p + h + offset) || p[9] == 6)
            {
                Adjust(p + h + offset, before, after);
                if (p[9] == 17 && !Read16(p + h + offset))
                    Write16(p + h + offset, 0xFFFF);
            }
        }
        // ICMP errors quote the packet which triggered the error. Translate its
        // opposite address as well; the outer ICMP checksum covers that change.
        if (!out && p[9] == 1 && n >= h + 8 + 20 && (p[h] == 3 || p[h] == 11 || p[h] == 12))
        {
            unsigned char *quote = p + h + 8;
            const unsigned qh = (quote[0] & 15) * 4;
            if (quote[0] >> 4 == 4 && qh >= 20 && h + 8 + qh <= n && Read32(quote + 12) == tunnel)
            {
                const unsigned oldHeaderChecksum = Read16(quote + 10);
                Adjust(p + h + 2, tunnel, local);
                Write32(quote + 12, local);
                Write16(quote + 10, 0);
                Write16(quote + 10, Checksum(quote, qh));
                Adjust(p + h + 2, oldHeaderChecksum, Read16(quote + 10));
                const unsigned offset = quote[9] == 6 ? 16 : 6;
                if (!(Read16(quote + 6) & 0x1FFF) && (quote[9] == 6 || quote[9] == 17) &&
                    n >= h + 8 + qh + offset + 2 && (quote[9] == 6 || Read16(quote + qh + offset)))
                {
                    const unsigned oldTransportChecksum = Read16(quote + qh + offset);
                    Adjust(quote + qh + offset, tunnel, local);
                    if (quote[9] == 17 && !Read16(quote + qh + offset))
                        Write16(quote + qh + offset, 0xFFFF);
                    Adjust(p + h + 2, oldTransportChecksum, Read16(quote + qh + offset));
                }
                // Incremental updates also preserve an ICMP checksum when only
                // the first fragment is present; recomputing that prefix cannot.
            }
        }
    }
    Write32(p + address, after);
    Write16(p + 10, 0);
    Write16(p + 10, Checksum(p, h));
    return true;
}
bool IsLocalAddress(uint32_t ip, uint32_t local, uint32_t mask)
{
    return ip == 0xFFFFFFFF || ip >> 24 == 127 || ip >> 16 == 0xA9FE || ip >> 24 == 10 || ip >> 20 == 0xAC1 ||
           ip >> 16 == 0xC0A8 || (ip & 0xF0000000) == 0xE0000000 || (mask && (ip & mask) == (local & mask));
}
bool Fragment(const unsigned char *p, unsigned size, unsigned &cursor, unsigned char *part,
              unsigned &partSize, unsigned mtu)
{
    unsigned h, n;
    partSize = 0;
    if (mtu < MinimumMtu || mtu > TunnelMtu ||
        !ValidateIp(p, size, h, n) || cursor >= n - h)
        return false;
    if (n <= mtu && cursor == 0)
    {
        memcpy(part, p, n);
        partSize = n;
        cursor = n - h;
        return true;
    }
    // IP option copy rules vary per option. Never manufacture a malformed
    // fragment for options we do not implement; return an MTU error instead.
    const unsigned flags = Read16(p + 6);
    if (h != 20 || (flags & 0x4000))
        return false;
    const unsigned remaining = n - h - cursor;
    const unsigned capacity = (mtu - h) & ~7u;
    const unsigned bytes = remaining < capacity ? remaining : capacity;
    memcpy(part, p, h);
    memcpy(part + h, p + h + cursor, bytes);
    Write16(part + 2, h + bytes);
    Write16(part + 6,
            ((flags & 0x1FFF) + cursor / 8) | ((bytes < remaining || (flags & 0x2000)) ? 0x2000 : 0));
    Write16(part + 10, 0);
    Write16(part + 10, Checksum(part, h));
    cursor += bytes;
    partSize = h + bytes;
    return true;
}
bool MtuReply(const unsigned char *p, unsigned size, unsigned char *reply, unsigned &replySize, unsigned mtu)
{
    unsigned h, n;
    replySize = 0;
    if (mtu < MinimumMtu || mtu > TunnelMtu ||
        !ValidateIp(p, size, h, n) || (Read16(p + 6) & 0x1FFF) || n < h + 8)
        return false;
    if (p[9] == 1 && p[h] != 8 && p[h] != 0)
        return false;
    replySize = 28 + h + 8;
    memset(reply, 0, replySize);
    reply[0] = 0x45;
    reply[8] = 64;
    reply[9] = 1;
    Write16(reply + 2, replySize);
    Write32(reply + 12, Read32(p + 16));
    Write32(reply + 16, Read32(p + 12));
    reply[20] = 3;
    reply[21] = 4;
    Write16(reply + 26, mtu);
    memcpy(reply + 28, p, h + 8);
    return RepairChecksums(reply, replySize);
}
} // namespace XboxVpn
