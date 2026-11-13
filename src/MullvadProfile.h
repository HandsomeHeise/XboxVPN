#pragma once

#include "Packet.h"
#include "../third_party/wireguard/src/wireguard.h"
#include "../third_party/wireguard/src/crypto.h"

namespace XboxVpn
{
enum { MullvadProfileMaxBytes = 4096 };

struct MullvadProfile
{
    uint32_t Address, Dns, Endpoint;
    unsigned Port, Mtu, KeepaliveSeconds;
    unsigned char PrivateKey[32], PublicKey[32];
};

namespace MullvadProfileDetail
{
inline char *Split(char *&text, char delimiter)
{
    char *part = text;
    text = strchr(text, delimiter);
    if (text)
        *text++ = '\0';
    return part;
}

inline bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

inline char *Trim(char *text)
{
    while (IsSpace(*text))
        ++text;
    char *end = text + strlen(text);
    while (end != text && IsSpace(end[-1]))
        --end;
    *end = '\0';
    return text;
}

inline bool Equals(const char *text, const char *lowercase)
{
    for (; *text && *lowercase; ++text, ++lowercase)
    {
        const char c = *text >= 'A' && *text <= 'Z' ? *text + ('a' - 'A') : *text;
        if (c != *lowercase)
            return false;
    }
    return *text == *lowercase;
}

inline bool Decimal(const char *&text, unsigned maximum, unsigned &value)
{
    if (*text < '0' || *text > '9')
        return false;
    value = 0;
    do
    {
        value = value * 10 + unsigned(*text++ - '0');
        if (value > maximum)
            return false;
    } while (*text >= '0' && *text <= '9');
    return true;
}

inline bool Number(const char *text, unsigned maximum, unsigned &value)
{
    return Decimal(text, maximum, value) && !*text;
}

inline bool Ipv4(const char *text, uint32_t &address)
{
    address = 0;
    for (unsigned octet = 0; octet < 4; ++octet)
    {
        const char *start = text;
        unsigned value;
        if (!Decimal(text, 255, value) || (*start == '0' && text - start > 1))
            return false;
        address = (address << 8) | value;
        if (octet < 3 && *text++ != '.')
            return false;
    }
    return !*text;
}

inline bool IsHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool Ipv6(const char *text)
{
    bool compressed = text[0] == ':' && text[1] == ':';
    if (compressed)
        text += 2;
    unsigned groups = 0;
    while (*text)
    {
        const char *start = text;
        while (IsHex(*text))
            ++text;
        if (text == start || text - start > 4)
            return false;
        if (*text == '.')
        {
            uint32_t ignored;
            return Ipv4(start, ignored) && (compressed ? groups + 2 < 8 : groups + 2 == 8);
        }
        ++groups;
        if (!*text)
            break;
        if (*text++ != ':')
            return false;
        if (*text == ':')
        {
            if (compressed)
                return false;
            compressed = true;
            ++text;
        }
        else if (!*text)
            return false;
    }
    return compressed ? groups < 8 : groups == 8;
}

inline bool IsUnicast(uint32_t address)
{
    const unsigned first = address >> 24;
    return first && first != 127 && first < 224;
}

enum ListKind { InterfaceAddress, DnsServer, AllowedNetworks };

inline bool AddressList(char *value, ListKind kind, uint32_t &address)
{
    bool haveIpv4 = false;
    bool haveIpv6 = false;
    while (value)
    {
        char *part = Split(value, ',');
        char *ip = Split(part, '/');
        ip = Trim(ip);
        if ((kind == DnsServer) == (part != 0))
            return false;
        unsigned prefix = 0;
        if (strchr(ip, ':'))
        {
            if (haveIpv6 || !Ipv6(ip) || (part && !Number(Trim(part), 128, prefix)))
                return false;
            haveIpv6 = true;
            continue;
        }
        if (haveIpv4 || !Ipv4(ip, address) || (part && !Number(Trim(part), 32, prefix)))
            return false;
        if (kind == AllowedNetworks ? address || prefix : !IsUnicast(address))
            return false;
        if (kind == InterfaceAddress && prefix != 32)
            return false;
        haveIpv4 = true;
    }
    return haveIpv4;
}

inline bool Key(const char *text, unsigned char *key)
{
    // A 32-byte WireGuard key uses one final '=' and two zero padding bits.
    if (strlen(text) != 44 || text[43] != '=' || strchr(text, '=') != text + 43 ||
        !strchr("AEIMQUYcgkosw048", text[42]))
        return false;
    size_t size = 32;
    return wireguard_base64_decode(text, key, &size) && size == 32 && HasKey(key);
}

inline bool Endpoint(char *value, MullvadProfile &profile)
{
    char *ip = Split(value, ':');
    return value && Ipv4(ip, profile.Endpoint) && IsUnicast(profile.Endpoint) &&
           Number(value, 65535, profile.Port) && profile.Port;
}

enum Section { NoSection, Interface, Peer };
enum Field { PrivateKey, Address, Dns, Mtu, PublicKey, AllowedIPs, EndpointAddress, Keepalive, FieldCount };

inline bool SetField(Field field, char *value, MullvadProfile &profile)
{
    switch (field)
    {
    case PrivateKey:
        return Key(value, profile.PrivateKey);
    case Address:
        return AddressList(value, InterfaceAddress, profile.Address);
    case Dns:
        return AddressList(value, DnsServer, profile.Dns);
    case Mtu:
        return Number(value, TunnelMtu, profile.Mtu) && profile.Mtu >= MinimumMtu;
    case PublicKey:
        return Key(value, profile.PublicKey);
    case AllowedIPs:
    {
        uint32_t ignored;
        return AddressList(value, AllowedNetworks, ignored);
    }
    case EndpointAddress:
        return Endpoint(value, profile);
    case Keepalive:
        return Equals(value, "off") || Number(value, 65535, profile.KeepaliveSeconds);
    default:
        return false;
    }
}

inline bool Parse(char *text, MullvadProfile &profile)
{
    if (!text)
        return false;
    unsigned length = 0;
    while (length <= MullvadProfileMaxBytes && text[length])
        ++length;
    if (length > MullvadProfileMaxBytes)
        return false;
    if (length >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF)
        text += 3;

    const char *const fieldNames[] = {"privatekey", "address", "dns", "mtu", "publickey", "allowedips",
                                      "endpoint", "persistentkeepalive"};
    const unsigned required = (1u << PrivateKey) | (1u << Address) | (1u << Dns) | (1u << PublicKey) |
                              (1u << AllowedIPs) | (1u << EndpointAddress);
    Section section = NoSection;
    unsigned seen = 0;
    profile.Mtu = TunnelMtu;
    while (text)
    {
        char *line = Split(text, '\n');
        char *comment = strchr(line, '#');
        if (comment)
            *comment = '\0';
        line = Trim(line);
        if (!*line)
            continue;
        if (Equals(line, "[interface]") && section == NoSection)
        {
            section = Interface;
            continue;
        }
        if (Equals(line, "[peer]") && section == Interface)
        {
            section = Peer;
            continue;
        }
        char *name = Trim(Split(line, '='));
        if (!line || section == NoSection)
            return false;
        const unsigned end = section == Interface ? PublicKey : FieldCount;
        unsigned field = section == Interface ? PrivateKey : PublicKey;
        while (field < end && !Equals(name, fieldNames[field]))
            ++field;
        if (field == end || (seen & (1u << field)) || !SetField(Field(field), Trim(line), profile))
            return false;
        seen |= 1u << field;
    }
    return (seen & required) == required;
}
} // namespace MullvadProfileDetail

// The caller supplies mutable NUL-terminated text and owns erasure of that text.
inline bool ParseMullvadProfile(char *text, MullvadProfile &profile)
{
    crypto_zero(&profile, sizeof(profile));
    if (MullvadProfileDetail::Parse(text, profile))
        return true;
    crypto_zero(&profile, sizeof(profile));
    return false;
}
} // namespace XboxVpn
