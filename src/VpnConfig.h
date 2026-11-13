#pragma once

#include <stddef.h>
#include <string.h>

#include "MullvadProfile.h"

namespace XboxVpn
{
enum ConfigReadStatus
{
    ConfigReadOk,
    ConfigReadMissing,
    ConfigReadUnavailable,
    ConfigReadTooLarge
};

enum ConfigResult
{
    ConfigLoaded,
    ConfigMissingCreated,
    ConfigUnavailable,
    ConfigInvalid
};

// Storage::Read returns a byte count excluding the terminator on success.
// Storage::CreateExclusive creates the same file only if it does not exist.
template <typename Storage>
ConfigResult ReadConfiguration(Storage &storage, MullvadProfile &profile)
{
    char text[MullvadProfileMaxBytes + 1];
    size_t length = 0;
    const ConfigReadStatus status = storage.Read(text, MullvadProfileMaxBytes, length);
    ConfigResult result = ConfigUnavailable;
    if (status == ConfigReadOk)
    {
        result = ConfigInvalid;
        if (length <= MullvadProfileMaxBytes && !memchr(text, 0, length))
        {
            text[length] = '\0';
            if (ParseMullvadProfile(text, profile))
                result = ConfigLoaded;
        }
    }
    else if (status == ConfigReadTooLarge)
        result = ConfigInvalid;

    crypto_zero(text, sizeof(text));
    if (result != ConfigLoaded)
        crypto_zero(&profile, sizeof(profile));

    if (status == ConfigReadMissing)
    {
        static const char templateText[] =
            "# Fill the blank fields or replace this file with a Mullvad WireGuard profile.\r\n"
            "[Interface]\r\n"
            "PrivateKey =\r\n"
            "Address =\r\n"
            "DNS =\r\n"
            "# MTU = 1420\r\n"
            "\r\n"
            "[Peer]\r\n"
            "PublicKey =\r\n"
            "AllowedIPs = 0.0.0.0/0\r\n"
            "Endpoint =\r\n"
            "# PersistentKeepalive = 25\r\n";
        if (storage.CreateExclusive(templateText, sizeof(templateText) - 1))
            return ConfigMissingCreated;
    }
    return result;
}
} // namespace XboxVpn
