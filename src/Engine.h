#pragma once
#include "../third_party/wireguard/src/wireguard.h"

namespace XboxVpn
{
class Engine
{
    wireguard_device Device;
    wireguard_peer *Peer;

  public:
    Engine();
    ~Engine();
    bool Initialize(const unsigned char privateKey[32]);
    bool SetPeer(const unsigned char publicKey[32]);
    const unsigned char *PublicKey() const
    {
        return Device.public_key;
    }
    bool Initiate(unsigned char *wire, unsigned &size);
    bool Receive(const unsigned char *wire, unsigned size, unsigned char *plain, unsigned &plainSize,
                 unsigned char *reply, unsigned &replySize);
    bool Encrypt(const unsigned char *plain, unsigned size, unsigned char *wire, unsigned &wireSize);
    bool Ready() const;
    bool NeedsHandshake() const;
    void Clear();

  private:
    Engine(const Engine &);
    Engine &operator=(const Engine &);
};
} // namespace XboxVpn
