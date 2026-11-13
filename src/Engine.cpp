#include "Engine.h"
#include "Packet.h"
#include "../third_party/wireguard/src/crypto.h"
#include <string.h>

namespace XboxVpn
{
Engine::Engine() : Peer(0)
{
    memset(&Device, 0, sizeof(Device));
}
Engine::~Engine()
{
    Clear();
}
void Engine::Clear()
{
    crypto_zero(&Device, sizeof(Device));
    Peer = 0;
}
bool Engine::Initialize(const unsigned char key[32])
{
    Clear();
    wireguard_init();
    return wireguard_device_init(&Device, key);
}
bool Engine::SetPeer(const unsigned char key[32])
{
    Peer = &Device.peers[0];
    return Device.valid && wireguard_peer_init(&Device, Peer, key, 0);
}
bool Engine::Ready() const
{
    return Peer && Peer->curr_keypair.valid && Peer->curr_keypair.sending_valid &&
           !wireguard_expired(Peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME);
}
bool Engine::NeedsHandshake() const
{
    return Peer && (!Ready() || Peer->send_handshake ||
                    wireguard_expired(Peer->curr_keypair.keypair_millis, REKEY_AFTER_TIME));
}
bool Engine::Initiate(unsigned char *wire, unsigned &size)
{
    size = 0;
    if (!Peer || !wireguard_create_handshake_initiation(&Device, Peer, (message_handshake_initiation *)wire))
        return false;
    size = sizeof(message_handshake_initiation);
    // The encrypted cookie reply authenticates the MAC1 of this exact request.
    // The transport adapter, rather than the protocol core, owns this history.
    memcpy(Peer->handshake_mac1, ((message_handshake_initiation *)wire)->mac1, WIREGUARD_COOKIE_LEN);
    Peer->handshake_mac1_valid = true;
    Peer->last_initiation_tx = wireguard_sys_now();
    Peer->send_handshake = false;
    return true;
}
bool Engine::Encrypt(const unsigned char *plain, unsigned size, unsigned char *wire, unsigned &wireSize)
{
    wireSize = 0;
    if (!Peer || size > 1500 || (!plain && size))
        return false;
    wireguard_keypair *key = &Peer->curr_keypair;
    if (key->valid && !key->initiator && !key->last_rx)
        key = &Peer->prev_keypair;
    if (!key->valid || !key->sending_valid || (!key->initiator && !key->last_rx) ||
        wireguard_expired(key->keypair_millis, REJECT_AFTER_TIME) ||
        key->sending_counter >= REJECT_AFTER_MESSAGES)
        return false;
    const unsigned padded = (size + 15) & ~15u;
    memset(wire, 0, 16 + padded + 16);
    message_transport_data *header = (message_transport_data *)wire;
    header->type = MESSAGE_TRANSPORT_DATA;
    header->receiver = key->remote_index;
    U64TO8_LITTLE(header->counter, key->sending_counter);
    if (size)
        memcpy(wire + 16, plain, size);
    wireguard_encrypt_packet(wire + 16, wire + 16, padded, key);
    wireSize = 32 + padded;
    key->last_tx = Peer->last_tx = wireguard_sys_now();
    return true;
}
bool Engine::Receive(const unsigned char *wire, unsigned size, unsigned char *plain, unsigned &plainSize,
                     unsigned char *reply, unsigned &replySize)
{
    plainSize = replySize = 0;
    if (!Peer || !wire || size > MaximumFrame)
        return false;
    const unsigned type = wireguard_get_message_type(wire, size);
    if (type == MESSAGE_HANDSHAKE_INITIATION)
    {
        message_handshake_initiation message;
        memcpy(&message, wire, sizeof(message));
        if (!wireguard_check_mac1(&Device, wire, size - 32, message.mac1))
            return false;
        wireguard_peer *peer = wireguard_process_initiation_message(&Device, &message);
        if (peer != Peer ||
            !wireguard_create_handshake_response(&Device, peer, (message_handshake_response *)reply))
            return false;
        wireguard_start_session(peer, false);
        replySize = sizeof(message_handshake_response);
        return true;
    }
    if (type == MESSAGE_HANDSHAKE_RESPONSE)
    {
        message_handshake_response message;
        memcpy(&message, wire, sizeof(message));
        if (peer_lookup_by_handshake(&Device, message.receiver) != Peer ||
            !wireguard_check_mac1(&Device, wire, size - 32, message.mac1) ||
            !wireguard_process_handshake_response(&Device, Peer, &message))
            return false;
        wireguard_start_session(Peer, true);
        return Encrypt(0, 0, reply, replySize);
    }
    if (type == MESSAGE_COOKIE_REPLY)
    {
        message_cookie_reply message;
        memcpy(&message, wire, sizeof(message));
        return peer_lookup_by_handshake(&Device, message.receiver) == Peer &&
               wireguard_process_cookie_message(&Device, Peer, &message);
    }
    if (type != MESSAGE_TRANSPORT_DATA || size < 32)
        return false;
    message_transport_data header;
    memcpy(&header, wire, 16);
    wireguard_keypair *key = get_peer_keypair_for_idx(Peer, header.receiver);
    const uint64_t nonce = U8TO64_LITTLE(header.counter);
    if (!key || !key->receiving_valid || nonce >= REJECT_AFTER_MESSAGES ||
        wireguard_expired(key->keypair_millis, REJECT_AFTER_TIME) ||
        !wireguard_decrypt_packet(plain, wire + 16, size - 16, nonce, key) ||
        !wireguard_check_replay(key, nonce))
        return false;
    key->last_rx = Peer->last_rx = wireguard_sys_now();
    keypair_update(Peer, key);
    if (size == 32)
        return true;
    unsigned headerSize, length;
    if (!ValidateIp(plain, size - 32, headerSize, length))
        return false;
    for (unsigned i = length; i < size - 32; ++i)
        if (plain[i])
            return false;
    plainSize = length;
    return true;
}
} // namespace XboxVpn
