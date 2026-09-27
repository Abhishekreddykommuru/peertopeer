// =============================================================================
// message.cpp — frame (de)serialisation and the encrypted channel.
// =============================================================================
#include "message.h"

#include <cstring>

namespace p2p {

namespace {

// Big-endian (network byte order) integer packing. Done by hand so the wire
// format is unambiguous regardless of host endianness.
void putU32(std::string& out, uint32_t v) {
  out.push_back(char(v >> 24));
  out.push_back(char(v >> 16));
  out.push_back(char(v >> 8));
  out.push_back(char(v));
}

uint32_t getU32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

void putU16(std::string& out, uint16_t v) {
  out.push_back(char(v >> 8));
  out.push_back(char(v));
}

uint16_t getU16(const uint8_t* p) {
  return uint16_t((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}

// Serialise the field list into a payload byte string.
std::string serializeFields(const std::vector<std::string>& fields) {
  std::string payload;
  size_t total = 4;
  for (const auto& f : fields) total += 4 + f.size();
  payload.reserve(total);

  putU32(payload, uint32_t(fields.size()));
  for (const auto& f : fields) {
    putU32(payload, uint32_t(f.size()));
    payload.append(f);
  }
  return payload;
}

// Parse a payload back into fields. Every length is bounds-checked against
// the actual buffer size so a corrupted frame can never cause an over-read.
bool parseFields(const uint8_t* p, size_t len, std::vector<std::string>& out) {
  if (len < 4) return false;
  uint32_t count = getU32(p);
  if (count > kMaxFields) return false;
  size_t off = 4;
  out.clear();
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    if (off + 4 > len) return false;
    uint32_t flen = getU32(p + off);
    off += 4;
    if (flen > len || off + flen > len) return false;
    out.emplace_back(reinterpret_cast<const char*>(p + off), flen);
    off += flen;
  }
  return off == len;  // reject trailing garbage
}

}  // namespace

std::array<uint8_t, 12> SecureChannel::makeNonce(uint32_t direction,
                                                 uint64_t counter) {
  std::array<uint8_t, 12> nonce{};
  // 4-byte direction tag (little-endian) + 8-byte message counter.
  for (int i = 0; i < 4; ++i) nonce[i] = uint8_t(direction >> (8 * i));
  for (int i = 0; i < 8; ++i) nonce[4 + i] = uint8_t(counter >> (8 * i));
  return nonce;
}

void SecureChannel::enableEncryption(const Key256& key, bool initiator) {
  // Separate the cipher key from the MAC key. Reusing one key for both is a
  // classic mistake; distinct KDF labels make them independent.
  key_ = deriveKey256(key.data(), key.size(), "frame-enc");
  macKey_ = deriveKey256(key.data(), key.size(), "frame-mac");
  // Initiator sends in nonce-space 1 and receives in 2; responder mirrors.
  // Distinct spaces guarantee the two directions never reuse a nonce even
  // though they share one session key.
  sendDir_ = initiator ? 1 : 2;
  recvDir_ = initiator ? 2 : 1;
  sendCounter_ = 0;
  recvCounter_ = 0;
  encrypted_ = true;
}

bool SecureChannel::send(const Message& m) {
  std::string payload = serializeFields(m.fields);
  if (payload.size() > kMaxPayload) return false;

  // Encrypting and writing must be atomic per message: the nonce counter and
  // the byte stream have to advance in lock-step across threads.
  std::lock_guard<std::mutex> lock(sendMutex_);

  uint16_t flags = 0;
  if (encrypted_) {
    flags |= kFlagEncrypted;
    auto nonce = makeNonce(sendDir_, sendCounter_++);
    aes256CtrXor(key_, nonce, 0,
                 reinterpret_cast<uint8_t*>(&payload[0]), payload.size());
  }

  std::string frame;
  frame.reserve(12 + payload.size() + (encrypted_ ? kMacLen : 0));
  putU32(frame, kWireMagic);
  frame.push_back(char(kWireVersion));
  frame.push_back(char(m.type));
  putU16(frame, flags);
  putU32(frame, uint32_t(payload.size()));
  frame.append(payload);

  if (encrypted_) {
    // Encrypt-then-MAC over header + ciphertext, so the type, flags and
    // length are authenticated too — not just the payload bytes.
    Sha1Digest tag = hmacSha1(macKey_.data(), macKey_.size(),
                              reinterpret_cast<const uint8_t*>(frame.data()),
                              frame.size());
    frame.append(reinterpret_cast<const char*>(tag.data()), tag.size());
  }

  // One sendAll for header+payload(+tag): fewer syscalls, no torn frames.
  return sock_.sendAll(frame.data(), frame.size());
}

bool SecureChannel::recv(Message& out) {
  uint8_t header[12];
  if (!sock_.recvAll(header, sizeof(header))) return false;

  // Validate everything before allocating or trusting a single byte.
  if (getU32(header) != kWireMagic) return false;
  if (header[4] != kWireVersion) return false;
  uint8_t type = header[5];
  uint16_t flags = getU16(header + 6);
  uint32_t payloadLen = getU32(header + 8);
  if (payloadLen > kMaxPayload) return false;

  std::vector<uint8_t> payload(payloadLen);
  if (payloadLen > 0 && !sock_.recvAll(payload.data(), payloadLen)) {
    return false;
  }

  if (flags & kFlagEncrypted) {
    if (!encrypted_) return false;  // peer claims encryption we never set up

    uint8_t tag[kMacLen];
    if (!sock_.recvAll(tag, sizeof(tag))) return false;

    // Verify BEFORE decrypting: a forged or tampered frame is dropped
    // without its bytes ever being interpreted.
    std::string authed(reinterpret_cast<const char*>(header), sizeof(header));
    authed.append(reinterpret_cast<const char*>(payload.data()),
                  payload.size());
    Sha1Digest want = hmacSha1(macKey_.data(), macKey_.size(),
                               reinterpret_cast<const uint8_t*>(authed.data()),
                               authed.size());
    if (!constantTimeEquals(tag, want.data(), kMacLen)) return false;

    auto nonce = makeNonce(recvDir_, recvCounter_++);
    aes256CtrXor(key_, nonce, 0, payload.data(), payload.size());
  } else if (encrypted_) {
    // Once a channel is secured, plaintext frames are a protocol violation
    // (a downgrade attempt) — drop the connection.
    return false;
  }

  out.type = MsgType(type);
  return parseFields(payload.data(), payload.size(), out.fields);
}

Message makeResponse(Status st, const std::string& text,
                     std::vector<std::string> data) {
  std::vector<std::string> fields;
  fields.reserve(2 + data.size());
  fields.push_back(std::to_string(int(st)));
  fields.push_back(text);
  for (auto& d : data) fields.push_back(std::move(d));
  return Message(MsgType::Response, std::move(fields));
}

}  // namespace p2p
