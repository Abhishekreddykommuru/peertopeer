// =============================================================================
// message.h — Frame format + SecureChannel (the custom protocol layer).
//
// Wire frame (all integers big-endian / network byte order):
//
//   +---------+---------+--------+---------+--------------+=============+
//   |  magic  | version |  type  |  flags  |  payloadLen  |   payload   |
//   |  4 B    |  1 B    |  1 B   |  2 B    |  4 B         |  variable   |
//   +---------+---------+--------+---------+--------------+=============+
//
// Payload = field list (a message is just an ordered list of byte strings):
//
//   +------------+----------+=========+----------+=========+ ...
//   | fieldCount |  len[0]  | data[0] |  len[1]  | data[1] |
//   |  4 B       |  4 B     |         |  4 B     |         |
//   +------------+----------+=========+----------+=========+
//
// Design notes:
//   * Length-prefixed framing (not delimiters) — pieces are raw binary and
//     may contain any byte, so sentinel-based parsing is impossible.
//   * The 12-byte header is fixed-size, so a receiver always knows exactly
//     how many bytes to read next: 12, then payloadLen. Combined with
//     recvAll() this makes partial-transmission handling trivial and total.
//   * payloadLen is validated against kMaxPayload BEFORE allocation — a
//     corrupted or hostile length field cannot trigger a huge allocation.
//
// SecureChannel wraps a connected socket and (after a handshake supplies a
// session key) transparently AES-256-CTR encrypts every payload. Each direction
// uses its own nonce space (direction byte + per-message counter), so a
// key+nonce pair is never reused — the one fatal mistake for stream ciphers.
// =============================================================================
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "crypto.h"
#include "protocol.h"
#include "tcp_socket.h"

namespace p2p {

// A parsed message: type tag + ordered fields. Fields are std::string used
// as byte buffers (they are 8-bit clean and handle binary piece data fine).
struct Message {
  MsgType type = MsgType::Request;
  std::vector<std::string> fields;

  Message() = default;
  Message(MsgType t, std::vector<std::string> f)
      : type(t), fields(std::move(f)) {}

  // Bounds-checked accessor: returns "" instead of crashing on a short
  // (malformed) message. Callers validate semantics on top.
  const std::string& field(size_t i) const {
    static const std::string kEmpty;
    return i < fields.size() ? fields[i] : kEmpty;
  }
};

class SecureChannel {
 public:
  // Takes ownership of the connected socket.
  explicit SecureChannel(TcpSocket sock) : sock_(std::move(sock)) {}

  // Switch all subsequent traffic to AES-256-CTR with an HMAC-SHA1 tag
  // (encrypt-then-MAC). `initiator` disambiguates the two directions so each
  // side encrypts with dir=1 for its own sends: the connect()-ing side sends
  // on nonce-direction 1, the accept()-ing side on direction 2.
  //
  // Two independent keys are derived from `key` with distinct labels — one
  // for the cipher, one for the MAC — so the same bytes are never used for
  // both purposes.
  void enableEncryption(const Key256& key, bool initiator);

  bool encrypted() const { return encrypted_; }

  // Serialise + (optionally) encrypt + write one frame. Thread-safe.
  bool send(const Message& m);

  // Read + validate + (optionally) decrypt + parse one frame.
  // Returns false on EOF, timeout, or a malformed/oversized frame.
  bool recv(Message& out);

  const TcpSocket& socket() const { return sock_; }
  void close() { sock_.close(); }
  void shutdownBoth() const { sock_.shutdownBoth(); }
  bool valid() const { return sock_.valid(); }

 private:
  // Build the 12-byte per-message AES-CTR nonce: 4-byte direction tag +
  // 8-byte little-endian message counter. Unique per (key, direction, msg).
  static std::array<uint8_t, 12> makeNonce(uint32_t direction, uint64_t counter);

  TcpSocket sock_;
  bool encrypted_ = false;
  Key256 key_{};     // AES-256 key
  Key256 macKey_{};  // HMAC key, derived from the same secret, different label
  uint32_t sendDir_ = 0, recvDir_ = 0;
  uint64_t sendCounter_ = 0, recvCounter_ = 0;
  std::mutex sendMutex_;  // serialises concurrent senders on one channel
};

// Convenience: build a Response message.
Message makeResponse(Status st, const std::string& text,
                     std::vector<std::string> data = {});

}  // namespace p2p
