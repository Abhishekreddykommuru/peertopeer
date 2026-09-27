// =============================================================================
// crypto.h — Cryptographic primitives layered on top of SHA-1.
//
// Everything here is implemented from scratch (no external crypto library;
// external libraries) and unit-tested against published RFC test vectors:
//
//   HMAC-SHA1          (RFC 2104, vectors from RFC 2202)
//     - message authentication: proves a message was produced by someone who
//       knows a shared secret. Used in every handshake in the system.
//   PBKDF2-HMAC-SHA1   (RFC 8018, vectors from RFC 6070)
//     - password hardening: turns a low-entropy password + random salt into
//       a key, deliberately slowly, so stolen verifier databases resist
//       offline dictionary attacks.
//   AES-256 in CTR mode (FIPS-197 block cipher, NIST SP 800-38A mode)
//     - encrypts every channel after its handshake. CTR turns the block
//       cipher into a stream cipher: the keystream is AES(counter block),
//       so encryption and decryption are the same XOR and no padding is
//       ever needed. Verified against the FIPS-197 worked example and the
//       NIST SP 800-38A CTR-AES256 vectors.
//   CSPRNG             (/dev/urandom)
//     - all salts, nonces, session tokens and group keys come from the
//       kernel's entropy pool, never from rand().
// =============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "sha1.h"

namespace p2p {

using Key256 = std::array<uint8_t, 32>;

// ---------------------------------------------------------------------------
// HMAC-SHA1 (RFC 2104): HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
// ---------------------------------------------------------------------------
Sha1Digest hmacSha1(const uint8_t* key, size_t keyLen,
                    const uint8_t* msg, size_t msgLen);

// Convenience overload for string keys/messages.
Sha1Digest hmacSha1(const std::string& key, const std::string& msg);

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1 (RFC 8018). Output fixed at 20 bytes (one HMAC block),
// which is all we need for a password verifier.
// ---------------------------------------------------------------------------
Sha1Digest pbkdf2Sha1(const std::string& password,
                      const uint8_t* salt, size_t saltLen,
                      uint32_t iterations);

// ---------------------------------------------------------------------------
// AES-256 single block encryption (FIPS-197). 14 rounds, 128-bit block.
// Exposed mainly so the unit tests can check it against the published
// worked example; application code uses the CTR wrappers below.
// ---------------------------------------------------------------------------
void aes256EncryptBlock(const Key256& key, const uint8_t in[16],
                        uint8_t out[16]);

// ---------------------------------------------------------------------------
// AES-256-CTR (NIST SP 800-38A §6.5). XORs AES(counter) into `data` in
// place, so encryption and decryption are the same call.
//
//   counter0 : the initial 128-bit counter block, incremented as a
//              big-endian integer once per 16-byte block.
//
// The whole counter block must never repeat under one key. This overload
// takes the raw block so the tests can drive the NIST vectors directly.
// ---------------------------------------------------------------------------
void aes256CtrXor(const Key256& key, const uint8_t counter0[16],
                  uint8_t* data, size_t len);

// Application-facing overload: builds the counter block as
// nonce(12) || counter(4, big-endian), the same layout AES-GCM uses.
//   nonce   : 12 bytes, MUST be unique per key — SecureChannel guarantees
//             this with a direction tag + message counter
//   counter : initial block counter (0 in this codebase)
void aes256CtrXor(const Key256& key, const std::array<uint8_t, 12>& nonce,
                  uint32_t counter, uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Key derivation helper (HKDF-expand style). Stretches a 20-byte HMAC secret
// into a 32-byte AES-256 key, bound to a human-readable label so keys
// derived for different purposes can never collide:
//   K = HMAC(secret, label || 0x01) || HMAC(secret, label || 0x02)[0..11]
// ---------------------------------------------------------------------------
Key256 deriveKey256(const uint8_t* secret, size_t secretLen,
                    const std::string& label);

// ---------------------------------------------------------------------------
// Cryptographically secure random bytes from /dev/urandom.
// Aborts the process if the kernel CSPRNG is unavailable — running a
// "secure" system with predictable nonces would be worse than crashing.
// ---------------------------------------------------------------------------
std::vector<uint8_t> randomBytes(size_t n);
std::string randomHex(size_t nBytes);  // 2*nBytes hex characters

// ---------------------------------------------------------------------------
// Constant-time comparison — prevents timing side-channels when checking
// authentication proofs (a naive memcmp leaks how many leading bytes match).
// ---------------------------------------------------------------------------
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len);
bool constantTimeEquals(const std::string& a, const std::string& b);

// ---------------------------------------------------------------------------
// Hex encoding helpers (digests travel as hex strings in protocol fields).
// ---------------------------------------------------------------------------
std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const Sha1Digest& d);
std::string toHex(const std::vector<uint8_t>& v);
std::vector<uint8_t> fromHex(const std::string& hex);  // empty on bad input

}  // namespace p2p
