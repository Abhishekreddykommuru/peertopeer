// =============================================================================
// sha1.cpp — SHA-1 core (FIPS 180-1).
//
// Verified against the standard test vectors in tests/unit_crypto.cpp:
//   SHA1("abc")                      = a9993e364706816aba3e25717850c26c9cd0d89d
//   SHA1("")                         = da39a3ee5e6b4b0d3255bfef95601890afd80709
// =============================================================================
#include "sha1.h"

#include <cstring>

namespace p2p {

namespace {
// Left-rotate — SHA-1's only bit-mixing primitive besides + and the f() funcs.
inline uint32_t rotl(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32 - n));
}
}  // namespace

void Sha1::reset() {
  // Initial hash values from FIPS 180-1 section 7.
  h_[0] = 0x67452301;
  h_[1] = 0xEFCDAB89;
  h_[2] = 0x98BADCFE;
  h_[3] = 0x10325476;
  h_[4] = 0xC3D2E1F0;
  bitCount_ = 0;
  bufLen_ = 0;
}

void Sha1::processBlock(const uint8_t* block) {
  // Message schedule: 16 big-endian words expanded to 80.
  uint32_t w[80];
  for (int i = 0; i < 16; ++i) {
    w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) |
           (uint32_t(block[i * 4 + 2]) << 8) | uint32_t(block[i * 4 + 3]);
  }
  for (int i = 16; i < 80; ++i) {
    w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];

  // 80 rounds in 4 stages, each with its own boolean function and constant.
  for (int i = 0; i < 80; ++i) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | ((~b) & d);          // Ch
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;                     // Parity
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);   // Maj
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;                     // Parity
      k = 0xCA62C1D6;
    }
    uint32_t tmp = rotl(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rotl(b, 30);
    b = a;
    a = tmp;
  }

  h_[0] += a;
  h_[1] += b;
  h_[2] += c;
  h_[3] += d;
  h_[4] += e;
}

void Sha1::update(const void* data, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  bitCount_ += uint64_t(len) * 8;

  // Fill any partial block left over from the previous update() first.
  if (bufLen_ > 0) {
    size_t need = 64 - bufLen_;
    size_t take = (len < need) ? len : need;
    std::memcpy(buf_ + bufLen_, p, take);
    bufLen_ += take;
    p += take;
    len -= take;
    if (bufLen_ == 64) {
      processBlock(buf_);
      bufLen_ = 0;
    }
  }

  // Compress full blocks straight from the caller's buffer (no extra copy).
  while (len >= 64) {
    processBlock(p);
    p += 64;
    len -= 64;
  }

  // Stash the tail for the next call.
  if (len > 0) {
    std::memcpy(buf_, p, len);
    bufLen_ = len;
  }
}

Sha1Digest Sha1::finish() {
  // Padding: a single 0x80 byte, zeros, then the 64-bit big-endian bit count,
  // aligned so the total is a multiple of 64 bytes.
  uint64_t bits = bitCount_;
  uint8_t pad = 0x80;
  update(&pad, 1);
  uint8_t zero = 0x00;
  while (bufLen_ != 56) {
    update(&zero, 1);
  }

  // Appending the length manually: bitCount_ must not include these 8 bytes,
  // so we bypass update()'s counter by writing into the buffer directly.
  uint8_t lenBytes[8];
  for (int i = 0; i < 8; ++i) {
    lenBytes[i] = uint8_t(bits >> (56 - 8 * i));
  }
  std::memcpy(buf_ + 56, lenBytes, 8);
  processBlock(buf_);
  bufLen_ = 0;

  Sha1Digest out;
  for (int i = 0; i < 5; ++i) {
    out[i * 4] = uint8_t(h_[i] >> 24);
    out[i * 4 + 1] = uint8_t(h_[i] >> 16);
    out[i * 4 + 2] = uint8_t(h_[i] >> 8);
    out[i * 4 + 3] = uint8_t(h_[i]);
  }
  return out;
}

Sha1Digest Sha1::digest(const void* data, size_t len) {
  Sha1 h;
  h.update(data, len);
  return h.finish();
}

}  // namespace p2p
