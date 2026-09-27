// =============================================================================
// crypto.cpp — HMAC-SHA1, PBKDF2, AES-256-CTR, CSPRNG, hex utilities.
// See crypto.h for design rationale; tests/unit_crypto.cpp for RFC vectors.
// =============================================================================
#include "crypto.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace p2p {

// ---------------------------------------------------------------------------
// HMAC-SHA1
// ---------------------------------------------------------------------------
Sha1Digest hmacSha1(const uint8_t* key, size_t keyLen,
                    const uint8_t* msg, size_t msgLen) {
  // Keys longer than the 64-byte SHA-1 block are first hashed (RFC 2104).
  uint8_t k[64] = {0};
  if (keyLen > 64) {
    Sha1Digest kd = Sha1::digest(key, keyLen);
    std::memcpy(k, kd.data(), kd.size());
  } else {
    std::memcpy(k, key, keyLen);
  }

  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; ++i) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }

  // inner = H(ipad || msg)
  Sha1 inner;
  inner.update(ipad, 64);
  inner.update(msg, msgLen);
  Sha1Digest innerDigest = inner.finish();

  // outer = H(opad || inner)
  Sha1 outer;
  outer.update(opad, 64);
  outer.update(innerDigest.data(), innerDigest.size());
  return outer.finish();
}

Sha1Digest hmacSha1(const std::string& key, const std::string& msg) {
  return hmacSha1(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                  reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA1 (single output block: dkLen == hLen == 20)
//   U1 = HMAC(P, S || INT(1)),  Ui = HMAC(P, Ui-1),  DK = U1 ^ U2 ^ ... ^ Uc
// ---------------------------------------------------------------------------
Sha1Digest pbkdf2Sha1(const std::string& password,
                      const uint8_t* salt, size_t saltLen,
                      uint32_t iterations) {
  const uint8_t* pw = reinterpret_cast<const uint8_t*>(password.data());

  // U1: salt with the big-endian block index 1 appended.
  std::vector<uint8_t> saltBlock(salt, salt + saltLen);
  saltBlock.push_back(0x00);
  saltBlock.push_back(0x00);
  saltBlock.push_back(0x00);
  saltBlock.push_back(0x01);

  Sha1Digest u = hmacSha1(pw, password.size(), saltBlock.data(), saltBlock.size());
  Sha1Digest dk = u;

  for (uint32_t i = 1; i < iterations; ++i) {
    u = hmacSha1(pw, password.size(), u.data(), u.size());
    for (size_t j = 0; j < dk.size(); ++j) dk[j] ^= u[j];
  }
  return dk;
}

// ---------------------------------------------------------------------------
// AES-256 (FIPS-197) and CTR mode (NIST SP 800-38A)
//
// Only the forward cipher is implemented: CTR mode encrypts the counter and
// XORs the result into the data, so decryption is the identical operation
// and the inverse cipher is never needed.
// ---------------------------------------------------------------------------
namespace {

// The AES S-box (FIPS-197 Figure 7): a fixed non-linear byte substitution,
// built from the multiplicative inverse in GF(2^8) plus an affine map.
const uint8_t kSbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Round constants for the key schedule: rcon[i] = x^(i-1) in GF(2^8).
const uint8_t kRcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

constexpr int kNk = 8;   // key length in 32-bit words (256 bits)
constexpr int kNr = 14;  // rounds for AES-256
constexpr int kNb = 4;   // block size in words (always 4 for AES)

// Multiply by x (0x02) in GF(2^8) modulo the AES polynomial 0x11b.
// The conditional reduction is written branchlessly so the timing does not
// depend on the data byte.
inline uint8_t xtime(uint8_t b) {
  return uint8_t((b << 1) ^ (uint8_t(0x1b) & uint8_t(-(b >> 7))));
}

// Expand the 256-bit key into Nb*(Nr+1) = 60 round-key words (FIPS-197 §5.2).
void expandKey(const Key256& key, uint8_t rk[(kNr + 1) * 16]) {
  std::memcpy(rk, key.data(), kNk * 4);  // first Nk words are the key itself

  for (int i = kNk; i < kNb * (kNr + 1); ++i) {
    uint8_t t[4] = {rk[(i - 1) * 4 + 0], rk[(i - 1) * 4 + 1],
                    rk[(i - 1) * 4 + 2], rk[(i - 1) * 4 + 3]};

    if (i % kNk == 0) {
      // RotWord, then SubWord, then XOR the round constant.
      uint8_t tmp = t[0];
      t[0] = uint8_t(kSbox[t[1]] ^ kRcon[i / kNk]);
      t[1] = kSbox[t[2]];
      t[2] = kSbox[t[3]];
      t[3] = kSbox[tmp];
    } else if (i % kNk == 4) {
      // AES-256 only: an extra SubWord every 8 words.
      for (int j = 0; j < 4; ++j) t[j] = kSbox[t[j]];
    }

    for (int j = 0; j < 4; ++j) {
      rk[i * 4 + j] = uint8_t(rk[(i - kNk) * 4 + j] ^ t[j]);
    }
  }
}

inline void addRoundKey(uint8_t st[16], const uint8_t* rk) {
  for (int i = 0; i < 16; ++i) st[i] ^= rk[i];
}

inline void subBytes(uint8_t st[16]) {
  for (int i = 0; i < 16; ++i) st[i] = kSbox[st[i]];
}

// The state is column-major: byte i sits at row i%4, column i/4.
// ShiftRows rotates row r left by r positions.
inline void shiftRows(uint8_t st[16]) {
  uint8_t t;
  // row 1 <<< 1
  t = st[1]; st[1] = st[5]; st[5] = st[9]; st[9] = st[13]; st[13] = t;
  // row 2 <<< 2
  t = st[2];  st[2]  = st[10]; st[10] = t;
  t = st[6];  st[6]  = st[14]; st[14] = t;
  // row 3 <<< 3  (equivalently >>> 1)
  t = st[15]; st[15] = st[11]; st[11] = st[7]; st[7] = st[3]; st[3] = t;
}

// Each column is multiplied by the fixed polynomial 3x^3+x^2+x+2 in GF(2^8).
inline void mixColumns(uint8_t st[16]) {
  for (int c = 0; c < 4; ++c) {
    uint8_t* p = st + c * 4;
    uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    uint8_t x = uint8_t(a0 ^ a1 ^ a2 ^ a3);
    p[0] ^= uint8_t(x ^ xtime(uint8_t(a0 ^ a1)));
    p[1] ^= uint8_t(x ^ xtime(uint8_t(a1 ^ a2)));
    p[2] ^= uint8_t(x ^ xtime(uint8_t(a2 ^ a3)));
    p[3] ^= uint8_t(x ^ xtime(uint8_t(a3 ^ a0)));
  }
}

}  // namespace

void aes256EncryptBlock(const Key256& key, const uint8_t in[16],
                        uint8_t out[16]) {
  uint8_t rk[(kNr + 1) * 16];
  expandKey(key, rk);

  uint8_t st[16];
  std::memcpy(st, in, 16);

  addRoundKey(st, rk);                       // initial round key
  for (int round = 1; round < kNr; ++round) {
    subBytes(st);
    shiftRows(st);
    mixColumns(st);
    addRoundKey(st, rk + round * 16);
  }
  subBytes(st);                              // final round omits MixColumns
  shiftRows(st);
  addRoundKey(st, rk + kNr * 16);

  std::memcpy(out, st, 16);
}

void aes256CtrXor(const Key256& key, const uint8_t counter0[16],
                  uint8_t* data, size_t len) {
  // Expand the key once for the whole message rather than per block.
  uint8_t rk[(kNr + 1) * 16];
  expandKey(key, rk);

  uint8_t ctr[16];
  std::memcpy(ctr, counter0, 16);
  uint8_t stream[16];

  size_t off = 0;
  while (off < len) {
    // Encrypt the counter block to produce the keystream.
    uint8_t st[16];
    std::memcpy(st, ctr, 16);
    addRoundKey(st, rk);
    for (int round = 1; round < kNr; ++round) {
      subBytes(st);
      shiftRows(st);
      mixColumns(st);
      addRoundKey(st, rk + round * 16);
    }
    subBytes(st);
    shiftRows(st);
    addRoundKey(st, rk + kNr * 16);
    std::memcpy(stream, st, 16);

    size_t n = (len - off < 16) ? (len - off) : 16;
    for (size_t i = 0; i < n; ++i) data[off + i] ^= stream[i];
    off += n;

    // Increment the counter block as a 128-bit big-endian integer.
    for (int i = 15; i >= 0; --i) {
      if (++ctr[i] != 0) break;  // no carry out of this byte -> done
    }
  }
}

void aes256CtrXor(const Key256& key, const std::array<uint8_t, 12>& nonce,
                  uint32_t counter, uint8_t* data, size_t len) {
  // nonce(12) || counter(4, big-endian) — the AES-GCM counter layout.
  uint8_t block[16];
  std::memcpy(block, nonce.data(), 12);
  block[12] = uint8_t(counter >> 24);
  block[13] = uint8_t(counter >> 16);
  block[14] = uint8_t(counter >> 8);
  block[15] = uint8_t(counter);
  aes256CtrXor(key, block, data, len);
}

// ---------------------------------------------------------------------------
// Key derivation (HKDF-expand style, see crypto.h)
// ---------------------------------------------------------------------------
Key256 deriveKey256(const uint8_t* secret, size_t secretLen,
                    const std::string& label) {
  std::string m1 = label;
  m1.push_back('\x01');
  std::string m2 = label;
  m2.push_back('\x02');

  Sha1Digest t1 = hmacSha1(secret, secretLen,
                           reinterpret_cast<const uint8_t*>(m1.data()), m1.size());
  Sha1Digest t2 = hmacSha1(secret, secretLen,
                           reinterpret_cast<const uint8_t*>(m2.data()), m2.size());

  Key256 out;
  std::memcpy(out.data(), t1.data(), 20);
  std::memcpy(out.data() + 20, t2.data(), 12);
  return out;
}

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------
std::vector<uint8_t> randomBytes(size_t n) {
  std::vector<uint8_t> out(n);
  int fd = ::open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    std::fprintf(stderr, "FATAL: cannot open /dev/urandom\n");
    std::abort();
  }
  size_t got = 0;
  while (got < n) {
    ssize_t r = ::read(fd, out.data() + got, n - got);
    if (r <= 0) {
      ::close(fd);
      std::fprintf(stderr, "FATAL: cannot read /dev/urandom\n");
      std::abort();
    }
    got += size_t(r);
  }
  ::close(fd);
  return out;
}

std::string randomHex(size_t nBytes) { return toHex(randomBytes(nBytes)); }

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
  // OR-accumulate every byte difference; total time is independent of where
  // (or whether) the buffers differ.
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= uint8_t(a[i] ^ b[i]);
  return diff == 0;
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  return constantTimeEquals(reinterpret_cast<const uint8_t*>(a.data()),
                            reinterpret_cast<const uint8_t*>(b.data()),
                            a.size());
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
namespace {
constexpr char kHexChars[] = "0123456789abcdef";

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
}  // namespace

std::string toHex(const uint8_t* data, size_t len) {
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHexChars[data[i] >> 4]);
    out.push_back(kHexChars[data[i] & 0x0f]);
  }
  return out;
}

std::string toHex(const Sha1Digest& d) { return toHex(d.data(), d.size()); }

std::string toHex(const std::vector<uint8_t>& v) {
  return toHex(v.data(), v.size());
}

std::vector<uint8_t> fromHex(const std::string& hex) {
  if (hex.size() % 2 != 0) return {};
  std::vector<uint8_t> out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = hexVal(hex[i]);
    int lo = hexVal(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(uint8_t((hi << 4) | lo));
  }
  return out;
}

}  // namespace p2p
