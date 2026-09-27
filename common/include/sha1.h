// =============================================================================
// sha1.h — Streaming SHA-1 implementation (FIPS 180-1), written from scratch.
//
// SHA-1 is used for piece and whole-file integrity, with no external
// libraries, so the algorithm is implemented here directly. The streaming
// (init / update / finish) interface is essential: it lets us hash a 1 GiB
// file 512 KiB at a time instead of loading it into memory.
//
// NOTE: SHA-1 is cryptographically broken for *collision resistance* (see
// SHAttered, 2017). It is used here for integrity against accidental
// corruption and non-adversarial error; the design
// documents discuss why production code would use SHA-256 or BLAKE3.
// =============================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace p2p {

using Sha1Digest = std::array<uint8_t, 20>;

class Sha1 {
 public:
  Sha1() { reset(); }

  // Re-initialise to the standard IV so one object can hash many inputs.
  void reset();

  // Absorb `len` bytes. May be called any number of times.
  void update(const void* data, size_t len);

  // Apply padding + length encoding and return the 160-bit digest.
  // The object must be reset() before being reused afterwards.
  Sha1Digest finish();

  // One-shot convenience for small inputs.
  static Sha1Digest digest(const void* data, size_t len);
  static Sha1Digest digest(const std::string& s) {
    return digest(s.data(), s.size());
  }

 private:
  // Compress one 64-byte block into the running state.
  void processBlock(const uint8_t* block);

  uint32_t h_[5];       // running hash state A..E
  uint64_t bitCount_;   // total message length in bits (for final padding)
  uint8_t buf_[64];     // partial-block accumulator
  size_t bufLen_;       // valid bytes currently in buf_
};

}  // namespace p2p
