// =============================================================================
// file_io.h — piece-level file access built directly on POSIX syscalls.
//
// No high-level filesystem library is used, so this module
// uses open/fstat/read/pread/pwrite/ftruncate/close only. Two properties
// matter for correctness and memory usage:
//
//   * Streaming: hashing a 1 GiB file touches one 512 KiB buffer, never the
//     whole file.
//   * Positioned I/O: pread/pwrite carry the offset in the call itself, so
//     many threads can read/write different pieces of ONE file descriptor
//     concurrently with no seek races and no per-thread fds.
// =============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sha1.h"

namespace p2p {

// Result of hashing a local file for upload.
struct FileFingerprint {
  uint64_t size = 0;
  Sha1Digest fileHash{};
  std::vector<Sha1Digest> pieceHashes;
};

// Streaming SHA1 over the whole file + per 512 KiB piece.
// Returns false (with errMsg set) on any I/O problem.
bool fingerprintFile(const std::string& path, FileFingerprint& out,
                     std::string& errMsg);

// Open an existing file read-only; -1 on failure.
int openForRead(const std::string& path);

// Create/truncate the download destination and reserve `size` bytes so that
// pieces can be pwrite()n at their final offsets in any order.
int createSized(const std::string& path, uint64_t size);

// Positioned piece I/O. Loop internally until the full length is
// transferred (short reads/writes are legal for pread/pwrite too).
bool readPiece(int fd, uint64_t offset, void* buf, size_t len);
bool writePiece(int fd, uint64_t offset, const void* buf, size_t len);

// Verify a completed download end-to-end (streaming, from disk).
bool verifyFileHash(int fd, uint64_t size, const Sha1Digest& expected);

// true if `path` names an existing directory (used to resolve the
// download destination argument).
bool isDirectory(const std::string& path);

}  // namespace p2p
