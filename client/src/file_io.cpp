// =============================================================================
// file_io.cpp — see file_io.h.
// =============================================================================
#include "file_io.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <memory>

#include "protocol.h"

namespace p2p {

bool fingerprintFile(const std::string& path, FileFingerprint& out,
                     std::string& errMsg) {
  int fd = ::open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    errMsg = std::string("cannot open '") + path + "': " + strerror(errno);
    return false;
  }

  struct stat st{};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    errMsg = "'" + path + "' is not a regular file";
    ::close(fd);
    return false;
  }
  out.size = uint64_t(st.st_size);
  if (out.size == 0 || out.size > kMaxFileSize) {
    errMsg = "file size must be between 1 byte and 1 GiB";
    ::close(fd);
    return false;
  }

  // One pass over the file computes both hash levels: each read() chunk is
  // fed to the whole-file hasher and to the current piece hasher.
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kPieceSize]);
  Sha1 whole, piece;
  uint64_t pieceFill = 0;

  uint64_t remaining = out.size;
  while (remaining > 0) {
    size_t want = size_t(std::min<uint64_t>(kPieceSize - pieceFill, remaining));
    ssize_t n = ::read(fd, buf.get(), want);
    if (n < 0) {
      if (errno == EINTR) continue;
      errMsg = std::string("read failed: ") + strerror(errno);
      ::close(fd);
      return false;
    }
    if (n == 0) {  // file shrank underneath us
      errMsg = "file changed while hashing";
      ::close(fd);
      return false;
    }
    whole.update(buf.get(), size_t(n));
    piece.update(buf.get(), size_t(n));
    pieceFill += uint64_t(n);
    remaining -= uint64_t(n);

    if (pieceFill == kPieceSize || remaining == 0) {
      out.pieceHashes.push_back(piece.finish());
      piece.reset();
      pieceFill = 0;
    }
  }

  out.fileHash = whole.finish();
  ::close(fd);
  return true;
}

int openForRead(const std::string& path) {
  return ::open(path.c_str(), O_RDONLY);
}

int createSized(const std::string& path, uint64_t size) {
  int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) return -1;
  // Reserve the full length up front: pieces then land at their final
  // offsets in whatever order the peers deliver them. (On most filesystems
  // this creates a sparse file, so no real 1 GiB write happens here.)
  if (::ftruncate(fd, off_t(size)) != 0) {
    ::close(fd);
    ::unlink(path.c_str());
    return -1;
  }
  return fd;
}

bool readPiece(int fd, uint64_t offset, void* buf, size_t len) {
  uint8_t* p = static_cast<uint8_t*>(buf);
  size_t got = 0;
  while (got < len) {
    ssize_t n = ::pread(fd, p + got, len - got, off_t(offset + got));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;  // unexpected EOF
    got += size_t(n);
  }
  return true;
}

bool writePiece(int fd, uint64_t offset, const void* buf, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(buf);
  size_t put = 0;
  while (put < len) {
    ssize_t n = ::pwrite(fd, p + put, len - put, off_t(offset + put));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    put += size_t(n);
  }
  return true;
}

bool verifyFileHash(int fd, uint64_t size, const Sha1Digest& expected) {
  std::unique_ptr<uint8_t[]> buf(new uint8_t[kPieceSize]);
  Sha1 h;
  uint64_t off = 0;
  while (off < size) {
    size_t want = size_t(std::min<uint64_t>(kPieceSize, size - off));
    if (!readPiece(fd, off, buf.get(), want)) return false;
    h.update(buf.get(), want);
    off += want;
  }
  return h.finish() == expected;
}

bool isDirectory(const std::string& path) {
  struct stat st{};
  return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

}  // namespace p2p
