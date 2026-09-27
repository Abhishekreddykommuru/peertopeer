// =============================================================================
// tcp_socket.h — RAII wrapper over POSIX TCP sockets.
//
// Why a wrapper instead of raw fds everywhere:
//   * RAII: the destructor closes the fd, so no code path (including
//     exceptions and early returns) can leak a socket — a hard requirement
//     descriptor is closed exactly once, on every path out of a function.
//   * Move-only semantics make fd ownership explicit and prevent the classic
//     double-close bug.
//   * sendAll/recvAll centralise the loop that handles partial send()/recv()
//     results and EINTR — TCP is a byte stream and a single call may transfer
//     fewer bytes than asked; every protocol above this layer relies on these
//     two functions for "handle partial transmissions gracefully".
// =============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace p2p {

class TcpSocket {
 public:
  TcpSocket() = default;
  explicit TcpSocket(int fd) : fd_(fd) {}
  ~TcpSocket() { close(); }

  // Move-only: exactly one owner per fd.
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;
  TcpSocket(TcpSocket&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  TcpSocket& operator=(TcpSocket&& other) noexcept;

  // --- Factory helpers -----------------------------------------------------

  // Blocking connect() to ip:port. Returns an invalid socket on failure.
  static TcpSocket connectTo(const std::string& ip, uint16_t port);

  // socket() + SO_REUSEADDR + bind() + listen(). Invalid socket on failure.
  static TcpSocket listenOn(const std::string& ip, uint16_t port,
                            int backlog = 64);

  // --- Operations ----------------------------------------------------------

  // Blocking accept(); returns invalid socket on failure/shutdown.
  TcpSocket accept() const;

  // Loop until all `len` bytes are written (handles partial send + EINTR).
  // False => peer gone or unrecoverable error.
  bool sendAll(const void* data, size_t len) const;

  // Loop until all `len` bytes are read. False on EOF/error/timeout.
  bool recvAll(void* data, size_t len) const;

  // SO_RCVTIMEO — bounds how long a peer can stall us mid-download.
  void setRecvTimeout(int seconds) const;

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }

  // Idempotent close; also called by the destructor.
  void close();

  // shutdown(SHUT_RDWR): wakes up any thread blocked in recv() on this
  // socket — the mechanism used for clean multi-threaded shutdown.
  void shutdownBoth() const;

 private:
  int fd_ = -1;
};

// "ip:port" <-> parts. Returns false if the string is malformed.
bool parseAddr(const std::string& addr, std::string& ip, uint16_t& port);

}  // namespace p2p
