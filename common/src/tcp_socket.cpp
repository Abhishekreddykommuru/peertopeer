// =============================================================================
// tcp_socket.cpp — see tcp_socket.h for design rationale.
// =============================================================================
#include "tcp_socket.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdlib>

namespace p2p {

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

TcpSocket TcpSocket::connectTo(const std::string& ip, uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return TcpSocket();

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return TcpSocket();
  }

  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return TcpSocket();
  }

  // Disable Nagle: our protocol is strictly request/response, and batching
  // small frames would only add latency to piece requests and handshakes.
  int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return TcpSocket(fd);
}

TcpSocket TcpSocket::listenOn(const std::string& ip, uint16_t port,
                              int backlog) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return TcpSocket();

  // SO_REUSEADDR lets the server restart immediately instead of waiting out
  // TIME_WAIT sockets from the previous run.
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (ip.empty() || ip == "0.0.0.0") {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  } else if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
    ::close(fd);
    return TcpSocket();
  }

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      ::listen(fd, backlog) != 0) {
    ::close(fd);
    return TcpSocket();
  }
  return TcpSocket(fd);
}

TcpSocket TcpSocket::accept() const {
  sockaddr_in peer{};
  socklen_t len = sizeof(peer);
  int cfd = ::accept(fd_, reinterpret_cast<sockaddr*>(&peer), &len);
  if (cfd < 0) return TcpSocket();
  int one = 1;
  ::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return TcpSocket(cfd);
}

bool TcpSocket::sendAll(const void* data, size_t len) const {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  size_t sent = 0;
  while (sent < len) {
    // MSG_NOSIGNAL is Linux-only; on macOS SIGPIPE is ignored globally
    // instead (see ignoreSigpipe() calls in both mains).
#ifdef MSG_NOSIGNAL
    ssize_t n = ::send(fd_, p + sent, len - sent, MSG_NOSIGNAL);
#else
    ssize_t n = ::send(fd_, p + sent, len - sent, 0);
#endif
    if (n < 0) {
      if (errno == EINTR) continue;  // interrupted by a signal — retry
      return false;
    }
    if (n == 0) return false;
    sent += size_t(n);
  }
  return true;
}

bool TcpSocket::recvAll(void* data, size_t len) const {
  uint8_t* p = static_cast<uint8_t*>(data);
  size_t got = 0;
  while (got < len) {
    ssize_t n = ::recv(fd_, p + got, len - got, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;  // includes EAGAIN from a receive timeout
    }
    if (n == 0) return false;  // orderly EOF — peer closed mid-message
    got += size_t(n);
  }
  return true;
}

void TcpSocket::setRecvTimeout(int seconds) const {
  timeval tv{};
  tv.tv_sec = seconds;
  ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void TcpSocket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

void TcpSocket::shutdownBoth() const {
  if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
}

bool parseAddr(const std::string& addr, std::string& ip, uint16_t& port) {
  size_t colon = addr.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= addr.size()) {
    return false;
  }
  ip = addr.substr(0, colon);
  char* end = nullptr;
  long p = std::strtol(addr.c_str() + colon + 1, &end, 10);
  if (end == nullptr || *end != '\0' || p <= 0 || p > 65535) return false;
  port = uint16_t(p);
  return true;
}

}  // namespace p2p
