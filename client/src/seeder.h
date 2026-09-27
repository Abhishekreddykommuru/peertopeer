// =============================================================================
// seeder.h — the client's upload side: serve pieces to other peers.
//
// Runs from client startup (its address is what login registers with the
// tracker). One acceptor thread; one detached thread per peer connection,
// bounded by a simple connection counter so a flood of peers cannot exhaust
// threads/fds.
//
// A seeder serves a piece if EITHER
//   * the file is a full local share (our own upload / promoted download), or
//   * it is an in-progress download and we already hold that verified piece
//     — this "partial seeding" is what turns a swarm of downloaders into
//     each other's sources, exactly like BitTorrent.
// =============================================================================
#pragma once

#include <atomic>
#include <string>
#include <thread>

#include "client_context.h"
#include "message.h"
#include "tcp_socket.h"

namespace p2p {

class Seeder {
 public:
  explicit Seeder(ClientContext& ctx) : ctx_(ctx) {}

  // Bind + start the acceptor thread. False if the address is unusable.
  bool start(const std::string& ip, uint16_t port);

  void stop();

 private:
  void acceptLoop();
  void serve(TcpSocket sock);  // one peer connection, start to finish

  ClientContext& ctx_;
  TcpSocket listener_;
  std::thread acceptor_;
  std::atomic<bool> stopping_{false};
  std::atomic<int> activeConns_{0};

  // Ceiling on concurrent peer connections (threads + fds are finite).
  static constexpr int kMaxConns = 64;
};

}  // namespace p2p
