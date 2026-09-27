// =============================================================================
// main.cpp (tracker) — process entry point.
//
//   Usage: ./tracker <tracker_info.txt> <tracker_no>
//
// Threading model:
//   * main thread          — console loop (only command: "quit")
//   * acceptor thread      — accept() loop on our listen port
//   * per-connection threads — one per client OR incoming sync connection;
//                              the first frame's type routes the connection
//                              (Auth*/Request => client, SyncHello => peer
//                              tracker). Sharing one port keeps deployment
//                              to exactly the two addresses in
//                              tracker_info.txt.
//   * sync sender thread   — outgoing replication stream (SyncManager)
//
// Thread-per-connection is a deliberate choice over epoll: the tracker
// serves at most a handful of clients whose requests are tiny metadata
// operations, so the simplicity and per-connection blocking-code clarity
// beat the scalability an event loop would add.
// =============================================================================
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "message.h"
#include "request_handler.h"
#include "sync_manager.h"
#include "tcp_socket.h"
#include "tracker_state.h"
#include "utils.h"

using namespace p2p;

namespace {

void serveConnection(TcpSocket sock, TrackerState* state,
                     SessionTable* sessions, SyncManager* sync,
                     const std::string* secret, const std::string* peerAddr) {
  SecureChannel chan(std::move(sock));
  // A silent client must not pin this thread forever.
  chan.socket().setRecvTimeout(600);

  Message first;
  if (!chan.recv(first)) return;

  if (first.type == MsgType::SyncHello) {
    // The peer tracker dialled us: run the replication responder.
    sync->serveIncoming(chan, first);
  } else {
    RequestHandler handler(*state, *sessions, *sync, *secret, *peerAddr);
    handler.run(chan, std::move(first));
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr,
                 "usage: %s <tracker_info.txt> <tracker_no>\n"
                 "  tracker 1 starts as leader, tracker 2 as follower;\n"
                 "  type 'promote' on the follower to fail over.\n",
                 argv[0]);
    return 1;
  }

  ignoreSigpipe();  // a vanished peer must never SIGPIPE-kill the tracker

  TrackerInfo info;
  if (!loadTrackerInfo(argv[1], info)) {
    std::fprintf(stderr, "error: cannot parse %s\n", argv[1]);
    return 1;
  }

  uint32_t trackerNo = 0;
  if (!parseU32(argv[2], trackerNo) || trackerNo < 1 ||
      trackerNo > info.ips.size()) {
    std::fprintf(stderr, "error: tracker_no must be 1..%zu\n",
                 info.ips.size());
    return 1;
  }
  const size_t self = trackerNo - 1;
  const size_t peer = 1 - self;  // exactly two trackers by design

  static TrackerState state(trackerNo);
  static SessionTable sessions;
  static SyncManager sync(state, info.ips[peer], info.ports[peer],
                          info.secret);
  static std::string secret = info.secret;
  static std::string peerAddr =
      info.ips[peer] + ":" + std::to_string(info.ports[peer]);

  // Tracker 1 boots as leader, tracker 2 as follower. Only the leader
  // accepts client commands, so only the leader ever originates an op.
  state.setInitialRole(/*leader=*/trackerNo == 1);

  TcpSocket listener = TcpSocket::listenOn(info.ips[self], info.ports[self]);
  if (!listener.valid()) {
    std::fprintf(stderr, "error: cannot bind %s:%u\n", info.ips[self].c_str(),
                 unsigned(info.ports[self]));
    return 1;
  }
  logInfo("tracker " + std::to_string(trackerNo) + " listening on " +
          info.ips[self] + ":" + std::to_string(info.ports[self]) +
          (state.isLeader() ? "  [LEADER]" : "  [FOLLOWER]"));
  if (!state.isLeader()) {
    logInfo("follower: serving no clients; type 'promote' to take over");
  }

  sync.start();

  // Acceptor thread: one detached handler thread per connection. Connection
  // count is bounded by the expected scale (a few clients + one peer
  // tracker), so no thread pool is needed here — unlike the client's piece
  // traffic, which is bounded explicitly.
  std::thread acceptor([&listener] {
    while (true) {
      TcpSocket conn = listener.accept();
      if (!conn.valid()) break;  // listener closed => shutting down
      std::thread(serveConnection, std::move(conn), &state, &sessions, &sync,
                  &secret, &peerAddr)
          .detach();
    }
  });

  // Console: quit, promote (manual failover), status.
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line == "quit") break;
    if (line == "status") {
      std::cout << (state.isLeader() ? "leader" : "follower")
                << ", term " << state.term() << std::endl;
    } else if (line == "promote") {
      if (state.promote()) {
        logInfo("promoted to LEADER (term " + std::to_string(state.term()) +
                ") - now accepting client commands");
        sync.notifyNewOp();  // advertise the new term to the peer at once
      } else {
        std::cout << "already leader" << std::endl;
      }
    } else if (!line.empty()) {
      std::cout << "commands: promote, status, quit" << std::endl;
    }
  }

  logInfo("tracker shutting down");
  sync.stop();
  listener.shutdownBoth();  // wakes the acceptor out of accept()
  listener.close();
  if (acceptor.joinable()) acceptor.join();
  // Connection threads are detached and blocked in recv(); the OS reclaims
  // their sockets on exit. State is in-memory only (documented limitation),
  // so there is nothing to flush.
  return 0;
}
