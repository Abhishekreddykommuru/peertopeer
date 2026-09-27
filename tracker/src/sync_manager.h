// =============================================================================
// sync_manager.h — tracker <-> tracker replication transport.
//
// Topology: each tracker maintains ONE outgoing connection to its peer and
// pushes ops on it; it receives the peer's ops on the connection the peer
// opened towards us. Two independent one-way pipes are far simpler to reason
// about than one bidirectional multiplexed link, and reconnection logic
// stays symmetric.
//
//   handshake (pre-shared secret from tracker_info.txt):
//     A -> B : SyncHello   [originA, nonceA]
//     B -> A : SyncWelcome [originB, watermark1, watermark2, nonceB, proofB]
//                proofB = HMAC(secret, "sync-resp" | nonceA | nonceB)
//     A -> B : SyncProof   [proofA]
//                proofA = HMAC(secret, "sync-init" | nonceA | nonceB)
//     both   : channel key = KDF(HMAC(secret, nonceA | nonceB), "sync-chan")
//              -> all subsequent frames AES-256-CTR encrypted
//
//   then A streams SyncOp frames: first every logged op above B's
//   watermarks (catch-up replay — this is how a partitioned or restarted
//   tracker recovers), then live ops as they are committed.
//
// The sender thread is *log-driven*: it does not consume from a fragile
// in-memory queue; it tracks "what have I sent" watermarks and reads
// anything newer straight from the op log. Losing the connection therefore
// loses nothing — the next handshake re-derives exactly what is missing.
// =============================================================================
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "message.h"
#include "tracker_state.h"

namespace p2p {

class SyncManager {
 public:
  SyncManager(TrackerState& state, std::string peerIp, uint16_t peerPort,
              std::string secret)
      : state_(state),
        peerIp_(std::move(peerIp)),
        peerPort_(peerPort),
        secret_(std::move(secret)) {}

  // Launch the outgoing sender thread (connect/handshake/stream/retry loop).
  void start();

  // Wake the sender: called after every locally-committed op.
  void notifyNewOp();

  // Handle an INCOMING sync connection (peer dialled us). Runs the responder
  // side of the handshake, then applies the streamed ops until EOF.
  // Called from the tracker server's connection thread.
  void serveIncoming(SecureChannel& chan, const Message& hello);

  void stop();

 private:
  void senderLoop();

  // One connected session: handshake + replay + live streaming.
  // Returns when the connection dies.
  void runSenderSession();

  TrackerState& state_;
  const std::string peerIp_;
  const uint16_t peerPort_;
  const std::string secret_;  // pre-shared tracker authentication key

  std::atomic<bool> stopping_{false};
  std::thread sender_;

  std::mutex cvM_;
  std::condition_variable cv_;
  uint64_t opTicket_ = 0;  // bumped by notifyNewOp(); sender waits on it
};

}  // namespace p2p
