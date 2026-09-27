// =============================================================================
// sync_manager.cpp — see sync_manager.h for the protocol description.
// =============================================================================
#include "sync_manager.h"

#include <chrono>

#include "crypto.h"
#include "utils.h"

namespace p2p {

namespace {

// Session key for an authenticated sync channel: mix the pre-shared secret
// with both nonces so every session gets a fresh key (replaying a recorded
// session is useless), then stretch to 256 bits for AES-256.
Key256 syncChannelKey(const std::string& secret, const std::string& nonceA,
                      const std::string& nonceB) {
  Sha1Digest mixed = hmacSha1(secret, nonceA + nonceB);
  return deriveKey256(mixed.data(), mixed.size(), "sync-chan");
}

std::string syncProof(const std::string& secret, const std::string& role,
                      const std::string& nonceA, const std::string& nonceB) {
  return toHex(hmacSha1(secret, role + "|" + nonceA + "|" + nonceB));
}

constexpr int kReconnectDelaySec = 2;

}  // namespace

void SyncManager::start() {
  sender_ = std::thread([this] { senderLoop(); });
}

void SyncManager::stop() {
  stopping_ = true;
  cv_.notify_all();
  if (sender_.joinable()) sender_.detach();  // blocked in connect/recv; the
                                             // process is exiting anyway
}

void SyncManager::notifyNewOp() {
  {
    std::lock_guard<std::mutex> guard(cvM_);
    ++opTicket_;
  }
  cv_.notify_all();
}

void SyncManager::senderLoop() {
  while (!stopping_) {
    runSenderSession();
    if (stopping_) break;
    // Peer unreachable or connection dropped — keep retrying forever. The
    // system has to keep working with one tracker up and heal by itself when
    // the second comes back, so there is no retry limit and no give-up state.
    std::this_thread::sleep_for(std::chrono::seconds(kReconnectDelaySec));
  }
}

void SyncManager::runSenderSession() {
  TcpSocket sock = TcpSocket::connectTo(peerIp_, peerPort_);
  if (!sock.valid()) return;
  SecureChannel chan(std::move(sock));

  // --- Initiator handshake -------------------------------------------------
  std::string nonceA = randomHex(kNonceLen);
  if (!chan.send(Message(MsgType::SyncHello,
                         {std::to_string(state_.myOrigin()), nonceA,
                          std::to_string(state_.term())}))) {
    return;
  }

  Message welcome;
  if (!chan.recv(welcome) || welcome.type != MsgType::SyncWelcome ||
      welcome.fields.size() < 5) {
    return;
  }
  uint64_t peerSeen1 = 0, peerSeen2 = 0;
  if (!parseU64(welcome.field(1), peerSeen1) ||
      !parseU64(welcome.field(2), peerSeen2)) {
    return;
  }
  const std::string nonceB = welcome.field(3);
  uint64_t peerTerm = 0;
  parseU64(welcome.field(5), peerTerm);  // absent -> 0 -> no effect

  // Verify the peer actually knows the shared secret before trusting its
  // watermarks or sending it anything.
  if (!constantTimeEquals(welcome.field(4),
                          syncProof(secret_, "sync-resp", nonceA, nonceB))) {
    logWarn("sync: peer failed authentication — dropping connection");
    return;
  }

  if (!chan.send(Message(MsgType::SyncProof,
                         {syncProof(secret_, "sync-init", nonceA, nonceB)}))) {
    return;
  }
  chan.enableEncryption(syncChannelKey(secret_, nonceA, nonceB),
                        /*initiator=*/true);

  // If the peer is in a later term it has been promoted since we last
  // spoke and we are a stale leader. Stand down before serving anyone.
  if (state_.observeTerm(peerTerm)) {
    logWarn("sync: peer is in term " + std::to_string(peerTerm) +
            " - stepping down to FOLLOWER");
  }

  logInfo("sync: connected to peer tracker, replaying from watermarks (" +
          std::to_string(peerSeen1) + ", " + std::to_string(peerSeen2) + ")");

  // --- Stream: catch-up replay, then live ops -----------------------------
  // sent1/sent2 track what the peer now has; every iteration ships anything
  // newer that has appeared in the log.
  uint64_t sent1 = peerSeen1, sent2 = peerSeen2;
  uint64_t assertedTerm = 0;
  while (!stopping_) {
    // Promotion can happen while this connection is already up, so re-check
    // and tell the peer whenever our term advances.
    uint64_t myTerm = state_.term();
    if (myTerm != assertedTerm) {
      if (!chan.send(Message(MsgType::SyncTerm, {std::to_string(myTerm)}))) {
        return;
      }
      assertedTerm = myTerm;
    }

    std::vector<Op> batch = state_.opsAfter(sent1, sent2);
    for (const Op& op : batch) {
      if (!chan.send(Message(MsgType::SyncOp, opToFields(op)))) return;
      (op.origin == 1 ? sent1 : sent2) =
          std::max(op.origin == 1 ? sent1 : sent2, op.seq);
    }

    // Sleep until a new local op is committed (or shutdown).
    std::unique_lock<std::mutex> guard(cvM_);
    uint64_t ticket = opTicket_;
    cv_.wait_for(guard, std::chrono::seconds(5), [this, ticket] {
      return stopping_.load() || opTicket_ != ticket;
    });
    // The periodic 5 s wake-up doubles as a connection liveness probe: the
    // next opsAfter() is cheap, and a dead socket surfaces on the next send.
  }
}

void SyncManager::serveIncoming(SecureChannel& chan, const Message& hello) {
  // --- Responder handshake -------------------------------------------------
  if (hello.fields.size() < 2) return;
  const std::string nonceA = hello.field(1);
  const std::string nonceB = randomHex(kNonceLen);

  uint64_t helloTerm = 0;
  parseU64(hello.field(2), helloTerm);

  uint64_t seen1 = 0, seen2 = 0;
  state_.watermarks(seen1, seen2);

  if (!chan.send(Message(
          MsgType::SyncWelcome,
          {std::to_string(state_.myOrigin()), std::to_string(seen1),
           std::to_string(seen2), nonceB,
           syncProof(secret_, "sync-resp", nonceA, nonceB),
           std::to_string(state_.term())}))) {
    return;
  }

  Message proof;
  if (!chan.recv(proof) || proof.type != MsgType::SyncProof) return;
  if (!constantTimeEquals(proof.field(0),
                          syncProof(secret_, "sync-init", nonceA, nonceB))) {
    logWarn("sync: incoming peer failed authentication");
    return;
  }
  chan.enableEncryption(syncChannelKey(secret_, nonceA, nonceB),
                        /*initiator=*/false);
  if (state_.observeTerm(helloTerm)) {
    logWarn("sync: peer is in term " + std::to_string(helloTerm) +
            " - stepping down to FOLLOWER");
  }
  logInfo("sync: peer tracker connected (incoming)");

  // --- Apply the peer's op stream until it disconnects ---------------------
  Message m;
  while (chan.recv(m)) {
    if (m.type == MsgType::SyncTerm) {
      uint64_t t = 0;
      if (parseU64(m.field(0), t) && state_.observeTerm(t)) {
        logWarn("sync: peer promoted to term " + std::to_string(t) +
                " - stepping down to FOLLOWER");
      }
      continue;
    }
    if (m.type != MsgType::SyncOp) continue;
    Op op;
    if (opFromFields(m.fields, op)) state_.applyRemote(op);
  }
  logInfo("sync: peer tracker disconnected");
}

}  // namespace p2p
