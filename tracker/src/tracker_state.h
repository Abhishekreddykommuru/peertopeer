// =============================================================================
// tracker_state.h — The tracker's replicated state machine.
//
// Everything both trackers must agree on (users, groups, files, who is
// online) is mutated ONLY through operations ("ops"). An op is a named,
// self-contained, deterministic mutation:
//
//     Op{origin=1, seq=182736441, name="group_create", args=[g, owner, key]}
//
// A tracker that wants to change state:
//   1. validates the command against current state (under the state lock),
//   2. creates an op stamped with its own origin id and a monotonically
//      increasing sequence number,
//   3. applies the op locally,
//   4. appends it to the op log, from which the sync layer streams it to the
//      peer tracker (and replays history when the peer reconnects/restarts).
//
// Only the LEADER runs steps 1-4; a follower applies the stream it is sent
// and originates nothing. Because there is exactly one writer, the ops form
// a single total order and the replicas cannot diverge — there is never a
// conflict to reconcile. Per-origin sequence numbers still make delivery
// idempotent ("apply only if newer"), which is what lets a follower
// reconnect and replay from where it left off. See isLeader()/promote()
// below for the leadership rules and why failover is manual.
//
// Sequence numbers embed the process start time in the high bits
// (epoch_seconds << 20 | counter) so that a tracker which crashes, loses its
// in-memory log, and restarts can never reissue an already-used sequence
// number.
//
// Locking: one coarse mutex guards all registries. Tracker operations are
// microsecond-scale metadata updates — the piece traffic that carries real
// load never touches the tracker — so fine-grained locking would buy nothing
// measurable while introducing lock-ordering/deadlock risk. This trade-off
// is deliberate.
// =============================================================================
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "protocol.h"

namespace p2p {

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

struct UserRecord {
  std::string saltHex;      // per-user random salt (client-generated)
  uint32_t iterations = 0;  // PBKDF2 cost parameter
  std::string verifierHex;  // hex(PBKDF2(password, salt)) — never the password
};

struct GroupRecord {
  std::string ownerId;
  std::set<std::string> members;          // includes the owner
  std::vector<std::string> pending;       // join requests, FIFO order
  std::string groupKeyHex;                // 32-byte group transfer secret
};

struct FileRecord {
  uint64_t size = 0;
  std::string fileHashHex;                // SHA1 of the whole file
  std::string pieceHashesCsv;             // comma-joined per-piece SHA1 hex
  std::set<std::string> seeders;          // userIds who claim to hold pieces
};

// A replicated operation (see file header).
struct Op {
  uint32_t origin = 0;  // tracker id (1 or 2) that created the op
  uint64_t seq = 0;     // monotonically increasing per origin
  std::string name;
  std::vector<std::string> args;
};

// ---------------------------------------------------------------------------
// TrackerState
// ---------------------------------------------------------------------------
class TrackerState {
 public:
  explicit TrackerState(uint32_t myOrigin);

  // ---- Op machinery -------------------------------------------------------

  // Create an op with our origin + next sequence number, apply it, log it.
  // Caller must hold lock() — command handlers validate and emit atomically.
  Op emitLocked(const std::string& name, std::vector<std::string> args);

  // Apply an op received from the peer tracker. Ignores ops we have already
  // seen (seq <= lastApplied[origin]); logs the op for future replay so that
  // a restarted peer can recover its own history from us.
  void applyRemote(const Op& op);

  // All logged ops with seq > the given per-origin watermarks, ordered by
  // sequence number. Used for catch-up replay after (re)connection.
  std::vector<Op> opsAfter(uint64_t seenFrom1, uint64_t seenFrom2);

  // Current per-origin watermarks (what this tracker has applied).
  void watermarks(uint64_t& from1, uint64_t& from2);

  // ---- Direct read access (callers hold lock()) ---------------------------
  std::mutex& lock() { return m_; }

  std::map<std::string, UserRecord>& users() { return users_; }
  std::map<std::string, GroupRecord>& groups() { return groups_; }
  // group -> (fileName -> record)
  std::map<std::string, std::map<std::string, FileRecord>>& files() {
    return files_;
  }
  // userId -> "ip:port" the user's client seeds on. Presence == online.
  std::map<std::string, std::string>& online() { return online_; }

  uint32_t myOrigin() const { return myOrigin_; }

  // ---- Leadership ---------------------------------------------------------
  // Exactly one tracker accepts writes. A follower serves no client
  // commands at all: it applies the leader's replication stream and waits.
  // Because a follower never originates an op, conflicting writes cannot
  // exist and the two replicas cannot diverge.
  //
  // `term` is a monotonically increasing generation counter, bumped on every
  // promotion. It is how a demoted leader learns it has been replaced: any
  // node that sees a strictly higher term from its peer steps down. Without
  // it, an old leader coming back after a promotion would believe it is
  // still leader and we would be back to two writers.
  //
  // Promotion is deliberately manual. With only two trackers there is no
  // majority to establish, so a follower cannot distinguish "the leader is
  // dead" from "I cannot reach the leader" — automatic promotion would risk
  // both nodes electing themselves. Safe automatic failover needs a third
  // voter.
  bool isLeader() {
    std::lock_guard<std::mutex> g(m_);
    return leader_;
  }
  uint64_t term() {
    std::lock_guard<std::mutex> g(m_);
    return term_;
  }
  // Operator-driven failover. Returns false if already leader.
  bool promote() {
    std::lock_guard<std::mutex> g(m_);
    if (leader_) return false;
    leader_ = true;
    ++term_;
    return true;
  }
  // Called when the peer advertises a higher term: we are stale, stand down.
  bool observeTerm(uint64_t peerTerm) {
    std::lock_guard<std::mutex> g(m_);
    if (peerTerm <= term_) return false;
    term_ = peerTerm;
    bool was = leader_;
    leader_ = false;
    return was;  // true == we just lost leadership
  }
  void setInitialRole(bool leader) {
    std::lock_guard<std::mutex> g(m_);
    leader_ = leader;
    term_ = 1;
  }

 private:
  // Deterministic state transition — the ONLY place state is mutated.
  // Must be called with m_ held.
  void applyLocked(const Op& op);

  std::mutex m_;

  std::map<std::string, UserRecord> users_;
  std::map<std::string, GroupRecord> groups_;
  std::map<std::string, std::map<std::string, FileRecord>> files_;
  std::map<std::string, std::string> online_;

  bool leader_ = false;   // only the leader accepts client commands
  uint64_t term_ = 1;     // generation counter, bumped on promotion

  uint32_t myOrigin_;
  uint64_t nextSeq_;                 // next seq for ops we originate
  std::map<uint32_t, uint64_t> lastApplied_;   // per-origin watermark
  std::map<uint32_t, std::vector<Op>> log_;    // per-origin op history
};

// (De)serialise an op into SyncOp message fields and back.
std::vector<std::string> opToFields(const Op& op);
bool opFromFields(const std::vector<std::string>& fields, Op& out);

}  // namespace p2p
