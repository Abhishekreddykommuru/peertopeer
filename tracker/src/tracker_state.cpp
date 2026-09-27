// =============================================================================
// tracker_state.cpp — replicated state machine (see tracker_state.h).
// =============================================================================
#include "tracker_state.h"

#include <algorithm>
#include <ctime>

#include "utils.h"

namespace p2p {

TrackerState::TrackerState(uint32_t myOrigin) : myOrigin_(myOrigin) {
  // Restart-safe sequence numbers: the high bits carry the process start
  // time, so a tracker that crashes (losing its in-memory log) and restarts
  // can never reissue a sequence number the peer has already applied.
  nextSeq_ = (uint64_t(::time(nullptr)) << 20) | 1;
  lastApplied_[1] = 0;
  lastApplied_[2] = 0;
}

Op TrackerState::emitLocked(const std::string& name,
                            std::vector<std::string> args) {
  Op op;
  op.origin = myOrigin_;
  op.seq = nextSeq_++;
  op.name = name;
  op.args = std::move(args);

  applyLocked(op);
  lastApplied_[op.origin] = op.seq;
  log_[op.origin].push_back(op);
  return op;
}

void TrackerState::applyRemote(const Op& op) {
  std::lock_guard<std::mutex> guard(m_);
  if (op.origin != 1 && op.origin != 2) return;

  // Idempotent delivery: the sync layer may replay history after a
  // reconnect; anything at or below our watermark has already been applied.
  if (op.seq <= lastApplied_[op.origin]) return;

  applyLocked(op);
  lastApplied_[op.origin] = op.seq;
  // Log remote ops too: if the peer restarts and loses its in-memory log,
  // we can replay its own history back to it.
  log_[op.origin].push_back(op);
}

std::vector<Op> TrackerState::opsAfter(uint64_t seenFrom1, uint64_t seenFrom2) {
  std::lock_guard<std::mutex> guard(m_);
  std::vector<Op> out;
  for (const auto& entry : log_) {
    uint64_t watermark = (entry.first == 1) ? seenFrom1 : seenFrom2;
    // Logs are appended in ascending seq order, so binary search works.
    const std::vector<Op>& ops = entry.second;
    auto it = std::upper_bound(
        ops.begin(), ops.end(), watermark,
        [](uint64_t w, const Op& o) { return w < o.seq; });
    out.insert(out.end(), it, ops.end());
  }
  // Sort by sequence number. Under single-leader replication only one
  // tracker originates ops, so this is already a total order and the sort is
  // a no-op in practice. Both origins are still handled because a tracker
  // keeps the ops it received from its peer as well, and replays them back if
  // that peer restarts having lost its in-memory log.
  std::sort(out.begin(), out.end(),
            [](const Op& a, const Op& b) { return a.seq < b.seq; });
  return out;
}

void TrackerState::watermarks(uint64_t& from1, uint64_t& from2) {
  std::lock_guard<std::mutex> guard(m_);
  from1 = lastApplied_[1];
  from2 = lastApplied_[2];
}

// ---------------------------------------------------------------------------
// The state transition function. Deterministic and total: it must accept any
// op that was valid at its origin, even if local state has since drifted
// (e.g. concurrent ops during a partition) — hence "best effort, never
// crash" semantics on every branch.
// ---------------------------------------------------------------------------
void TrackerState::applyLocked(const Op& op) {
  const auto& a = op.args;

  if (op.name == "user_create" && a.size() == 4) {
    // args: [userId, saltHex, iterations, verifierHex]
    uint32_t iters = 0;
    if (!parseU32(a[2], iters)) return;
    if (users_.count(a[0])) return;  // concurrent duplicate — first wins
    users_[a[0]] = UserRecord{a[1], iters, a[3]};

  } else if (op.name == "group_create" && a.size() == 3) {
    // args: [groupId, ownerId, groupKeyHex]
    if (groups_.count(a[0])) return;
    GroupRecord g;
    g.ownerId = a[1];
    g.members.insert(a[1]);
    g.groupKeyHex = a[2];
    groups_[a[0]] = std::move(g);

  } else if (op.name == "join_request" && a.size() == 2) {
    // args: [groupId, userId]
    auto it = groups_.find(a[0]);
    if (it == groups_.end()) return;
    GroupRecord& g = it->second;
    if (g.members.count(a[1])) return;
    if (std::find(g.pending.begin(), g.pending.end(), a[1]) != g.pending.end())
      return;
    g.pending.push_back(a[1]);

  } else if (op.name == "join_accept" && a.size() == 2) {
    // args: [groupId, userId]
    auto it = groups_.find(a[0]);
    if (it == groups_.end()) return;
    GroupRecord& g = it->second;
    auto p = std::find(g.pending.begin(), g.pending.end(), a[1]);
    if (p != g.pending.end()) g.pending.erase(p);
    g.members.insert(a[1]);

  } else if (op.name == "group_leave" && a.size() == 2) {
    // args: [groupId, userId]
    auto it = groups_.find(a[0]);
    if (it == groups_.end()) return;
    GroupRecord& g = it->second;
    g.members.erase(a[1]);

    // The leaver's shared files lose their seeder entry.
    auto fit = files_.find(a[0]);
    if (fit != files_.end()) {
      for (auto f = fit->second.begin(); f != fit->second.end();) {
        f->second.seeders.erase(a[1]);
        f = f->second.seeders.empty() ? fit->second.erase(f) : std::next(f);
      }
    }

    if (g.members.empty()) {
      // Last member out — the group and its file metadata disappear.
      groups_.erase(it);
      files_.erase(a[0]);
    } else if (g.ownerId == a[1]) {
      // Owner left: ownership passes to the lexicographically-first member.
      // Deterministic, so both trackers pick the same successor.
      g.ownerId = *g.members.begin();
    }

  } else if (op.name == "user_online" && a.size() == 2) {
    // args: [userId, seedAddr] — a re-login simply replaces the address.
    online_[a[0]] = a[1];

  } else if (op.name == "user_offline" && a.size() == 1) {
    online_.erase(a[0]);

  } else if (op.name == "file_share" && a.size() == 6) {
    // args: [groupId, fileName, size, fileHashHex, pieceHashesCsv, userId]
    uint64_t size = 0;
    if (!parseU64(a[2], size)) return;
    FileRecord& rec = files_[a[0]][a[1]];
    if (rec.seeders.empty()) {
      // First seeder defines the file's identity (size + hashes).
      rec.size = size;
      rec.fileHashHex = a[3];
      rec.pieceHashesCsv = a[4];
    } else if (rec.fileHashHex != a[3]) {
      // Same name, different content, raced through both trackers during a
      // partition: first registration wins, this one is dropped.
      logWarn("file_share conflict for " + a[0] + "/" + a[1] + " — ignored");
      return;
    }
    rec.seeders.insert(a[5]);

  } else if (op.name == "file_unshare" && a.size() == 3) {
    // args: [groupId, fileName, userId]
    auto git = files_.find(a[0]);
    if (git == files_.end()) return;
    auto fit = git->second.find(a[1]);
    if (fit == git->second.end()) return;
    fit->second.seeders.erase(a[2]);
    if (fit->second.seeders.empty()) git->second.erase(fit);

  } else {
    logWarn("unknown/malformed op '" + op.name + "' ignored");
  }
}

// ---------------------------------------------------------------------------
// Op <-> SyncOp message fields
// ---------------------------------------------------------------------------
std::vector<std::string> opToFields(const Op& op) {
  std::vector<std::string> f;
  f.reserve(3 + op.args.size());
  f.push_back(std::to_string(op.origin));
  f.push_back(std::to_string(op.seq));
  f.push_back(op.name);
  for (const auto& a : op.args) f.push_back(a);
  return f;
}

bool opFromFields(const std::vector<std::string>& fields, Op& out) {
  if (fields.size() < 3) return false;
  uint32_t origin;
  uint64_t seq;
  if (!parseU32(fields[0], origin) || !parseU64(fields[1], seq)) return false;
  out.origin = origin;
  out.seq = seq;
  out.name = fields[2];
  out.args.assign(fields.begin() + 3, fields.end());
  return true;
}

}  // namespace p2p
