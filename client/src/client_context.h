// =============================================================================
// client_context.h — state shared between the client's three subsystems
// (REPL / seeder / download engine) plus the tuning constants.
//
// Concurrency map (who touches what):
//   shares      REPL writes (upload/stop_share), seeder threads read
//   downloads   REPL creates, download workers write, seeder threads read
//   groupKeys   REPL writes (from tracker responses), seeder threads read
// All three are guarded by one context mutex; DownloadTask has its OWN finer
// mutex because piece bookkeeping is hot (touched per 512 KiB piece) while
// the context maps are touched a handful of times per command.
// =============================================================================
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "protocol.h"
#include "sha1.h"

namespace p2p {

// ---- Client tuning constants ----------------------------------------------

// Parallel peer connections per download. 4 saturates a LAN link for this
// piece size while bounding thread count and peer load.
constexpr size_t kMaxPeersPerDownload = 4;

// How long a worker waits for one piece before declaring the peer dead.
constexpr int kPeerRecvTimeoutSec = 60;

// Seeder-side idle timeout for a peer connection.
constexpr int kSeederTimeoutSec = 120;

// A download aborts after this many piece-level failures (hash mismatches +
// transport errors) — prevents an endless loop against corrupt seeders.
constexpr int kMaxPieceFailures = 50;

// How many times the coordinator re-queries the tracker for fresh peers
// before giving up on an incomplete download.
constexpr int kMaxDownloadRounds = 5;

// ---- Shared records ---------------------------------------------------------

// A fully-available file this client seeds (its own upload or a finished
// download promoted into a share).
struct ShareInfo {
  std::string path;      // where the bytes live locally
  uint64_t size = 0;
  uint32_t pieceCount = 0;
};

// One in-flight (or finished/failed) download. Lifetime is managed by
// shared_ptr: the REPL table, the coordinator thread and any seeder thread
// serving our partial pieces may all hold it concurrently.
struct DownloadTask {
  enum class State { Downloading, Complete, Failed };

  std::string groupId, fileName, destPath;
  uint64_t size = 0;
  uint32_t pieceCount = 0;
  std::vector<Sha1Digest> pieceHashes;
  Sha1Digest fileHash{};

  int fd = -1;  // destination file, opened O_RDWR for pwrite/pread

  // ---- Guarded by m ----
  std::mutex m;
  std::condition_variable cv;
  std::vector<bool> have;        // verified pieces
  std::set<uint32_t> inflight;   // pieces currently being fetched
  std::vector<int> availability; // how many connected peers hold each piece
  int failures = 0;

  std::atomic<uint32_t> completed{0};
  std::atomic<State> state{State::Downloading};
  std::atomic<bool> cancel{false};

  // Bytes of piece `idx` (the final piece may be short).
  uint64_t pieceLen(uint32_t idx) const {
    uint64_t off = uint64_t(idx) * kPieceSize;
    return (size - off < kPieceSize) ? (size - off) : kPieceSize;
  }
};

// ---- The context ------------------------------------------------------------

class ClientContext {
 public:
  using FileKey = std::pair<std::string, std::string>;  // (group, file)

  std::mutex m;
  std::map<FileKey, ShareInfo> shares;
  std::map<FileKey, std::shared_ptr<DownloadTask>> downloads;
  std::map<std::string, std::vector<uint8_t>> groupKeys;  // 32 raw bytes

  // Seeder refuses new peer handshakes while logged out ("logout ... stop
  // sharing files").
  std::atomic<bool> loggedIn{false};

  // Cache a group key delivered by the tracker (hex, over the encrypted
  // session channel).
  void storeGroupKey(const std::string& groupId, const std::string& keyHex);

  // Empty vector if we don't have the key (=> refuse peer handshake).
  std::vector<uint8_t> groupKey(const std::string& groupId);
};

}  // namespace p2p
