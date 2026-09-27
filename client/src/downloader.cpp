// =============================================================================
// downloader.cpp — see downloader.h for the threading/selection design.
// =============================================================================
#include "downloader.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <thread>

#include "crypto.h"
#include "file_io.h"
#include "peer_protocol.h"
#include "utils.h"

namespace p2p {

namespace {

// Pick the next piece for a worker whose peer holds `peerHas`. Caller holds
// task->m. Returns false if nothing this peer can contribute right now.
bool pickPiece(DownloadTask& task, const std::vector<bool>& peerHas,
               uint32_t& outIdx) {
  // Rarest-first: scan for the needed piece with minimum availability.
  // 2048 pieces max => a linear scan is cheaper than maintaining a heap.
  uint32_t best = UINT32_MAX;
  int bestAvail = INT32_MAX;
  int ties = 0;
  static thread_local std::mt19937 rng(std::random_device{}());

  for (uint32_t i = 0; i < task.pieceCount; ++i) {
    if (task.have[i] || task.inflight.count(i) || !peerHas[i]) continue;
    int avail = task.availability[i];
    if (avail < bestAvail) {
      bestAvail = avail;
      best = i;
      ties = 1;
    } else if (avail == bestAvail) {
      // Reservoir-sample among equal-rarity pieces: uniform random
      // tie-break without a second pass.
      if (std::uniform_int_distribution<int>(0, ties)(rng) == 0) best = i;
      ++ties;
    }
  }
  if (best == UINT32_MAX) return false;
  outIdx = best;
  task.inflight.insert(best);
  return true;
}

// Decode an MSB-first bitfield into per-piece booleans.
std::vector<bool> decodeBitfield(const std::string& bits, uint32_t pieces) {
  std::vector<bool> has(pieces, false);
  for (uint32_t i = 0; i < pieces; ++i) {
    if (i / 8 < bits.size() && (uint8_t(bits[i / 8]) & (0x80 >> (i % 8)))) {
      has[i] = true;
    }
  }
  return has;
}

const char* stateTag(DownloadTask::State s) {
  switch (s) {
    case DownloadTask::State::Downloading: return "[D]";
    case DownloadTask::State::Complete: return "[C]";
    case DownloadTask::State::Failed: return "[F]";
  }
  return "[?]";
}

}  // namespace

// ---------------------------------------------------------------------------
// startDownload — everything that must happen synchronously at the prompt.
// ---------------------------------------------------------------------------
bool Downloader::startDownload(const std::string& groupId,
                               const std::string& fileName,
                               const std::string& destArg,
                               std::string& errMsg) {
  {
    std::lock_guard<std::mutex> guard(ctx_.m);
    if (ctx_.downloads.count({groupId, fileName})) {
      errMsg = "that file is already being downloaded";
      return false;
    }
    if (ctx_.shares.count({groupId, fileName})) {
      errMsg = "you already share that file";
      return false;
    }
  }

  // Tracker: metadata + current peer list + the group transfer key.
  Message resp;
  if (!tracker_.request(cmd::kDownloadFile, {groupId, fileName}, resp,
                        errMsg)) {
    return false;
  }
  if (resp.field(0) != "0") {
    errMsg = resp.field(1);
    return false;
  }
  // Response data starts at field 2: [size, fileHash, piecesCsv, groupKey,
  // peers...]
  uint64_t size = 0;
  if (!parseU64(resp.field(2), size) || size == 0 || size > kMaxFileSize) {
    errMsg = "tracker sent invalid metadata";
    return false;
  }
  std::vector<uint8_t> fileHash = fromHex(resp.field(3));
  std::vector<std::string> pieceHex = splitChar(resp.field(4), ',');
  uint32_t pieceCount = uint32_t((size + kPieceSize - 1) / kPieceSize);
  if (fileHash.size() != 20 || pieceHex.size() != pieceCount) {
    errMsg = "tracker sent invalid metadata";
    return false;
  }
  ctx_.storeGroupKey(groupId, resp.field(5));

  std::vector<std::string> peers(resp.fields.begin() + 6, resp.fields.end());

  // Resolve destination: a directory gets the original file name appended.
  std::string dest = destArg;
  if (isDirectory(dest)) {
    if (!dest.empty() && dest.back() != '/') dest.push_back('/');
    dest += fileName;
  }

  int fd = createSized(dest, size);
  if (fd < 0) {
    errMsg = "cannot create destination file '" + dest + "'";
    return false;
  }

  // Build the task.
  auto task = std::make_shared<DownloadTask>();
  task->groupId = groupId;
  task->fileName = fileName;
  task->destPath = dest;
  task->size = size;
  task->pieceCount = pieceCount;
  task->fd = fd;
  std::copy(fileHash.begin(), fileHash.end(), task->fileHash.begin());
  task->pieceHashes.reserve(pieceCount);
  for (const auto& hx : pieceHex) {
    std::vector<uint8_t> raw = fromHex(hx);
    if (raw.size() != 20) {
      ::close(fd);
      errMsg = "tracker sent invalid piece hashes";
      return false;
    }
    Sha1Digest d;
    std::copy(raw.begin(), raw.end(), d.begin());
    task->pieceHashes.push_back(d);
  }
  task->have.assign(pieceCount, false);
  task->availability.assign(pieceCount, 0);

  {
    std::lock_guard<std::mutex> guard(ctx_.m);
    ctx_.downloads[{groupId, fileName}] = task;
  }

  // Announce ourselves as a seeder NOW (with zero pieces): other members
  // downloading the same file can immediately pull our verified pieces —
  // this is what makes a swarm of downloaders help each other.
  std::string announceErr;
  Message announceResp;
  tracker_.request(cmd::kUploadFile,
                   {groupId, fileName, std::to_string(size), resp.field(3),
                    resp.field(4)},
                   announceResp, announceErr);

  // Fire and forget: the coordinator owns the task from here.
  std::thread(&Downloader::coordinate, this, task).detach();

  std::printf("download started: %s -> %s (%u pieces, %zu peer(s))\n",
              fileName.c_str(), dest.c_str(), pieceCount, peers.size());
  std::fflush(stdout);

  // The initial peer list is deliberately not handed to the coordinator:
  // it re-queries the tracker at the start of every round, so rounds 1..N
  // share one code path and always work from a fresh view of the swarm.
  return true;
}

std::vector<std::string> Downloader::fetchPeers(const std::string& groupId,
                                                const std::string& fileName) {
  Message resp;
  std::string err;
  if (!tracker_.request(cmd::kDownloadFile, {groupId, fileName}, resp, err) ||
      resp.field(0) != "0" || resp.fields.size() < 6) {
    return {};
  }
  return std::vector<std::string>(resp.fields.begin() + 6, resp.fields.end());
}

// ---------------------------------------------------------------------------
// Coordinator: rounds of (fetch peers -> spawn workers -> join), then final
// whole-file verification.
// ---------------------------------------------------------------------------
void Downloader::coordinate(std::shared_ptr<DownloadTask> task) {
  for (int round = 0; round < kMaxDownloadRounds; ++round) {
    if (task->cancel.load()) break;
    if (task->completed.load() == task->pieceCount) break;

    std::vector<std::string> peers =
        fetchPeers(task->groupId, task->fileName);
    // Cap parallelism; the tracker already excluded ourselves.
    if (peers.size() > kMaxPeersPerDownload) {
      peers.resize(kMaxPeersPerDownload);
    }

    if (!peers.empty()) {
      std::vector<std::thread> workers;
      workers.reserve(peers.size());
      for (const auto& p : peers) {
        workers.emplace_back(&Downloader::worker, this, task, p);
      }
      for (auto& w : workers) w.join();
    }

    if (task->completed.load() == task->pieceCount) break;

    {
      std::lock_guard<std::mutex> guard(task->m);
      if (task->failures >= kMaxPieceFailures) break;
    }
    // Give departed/lagging seeders a moment before the next round.
    std::this_thread::sleep_for(std::chrono::seconds(2));
  }

  // ---- Final verdict -------------------------------------------------------
  bool ok = task->completed.load() == task->pieceCount &&
            verifyFileHash(task->fd, task->size, task->fileHash);
  ::close(task->fd);
  task->fd = -1;

  if (ok && !task->cancel.load()) {
    task->state = DownloadTask::State::Complete;
    // Promote to a full share so the seeder serves it as a normal file
    // (and keeps serving it across our partial-download bookkeeping).
    std::lock_guard<std::mutex> guard(ctx_.m);
    ctx_.shares[{task->groupId, task->fileName}] =
        ShareInfo{task->destPath, task->size, task->pieceCount};
    std::printf("\n[C] [%s] %s\n", task->groupId.c_str(),
                task->fileName.c_str());
    std::fflush(stdout);
  } else {
    task->state = DownloadTask::State::Failed;
    ::unlink(task->destPath.c_str());  // never leave a corrupt file behind
    std::printf("\n[F] [%s] %s (download failed)\n", task->groupId.c_str(),
                task->fileName.c_str());
    std::fflush(stdout);
  }
}

// ---------------------------------------------------------------------------
// Worker: one seeder connection.
// ---------------------------------------------------------------------------
void Downloader::worker(std::shared_ptr<DownloadTask> task,
                        const std::string& peerAddr) {
  // peerAddr = "user@ip:port"
  size_t at = peerAddr.find('@');
  if (at == std::string::npos) return;
  std::string ip;
  uint16_t port = 0;
  if (!parseAddr(peerAddr.substr(at + 1), ip, port)) return;

  std::vector<uint8_t> groupKey = ctx_.groupKey(task->groupId);
  if (groupKey.empty()) return;

  TcpSocket sock = TcpSocket::connectTo(ip, port);
  if (!sock.valid()) return;
  sock.setRecvTimeout(kPeerRecvTimeoutSec);
  SecureChannel chan(std::move(sock));

  // ---- Handshake: authenticate the seeder, prove ourselves ----------------
  const std::string nonceD = randomHex(kNonceLen);
  if (!chan.send(Message(MsgType::PeerHello,
                         {task->groupId, task->fileName, nonceD}))) {
    return;
  }
  Message challenge;
  if (!chan.recv(challenge) || challenge.type != MsgType::PeerChallenge ||
      challenge.fields.size() < 2) {
    return;
  }
  const std::string nonceS = challenge.field(0);
  // Verify FIRST: never send our proof to a peer that cannot prove group
  // membership itself (it could be a non-member fishing for proofs).
  if (!constantTimeEquals(challenge.field(1),
                          peerProof(groupKey, "seeder", nonceD, nonceS,
                                    task->groupId, task->fileName))) {
    logWarn("seeder " + peerAddr + " failed group authentication");
    return;
  }
  Message okMsg;
  if (!chan.send(Message(MsgType::PeerProof,
                         {peerProof(groupKey, "downloader", nonceD, nonceS,
                                    task->groupId, task->fileName)})) ||
      !chan.recv(okMsg) || okMsg.type != MsgType::PeerOk) {
    return;
  }
  chan.enableEncryption(peerChannelKey(groupKey, nonceD, nonceS),
                        /*initiator=*/true);

  // ---- Bitfield -> availability --------------------------------------------
  Message bf;
  if (!chan.send(Message(MsgType::PeerGetBitfield, {})) || !chan.recv(bf) ||
      bf.type != MsgType::PeerBitfield) {
    return;
  }
  std::vector<bool> peerHas = decodeBitfield(bf.field(0), task->pieceCount);
  {
    std::lock_guard<std::mutex> guard(task->m);
    for (uint32_t i = 0; i < task->pieceCount; ++i) {
      if (peerHas[i]) task->availability[i]++;
    }
  }

  // ---- Piece loop -----------------------------------------------------------
  while (!task->cancel.load()) {
    uint32_t idx = 0;
    {
      std::lock_guard<std::mutex> guard(task->m);
      if (task->failures >= kMaxPieceFailures) break;
      if (!pickPiece(*task, peerHas, idx)) break;  // peer exhausted
    }

    bool pieceOk = false;
    Message piece;
    if (chan.send(Message(MsgType::PeerGetPiece, {std::to_string(idx)})) &&
        chan.recv(piece) && piece.type == MsgType::PeerPiece &&
        piece.field(0) == std::to_string(idx)) {
      const std::string& data = piece.field(1);
      // Verify BEFORE writing: a corrupt piece never touches the file, and
      // the hash also authenticates content end-to-end (the tracker gave us
      // these hashes over an authenticated channel).
      if (data.size() == task->pieceLen(idx) &&
          Sha1::digest(data.data(), data.size()) == task->pieceHashes[idx]) {
        pieceOk = writePiece(task->fd, uint64_t(idx) * kPieceSize,
                             data.data(), data.size());
      }
    }

    {
      std::lock_guard<std::mutex> guard(task->m);
      task->inflight.erase(idx);
      if (pieceOk) {
        task->have[idx] = true;
        task->completed.fetch_add(1);
      } else {
        // Re-queued implicitly (still !have): another worker/round retries
        // it, preferably from a different peer.
        task->failures++;
        break;  // this peer is corrupt/broken/slow — abandon it
      }
    }
  }

  // Leaving: our view of this peer's pieces no longer contributes.
  std::lock_guard<std::mutex> guard(task->m);
  for (uint32_t i = 0; i < task->pieceCount; ++i) {
    if (peerHas[i]) task->availability[i]--;
  }
}

// ---------------------------------------------------------------------------
// show_downloads
// ---------------------------------------------------------------------------
std::string Downloader::formatDownloads() {
  std::lock_guard<std::mutex> guard(ctx_.m);
  if (ctx_.downloads.empty()) return "(no downloads)";
  std::string out;
  for (const auto& entry : ctx_.downloads) {
    const DownloadTask& t = *entry.second;
    if (!out.empty()) out.push_back('\n');
    out += stateTag(t.state.load());
    out += " [" + t.groupId + "] " + t.fileName;
    if (t.state.load() == DownloadTask::State::Downloading) {
      uint32_t done = t.completed.load();
      out += " — " + std::to_string(done * 100 / std::max(1u, t.pieceCount)) +
             "% (" + std::to_string(done) + "/" +
             std::to_string(t.pieceCount) + " pieces)";
    }
  }
  return out;
}

}  // namespace p2p
