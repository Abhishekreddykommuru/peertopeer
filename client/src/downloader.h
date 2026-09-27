// =============================================================================
// downloader.h — the multi-peer download engine.
//
// Thread anatomy of ONE download (files download concurrently because each
// gets its own coordinator):
//
//   REPL thread
//     └─ startDownload(): tracker round-trip, create+register the task,
//        announce ourselves as a (partial) seeder, then return immediately —
//        downloads never block the prompt.
//          └─ coordinator thread (detached, owns the task via shared_ptr)
//               ├─ worker thread — peer A ──┐
//               ├─ worker thread — peer B   ├─ up to kMaxPeersPerDownload
//               └─ worker thread — peer C ──┘
//
// Each worker owns one TCP connection to one seeder and loops:
//   pick a piece (rarest-first) -> request -> SHA1-verify -> pwrite -> mark.
// Workers share the task's piece table under task->m; pieces are written
// with pwrite so no two threads ever contend on a file offset.
//
// Piece selection: RAREST-FIRST among the pieces this worker's peer holds,
// with random tie-breaking. Rarest-first maximises piece diversity in the
// swarm (the piece most likely to disappear is fetched first) and the random
// tie-break decorrelates workers so they do not stampede the same seeder
// range. An `inflight` set prevents duplicate fetches of a piece.
//
// Failure model: a corrupt piece (hash mismatch) is discarded, counted, and
// re-queued so a DIFFERENT peer may pick it up. When every
// worker exits with pieces still missing, the coordinator re-queries the
// tracker for fresh peers (up to kMaxDownloadRounds) before failing the task.
// =============================================================================
#pragma once

#include <memory>
#include <string>

#include "client_context.h"
#include "tracker_client.h"

namespace p2p {

class Downloader {
 public:
  Downloader(ClientContext& ctx, TrackerClient& tracker)
      : ctx_(ctx), tracker_(tracker) {}

  // Implements `download_file <group> <file> <dest>`: validates, fetches
  // metadata + peer list from the tracker, kicks off the coordinator.
  // Returns false with errMsg set if the download could not START; once it
  // starts, progress/failure is reported via show_downloads and the
  // asynchronous completion line.
  bool startDownload(const std::string& groupId, const std::string& fileName,
                     const std::string& destArg, std::string& errMsg);

  // `show_downloads` output.
  std::string formatDownloads();

 private:
  void coordinate(std::shared_ptr<DownloadTask> task);
  void worker(std::shared_ptr<DownloadTask> task, const std::string& peerAddr);

  // Ask the tracker for the current online seeder list ("user@ip:port"...).
  std::vector<std::string> fetchPeers(const std::string& groupId,
                                      const std::string& fileName);

  ClientContext& ctx_;
  TrackerClient& tracker_;
};

}  // namespace p2p
