// =============================================================================
// seeder.cpp — see seeder.h.
// =============================================================================
#include "seeder.h"

#include <unistd.h>

#include <algorithm>
#include <memory>

#include "file_io.h"
#include "peer_protocol.h"
#include "utils.h"

namespace p2p {

namespace {

// What the seeder knows about one requested (group, file): where the bytes
// are and which pieces are safe to serve.
struct ServeSource {
  std::string path;
  uint64_t size = 0;
  uint32_t pieceCount = 0;
  std::shared_ptr<DownloadTask> partial;  // set iff serving a live download

  bool hasPiece(uint32_t idx) {
    if (!partial) return true;  // full share: everything available
    std::lock_guard<std::mutex> guard(partial->m);
    return idx < partial->have.size() && partial->have[idx];
  }
};

// MSB-first bitfield, one bit per piece (BitTorrent convention).
std::string buildBitfield(ServeSource& src) {
  std::string bits((src.pieceCount + 7) / 8, '\0');
  for (uint32_t i = 0; i < src.pieceCount; ++i) {
    if (src.hasPiece(i)) bits[i / 8] |= char(0x80 >> (i % 8));
  }
  return bits;
}

}  // namespace

bool Seeder::start(const std::string& ip, uint16_t port) {
  listener_ = TcpSocket::listenOn(ip, port);
  if (!listener_.valid()) return false;
  acceptor_ = std::thread([this] { acceptLoop(); });
  logInfo("seeder listening on " + ip + ":" + std::to_string(port));
  return true;
}

void Seeder::stop() {
  stopping_ = true;
  listener_.shutdownBoth();
  listener_.close();
  if (acceptor_.joinable()) acceptor_.join();
}

void Seeder::acceptLoop() {
  while (!stopping_) {
    TcpSocket conn = listener_.accept();
    if (!conn.valid()) break;  // listener closed
    if (activeConns_.load() >= kMaxConns) continue;  // shed load: drop conn
    ++activeConns_;
    std::thread([this](TcpSocket s) {
      serve(std::move(s));
      --activeConns_;
    }, std::move(conn)).detach();
  }
}

void Seeder::serve(TcpSocket sock) {
  sock.setRecvTimeout(kSeederTimeoutSec);
  SecureChannel chan(std::move(sock));

  // ---- Handshake (see peer_protocol.h) ------------------------------------
  Message hello;
  if (!chan.recv(hello) || hello.type != MsgType::PeerHello ||
      hello.fields.size() < 3) {
    return;
  }
  const std::string group = hello.field(0);
  const std::string file = hello.field(1);
  const std::string nonceD = hello.field(2);

  // Refuse everything while logged out: "logout ... stop sharing files".
  if (!ctx_.loggedIn.load()) {
    chan.send(Message(MsgType::PeerError,
                      {std::to_string(int(Status::ErrPermission)),
                       "peer is not logged in"}));
    return;
  }

  // Locate the bytes: full share first, then live download (partial seed).
  ServeSource src;
  {
    std::lock_guard<std::mutex> guard(ctx_.m);
    auto sit = ctx_.shares.find({group, file});
    if (sit != ctx_.shares.end()) {
      src.path = sit->second.path;
      src.size = sit->second.size;
      src.pieceCount = sit->second.pieceCount;
    } else {
      auto dit = ctx_.downloads.find({group, file});
      if (dit != ctx_.downloads.end() &&
          dit->second->state.load() != DownloadTask::State::Failed) {
        src.partial = dit->second;
        src.path = dit->second->destPath;
        src.size = dit->second->size;
        src.pieceCount = dit->second->pieceCount;
      }
    }
  }
  std::vector<uint8_t> groupKey = ctx_.groupKey(group);
  if (src.path.empty() || groupKey.empty()) {
    chan.send(Message(MsgType::PeerError,
                      {std::to_string(int(Status::ErrNotFound)),
                       "file not available here"}));
    return;
  }

  // Challenge the downloader; prove ourselves in the same message.
  const std::string nonceS = randomHex(kNonceLen);
  if (!chan.send(Message(
          MsgType::PeerChallenge,
          {nonceS, peerProof(groupKey, "seeder", nonceD, nonceS, group, file)}))) {
    return;
  }

  Message proof;
  if (!chan.recv(proof) || proof.type != MsgType::PeerProof) return;
  if (!constantTimeEquals(
          proof.field(0),
          peerProof(groupKey, "downloader", nonceD, nonceS, group, file))) {
    logWarn("peer failed group authentication for " + group + "/" + file);
    chan.send(Message(MsgType::PeerError,
                      {std::to_string(int(Status::ErrAuth)),
                       "group authentication failed"}));
    return;
  }
  if (!chan.send(Message(MsgType::PeerOk, {}))) return;
  chan.enableEncryption(peerChannelKey(groupKey, nonceD, nonceS),
                        /*initiator=*/false);

  // ---- Serve requests ------------------------------------------------------
  int fd = openForRead(src.path);
  if (fd < 0) return;

  std::unique_ptr<uint8_t[]> buf(new uint8_t[kPieceSize]);
  Message req;
  while (chan.recv(req)) {
    if (req.type == MsgType::PeerGetBitfield) {
      // Rebuilt per request: an in-progress download gains pieces over
      // time, and downloaders may re-poll to discover them.
      if (!chan.send(Message(MsgType::PeerBitfield, {buildBitfield(src)})))
        break;

    } else if (req.type == MsgType::PeerGetPiece) {
      uint32_t idx = 0;
      if (!parseU32(req.field(0), idx) || idx >= src.pieceCount ||
          !src.hasPiece(idx)) {
        if (!chan.send(Message(MsgType::PeerError,
                               {std::to_string(int(Status::ErrNotFound)),
                                "piece not available"})))
          break;
        continue;
      }
      uint64_t offset = uint64_t(idx) * kPieceSize;
      uint64_t len = std::min<uint64_t>(kPieceSize, src.size - offset);
      if (!readPiece(fd, offset, buf.get(), size_t(len))) {
        chan.send(Message(MsgType::PeerError,
                          {std::to_string(int(Status::ErrInternal)),
                           "local read failed"}));
        break;
      }
      if (!chan.send(Message(
              MsgType::PeerPiece,
              {req.field(0),
               std::string(reinterpret_cast<char*>(buf.get()), size_t(len))})))
        break;

    } else {
      break;  // protocol violation — drop the connection
    }
  }
  ::close(fd);
}

}  // namespace p2p
