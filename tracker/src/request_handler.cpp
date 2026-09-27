// =============================================================================
// request_handler.cpp — tracker-side session + command logic.
// =============================================================================
#include "request_handler.h"

#include <algorithm>

#include "crypto.h"
#include "sync_manager.h"
#include "utils.h"

namespace p2p {

// ---------------------------------------------------------------------------
// SessionTable
// ---------------------------------------------------------------------------
std::string SessionTable::create(const std::string& userId) {
  std::string token = randomHex(kTokenLen);
  std::lock_guard<std::mutex> guard(m_);
  tokens_[token] = userId;
  return token;
}

bool SessionTable::lookup(const std::string& token, std::string& userId) {
  std::lock_guard<std::mutex> guard(m_);
  auto it = tokens_.find(token);
  if (it == tokens_.end()) return false;
  userId = it->second;
  return true;
}

void SessionTable::remove(const std::string& token) {
  std::lock_guard<std::mutex> guard(m_);
  tokens_.erase(token);
}

// ---------------------------------------------------------------------------
// Connection loop
// ---------------------------------------------------------------------------
void RequestHandler::run(SecureChannel& chan, Message first) {
  bool haveFirst = true;
  Message m = std::move(first);

  while (true) {
    if (!haveFirst && !chan.recv(m)) break;  // EOF / error / bad frame
    haveFirst = false;

    // A follower serves nothing. Refusing every command here — not just
    // writes — is what makes divergence impossible: a follower can never
    // originate an op, so there is never a second version of the truth to
    // reconcile. The reply names the other tracker so the client can retry
    // there without being reconfigured.
    if (!state_.isLeader()) {
      chan.send(makeResponse(Status::ErrNotLeader,
                             "this tracker is a follower", {peerAddr_}));
      continue;
    }

    if (m.type == MsgType::AuthRegister) {
      handleRegister(chan, m);

    } else if (m.type == MsgType::AuthLoginStart) {
      if (!userId_.empty()) {
        chan.send(makeResponse(Status::ErrBadRequest, "already logged in"));
        continue;
      }
      handleLogin(chan, m);  // on success sets userId_/token_, encrypts chan

    } else if (m.type == MsgType::Request) {
      Message resp = dispatch(m);
      if (!chan.send(resp)) break;

    } else {
      chan.send(makeResponse(Status::ErrBadRequest, "unexpected message"));
    }
  }

  // Connection gone. If a user was logged in here, their client (and its
  // seeder) is unreachable — take them offline everywhere so other clients
  // stop being handed a dead peer.
  if (!userId_.empty()) {
    sessions_.remove(token_);
    {
      std::lock_guard<std::mutex> guard(state_.lock());
      // Only mark offline if this login is still the current one (the user
      // may have re-logged-in from a new connection in the meantime).
      auto it = state_.online().find(userId_);
      if (it != state_.online().end() && it->second == seedAddr_) {
        state_.emitLocked("user_offline", {userId_});
      }
    }
    sync_.notifyNewOp();
    logInfo("session closed: " + userId_);
  }
}

// ---------------------------------------------------------------------------
// Registration: the client sends a salted PBKDF2 verifier — the tracker
// never sees, stores, or transmits the actual password.
// ---------------------------------------------------------------------------
void RequestHandler::handleRegister(SecureChannel& chan, const Message& m) {
  const std::string& user = m.field(0);
  const std::string& saltHex = m.field(1);
  const std::string& verifierHex = m.field(3);
  uint32_t iters = 0;

  if (!isSafeName(user, kMaxNameLen) ||
      fromHex(saltHex).size() != kSaltLen ||
      !parseU32(m.field(2), iters) || iters < 1000 ||
      fromHex(verifierHex).size() != 20) {
    chan.send(makeResponse(Status::ErrBadRequest, "malformed registration"));
    return;
  }

  std::lock_guard<std::mutex> guard(state_.lock());
  if (state_.users().count(user)) {
    chan.send(makeResponse(Status::ErrExists, "user already exists"));
    return;
  }
  state_.emitLocked("user_create", {user, saltHex, m.field(2), verifierHex});
  sync_.notifyNewOp();
  logInfo("user registered: " + user);
  chan.send(makeResponse(Status::Ok, "user created"));
}

// ---------------------------------------------------------------------------
// Login: mutual challenge-response (password never on the wire).
//
//   C -> T : AuthLoginStart [user, nonceC, seedAddr]
//   T -> C : AuthChallenge  [salt, iterations, nonceT]
//   C -> T : AuthProof      [HMAC(Kpw, "client-auth"|user|nonceC|nonceT)]
//   T -> C : AuthOk         [token, HMAC(Kpw, "server-auth"|nonceT|nonceC)]
//   both   : channel key = KDF(HMAC(Kpw, nonceC|nonceT), "login-chan")
//
// where Kpw = PBKDF2(password, salt) — the stored verifier. The server proof
// authenticates the TRACKER to the client too (a fake tracker without the
// verifier database cannot produce it).
//
// For unknown users we return a plausible fake challenge (salt derived
// deterministically from the username) and fail only at the proof step, so
// an attacker cannot enumerate which usernames exist from the handshake
// shape or timing.
// ---------------------------------------------------------------------------
bool RequestHandler::handleLogin(SecureChannel& chan, const Message& m) {
  const std::string user = m.field(0);
  const std::string nonceC = m.field(1);
  const std::string seedAddr = m.field(2);

  std::string sip;
  uint16_t sport;
  if (user.empty() || nonceC.size() != kNonceLen * 2 ||
      !parseAddr(seedAddr, sip, sport)) {
    chan.send(makeResponse(Status::ErrBadRequest, "malformed login"));
    return false;
  }

  // Fetch the user's verifier — or fabricate a consistent decoy.
  std::string saltHex, verifierHex;
  uint32_t iters = kKdfIterations;
  bool realUser = false;
  {
    std::lock_guard<std::mutex> guard(state_.lock());
    auto it = state_.users().find(user);
    if (it != state_.users().end()) {
      realUser = true;
      saltHex = it->second.saltHex;
      iters = it->second.iterations;
      verifierHex = it->second.verifierHex;
    }
  }
  if (!realUser) {
    Sha1Digest fake = hmacSha1(trackerSecret_, "fake-salt|" + user);
    saltHex = toHex(fake.data(), kSaltLen);  // stable per user, looks random
  }

  const std::string nonceT = randomHex(kNonceLen);
  if (!chan.send(Message(MsgType::AuthChallenge,
                         {saltHex, std::to_string(iters), nonceT}))) {
    return false;
  }

  Message proofMsg;
  if (!chan.recv(proofMsg) || proofMsg.type != MsgType::AuthProof) {
    return false;
  }

  std::vector<uint8_t> verifier = fromHex(verifierHex);
  std::string expected;
  if (realUser && verifier.size() == 20) {
    std::string msg = "client-auth|" + user + "|" + nonceC + "|" + nonceT;
    expected = toHex(hmacSha1(verifier.data(), verifier.size(),
                              reinterpret_cast<const uint8_t*>(msg.data()),
                              msg.size()));
  } else {
    expected = std::string(40, 'x');  // unmatchable — decoy users always fail
  }

  if (!constantTimeEquals(proofMsg.field(0), expected)) {
    logWarn("failed login attempt for '" + user + "'");
    chan.send(makeResponse(Status::ErrAuth, "invalid credentials"));
    return false;
  }

  // Authenticated. Mint a session, prove ourselves back, then encrypt.
  token_ = sessions_.create(user);
  userId_ = user;
  seedAddr_ = seedAddr;

  std::string srvMsg = "server-auth|" + nonceT + "|" + nonceC;
  std::string serverProof =
      toHex(hmacSha1(verifier.data(), verifier.size(),
                     reinterpret_cast<const uint8_t*>(srvMsg.data()),
                     srvMsg.size()));
  if (!chan.send(Message(MsgType::AuthOk, {token_, serverProof}))) {
    return false;
  }

  Sha1Digest chanSecret = hmacSha1(verifier.data(), verifier.size(),
                                   reinterpret_cast<const uint8_t*>(
                                       (nonceC + nonceT).data()),
                                   nonceC.size() + nonceT.size());
  chan.enableEncryption(
      deriveKey256(chanSecret.data(), chanSecret.size(), "login-chan"),
      /*initiator=*/false);

  {
    std::lock_guard<std::mutex> guard(state_.lock());
    state_.emitLocked("user_online", {user, seedAddr});
  }
  sync_.notifyNewOp();
  logInfo("login: " + user + " seeding at " + seedAddr);
  return true;
}

// ---------------------------------------------------------------------------
// Command dispatch (post-auth, encrypted channel)
// ---------------------------------------------------------------------------
Message RequestHandler::dispatch(const Message& req) {
  const std::string& command = req.field(0);
  const std::string& token = req.field(1);

  std::string tokenUser;
  if (userId_.empty() || !sessions_.lookup(token, tokenUser) ||
      tokenUser != userId_) {
    return makeResponse(Status::ErrAuth, "not logged in");
  }

  std::vector<std::string> args(
      req.fields.begin() + std::min<size_t>(2, req.fields.size()),
      req.fields.end());

  if (command == cmd::kCreateGroup) return cmdCreateGroup(args);
  if (command == cmd::kJoinGroup) return cmdJoinGroup(args);
  if (command == cmd::kLeaveGroup) return cmdLeaveGroup(args);
  if (command == cmd::kListGroups) return cmdListGroups();
  if (command == cmd::kListRequests) return cmdListRequests(args);
  if (command == cmd::kAcceptRequest) return cmdAcceptRequest(args);
  if (command == cmd::kUploadFile) return cmdUploadFile(args);
  if (command == cmd::kListFiles) return cmdListFiles(args);
  if (command == cmd::kDownloadFile) return cmdDownloadFile(args);
  if (command == cmd::kStopShare) return cmdStopShare(args);
  if (command == cmd::kLogout) return cmdLogout();
  return makeResponse(Status::ErrBadRequest, "unknown command " + command);
}

void RequestHandler::commit(const std::string& name,
                            std::vector<std::string> args) {
  state_.emitLocked(name, std::move(args));
  sync_.notifyNewOp();
}

bool RequestHandler::isMemberLocked(const std::string& groupId,
                                    const std::string& user) {
  auto it = state_.groups().find(groupId);
  return it != state_.groups().end() && it->second.members.count(user) > 0;
}

Message RequestHandler::cmdCreateGroup(const std::vector<std::string>& args) {
  if (args.size() != 1 || !isSafeName(args[0], kMaxNameLen)) {
    return makeResponse(Status::ErrBadRequest,
                        "group id must be 1-64 printable characters, no "
                        "spaces or slashes");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  if (state_.groups().count(args[0])) {
    return makeResponse(Status::ErrExists, "group already exists");
  }
  // The group transfer key is born here: 32 random bytes that will only ever
  // be handed to authenticated group members. Knowledge of this key is what
  // a seeder later demands before serving pieces.
  commit("group_create", {args[0], userId_, randomHex(kGroupKeyLen)});
  return makeResponse(Status::Ok, "group created; you are the owner");
}

Message RequestHandler::cmdJoinGroup(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    return makeResponse(Status::ErrBadRequest, "usage: join_group <group_id>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  auto it = state_.groups().find(args[0]);
  if (it == state_.groups().end()) {
    return makeResponse(Status::ErrNotFound, "no such group");
  }
  GroupRecord& g = it->second;
  if (g.members.count(userId_)) {
    return makeResponse(Status::ErrExists, "already a member");
  }
  if (std::find(g.pending.begin(), g.pending.end(), userId_) !=
      g.pending.end()) {
    return makeResponse(Status::ErrExists, "request already pending");
  }
  commit("join_request", {args[0], userId_});
  return makeResponse(Status::Ok, "join request sent to group owner");
}

Message RequestHandler::cmdLeaveGroup(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    return makeResponse(Status::ErrBadRequest, "usage: leave_group <group_id>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  if (!isMemberLocked(args[0], userId_)) {
    return makeResponse(Status::ErrPermission, "not a member of that group");
  }
  commit("group_leave", {args[0], userId_});
  return makeResponse(Status::Ok, "left group");
}

Message RequestHandler::cmdListGroups() {
  std::lock_guard<std::mutex> guard(state_.lock());
  std::string out;
  for (const auto& g : state_.groups()) {
    if (!out.empty()) out.push_back('\n');
    out += g.first + " (owner: " + g.second.ownerId +
           ", members: " + std::to_string(g.second.members.size()) + ")";
  }
  if (out.empty()) out = "(no groups)";
  return makeResponse(Status::Ok, "", {out});
}

Message RequestHandler::cmdListRequests(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    return makeResponse(Status::ErrBadRequest,
                        "usage: list_requests <group_id>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  auto it = state_.groups().find(args[0]);
  if (it == state_.groups().end()) {
    return makeResponse(Status::ErrNotFound, "no such group");
  }
  if (it->second.ownerId != userId_) {
    return makeResponse(Status::ErrPermission, "only the owner may do that");
  }
  std::string out = join(it->second.pending, '\n');
  if (out.empty()) out = "(no pending requests)";
  return makeResponse(Status::Ok, "", {out});
}

Message RequestHandler::cmdAcceptRequest(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    return makeResponse(Status::ErrBadRequest,
                        "usage: accept_request <group_id> <user_id>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  auto it = state_.groups().find(args[0]);
  if (it == state_.groups().end()) {
    return makeResponse(Status::ErrNotFound, "no such group");
  }
  GroupRecord& g = it->second;
  if (g.ownerId != userId_) {
    return makeResponse(Status::ErrPermission, "only the owner may do that");
  }
  if (std::find(g.pending.begin(), g.pending.end(), args[1]) ==
      g.pending.end()) {
    return makeResponse(Status::ErrNotFound, "no such pending request");
  }
  commit("join_accept", {args[0], args[1]});
  return makeResponse(Status::Ok, args[1] + " added to " + args[0]);
}

// upload_file args: [groupId, fileName, size, fileHashHex, pieceHashesCsv]
// The same command doubles as the "announce" a downloader sends when it
// starts fetching a file, registering itself as an additional (partial)
// seeder — exactly how joining a BitTorrent swarm makes you a peer.
Message RequestHandler::cmdUploadFile(const std::vector<std::string>& args) {
  if (args.size() != 5) {
    return makeResponse(Status::ErrBadRequest, "malformed upload");
  }
  const std::string& group = args[0];
  const std::string& file = args[1];
  uint64_t size = 0;
  // The file name is chosen by the uploader and later appended to whatever
  // destination directory a DOWNLOADER passes to download_file. Rejecting
  // '/' and ".." here is what stops one member from naming a file
  // "../../.ssh/authorized_keys" and having every downloader write outside
  // the directory they asked for.
  if (!isSafeName(file, kMaxNameLen) || !parseU64(args[2], size) ||
      size == 0 || size > kMaxFileSize || args[3].size() != 40) {
    return makeResponse(Status::ErrBadRequest, "bad file metadata");
  }
  // Piece-count sanity: hashes must cover the claimed size exactly.
  uint64_t expectedPieces = (size + kPieceSize - 1) / kPieceSize;
  if (splitChar(args[4], ',').size() != expectedPieces) {
    return makeResponse(Status::ErrBadRequest, "piece hash count mismatch");
  }

  std::lock_guard<std::mutex> guard(state_.lock());
  if (!isMemberLocked(group, userId_)) {
    return makeResponse(Status::ErrPermission, "not a member of that group");
  }
  auto& groupFiles = state_.files()[group];
  auto it = groupFiles.find(file);
  if (it != groupFiles.end() && it->second.fileHashHex != args[3]) {
    return makeResponse(Status::ErrExists,
                        "a different file with that name is already shared");
  }
  commit("file_share", {group, file, args[2], args[3], args[4], userId_});

  // Hand the member the group transfer key over the encrypted channel —
  // they need it to authenticate to (and be authenticated by) other peers.
  return makeResponse(Status::Ok, "file shared",
                      {state_.groups()[group].groupKeyHex});
}

Message RequestHandler::cmdListFiles(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    return makeResponse(Status::ErrBadRequest, "usage: list_files <group_id>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  if (!isMemberLocked(args[0], userId_)) {
    return makeResponse(Status::ErrPermission, "not a member of that group");
  }
  std::string out;
  auto git = state_.files().find(args[0]);
  if (git != state_.files().end()) {
    for (const auto& f : git->second) {
      size_t onlineSeeders = 0;
      for (const auto& s : f.second.seeders) {
        if (state_.online().count(s)) ++onlineSeeders;
      }
      if (!out.empty()) out.push_back('\n');
      out += f.first + "  (" + std::to_string(f.second.size) + " bytes, " +
             std::to_string(onlineSeeders) + " seeder(s) online)";
    }
  }
  if (out.empty()) out = "(no files shared in this group)";
  return makeResponse(Status::Ok, "", {out});
}

// download_file args: [groupId, fileName]
// Response data: [size, fileHashHex, pieceHashesCsv, groupKeyHex,
//                 peer1 ("user@ip:port"), peer2, ...]
Message RequestHandler::cmdDownloadFile(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    return makeResponse(Status::ErrBadRequest, "malformed download request");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  if (!isMemberLocked(args[0], userId_)) {
    return makeResponse(Status::ErrPermission, "not a member of that group");
  }
  auto git = state_.files().find(args[0]);
  if (git == state_.files().end() || !git->second.count(args[1])) {
    return makeResponse(Status::ErrNotFound, "no such file in that group");
  }
  const FileRecord& rec = git->second.at(args[1]);

  std::vector<std::string> data{std::to_string(rec.size), rec.fileHashHex,
                                rec.pieceHashesCsv,
                                state_.groups()[args[0]].groupKeyHex};
  size_t peers = 0;
  for (const auto& seeder : rec.seeders) {
    if (seeder == userId_) continue;  // don't tell a client to dial itself
    auto on = state_.online().find(seeder);
    if (on == state_.online().end()) continue;  // offline — unreachable
    data.push_back(seeder + "@" + on->second);
    ++peers;
  }
  if (peers == 0) {
    return makeResponse(Status::ErrNoPeers, "no online seeders for that file");
  }
  return makeResponse(Status::Ok, "download metadata", std::move(data));
}

Message RequestHandler::cmdStopShare(const std::vector<std::string>& args) {
  if (args.size() != 2) {
    return makeResponse(Status::ErrBadRequest,
                        "usage: stop_share <group_id> <file_name>");
  }
  std::lock_guard<std::mutex> guard(state_.lock());
  auto git = state_.files().find(args[0]);
  if (git == state_.files().end() || !git->second.count(args[1]) ||
      !git->second.at(args[1]).seeders.count(userId_)) {
    return makeResponse(Status::ErrNotFound, "you are not sharing that file");
  }
  commit("file_unshare", {args[0], args[1], userId_});
  return makeResponse(Status::Ok, "stopped sharing");
}

Message RequestHandler::cmdLogout() {
  sessions_.remove(token_);
  {
    std::lock_guard<std::mutex> guard(state_.lock());
    auto it = state_.online().find(userId_);
    if (it != state_.online().end() && it->second == seedAddr_) {
      state_.emitLocked("user_offline", {userId_});
    }
  }
  sync_.notifyNewOp();
  logInfo("logout: " + userId_);
  userId_.clear();
  token_.clear();
  // NOTE: the channel stays encrypted with the old session key until the
  // client disconnects — harmless, since the session token is already dead.
  return makeResponse(Status::Ok, "logged out");
}

}  // namespace p2p
