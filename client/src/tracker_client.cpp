// =============================================================================
// tracker_client.cpp — see tracker_client.h.
// =============================================================================
#include "tracker_client.h"

#include "crypto.h"
#include "protocol.h"
#include "tcp_socket.h"

namespace p2p {

namespace {
// Interpret a Response frame; false if it isn't a well-formed response.
bool isResponse(const Message& m) {
  return m.type == MsgType::Response && m.fields.size() >= 2;
}

bool isNotLeader(const Message& m) {
  return isResponse(m) &&
         m.field(0) == std::to_string(int(Status::ErrNotLeader));
}
}  // namespace

bool TrackerClient::ensureConnectedLocked(std::string& errMsg) {
  if (chan_ && chan_->valid()) return true;
  chan_.reset();

  // Only the leader accepts commands, so connecting is really "find the
  // leader". Try the tracker we used last, then the other; a follower
  // answers any command with ErrNotLeader, which is our cue to move on.
  // This is why promotion needs no client reconfiguration.
  for (size_t attempt = 0; attempt < info_.ips.size(); ++attempt) {
    size_t idx = (currentTracker_ + attempt) % info_.ips.size();
    TcpSocket sock = TcpSocket::connectTo(info_.ips[idx], info_.ports[idx]);
    if (!sock.valid()) continue;
    sock.setRecvTimeout(30);

    currentTracker_ = idx;
    chan_.reset(new SecureChannel(std::move(sock)));

    // Leader probe. An unauthenticated request costs one round trip and is
    // answered before any session check: a leader says "not logged in",
    // a follower says ErrNotLeader.
    {
      Message probe(MsgType::Request, {cmd::kListGroups, std::string()});
      Message probeResp;
      if (!chan_->send(probe) || !chan_->recv(probeResp)) {
        chan_.reset();
        continue;  // dead socket
      }
      if (isNotLeader(probeResp)) {
        chan_.reset();
        errMsg = "tracker " + std::to_string(idx + 1) + " is a follower";
        continue;  // try the other one
      }
    }

    // If we held a session on the dead tracker, transparently establish a
    // fresh one here. Session tokens are deliberately per-tracker (they are
    // never replicated), so failover means re-authentication — with the
    // cached derived key, not the password.
    if (!user_.empty() && !kpw_.empty()) {
      token_.clear();
      if (!authenticateLocked(errMsg)) {
        chan_.reset();
        continue;  // maybe the OTHER tracker is healthy
      }
    }
    return true;
  }
  if (errMsg.empty() || errMsg.find("follower") == std::string::npos) {
    errMsg = "no tracker reachable";
  } else {
    errMsg = "no leader available (promote a tracker to accept writes)";
  }
  return false;
}

bool TrackerClient::registerUser(const std::string& user,
                                 const std::string& password,
                                 std::string& errMsg) {
  std::lock_guard<std::mutex> guard(m_);
  if (!ensureConnectedLocked(errMsg)) return false;

  // The verifier is derived HERE: the tracker never sees the password, only
  // salt + PBKDF2(password, salt). Note the verifier still crosses the
  // pre-auth plaintext channel — see the README's limitations.
  std::vector<uint8_t> salt = randomBytes(kSaltLen);
  Sha1Digest verifier =
      pbkdf2Sha1(password, salt.data(), salt.size(), kKdfIterations);

  Message resp;
  if (!chan_->send(Message(MsgType::AuthRegister,
                           {user, toHex(salt), std::to_string(kKdfIterations),
                            toHex(verifier)})) ||
      !chan_->recv(resp) || !isResponse(resp)) {
    chan_.reset();
    errMsg = "connection to tracker lost";
    return false;
  }
  if (resp.field(0) != "0") {
    errMsg = resp.field(1);
    return false;
  }
  return true;
}

bool TrackerClient::authenticateLocked(std::string& errMsg) {
  const std::string nonceC = randomHex(kNonceLen);
  Message challenge;
  if (!chan_->send(Message(MsgType::AuthLoginStart, {user_, nonceC, seedAddr_})) ||
      !chan_->recv(challenge)) {
    errMsg = "connection to tracker lost";
    return false;
  }
  if (challenge.type == MsgType::Response) {  // tracker-side rejection
    errMsg = challenge.field(1);
    return false;
  }
  if (challenge.type != MsgType::AuthChallenge || challenge.fields.size() < 3) {
    errMsg = "protocol error during login";
    return false;
  }

  const std::string saltHex = challenge.field(0);
  uint32_t iters = 0;
  if (!parseU32(challenge.field(1), iters)) {
    errMsg = "protocol error during login";
    return false;
  }
  const std::string nonceT = challenge.field(2);

  // Derive (or reuse) Kpw. On failover the salt is unchanged, so the cached
  // key is valid and we skip the expensive PBKDF2 — and we never kept the
  // password around to redo it anyway.
  if (kpw_.empty() || saltHex != saltHex_ || iters != iterations_) {
    errMsg = "cached credentials no longer valid; please login again";
    return false;
  }

  std::string proofMsg = "client-auth|" + user_ + "|" + nonceC + "|" + nonceT;
  std::string proof = toHex(hmacSha1(
      kpw_.data(), kpw_.size(),
      reinterpret_cast<const uint8_t*>(proofMsg.data()), proofMsg.size()));

  Message ok;
  if (!chan_->send(Message(MsgType::AuthProof, {proof})) || !chan_->recv(ok)) {
    errMsg = "connection to tracker lost";
    return false;
  }
  if (ok.type == MsgType::Response) {
    errMsg = ok.field(1);
    return false;
  }
  if (ok.type != MsgType::AuthOk || ok.fields.size() < 2) {
    errMsg = "protocol error during login";
    return false;
  }

  // Mutual authentication: verify the TRACKER's proof before trusting it.
  // A rogue "tracker" that doesn't hold the verifier database cannot
  // compute this and will be rejected here.
  std::string srvMsg = "server-auth|" + nonceT + "|" + nonceC;
  std::string expectedSrv = toHex(hmacSha1(
      kpw_.data(), kpw_.size(),
      reinterpret_cast<const uint8_t*>(srvMsg.data()), srvMsg.size()));
  if (!constantTimeEquals(ok.field(1), expectedSrv)) {
    errMsg = "tracker failed mutual authentication — refusing to proceed";
    chan_.reset();
    return false;
  }

  token_ = ok.field(0);

  // Both sides now derive the session channel key; everything after this
  // line is AES-256-CTR encrypted.
  std::string mix = nonceC + nonceT;
  Sha1Digest chanSecret = hmacSha1(
      kpw_.data(), kpw_.size(),
      reinterpret_cast<const uint8_t*>(mix.data()), mix.size());
  chan_->enableEncryption(
      deriveKey256(chanSecret.data(), chanSecret.size(), "login-chan"),
      /*initiator=*/true);
  return true;
}

bool TrackerClient::login(const std::string& user, const std::string& password,
                          std::string& errMsg) {
  std::lock_guard<std::mutex> guard(m_);
  if (loggedIn()) {
    errMsg = "already logged in as " + user_;
    return false;
  }
  if (!ensureConnectedLocked(errMsg)) return false;

  // First exchange just fetches the salt so we can derive Kpw; we then run
  // the real authentication. (AuthLoginStart is idempotent server-side.)
  const std::string probeNonce = randomHex(kNonceLen);
  Message challenge;
  if (!chan_->send(
          Message(MsgType::AuthLoginStart, {user, probeNonce, seedAddr_})) ||
      !chan_->recv(challenge)) {
    chan_.reset();
    errMsg = "connection to tracker lost";
    return false;
  }
  if (challenge.type != MsgType::AuthChallenge || challenge.fields.size() < 3) {
    errMsg = challenge.type == MsgType::Response ? challenge.field(1)
                                                 : "protocol error";
    return false;
  }

  std::vector<uint8_t> salt = fromHex(challenge.field(0));
  uint32_t iters = 0;
  if (salt.size() != kSaltLen || !parseU32(challenge.field(1), iters)) {
    errMsg = "protocol error during login";
    return false;
  }

  // The expensive part (deliberately): stretch the password.
  Sha1Digest kpw = pbkdf2Sha1(password, salt.data(), salt.size(), iters);

  // Answer the challenge we already hold.
  const std::string nonceT = challenge.field(2);
  std::string proofMsg = "client-auth|" + user + "|" + probeNonce + "|" + nonceT;
  std::string proof = toHex(hmacSha1(
      kpw.data(), kpw.size(),
      reinterpret_cast<const uint8_t*>(proofMsg.data()), proofMsg.size()));

  Message ok;
  if (!chan_->send(Message(MsgType::AuthProof, {proof})) || !chan_->recv(ok)) {
    chan_.reset();
    errMsg = "connection to tracker lost";
    return false;
  }
  if (ok.type != MsgType::AuthOk || ok.fields.size() < 2) {
    errMsg = ok.type == MsgType::Response ? ok.field(1) : "protocol error";
    return false;
  }

  std::string srvMsg = "server-auth|" + nonceT + "|" + probeNonce;
  std::string expectedSrv = toHex(hmacSha1(
      kpw.data(), kpw.size(),
      reinterpret_cast<const uint8_t*>(srvMsg.data()), srvMsg.size()));
  if (!constantTimeEquals(ok.field(1), expectedSrv)) {
    errMsg = "tracker failed mutual authentication — refusing to proceed";
    chan_.reset();
    return false;
  }

  // Success: cache the derived key (NOT the password) for failover.
  user_ = user;
  saltHex_ = challenge.field(0);
  iterations_ = iters;
  kpw_.assign(kpw.begin(), kpw.end());
  token_ = ok.field(0);

  std::string mix = probeNonce + nonceT;
  Sha1Digest chanSecret = hmacSha1(
      kpw.data(), kpw.size(),
      reinterpret_cast<const uint8_t*>(mix.data()), mix.size());
  chan_->enableEncryption(
      deriveKey256(chanSecret.data(), chanSecret.size(), "login-chan"),
      /*initiator=*/true);
  return true;
}

bool TrackerClient::request(const std::string& command,
                            const std::vector<std::string>& args,
                            Message& resp, std::string& errMsg) {
  std::lock_guard<std::mutex> guard(m_);
  if (token_.empty()) {
    errMsg = "not logged in";
    return false;
  }

  std::vector<std::string> fields;
  fields.reserve(2 + args.size());
  fields.push_back(command);
  fields.push_back(token_);
  for (const auto& a : args) fields.push_back(a);
  Message req(MsgType::Request, fields);

  // Two attempts: current connection, then reconnect+failover once. A
  // request that failed mid-flight is safe to retry — every tracker
  // mutation is validated against current state and idempotent in effect.
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (!ensureConnectedLocked(errMsg)) return false;
    // Failover re-auth minted a new token — refresh it in the frame.
    fields[1] = token_;
    Message freshReq(MsgType::Request, fields);
    if (chan_->send(freshReq) && chan_->recv(resp) && isResponse(resp)) {
      if (!isNotLeader(resp)) return true;
      // This tracker was demoted under us (the peer was promoted). Move on
      // and let the next attempt re-discover the leader.
      currentTracker_ = (currentTracker_ + 1) % info_.ips.size();
      chan_.reset();
      continue;
    }
    chan_.reset();  // dead connection — loop tries the other tracker
  }
  errMsg = "no tracker reachable";
  return false;
}

void TrackerClient::clearSession() {
  std::lock_guard<std::mutex> guard(m_);
  token_.clear();
  user_.clear();
  kpw_.clear();
  saltHex_.clear();
  chan_.reset();  // drop the connection; a new login starts clean
}

}  // namespace p2p
