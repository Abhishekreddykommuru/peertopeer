// =============================================================================
// tracker_client.h — the client's connection to the tracker system.
//
// Responsibilities:
//   * run the registration / login handshakes (client side of the mutual
//     challenge-response described in request_handler.h),
//   * carry Request/Response traffic over the encrypted session channel,
//   * transparent failover: if the current tracker dies, connect to the
//     other one and RE-AUTHENTICATE with the cached derived key, then retry
//     the in-flight request. The user never notices a tracker failure.
//
// Security note: after the first login the client caches only
// Kpw = PBKDF2(password, salt) — the password itself is wiped. Kpw is what
// failover re-authentication needs; the plaintext password is needed for
// nothing and therefore kept for nothing.
//
// Thread-safety: request() is fully serialised by an internal mutex, so the
// REPL thread and download coordinator threads can share one instance.
// =============================================================================
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "message.h"
#include "utils.h"

namespace p2p {

class TrackerClient {
 public:
  TrackerClient(TrackerInfo info, std::string seedAddr)
      : info_(std::move(info)), seedAddr_(std::move(seedAddr)) {}

  // create_user: generates salt, derives the verifier locally, registers.
  bool registerUser(const std::string& user, const std::string& password,
                    std::string& errMsg);

  // login: mutual challenge-response; on success the channel is encrypted
  // and subsequent request() calls carry the session token automatically.
  bool login(const std::string& user, const std::string& password,
             std::string& errMsg);

  // Send one command; returns false only if BOTH trackers are unreachable
  // (after failover + one retry). `resp` fields: [status, message, data...].
  bool request(const std::string& command,
               const std::vector<std::string>& args, Message& resp,
               std::string& errMsg);

  // Forget the session locally (used after a successful logout command).
  void clearSession();

  bool loggedIn() const { return !token_.empty(); }
  const std::string& userId() const { return user_; }

 private:
  // Connect to any tracker (current preferred). False if none reachable.
  bool ensureConnectedLocked(std::string& errMsg);

  // Run the login handshake on the current channel using cached Kpw.
  bool authenticateLocked(std::string& errMsg);

  TrackerInfo info_;
  std::string seedAddr_;

  std::mutex m_;
  std::unique_ptr<SecureChannel> chan_;
  size_t currentTracker_ = 0;

  // Cached credentials (populated at login; password itself is discarded).
  std::string user_;
  std::string saltHex_;
  uint32_t iterations_ = 0;
  std::vector<uint8_t> kpw_;  // 20-byte derived key / verifier
  std::string token_;
};

}  // namespace p2p
