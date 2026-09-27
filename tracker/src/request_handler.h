// =============================================================================
// request_handler.h — one client connection's session on the tracker.
//
// Each accepted client socket gets a RequestHandler running on its own
// thread. The handler owns per-connection session state (who is logged in on
// THIS connection) and drives two phases:
//
//   1. Pre-auth: only AuthRegister / AuthLoginStart handshakes are accepted.
//      The login handshake is a mutual challenge-response: the password
//      never crosses the wire, both sides prove key
//      possession, and on success the channel switches to AES-256-CTR using a
//      key derived from the password verifier + both nonces.
//
//   2. Post-auth: encrypted Request frames [command, token, args...] are
//      validated against the session token and dispatched to command logic
//      that reads/mutates TrackerState.
//
// If the socket drops while a user is logged in, the destructor path marks
// the user offline (replicated), so dead peers vanish from seeder lists.
// =============================================================================
#pragma once

#include <map>
#include <mutex>
#include <string>

#include "message.h"
#include "tracker_state.h"

namespace p2p {

class SyncManager;

// Session tokens issued by THIS tracker (token -> userId). Tokens are
// deliberately not replicated: a client that fails over to the other tracker
// re-authenticates, so session keys never leave the tracker that minted them.
class SessionTable {
 public:
  std::string create(const std::string& userId);      // returns new token
  bool lookup(const std::string& token, std::string& userId);
  void remove(const std::string& token);

 private:
  std::mutex m_;
  std::map<std::string, std::string> tokens_;
};

class RequestHandler {
 public:
  RequestHandler(TrackerState& state, SessionTable& sessions,
                 SyncManager& sync, const std::string& trackerSecret,
                 const std::string& peerAddr)
      : state_(state), sessions_(sessions), sync_(sync),
        peerAddr_(peerAddr), trackerSecret_(trackerSecret) {}

  // Serve the connection until EOF. `first` is the message the server
  // already read to route this connection here.
  void run(SecureChannel& chan, Message first);

 private:
  // --- Auth phase ---
  void handleRegister(SecureChannel& chan, const Message& m);
  bool handleLogin(SecureChannel& chan, const Message& m);  // true = logged in

  // --- Command phase ---
  Message dispatch(const Message& req);

  Message cmdCreateGroup(const std::vector<std::string>& args);
  Message cmdJoinGroup(const std::vector<std::string>& args);
  Message cmdLeaveGroup(const std::vector<std::string>& args);
  Message cmdListGroups();
  Message cmdListRequests(const std::vector<std::string>& args);
  Message cmdAcceptRequest(const std::vector<std::string>& args);
  Message cmdUploadFile(const std::vector<std::string>& args);
  Message cmdListFiles(const std::vector<std::string>& args);
  Message cmdDownloadFile(const std::vector<std::string>& args);
  Message cmdStopShare(const std::vector<std::string>& args);
  Message cmdLogout();

  // Commit a locally-validated op and push it to the peer tracker.
  void commit(const std::string& name, std::vector<std::string> args);

  // Membership check helper (caller holds the state lock).
  bool isMemberLocked(const std::string& groupId, const std::string& user);

  TrackerState& state_;
  SessionTable& sessions_;
  SyncManager& sync_;
  // Advertised to clients that reach this tracker while it is a follower,
  // so they can retry against whoever is actually leader.
  std::string peerAddr_;
  const std::string trackerSecret_;

  // Per-connection session (only touched by this connection's thread).
  std::string userId_;   // empty until login succeeds
  std::string token_;
  std::string seedAddr_; // the client's ip:port for serving pieces
};

}  // namespace p2p
