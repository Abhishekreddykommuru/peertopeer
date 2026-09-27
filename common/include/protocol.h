// =============================================================================
// protocol.h — Wire-protocol constants shared by tracker and client.
//
// Every value that both endpoints of a connection must agree on lives here:
// message types, status codes, framing limits and the piece size. Keeping the
// contract in one header guarantees the tracker and the client can never
// drift apart silently.
// =============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

namespace p2p {

// ---------------------------------------------------------------------------
// Framing constants
// ---------------------------------------------------------------------------

// Magic number placed at the start of every frame ("P2FS" in ASCII). Lets a
// receiver immediately reject garbage / mis-routed connections instead of
// mis-parsing them.
constexpr uint32_t kWireMagic = 0x50324653;

// Protocol version. Bumped on any incompatible wire change so old binaries
// fail fast with a clear error instead of corrupting state.
constexpr uint8_t kWireVersion = 1;

// Hard upper bound on a single frame's payload. A piece transfer is the
// largest legitimate message (512 KiB piece + small metadata), so 1 MiB gives
// comfortable headroom while still protecting against memory-exhaustion from
// a hostile or corrupted length field.
constexpr uint32_t kMaxPayload = 1u << 20;

// Upper bound on fields inside one message (defensive limit only).
constexpr uint32_t kMaxFields = 8192;

// ---------------------------------------------------------------------------
// File chunking
// ---------------------------------------------------------------------------

// Piece size: files are split into exactly 512 KiB pieces; only the final
// piece may be smaller.
constexpr uint64_t kPieceSize = 512ull * 1024;

// Upper bound on a shared file (1 GiB) => at most 2048 pieces. Bounding it
// keeps the per-file piece-hash list small enough to send in one message.
constexpr uint64_t kMaxFileSize = 1ull << 30;

// Longest accepted user id, group id or file name. Short enough that a whole
// listing fits in one frame, long enough for real file names.
constexpr size_t kMaxNameLen = 64;

// ---------------------------------------------------------------------------
// Frame flags
// ---------------------------------------------------------------------------

// Payload of this frame is AES-256-CTR encrypted (set automatically by
// SecureChannel once a session key has been negotiated).
constexpr uint16_t kFlagEncrypted = 0x0001;

// Length of the HMAC-SHA1 tag appended to every encrypted frame. AES-CTR
// alone is malleable — flipping a ciphertext bit flips the same plaintext
// bit — so each encrypted frame carries an authentication tag computed over
// the header AND the ciphertext (encrypt-then-MAC). A frame whose tag does
// not verify is discarded without being decrypted.
constexpr size_t kMacLen = 20;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------
// One byte on the wire. Grouped by the conversation they belong to; gaps are
// left between groups so each can grow without renumbering.
enum class MsgType : uint8_t {
  // --- Generic request/response (client -> tracker after login) ---
  Request = 1,   // [command, sessionToken, args...]
  Response = 2,  // [statusCode, humanMessage, data...]

  // --- Authentication handshake (client -> tracker, before encryption) ---
  AuthRegister = 10,    // [userId, saltHex, iterations, verifierHex]
  AuthLoginStart = 11,  // [userId, clientNonceHex, seedListenAddr]
  AuthChallenge = 12,   // [saltHex, iterations, serverNonceHex]
  AuthProof = 13,       // [clientProofHex]
  AuthOk = 14,          // [sessionToken, serverProofHex]

  // --- Peer wire protocol (client <-> client piece transfer) ---
  PeerHello = 20,        // [groupId, fileName, downloaderNonceHex]
  PeerChallenge = 21,    // [seederNonceHex, seederProofHex]
  PeerProof = 22,        // [downloaderProofHex]
  PeerOk = 23,           // []           (channel becomes encrypted after this)
  PeerGetBitfield = 24,  // []
  PeerBitfield = 25,     // [bitfieldBytes]
  PeerGetPiece = 26,     // [pieceIndex]
  PeerPiece = 27,        // [pieceIndex, rawBytes]
  PeerError = 28,        // [statusCode, humanMessage]

  // --- Tracker <-> tracker synchronisation ---
  SyncHello = 40,    // [originId, lastSeqSeenFromYou, nonceAHex, term, role]
  SyncWelcome = 41,  // [originId, lastSeqSeenFromYou, nonceBHex, proofBHex]
  SyncProof = 42,    // [proofAHex]  (after this the sync channel is encrypted)
  SyncOp = 43,       // [originId, seq, opName, opArgs...]
  SyncTerm = 44,     // [term]  leader asserts its term; higher term wins
};

// ---------------------------------------------------------------------------
// Status codes carried in Response / PeerError messages
// ---------------------------------------------------------------------------
enum class Status : uint8_t {
  Ok = 0,
  ErrAuth = 1,        // bad credentials / invalid session / not logged in
  ErrExists = 2,      // entity already exists (user, group, file...)
  ErrNotFound = 3,    // entity does not exist
  ErrPermission = 4,  // caller is not allowed (not owner / not a member)
  ErrBadRequest = 5,  // malformed arguments
  ErrNoPeers = 6,     // no online seeder holds the requested file
  ErrInternal = 7,    // I/O failure, allocation failure, ...
  ErrNotLeader = 8,   // this tracker is a follower; data[0] = leader address
};

// ---------------------------------------------------------------------------
// Command names (field[0] of a Request). Using strings keeps the generic
// Request/Response pair extensible without touching the framing layer.
// ---------------------------------------------------------------------------
namespace cmd {
constexpr const char* kCreateGroup = "create_group";
constexpr const char* kJoinGroup = "join_group";
constexpr const char* kLeaveGroup = "leave_group";
constexpr const char* kListGroups = "list_groups";
constexpr const char* kListRequests = "list_requests";
constexpr const char* kAcceptRequest = "accept_request";
constexpr const char* kLogout = "logout";
constexpr const char* kUploadFile = "upload_file";
constexpr const char* kListFiles = "list_files";
constexpr const char* kDownloadFile = "download_file";  // metadata fetch
constexpr const char* kAnnounceHave = "announce_have";  // register as seeder
constexpr const char* kStopShare = "stop_share";
}  // namespace cmd

// ---------------------------------------------------------------------------
// Key-derivation parameters (client and tracker must agree)
// ---------------------------------------------------------------------------

// PBKDF2-HMAC-SHA1 iteration count for password hardening. High enough to
// make offline dictionary attacks expensive, low enough that login stays
// interactive (<50 ms on commodity hardware).
constexpr uint32_t kKdfIterations = 10000;

// Byte lengths used throughout the crypto layer.
constexpr size_t kSaltLen = 16;    // per-user random salt
constexpr size_t kNonceLen = 16;   // handshake nonces
constexpr size_t kTokenLen = 16;   // session tokens (128-bit)
constexpr size_t kGroupKeyLen = 32;  // per-group transfer secret

}  // namespace p2p
