// =============================================================================
// utils.h — small shared helpers (string handling, logging, config parsing).
// =============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace p2p {

// Split on any run of whitespace (command parsing).
std::vector<std::string> splitWs(const std::string& s);

// Split on a single character (e.g. comma-joined piece-hash lists).
std::vector<std::string> splitChar(const std::string& s, char sep);

// Join with a separator.
std::string join(const std::vector<std::string>& v, char sep);

// Strict string -> unsigned integer conversion; false on any junk.
bool parseU64(const std::string& s, uint64_t& out);
bool parseU32(const std::string& s, uint32_t& out);

// basename("a/b/c.txt") == "c.txt" — used to name uploaded files.
std::string baseName(const std::string& path);

// Is this string safe to use as a user id, group id or file name?
//
// Accepts 1..maxLen bytes of printable ASCII, excluding whitespace, '/' and
// '\\', and rejects "." and "..". Everything the tracker stores under a name
// eventually gets pasted into a local path or echoed to a terminal, so this
// is the one gate that has to hold:
//
//   * '/' and ".." would let an uploader pick a file name like
//     "../../.ssh/authorized_keys" that a downloader then writes to, escaping
//     the destination directory it was told to use.
//   * control bytes would let a name rewrite the terminal when it is printed
//     back in list_files output.
//
// Applied at the tracker, so it holds no matter what client sent the request.
bool isSafeName(const std::string& s, size_t maxLen = 64);

// ---------------------------------------------------------------------------
// Thread-safe timestamped logging to stderr. stderr is used so that log
// output never interleaves with the interactive REPL on stdout.
// ---------------------------------------------------------------------------
void logInfo(const std::string& msg);
void logWarn(const std::string& msg);
void logError(const std::string& msg);

// Suppress logInfo (client keeps its console clean; tracker logs verbosely).
void setQuietLogging(bool quiet);

// ---------------------------------------------------------------------------
// tracker_info.txt parsing. Format (one entry per line, '#' comments):
//
//     127.0.0.1:9000
//     127.0.0.1:9001
//     secret=<hex shared secret for tracker<->tracker authentication>
//
// The first two address lines are tracker 1 and tracker 2. The optional
// secret line is the pre-shared key that lets trackers authenticate each
// other; a compiled-in default is used (with a warning) if it is missing.
// ---------------------------------------------------------------------------
struct TrackerInfo {
  std::vector<std::string> ips;
  std::vector<uint16_t> ports;
  std::string secret;  // raw bytes (decoded from hex)
};

bool loadTrackerInfo(const std::string& path, TrackerInfo& out);

// Ignore SIGPIPE process-wide: a peer closing its socket mid-write must
// surface as an EPIPE error from send(), never kill the whole process.
void ignoreSigpipe();

}  // namespace p2p
