// =============================================================================
// utils.cpp — see utils.h.
// =============================================================================
#include "utils.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>

#include "crypto.h"
#include "tcp_socket.h"

namespace p2p {

std::vector<std::string> splitWs(const std::string& s) {
  std::vector<std::string> out;
  std::istringstream iss(s);
  std::string tok;
  while (iss >> tok) out.push_back(tok);
  return out;
}

std::vector<std::string> splitChar(const std::string& s, char sep) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == sep) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

std::string join(const std::vector<std::string>& v, char sep) {
  std::string out;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i > 0) out.push_back(sep);
    out.append(v[i]);
  }
  return out;
}

bool parseU64(const std::string& s, uint64_t& out) {
  if (s.empty() || s.size() > 20) return false;
  uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    uint64_t nv = v * 10 + uint64_t(c - '0');
    if (nv < v) return false;  // overflow
    v = nv;
  }
  out = v;
  return true;
}

bool parseU32(const std::string& s, uint32_t& out) {
  uint64_t v;
  if (!parseU64(s, v) || v > 0xffffffffull) return false;
  out = uint32_t(v);
  return true;
}

std::string baseName(const std::string& path) {
  size_t slash = path.find_last_of('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool isSafeName(const std::string& s, size_t maxLen) {
  if (s.empty() || s.size() > maxLen) return false;
  if (s == "." || s == "..") return false;
  for (char c : s) {
    unsigned char ch = (unsigned char)c;
    // Printable ASCII only: below 0x21 covers space and every control byte,
    // 0x7f is DEL, and >= 0x80 would be a multi-byte sequence we cannot
    // reason about here.
    if (ch <= 0x20 || ch >= 0x7f) return false;
    if (c == '/' || c == '\\') return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
namespace {
std::mutex gLogMutex;
bool gQuiet = false;

void logLine(const char* level, const std::string& msg) {
  // Timestamp + level prefix; single fprintf under a mutex so lines from
  // different threads never interleave mid-line.
  char ts[32];
  time_t now = time(nullptr);
  struct tm tmv;
  localtime_r(&now, &tmv);
  strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

  std::lock_guard<std::mutex> lock(gLogMutex);
  std::fprintf(stderr, "[%s] %-5s %s\n", ts, level, msg.c_str());
}
}  // namespace

void setQuietLogging(bool quiet) { gQuiet = quiet; }

void logInfo(const std::string& msg) {
  if (!gQuiet) logLine("INFO", msg);
}
void logWarn(const std::string& msg) { logLine("WARN", msg); }
void logError(const std::string& msg) { logLine("ERROR", msg); }

// ---------------------------------------------------------------------------
// tracker_info.txt
// ---------------------------------------------------------------------------
bool loadTrackerInfo(const std::string& path, TrackerInfo& out) {
  std::ifstream in(path);
  if (!in) return false;

  std::string line;
  while (std::getline(in, line)) {
    // Trim whitespace and skip blanks/comments.
    size_t b = line.find_first_not_of(" \t\r");
    if (b == std::string::npos) continue;
    size_t e = line.find_last_not_of(" \t\r");
    line = line.substr(b, e - b + 1);
    if (line.empty() || line[0] == '#') continue;

    if (line.rfind("secret=", 0) == 0) {
      std::vector<uint8_t> raw = fromHex(line.substr(7));
      if (raw.empty()) return false;
      out.secret.assign(raw.begin(), raw.end());
      continue;
    }

    std::string ip;
    uint16_t port;
    if (!parseAddr(line, ip, port)) return false;
    out.ips.push_back(ip);
    out.ports.push_back(port);
  }

  if (out.ips.size() < 2) return false;  // the design requires two trackers

  if (out.secret.empty()) {
    // A working default keeps the demo turnkey, but a real deployment must
    // set its own secret — hence the loud warning.
    logWarn("tracker_info.txt has no secret= line; using built-in default "
            "(fine for local testing, insecure for real deployments)");
    out.secret = "p2pfs-default-tracker-secret";
  }
  return true;
}

void ignoreSigpipe() { std::signal(SIGPIPE, SIG_IGN); }

}  // namespace p2p
