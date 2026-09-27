// =============================================================================
// main.cpp (client) — REPL and command dispatch.
//
//   Usage: ./client <IP>:<PORT> <tracker_info.txt>
//
// <IP>:<PORT> is THIS client's seeding address: the port other peers connect
// to for pieces, registered with the tracker at login.
//
// Threading model:
//   * main thread            — the interactive prompt (this file)
//   * seeder acceptor thread — + one detached thread per serving connection
//   * per download           — one coordinator + up to 4 worker threads
// The REPL never blocks on a download; progress is polled via
// show_downloads and completion prints asynchronously as "[C] [group] file".
// =============================================================================
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "client_context.h"
#include "crypto.h"
#include "downloader.h"
#include "file_io.h"
#include "protocol.h"
#include "seeder.h"
#include "tracker_client.h"
#include "utils.h"

using namespace p2p;

namespace {

// The terminal is in canonical ("cooked") mode and we read with getline, so
// the kernel's line discipline handles backspace for us — but ONLY while the
// line is still being typed. Anything that survives into the string is a
// control byte the discipline did not consume: a literal ^H typed as Ctrl-V
// Ctrl-H, an arrow key (ESC [ A), a pasted newline, or input arriving from a
// pipe where there is no line discipline at all.
//
// Those bytes are invisible trouble. A stray ^H makes the terminal move its
// cursor back when we echo the command in an error message, so the screen
// shows "create_useice" while the bytes are "create_user\bice" — the command
// looks right and fails anyway. Strip them before parsing, so what the user
// sees is what the client acts on.
//
// Returns the number of bytes removed, so the caller can say something.
size_t stripControlBytes(std::string& s) {
  std::string clean;
  clean.reserve(s.size());
  size_t removed = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    unsigned char ch = (unsigned char)s[i];
    // CSI / SS3 escape sequence from an arrow or function key: ESC followed
    // by '[' or 'O', then parameter bytes, ended by a final byte in @-~.
    if (ch == 0x1b) {
      ++removed;
      if (i + 1 < s.size() && (s[i + 1] == '[' || s[i + 1] == 'O')) {
        i += 2;
        while (i < s.size() && (unsigned char)s[i] < 0x40) ++i;
      }
      continue;
    }
    // Tabs become spaces (splitWs treats them as separators anyway); every
    // other C0 control byte and DEL is dropped. Bytes >= 0x80 are kept so
    // UTF-8 file names still work.
    if (ch == '\t') {
      clean.push_back(' ');
    } else if (ch < 0x20 || ch == 0x7f) {
      ++removed;
    } else {
      clean.push_back((char)ch);
    }
  }
  s.swap(clean);
  return removed;
}

// Commands are accepted both as two words ("create user") and joined with an
// underscore ("create_user"), because both spellings are in common use.
// Merge the known two-word verbs into their underscore form.
std::vector<std::string> normalize(std::vector<std::string> tok) {
  static const std::vector<std::pair<std::string, std::string>> kPairs = {
      {"create", "user"},    {"create", "group"},   {"join", "group"},
      {"leave", "group"},    {"list", "groups"},    {"list", "requests"},
      {"accept", "request"}, {"upload", "file"},    {"list", "files"},
      {"download", "file"},  {"show", "downloads"}, {"stop", "share"},
  };
  if (tok.size() >= 2) {
    for (const auto& p : kPairs) {
      if (tok[0] == p.first && tok[1] == p.second) {
        tok[0] += "_" + tok[1];
        tok.erase(tok.begin() + 1);
        break;
      }
    }
  }
  return tok;
}

// Print a tracker Response: data fields (if any) else the status text.
void printResponse(const Message& resp) {
  if (resp.field(0) != "0") {
    std::printf("error: %s\n", resp.field(1).c_str());
    return;
  }
  if (resp.fields.size() > 2) {
    std::printf("%s\n", resp.field(2).c_str());
  } else {
    std::printf("%s\n",
                resp.field(1).empty() ? "ok" : resp.field(1).c_str());
  }
}

void printUsage() {
  std::printf(
      "commands:\n"
      "  create_user <user> <password>\n"
      "  login <user> <password>\n"
      "  create_group <group> | join_group <group> | leave_group <group>\n"
      "  list_groups | list_requests <group> | accept_request <group> <user>\n"
      "  upload_file <group> <path> | list_files <group>\n"
      "  download_file <group> <file> <dest> | show_downloads\n"
      "  stop_share <group> <file> | logout | quit\n");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s <IP>:<PORT> <tracker_info.txt>\n",
                 argv[0]);
    return 1;
  }

  ignoreSigpipe();
  setQuietLogging(true);  // keep the interactive console clean

  std::string seedIp;
  uint16_t seedPort = 0;
  if (!parseAddr(argv[1], seedIp, seedPort)) {
    std::fprintf(stderr, "error: bad address '%s' (expected IP:PORT)\n",
                 argv[1]);
    return 1;
  }

  TrackerInfo info;
  if (!loadTrackerInfo(argv[2], info)) {
    std::fprintf(stderr, "error: cannot parse %s\n", argv[2]);
    return 1;
  }

  static ClientContext ctx;
  static Seeder seeder(ctx);
  if (!seeder.start(seedIp, seedPort)) {
    std::fprintf(stderr, "error: cannot listen on %s (port in use?)\n",
                 argv[1]);
    return 1;
  }

  TrackerClient tracker(info, argv[1]);
  Downloader downloader(ctx, tracker);

  std::printf("p2p client ready — seeding address %s (type 'help')\n",
              argv[1]);

  std::string line;
  while (std::printf("> "), std::fflush(stdout),
         std::getline(std::cin, line)) {
    // Do this before anything looks at the line: a command carrying an
    // invisible control byte would otherwise fail in a way that is very hard
    // to see, because the terminal renders the byte instead of showing it.
    if (size_t dropped = stripControlBytes(line)) {
      std::printf("note: ignored %zu control character(s) in that line\n",
                  dropped);
    }
    std::vector<std::string> tok = normalize(splitWs(line));
    if (tok.empty()) continue;
    const std::string& c = tok[0];
    std::string err;

    // ---- Session commands (handled by TrackerClient directly) ------------
    if (c == "create_user") {
      if (tok.size() != 3) { std::printf("usage: create_user <user> <password>\n"); continue; }
      if (tracker.registerUser(tok[1], tok[2], err)) {
        std::printf("user created\n");
      } else {
        std::printf("error: %s\n", err.c_str());
      }

    } else if (c == "login") {
      if (tok.size() != 3) { std::printf("usage: login <user> <password>\n"); continue; }
      if (tracker.login(tok[1], tok[2], err)) {
        ctx.loggedIn = true;
        std::printf("logged in as %s (session channel encrypted)\n",
                    tok[1].c_str());
      } else {
        std::printf("error: %s\n", err.c_str());
      }

    } else if (c == "logout") {
      Message resp;
      if (tracker.request(cmd::kLogout, {}, resp, err)) printResponse(resp);
      else std::printf("error: %s\n", err.c_str());
      ctx.loggedIn = false;      // seeder stops accepting new peers
      tracker.clearSession();

    // ---- Simple pass-through commands -------------------------------------
    } else if (c == "create_group" || c == "join_group" ||
               c == "leave_group" || c == "list_requests" ||
               c == "list_files") {
      if (tok.size() != 2) { std::printf("usage: %s <group_id>\n", c.c_str()); continue; }
      Message resp;
      if (tracker.request(c, {tok[1]}, resp, err)) printResponse(resp);
      else std::printf("error: %s\n", err.c_str());

    } else if (c == "list_groups") {
      Message resp;
      if (tracker.request(c, {}, resp, err)) printResponse(resp);
      else std::printf("error: %s\n", err.c_str());

    } else if (c == "accept_request") {
      if (tok.size() != 3) { std::printf("usage: accept_request <group_id> <user_id>\n"); continue; }
      Message resp;
      if (tracker.request(c, {tok[1], tok[2]}, resp, err)) printResponse(resp);
      else std::printf("error: %s\n", err.c_str());

    // ---- File commands -----------------------------------------------------
    } else if (c == "upload_file") {
      if (tok.size() != 3) { std::printf("usage: upload_file <group_id> <file_path>\n"); continue; }
      const std::string& group = tok[1];
      const std::string& path = tok[2];

      // Hash locally first (streaming) — the tracker only ever sees
      // metadata, never file bytes.
      FileFingerprint fp;
      if (!fingerprintFile(path, fp, err)) {
        std::printf("error: %s\n", err.c_str());
        continue;
      }
      std::vector<std::string> pieceHex;
      pieceHex.reserve(fp.pieceHashes.size());
      for (const auto& d : fp.pieceHashes) pieceHex.push_back(toHex(d));

      std::string name = baseName(path);
      Message resp;
      if (!tracker.request(cmd::kUploadFile,
                           {group, name, std::to_string(fp.size),
                            toHex(fp.fileHash), join(pieceHex, ',')},
                           resp, err)) {
        std::printf("error: %s\n", err.c_str());
        continue;
      }
      if (resp.field(0) != "0") {
        std::printf("error: %s\n", resp.field(1).c_str());
        continue;
      }
      ctx.storeGroupKey(group, resp.field(2));  // key rides the Ok response
      {
        std::lock_guard<std::mutex> guard(ctx.m);
        ctx.shares[{group, name}] = ShareInfo{
            path, fp.size, uint32_t(fp.pieceHashes.size())};
      }
      std::printf("shared %s in %s (%llu bytes, %zu pieces)\n", name.c_str(),
                  group.c_str(), (unsigned long long)fp.size,
                  fp.pieceHashes.size());

    } else if (c == "download_file") {
      if (tok.size() != 4) { std::printf("usage: download_file <group_id> <file_name> <dest_path>\n"); continue; }
      if (!downloader.startDownload(tok[1], tok[2], tok[3], err)) {
        std::printf("error: %s\n", err.c_str());
      }

    } else if (c == "show_downloads") {
      std::printf("%s\n", downloader.formatDownloads().c_str());

    } else if (c == "stop_share") {
      if (tok.size() != 3) { std::printf("usage: stop_share <group_id> <file_name>\n"); continue; }
      Message resp;
      if (tracker.request(cmd::kStopShare, {tok[1], tok[2]}, resp, err)) {
        printResponse(resp);
        std::lock_guard<std::mutex> guard(ctx.m);
        ctx.shares.erase({tok[1], tok[2]});
      } else {
        std::printf("error: %s\n", err.c_str());
      }

    } else if (c == "help") {
      printUsage();

    } else if (c == "quit" || c == "exit") {
      break;

    } else {
      std::printf("unknown command '%s' (type 'help')\n", c.c_str());
    }
  }

  // Cancel active downloads so worker threads stop touching files, then let
  // process exit reclaim the detached threads and their sockets.
  {
    std::lock_guard<std::mutex> guard(ctx.m);
    for (auto& d : ctx.downloads) d.second->cancel = true;
  }
  ctx.loggedIn = false;
  seeder.stop();
  return 0;
}
