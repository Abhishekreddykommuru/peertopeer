# Peer-to-peer file sharing

A group-based file sharing system: two coordinating tracker servers hold the
metadata, and peers exchange file pieces directly with each other. C++17 on
POSIX sockets, no external libraries.

Files are split into 512 KiB pieces. A peer downloading a file pulls pieces
from up to four other peers at once, taking the rarest piece first, and starts
serving each piece as soon as it has verified it. Every piece is checked
against a SHA-1 hash on arrival, and the assembled file is checked again at the
end.

Sharing is group-based. An owner creates a group and approves who joins, and a
non-member cannot fetch a piece from anyone: peers prove knowledge of a
per-group key to each other before any data moves. Login is a challenge-response
exchange, so the password is never sent and the tracker stores only a PBKDF2
verifier. Every message on a secured channel is AES-256-CTR encrypted
and carries an HMAC-SHA1 tag, so a modified frame is rejected instead of
decrypted.

SHA-1, HMAC-SHA1, PBKDF2 and AES-256 are implemented in `common/` and checked
against the published vectors from FIPS 180-1, FIPS 197, RFC 2202, RFC 6070 and
NIST SP 800-38A.

## Build

Needs g++ or clang++ with C++17, and make. Developed on macOS, runs on Linux.

    make
    make clean

The build is clean under `-Wall -Wextra`.

## Running it

[execution.md](execution.md) has the full walkthrough with real output. The
short version:

`tracker_info.txt` holds the two tracker addresses and the key they use to
authenticate each other.

    127.0.0.1:9000
    127.0.0.1:9001
    secret=<64 hex chars>

Start both trackers, each in its own terminal:

    ./tracker/tracker tracker_info.txt 1
    ./tracker/tracker tracker_info.txt 2

Start a client. The address is the port this client listens on for incoming
piece requests, so every client needs a different one:

    ./client/client 127.0.0.1:9500 tracker_info.txt

At the prompt:

    create_user alice pw123
    login alice pw123
    create_group cs101
    upload_file cs101 ./somefile.bin

A second client joins, the owner accepts, and it downloads:

    join_group cs101          # second client
    list_requests cs101       # alice
    accept_request cs101 bob  # alice
    download_file cs101 somefile.bin ./out/

## Commands

    create_user <user> <pass>              register
    login <user> <pass>                    log in and start seeding
    logout                                 log out and stop seeding
    create_group <group>                   create a group you own
    join_group <group>                     ask to join
    list_requests <group>                  owner: see pending requests
    accept_request <group> <user>          owner: approve a request
    leave_group <group>                    leave a group
    list_groups                            list every group
    upload_file <group> <path>             share a file with the group
    list_files <group>                     list the group's files
    download_file <group> <file> <dest>    download from the swarm
    show_downloads                         D = running, C = done, F = failed
    stop_share <group> <file>              stop sharing a file
    quit                                   exit

## How it works

    LEADER (tracker 1) ----- operation log -----> FOLLOWER (tracker 2)
        |                                              |
        | all client commands                          | serves no clients
        | metadata only: users, groups,                | until promoted
        | file hashes, who has what                    |
        |
    CLIENT A <----- pieces -----> CLIENT B <----> CLIENT C

    file contents only ever travel between clients

The trackers never see file contents. Every change the leader makes is recorded
as a numbered operation and streamed to the follower, which applies it. The
follower tracks how far it has consumed the log, so one that goes down and
comes back asks for everything after that point and replays it. Operations are
idempotent, so replaying one twice is harmless.

Only the leader accepts client commands. A follower answers anything with "I am
a follower" and names the other tracker, which is how a client finds the
leader: it tries one, and if it gets that answer it tries the other. Promoting
a follower therefore needs no client-side change.

Failover is manual. With two trackers there is no majority to appeal to, so a
follower cannot tell "the leader is dead" from "I cannot reach the leader". If
it promoted itself, a broken link between two healthy trackers would produce
two leaders, which is worse than being unavailable. Automatic promotion needs a
third voter.

To stop an old leader coming back and acting as a second one, each tracker
carries a term number that increases on every promotion. The two exchange terms
when they connect and whoever is behind steps down. A restarted tracker 1
starts as leader, learns tracker 2 is on a later term, and demotes itself.

Each client runs a seeder and a downloader at once. A download opens up to four
peer connections, and each one loops: ask for the peer's bitfield, pick the
rarest piece it has that nobody is already fetching, request it, check the
hash, write it at its offset with `pwrite`. Pieces are never buffered
whole-file, so memory stays flat whatever the file size.

### Design notes

Rarest-first piece selection stops the last pieces ending up on a single peer,
where its departure would strand everyone; ties break randomly so four workers
do not all request the same piece. Two hash levels mean a bad piece is caught
within 512 KiB and refetched from someone else, while the whole-file hash still
catches an assembly error where every piece is individually valid. Message
framing is explicit because TCP is a byte stream, and the length is checked
against a maximum before any buffer is allocated. Replication ships an
operation log rather than whole state, since the sequence numbers make it
obvious what a recovering tracker missed.

The two decisions that required the most consideration follow.

Encryption alone was not sufficient. AES-CTR is a stream cipher, so flipping a
ciphertext bit flips exactly that plaintext bit, and someone in the middle
could edit a message without being able to read it. Every frame now carries an
HMAC-SHA1 tag over the header and the ciphertext, verified before anything is
decrypted. The cipher key and MAC key come from the session key under different
labels.

One writable tracker, not two. Letting both accept writes keeps the system
available through either failing, but two clients on opposite trackers can then
create the same group or claim the same file name during a split, and the two
versions have to be reconciled afterwards. There is no correct reconciliation
for ownership data: whichever way it resolves, somebody was told they own
something and silently does not. Funnelling writes through one node makes that
impossible rather than unlikely. The cost is that writes stop when the leader
dies until somebody promotes the follower.

## Layout

    common/    sha1, crypto, tcp socket, message framing, protocol constants
    tracker/   tracker server: state machine, replication, request handling
    client/    peer: seeder, downloader, tracker client, command loop

Roughly 4,800 lines. `common/include/protocol.h` is the entry point for reading
the code: every constant both sides must agree on is defined there.

## Verification

The crypto primitives are checked against published vectors rather than only
round-tripped: SHA-1 against FIPS 180-1 including the million-character case,
HMAC-SHA1 against RFC 2202 including the long-key case, PBKDF2 against RFC 6070
including 4096 iterations, the AES-256 block against FIPS 197 C.3, and
AES-256-CTR against NIST SP 800-38A F.5.5.

The framing and encryption layer runs over a real socket pair. Frames survive
the round trip, binary payloads containing NUL bytes are unharmed, and the
receiver refuses a frame whose ciphertext or header has been altered, a
truncated frame, one with the wrong magic, and a plaintext frame on a secured
channel.

End to end, with two trackers and three clients: registration and login, a
wrong password rejected, group join and approval, a multi-piece download
compared byte for byte with `cmp`, a second download while two peers seed, a
file smaller than one piece, a group name containing a path separator refused,
and killing the leader so commands fail rather than diverge before promotion
restores them with the replicated state intact.

Also run by hand with a 128 MiB file: output identical to the input, client
memory flat at around 7 MB.

## Known limitations

State lives in memory. If both trackers go down, everything is lost.
Persisting the operation log would fix this and is the highest-value change
remaining.

Promotion is manual, so a leader failure stops writes until an operator
intervenes. Two nodes cannot safely elect a leader on their own.

A tracker boots as whatever its number says, so a restarted tracker 1 believes
it is leader for the moment before it connects to tracker 2 and sees the later
term. During that window it would accept a command. A real consensus protocol
closes this by refusing to serve until it has heard from a majority.

SHA-1 is broken for collision resistance, so someone who controls a file before
upload could construct two with the same hash. It still detects accidental
corruption and a peer serving wrong bytes. Moving to SHA-256 changes a length
constant and a typedef, nothing structural.

There is no forward secrecy. Session keys come from long-term secrets, so
recovering one exposes recorded traffic. Ephemeral Diffie-Hellman per session
would fix it.

Registration sends the verifier before the channel is encrypted, so the user
name and verifier are visible at `create_user`. Login cannot encrypt first
because the session key comes out of the login handshake, but registration
could run inside an encrypted channel.

Nothing stops a peer downloading without ever uploading. BitTorrent solves this
with choking and tit-for-tat.

Peers have to be directly reachable. No NAT traversal and no DHT, so the
trackers cannot be removed from the design.
