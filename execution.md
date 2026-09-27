# Running the system

Build, configuration, and a full walkthrough: two trackers and three clients
sharing files, downloading them, and recovering from a leader failure. All
output shown was captured from a run on macOS. Linux behaves identically.

The walkthrough uses five terminals, two for trackers and three for clients.
Each begins in the project directory:

    cd ~/Desktop/projects/peer-to-peer

Substitute the actual clone location if it differs.


## Build

    make

Requires g++ or clang++ with C++17 support, and make. There are no other
dependencies: no OpenSSL, no Boost, nothing to install. The build completes
with no warnings and produces two binaries:

    $ ls -l tracker/tracker client/client
    -rwxr-xr-x  1 abhi  staff  216136 26 Sep 18:42 client/client
    -rwxr-xr-x  1 abhi  staff  214728 26 Sep 18:41 tracker/tracker

To confirm the build is warning-free:

    $ make clean && make 2>&1 | grep -ci warning
    0


## Configuration

`tracker_info.txt` holds the two tracker addresses and the key the trackers
use to authenticate each other. The copy in the repo has an all-zero
placeholder. Generate a real one:

    printf '127.0.0.1:9000\n127.0.0.1:9001\nsecret=%s\n' \
        "$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')" > tracker_info.txt
    chmod 600 tracker_info.txt

    $ cat tracker_info.txt
    127.0.0.1:9000
    127.0.0.1:9001
    secret=c4f1e08b9a7d2653fe81b0c94a7e5d3268fb019c7e4a8d5b2c6f0913ae7d4b85

Anyone who can read that key can inject operations into both trackers, hence
the chmod.


## Sample files

Three files, so the walkthrough covers a multi-piece transfer, a single-piece
one, and a file far smaller than a piece:

    mkdir -p demo out_bob out_carol

    head -c 2500000 /dev/urandom > demo/dataset.bin

    printf 'id,name,score\n' > demo/results.csv
    for i in $(seq 1 20000); do
        printf '%d,user%d,%d\n' "$i" "$i" "$((i * 7 % 100))"
    done >> demo/results.csv

    printf 'Project notes.\nSecond line.\n' > demo/notes.txt

    $ ls -l demo/
    -rw-r--r--  1 abhi  staff  2500000 26 Sep 14:08 dataset.bin
    -rw-r--r--  1 abhi  staff       28 26 Sep 14:08 notes.txt
    -rw-r--r--  1 abhi  staff   355802 26 Sep 14:08 results.csv

Record the checksums for comparison after downloading:

    shasum demo/dataset.bin demo/results.csv demo/notes.txt


## Starting the trackers

Each tracker needs its own terminal because it reads commands from stdin.

Terminal 1:

    $ ./tracker/tracker tracker_info.txt 1
    [14:08:17] INFO  tracker 1 listening on 127.0.0.1:9000  [LEADER]
    [14:08:17] INFO  sync: connected to peer tracker, replaying from watermarks (0, 0)
    [14:08:17] INFO  sync: peer tracker connected (incoming)

Terminal 2:

    $ ./tracker/tracker tracker_info.txt 2
    [14:08:17] INFO  tracker 2 listening on 127.0.0.1:9001  [FOLLOWER]
    [14:08:17] INFO  follower: serving no clients; type 'promote' to take over
    [14:08:17] INFO  sync: connected to peer tracker, replaying from watermarks (0, 0)
    [14:08:17] INFO  sync: peer tracker connected (incoming)

The second argument says which line of `tracker_info.txt` this process is.
Tracker 1 starts as leader and handles every client command. Tracker 2 applies
what the leader sends it and serves no clients at all.

A lone "listening" line means the other tracker is not running yet. The two
connect on their own once both are up.

Three console commands work in either terminal:

    status     print leader/follower and the current term
    promote    make this tracker the leader
    quit       shut down

Check the roles:

    tracker 1 $ status
    leader, term 1

    tracker 2 $ status
    follower, term 1

Note that the tracker treats end-of-file on stdin as `quit`,
so backgrounding it with `&` and no terminal makes it exit immediately. To run
it in the background, hold stdin open with a FIFO:

    mkfifo /tmp/t1.in
    sleep 86400 > /tmp/t1.in &
    ./tracker/tracker tracker_info.txt 1 < /tmp/t1.in > /tmp/t1.log 2>&1 &
    echo "status" > /tmp/t1.in


## Starting the clients

Three more terminals. The address argument is the port this client listens on
for incoming piece requests, so each needs a different one, and none may
collide with 9000 or 9001.

    terminal 3 $ ./client/client 127.0.0.1:9500 tracker_info.txt
    terminal 4 $ ./client/client 127.0.0.1:9501 tracker_info.txt
    terminal 5 $ ./client/client 127.0.0.1:9502 tracker_info.txt

Each prints:

    p2p client ready — seeding address 127.0.0.1:9500 (type 'help')
    >

A client is never told which tracker leads. It determines that by asking.


## Sharing files

In terminal 3:

    > create_user alice pw_alice_123
    user created
    > login alice pw_alice_123
    logged in as alice (session channel encrypted)
    > create_group cs101
    group created; you are the owner

The password did not cross the network. The client derived a PBKDF2 key from
it and proved knowledge with an HMAC exchange. Everything after this point is
AES-256-CTR encrypted with an HMAC-SHA1 tag on every frame.

    > upload_file cs101 ./demo/dataset.bin
    shared dataset.bin in cs101 (2500000 bytes, 5 pieces)
    > upload_file cs101 ./demo/results.csv
    shared results.csv in cs101 (355802 bytes, 1 pieces)
    > upload_file cs101 ./demo/notes.txt
    shared notes.txt in cs101 (28 bytes, 1 pieces)

2,500,000 bytes over a 512 KiB piece size gives 5 pieces; the other two fit in
one short piece each. Nothing was copied anywhere. `upload_file` hashes the
file where it sits and registers the metadata, so the tracker learns the name,
size and hashes but never sees the contents.

    > list_files cs101
    dataset.bin  (2500000 bytes, 1 seeder(s) online)
    notes.txt  (28 bytes, 1 seeder(s) online)
    results.csv  (355802 bytes, 1 seeder(s) online)

Leave this terminal open. If alice exits, nobody can download from her.


## Joining the group

Terminal 4:

    > create_user bob pw_bob_456
    user created
    > login bob pw_bob_456
    logged in as bob (session channel encrypted)
    > join_group cs101
    join request sent to group owner

Bob cannot see anything yet:

    > list_files cs101
    error: not a member of that group

This is the access control working as intended. Without membership there is no
group key, and without the group key no peer will serve a single piece.

Back in terminal 3, alice approves him:

    > list_requests cs101
    bob
    > accept_request cs101 bob
    bob added to cs101

Terminal 4 again:

    > list_files cs101
    dataset.bin  (2500000 bytes, 1 seeder(s) online)
    notes.txt  (28 bytes, 1 seeder(s) online)
    results.csv  (355802 bytes, 1 seeder(s) online)


## Downloading

Still terminal 4. The last argument is a destination directory or a full path.

    > download_file cs101 dataset.bin ./out_bob
    download started: dataset.bin -> ./out_bob/dataset.bin (5 pieces, 1 peer(s))
    >
    [C] [cs101] dataset.bin

The `[C]` line arrives on its own once the download finishes and the whole-file
hash checks out, so it can land in the middle of the next prompt. The REPL
never blocks on a transfer. `[D]` means running, `[C]` complete, `[F]` failed.

    > download_file cs101 results.csv ./out_bob
    download started: results.csv -> ./out_bob/results.csv (1 pieces, 1 peer(s))
    [C] [cs101] results.csv
    > download_file cs101 notes.txt ./out_bob
    download started: notes.txt -> ./out_bob/notes.txt (1 pieces, 1 peer(s))
    [C] [cs101] notes.txt
    > show_downloads
    [C] [cs101] dataset.bin
    [C] [cs101] notes.txt
    [C] [cs101] results.csv

Open a sixth terminal and check the copies are exact:

    $ cd ~/Desktop/projects/peer-to-peer
    $ cmp demo/dataset.bin out_bob/dataset.bin && echo same
    same
    $ cmp demo/results.csv out_bob/results.csv && echo same
    same
    $ cmp demo/notes.txt out_bob/notes.txt && echo same
    same

`cmp` prints nothing when files match, so the echo is the confirmation. The
checksums recorded in the previous section serve the same purpose.

Always verify with `cmp` or `shasum`, never by looking at file sizes. The
destination is pre-allocated at full length so pieces can be written at their
real offsets in any order, which means an interrupted download leaves a
full-size file that is mostly zeros and looks finished to `ls`.


## Downloading from two peers

Bob now holds complete copies, and a finished download is promoted to a full
share automatically, so bob is a seeder too.

Terminal 5:

    > create_user carol pw_carol_789
    user created
    > login carol pw_carol_789
    logged in as carol (session channel encrypted)
    > join_group cs101
    join request sent to group owner

Terminal 3:

    > accept_request cs101 carol
    carol added to cs101

Terminal 5:

    > list_files cs101
    dataset.bin  (2500000 bytes, 2 seeder(s) online)
    notes.txt  (28 bytes, 2 seeder(s) online)
    results.csv  (355802 bytes, 2 seeder(s) online)
    > download_file cs101 dataset.bin ./out_carol
    download started: dataset.bin -> ./out_carol/dataset.bin (5 pieces, 2 peer(s))
    [C] [cs101] dataset.bin

Two seeders, two peer connections. Carol pulled pieces from alice and bob at
the same time, taking the rarest piece first each round.

    $ cmp demo/dataset.bin out_carol/dataset.bin && echo same
    same

A peer that is still downloading also serves the pieces it has already
verified, so the swarm grows from the first moments of a transfer rather than
only after somebody finishes. Start a large download in one client and run
`list_files` in another to see the seeder count rise before it completes.


## Failover

Kill the leader. In terminal 1 type `quit`, or from anywhere:

    pkill -f 'tracker_info.txt 1'

Now try a command in terminal 4:

    > list_groups
    error: no leader available (promote a tracker to accept writes)

This is the intended behaviour rather than a bug. Tracker 2 holds a complete
copy of the state but will not start serving on its own, because it cannot
tell these two situations apart:

    tracker 1 is dead                   -> promoting is correct
    the link broke but tracker 1 is     -> promoting gives two leaders
    alive and still serving clients        and two versions of the truth

They look identical from tracker 2's side. No timeout distinguishes them. One
wrong guess causes a pause; the other causes silent permanent divergence, so
the system waits for a human. Two nodes cannot form a majority, so safe
automatic election needs a third.

Promote it. In terminal 2:

    > promote
    [14:24:36] INFO  promoted to LEADER (term 2) - now accepting client commands

Terminal 4:

    > list_groups
    cs101 (owner: alice, members: 3)
    > list_files cs101
    dataset.bin  (2500000 bytes, 2 seeder(s) online)
    notes.txt  (28 bytes, 2 seeder(s) online)
    results.csv  (355802 bytes, 2 seeder(s) online)

Everything survived: the group alice created through tracker 1, all three
members, all three files. The client reconnected and re-authenticated with its
cached key without asking for a password again.

Now restart the old leader in terminal 1:

    $ ./tracker/tracker tracker_info.txt 1
    [14:46:38] INFO  tracker 1 listening on 127.0.0.1:9000  [LEADER]
    [14:46:38] WARN  sync: peer is in term 2 - stepping down to FOLLOWER
    [14:46:38] INFO  sync: connected to peer tracker, replaying from watermarks (0, 0)

    > status
    follower, term 2

It booted as leader because that is what its command-line number says, then
saw tracker 2 was on a higher term and demoted itself. Without the term
counter it would have carried on as a second leader.

One gap remains. Between binding the port and completing that handshake,
tracker 1 does consider itself the leader and would accept a command. Closing
the window requires a quorum, which requires a third tracker.


## Security controls

A wrong password fails:

    > logout
    logged out
    > login bob wrong_password
    error: invalid credentials
    > login bob pw_bob_456
    logged in as bob (session channel encrypted)

The tracker never had the password. It checked an HMAC proof under the
PBKDF2-derived key, in constant time.

File and group names that could escape a directory are refused:

    > create_group ../escape
    error: group id must be 1-64 printable characters, no spaces or slashes

A file name chosen by an uploader ends up appended to whatever destination a
downloader passes, so a name like `../../../.ssh/authorized_keys` would make
every downloader write outside the directory they asked for. The check runs on
the tracker, not just in the client, since an attacker can write their own
client.

Control characters in a command line get reported instead of silently mangling
it:

    $ printf 'create_group bad\bname\nquit\n' | ./client/client 127.0.0.1:9599 tracker_info.txt
    p2p client ready — seeding address 127.0.0.1:9599 (type 'help')
    > note: ignored 1 control character(s) in that line
    error: not logged in

This used to be invisible. Echoing the bad command back made the terminal act
on the control byte, so `create_user\bice` displayed as `create_useice`: the
command looked right on screen and failed anyway.

Garbage on a tracker port is dropped rather than parsed:

    $ printf 'GET / HTTP/1.1\r\n\r\n' | nc 127.0.0.1 9000; echo "closed"
    closed

The tracker reads the 12-byte header, finds the magic is not P2FS, and closes
the connection. The same code rejects a frame declaring an impossible payload
length before allocating anything, so twelve hostile bytes cannot trigger a
4 GB allocation.

Every encrypted frame carries an HMAC-SHA1 tag over the header and the
ciphertext, checked before anything is decrypted. AES-CTR on its own is
malleable: flipping a ciphertext bit flips the same plaintext bit, so without
the tag someone in the middle could make targeted edits to a message they
cannot read.


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
    help                                   print this list
    quit                                   exit

Both spellings work: `create_user` and `create user`, `download_file` and
`download file`, and so on.


## Scripting

Both programs quit on end-of-file, so piping commands in does not work. Use a
FIFO with the write end held open:

    mkfifo /tmp/alice.in
    sleep 3600 > /tmp/alice.in &
    ./client/client 127.0.0.1:9500 tracker_info.txt < /tmp/alice.in > /tmp/alice.log 2>&1 &

    send() { echo "$1" > /tmp/alice.in; sleep "${2:-0.5}"; }
    send "create_user alice pw_alice_123"
    send "login alice pw_alice_123"
    send "create_group cs101"
    send "upload_file cs101 ./demo/dataset.bin" 3
    send "list_files cs101"

    cat /tmp/alice.log

The `sleep` keeps the pipe from reaching EOF. The same technique applies to
sending `promote` to a backgrounded tracker. Clean up with:

    pkill -f 'client/client'; rm -f /tmp/alice.in /tmp/alice.log


## Troubleshooting

`error: no tracker reachable` means neither tracker is running, or the
addresses in `tracker_info.txt` do not match those the trackers were started
with:

    lsof -iTCP:9000 -sTCP:LISTEN
    lsof -iTCP:9001 -sTCP:LISTEN
    cat tracker_info.txt

Also confirm the correct index (1 or 2) was passed to each.

`error: no leader available` means both trackers are up but neither leads,
usually because the original leader died. Run `status` in each and `promote`
one of them.

`error: not logged in` covers every command except `create_user` and `login`.
If the leader changed, the client re-authenticates by itself; after an
explicit `logout`, log in again.

`error: not a member of that group` is expected until the owner runs
`accept_request`.

`error: cannot listen on 127.0.0.1:9500 (port in use?)` means a previous client
still holds the port. Find it with `lsof -iTCP:9500 -sTCP:LISTEN`, or use a
different port.

`error: '...' is not a regular file` means `upload_file` was given a directory
or a device. Only regular files are accepted; otherwise `upload_file /dev/zero`
would attempt to hash an endless stream.

A tracker or client that exits immediately on startup was backgrounded without
a terminal. Both read commands from stdin and treat EOF as `quit`. Use the FIFO
recipe above.

A download reporting `0 peer(s)` means no seeder is online. The uploading
client must still be running; once alice quits, her files cannot be served.
Confirm with `list_files`.

A download that died mid-transfer leaves a full-size file at the destination
that is mostly zeros. Delete it and download again. Failures that happen while
the client is still running clean up after themselves; only killing the process
leaves one behind.


## Cleaning up

Type `quit` in each terminal, or:

    pkill -f 'tracker/tracker'
    pkill -f 'client/client'

Then:

    rm -rf demo out_bob out_carol
    make clean

Tracker state lives entirely in memory. Stop both trackers and every user,
group and file registration is gone, so the walkthrough restarts from
`create_user`. Restarting one tracker while the other is still running resets
nothing, since the survivor replays its log into the one that came back.

After a promotion tracker 2 is the leader. Stopping everything and starting
again returns tracker 1 to the leader role, because the role comes from the
command-line number and terms are not persisted either.
