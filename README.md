# spsync

A synchronisation engine and servers for end-to-end encrypted, multi-device data.
Every storage is an authenticated chain of records: clients sign and encrypt the
records, servers order and replicate them without seeing their content, and the
data of a record (a file) travels out of band in encrypted chunks. groupchat is
the reference application on top of it: encrypted group chats with shared files,
with a JSON API for app front ends and an ncurses client.

Built on the [securepath](https://github.com/mkilpe/securepath) libraries
(git submodule): post-quantum crypto, the encrypted transport, the key and packet
servers, and the test frame.

| component | what it is | depends on |
|---|---|---|
| `spsync/util` | sequence numbers, object ids, users and access rights, metadata, configuration | securepath `util`, `serialisation` |
| `spsync/core` | records (chain blocks, data change / user change / segment records, server envelopes, equivocation proofs), the sqlite record storage, encryption keys, membership merge, record data (chunked encrypted data, descriptors, manifests, tickets, the chunk store), the divergence finder | `util`, securepath `crypto`, `database` |
| `spsync/protocol` | the wire: client-server, server-to-server and data server packets, error codes, storage modes, default ports | `core`, securepath `network` |
| `spsync/engine` | the client sync engine: chain acceptance in strict and weak modes, rebase on conflict, fork suspicion and trusted anchors, record data sync, history verification and pruning at segments | `core`, `comm` interface |
| `spsync/transfer` | record data transfer machinery: channels to the data servers, uploader and downloader, retries; used by clients and by the servers' replicator | `protocol`, securepath `network` |
| `spsync/comm` | the client's record connection: the storage session over the encrypted transport, the engine's view of a server | `protocol`, securepath `network` |
| `spsync/client` | `client_sync` (members, keys and record data of one storage), contacts, requests and invitations over the packet transport | `engine`, `transfer`, securepath `packet_transport`, `key_client` |
| `spsync/server` | `spsync_server`: the storage server (chain rules, chain log, one sqlite database per storage), server-to-server replication (weak multi-master with anti-entropy, bootstrap of a new replica, divergence and equivocation evidence), the data server role (out-of-band data, tickets, copies among data servers) | `transfer`, `protocol`, securepath `key_server` |
| `spsync/tools` | `spsync_storage_tool`: look into a storage database | `server` |
| `spsync/test` | shared test helpers (header-only) and the `spsync_test` support library for tests that run servers | all of the above |
| `groupchat/core` | chats over spsync: channels, messages, members, invitations, shared files | `spsync/client` |
| `groupchat/json_protocol` | the JSON command and notification API app front ends use (the mobile builds link `gc_lib`), documented in [groupchat/json_protocol/doc](groupchat/json_protocol/doc) | `groupchat/core`, Boost.JSON |
| `groupchat/cli_client` | `gc_cli`, an ncurses chat client | `groupchat/core`, securepath `console` |

[doc/architecture.adoc](doc/architecture.adoc) is the overview with diagrams: the
pieces and how they talk, the chain of records, the code layout, the client's sync
engine, record data, the server and its replication, security, and groupchat on
top (render it with `asciidoctor -r asciidoctor-diagram`). The design lives in
[doc/](doc/) as plain text plans with progress markers:
[distributed_sync.txt](doc/distributed_sync.txt) (the multi-server work: weak
multi-master replication done, strict mode with an own minimal Raft designed),
[record_data.txt](doc/record_data.txt) (out-of-band record data, data servers),
[segments.txt](doc/segments.txt) (chain hardening and history cuts),
[shared_files.txt](doc/shared_files.txt) (files in a chat),
[user_changes.txt](doc/user_changes.txt) and [users.txt](doc/users.txt)
(membership and keys), [use_cases.txt](doc/use_cases.txt),
[testing.txt](doc/testing.txt) and [todos.txt](doc/todos.txt).

Requirements: CMake >= 3.25, a C++23 compiler (GCC 14 or newer; developed with
GCC 16, the Android NDK's clang 21 builds it too), asio (a system copy, or
fetched automatically), sqlite3 and Botan >= 3.9 development packages, and
ncursesw for `gc_cli`. The securepath submodule pulls Catch2 for the tests. The
code uses no C++26 feature; the build asks for `-std=c++26` where the compiler
has it because securepath does, and builds as C++23 unchanged.

## Building and testing

Out-of-source only, driven by `CMakePresets.json`:

```sh
git submodule update --init --recursive
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Builds land in `build/` (binaries in `build/bin`, archives in `build/lib`).
`build_tests` (default on) builds the test suites.

For Android, `scripts/build-android-deps.sh <deps dir>` builds Botan and sqlite3
for an ABI with the NDK and copies the asio headers next to them, and
`build-android.sh <deps dir>` then builds `gc_lib`, everything a mobile front end
links, against them (both take `ANDROID_NDK` from the environment, see their
headers). [groupchat/android](groupchat/android/README.md) has the JNI adapter
and the Java class an app uses. The NDK's libc++ lacks
`std::move_only_function`, so the code uses `securepath::move_only_function`
from `spsync/util/move_only_function.hpp`, the standard one where the library
has it. Run ctest without `-j`: the
suites bind fixed ports and share database file names in the working directory,
and a full serial run takes about ten minutes. A single suite runs directly, e.g.
`build/bin/test_spsync_core`.

## Running a local environment

`scripts/multi_server_env.sh <dir>` creates the key material with `sp_keygen`
and starts two peered replicas of `spsync_server` (both with the data role) and a
`packet_server` on localhost, then prints the `gc_cli` command lines for two
accounts and the commands to create a chat, invite, join, chat and share files.
`scripts/multi_server_env.sh <dir> stop` stops them. The servers' options are
listed by `spsync_server --help`.

## Licence

MIT, Copyright (c) 2026 Secure Path Oy — see [LICENSE](LICENSE).
securepath (submodule) is MIT, Catch2 (submodule of securepath) is BSL-1.0, and
the Boost.JSON copy in `external/json` is BSL-1.0.
