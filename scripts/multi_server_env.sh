#!/bin/bash
# Two peered spsync replicas, a packet server and two gc_cli accounts on localhost: the
# M3 gate session (doc/distributed_sync.txt, phase 4). Creates the key material with
# sp_keygen on first use and starts the servers; prints the cli command lines.
#
#   scripts/multi_server_env.sh <dir> [build-bin-dir]     start (or restart) the servers
#   scripts/multi_server_env.sh <dir> stop                 stop them
#
# Replica A: key 18188 / storage 18200 / s2s 18201 / data 18203, replica B: 18198 /
# 18210 / 18211 / 18213, packet server 18202. Both replicas have the data role (all-in-one,
# record_data.txt RD12) and list each other's data server, so a file shared in a chat
# (doc/shared_files.txt) is held by both (--data_copies 2). Kill one replica with
# `kill $(cat <dir>/srv_a.pid)` while the two clients talk, watch them hop to the other
# one, start it again with this script.
set -e
DIR=${1:?usage: $0 <dir> [build-bin-dir|stop]}
mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
if [ "$2" = stop ]; then
	for s in srv_a srv_b packet; do
		[ -f "$DIR/$s.pid" ] && kill "$(cat "$DIR/$s.pid")" 2>/dev/null && rm -f "$DIR/$s.pid"
	done
	exit 0
fi
BIN=$(cd "${2:-$(dirname "$0")/../build/bin}" && pwd)
cd "$DIR"

if [ ! -d pki ]; then
	"$BIN/sp_keygen" --pki pki --init
	"$BIN/sp_keygen" --pki pki --server srv_a | tee srv_a.key
	"$BIN/sp_keygen" --pki pki --server srv_b | tee srv_b.key
	"$BIN/sp_keygen" --pki pki --server packet
	"$BIN/sp_keygen" --pki pki --client alice/gc_client.db | tee alice.key
	"$BIN/sp_keygen" --pki pki --client bob/gc_client.db | tee bob.key
fi
A=$(awk '{print $3}' srv_a.key)
B=$(awk '{print $3}' srv_b.key)

start() { # name, command...
	local name=$1; shift
	if [ -f "$name.pid" ] && kill -0 "$(cat "$name.pid")" 2>/dev/null; then
		echo "$name already running"
	else
		(cd "$name" && exec nohup "$@" > stdout.log 2>&1) &
		echo $! > "$name.pid"
		echo "$name started (pid $(cat "$name.pid"))"
	fi
}
DATA="--data_servers 127.0.0.1:18203/$A 127.0.0.1:18213/$B --data_copies 2 --max_data_size 1073741824"
start srv_a "$BIN/spsync_server" --root ../pki/root.pub --key_port 18188 --storage_port 18200 --s2s_port 18201 --peers "127.0.0.1:18211/$B" --anti_entropy 5 \
	--data_role --data_port 18203 --record_servers "127.0.0.1:18211/$B" $DATA
start srv_b "$BIN/spsync_server" --root ../pki/root.pub --key_port 18198 --storage_port 18210 --s2s_port 18211 --peers "127.0.0.1:18201/$A" --anti_entropy 5 \
	--data_role --data_port 18213 --record_servers "127.0.0.1:18201/$A" $DATA
start packet "$BIN/packet_server" --root ../pki/root.pub --port 18202

CLI="$BIN/gc_cli --root $DIR/pki/root.pub --server 127.0.0.1 --keyport 18188 --syncport 18200 --packetport 18202 --fallback 127.0.0.1:18210:18198"
cat <<INFO

alice:  $CLI -p $DIR/alice
bob:    $CLI -p $DIR/bob
  alice: /create-account alice   /connect   /create-chat room   /invite $(awk '{print $3}' bob.key)
  bob:   /create-account bob     /connect   /requests   /join 1
  then type messages; /window 0 shows the connection log, /window 1 the chat
  files: /share <path> [name]   /files   /get <index> <path> (fetches first, saves when fetched)   /unfetch <index>
INFO
