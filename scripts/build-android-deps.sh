#!/bin/bash
# Build what gc_lib needs on Android, per ABI, into <deps dir>/android/<abi>: Botan 3.9 as
# a static library (its cmake package config with it), sqlite3 as a static library from the
# amalgamation, and the asio headers copied from the system. Sources are downloaded into
# <deps dir>/src once. Then build-android.sh <deps dir> builds gc_lib against them.
#
#   ANDROID_NDK=<ndk dir> scripts/build-android-deps.sh <deps dir> [abi ...]
#
# Default ABI: arm64-v8a (also armeabi-v7a, x86_64, x86); ANDROID_PLATFORM defaults to
# android-26. Needs python3 (Botan's configure), curl and tar on the host.
set -e
DEST=${1:?usage: ANDROID_NDK=<ndk dir> $0 <deps dir> [abi ...]}
NDK=${ANDROID_NDK:?set ANDROID_NDK to the NDK directory}
API=${ANDROID_PLATFORM:-android-26}
API=${API#android-}
shift
ABIS=${*:-arm64-v8a}
BOTAN_VERSION=3.9.0
SQLITE_URL=https://sqlite.org/2026/sqlite-autoconf-3530400.tar.gz
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
mkdir -p "$DEST/src"
DEST=$(cd "$DEST" && pwd)

# the clang target triple and Botan's cpu name of an ABI
triple() {
	case $1 in
		arm64-v8a) echo aarch64-linux-android ;;
		armeabi-v7a) echo armv7a-linux-androideabi ;;
		x86_64) echo x86_64-linux-android ;;
		x86) echo i686-linux-android ;;
		*) echo "unknown abi $1" >&2; exit 1 ;;
	esac
}
botan_cpu() {
	case $1 in
		arm64-v8a) echo arm64 ;;
		armeabi-v7a) echo armv7 ;;
		x86_64) echo x86_64 ;;
		x86) echo x86 ;;
	esac
}

fetch() { # url
	local file="$DEST/src/$(basename "$1")"
	[ -f "$file" ] || curl -fL -o "$file" "$1"
	echo "$file"
}

build_botan() { # abi prefix
	local abi=$1 prefix=$2
	local tar; tar=$(fetch "https://botan.randombit.net/releases/Botan-$BOTAN_VERSION.tar.xz")
	local src="$DEST/src/$abi/Botan-$BOTAN_VERSION"
	rm -rf "$src"; mkdir -p "$DEST/src/$abi"; tar -xJf "$tar" -C "$DEST/src/$abi"
	(cd "$src" && python3 configure.py --os=android --cpu="$(botan_cpu "$abi")" --cc=clang \
		--cc-bin="$TOOLCHAIN/bin/$(triple "$abi")$API-clang++" --ar-command="$TOOLCHAIN/bin/llvm-ar" \
		--prefix="$prefix" --disable-shared-library --without-documentation \
		&& make -j"$(nproc)" libs && make install)
}

build_sqlite() { # abi prefix
	local abi=$1 prefix=$2
	local tar; tar=$(fetch "$SQLITE_URL")
	local dir="$DEST/src/$abi/sqlite"
	rm -rf "$dir"; mkdir -p "$dir"; tar -xzf "$tar" -C "$dir" --strip-components=1
	local cc="$TOOLCHAIN/bin/$(triple "$abi")$API-clang"
	(cd "$dir" && "$cc" -O2 -fPIC -c -DSQLITE_THREADSAFE=1 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1 sqlite3.c -o sqlite3.o \
		&& "$TOOLCHAIN/bin/llvm-ar" rcs libsqlite3.a sqlite3.o)
	mkdir -p "$prefix/lib" "$prefix/include"
	cp -f "$dir/libsqlite3.a" "$prefix/lib/"
	cp -f "$dir/sqlite3.h" "$dir/sqlite3ext.h" "$prefix/include/"
}

copy_asio() { # prefix
	[ -f /usr/include/asio.hpp ] || { echo "asio headers not found in /usr/include (install asio-devel)" >&2; exit 1; }
	mkdir -p "$1/include"
	cp -rf /usr/include/asio /usr/include/asio.hpp "$1/include/"
}

for abi in $ABIS; do
	prefix="$DEST/android/$abi"
	echo "=== $abi -> $prefix"
	mkdir -p "$prefix"
	build_botan "$abi" "$prefix"
	build_sqlite "$abi" "$prefix"
	copy_asio "$prefix"
	echo "=== $abi done"
done
