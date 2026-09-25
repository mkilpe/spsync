#!/bin/bash
# Build gc_lib (the groupchat core with the JSON API, everything a mobile front end
# links) for Android, one out-of-source tree per ABI, and collect the archives and the
# API header into a deps directory.
#
#   ANDROID_NDK=<ndk dir> build-android.sh <deps dir> [abi ...]
#
# <deps dir> must hold the dependencies built for Android per ABI under
# <deps dir>/android/<abi>: what scripts/build-android-deps.sh puts there (Botan >= 3.9
# static with its cmake package, sqlite3 static, the asio headers), found through
# CMAKE_FIND_ROOT_PATH. The archives land in <deps dir>/android/<abi>/libgc_lib.a and the
# header in <deps dir>/include. Default ABIs: armeabi-v7a arm64-v8a x86_64;
# ANDROID_PLATFORM defaults to android-26.
set -e
DEST=${1:?usage: ANDROID_NDK=<ndk dir> $0 <deps dir> [abi ...]}
NDK=${ANDROID_NDK:?set ANDROID_NDK to the NDK directory}
PLATFORM=${ANDROID_PLATFORM:-android-26}
shift
ABIS=${*:-armeabi-v7a arm64-v8a x86_64}
SRC=$(cd "$(dirname "$0")" && pwd)

build() { # abi
	local abi=$1
	local dir="$SRC/build-android-$abi"
	echo "Building gc_lib for $abi in $dir"
	cmake -S "$SRC" -B "$dir" \
		-DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
		-DANDROID_ABI="$abi" -DANDROID_PLATFORM="$PLATFORM" \
		-DCMAKE_BUILD_TYPE=Release -Dbuild_tests=OFF \
		-DCMAKE_FIND_ROOT_PATH="$DEST/android/$abi"
	cmake --build "$dir" --target gc_lib -j"$(nproc)"
	mkdir -p "$DEST/android/$abi"
	cp -f "$dir/lib/libgc_lib.a" "$DEST/android/$abi/"
}

mkdir -p "$DEST/include"
cp -f "$SRC/groupchat/json_protocol/json_manager.hpp" "$DEST/include/"
for abi in $ABIS; do
	build "$abi"
done
