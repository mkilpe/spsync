#/bin/bash

DEST="/home/mikael/dev/gc-deps"

build() {
  local ABI=$1
  make clean -j10
  rm -f CMakeCache.txt
  echo "Building android for abi ${ABI}"
  cmake . -DANDROID_ABI=${ABI} &&
     make gc_lib -j12 &&
     echo "Copying libgc_lib.a to ${DEST}/android/${ABI}" &&
     cp -f lib/libgc_lib.a "${DEST}/android/${ABI}"
}

echo "Copying header to ${DEST}/include"
cp -f ./groupchat/json_protocol/json_manager.hpp "${DEST}/include"

build "armeabi-v7a"
build "arm64-v8a"
build "x86_64"

