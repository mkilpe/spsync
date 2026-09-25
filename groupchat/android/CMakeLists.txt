# The JNI adapter of the groupchat core for Android: libgc_adapter.so from jni/adapter.cpp,
# linked against the gc_lib archive and the dependencies build-android.sh and
# scripts/build-android-deps.sh put under <deps dir>/android/<abi>. An app's Gradle
# externalNativeBuild points at this file with -DGC_DEPS=<deps dir>; the Java side is
# java/fi/securepath/groupchat/GroupChat.java.
cmake_minimum_required(VERSION 3.25)

project(gc_adapter LANGUAGES CXX)

set(GC_DEPS "" CACHE PATH "the deps directory build-android.sh filled (android/<abi>/libgc_lib.a, include/json_manager.hpp)")
if(NOT GC_DEPS)
	message(FATAL_ERROR "set GC_DEPS to the deps directory build-android.sh filled")
endif()
if(NOT ANDROID_ABI)
	message(FATAL_ERROR "configure with the NDK toolchain file: ANDROID_ABI is not set")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(gc_adapter SHARED jni/adapter.cpp)
target_include_directories(gc_adapter PRIVATE ${GC_DEPS}/include)
target_link_directories(gc_adapter PRIVATE ${GC_DEPS}/android/${ANDROID_ABI}/lib ${GC_DEPS}/android/${ANDROID_ABI})
# the archives in dependency order: the core, then what it uses
target_link_libraries(gc_adapter PRIVATE gc_lib botan-3 sqlite3 log)
