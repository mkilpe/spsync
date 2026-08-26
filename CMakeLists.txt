cmake_minimum_required(VERSION 3.25)

project("SPSync" LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-source builds are not supported; configure with "
		"'cmake --preset default' (or 'cmake -S . -B build'). Remove the "
		"CMakeCache.txt and CMakeFiles/ this attempt just created.")
endif()

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
	message(STATUS "Enabling debug build")
endif()
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -ggdb")

option(build_tests "Build test programs" ON)
if(build_tests)
	enable_testing()
endif()

# --- securepath base libraries (git submodule) ---
set(SECUREPATH_BUILD_TESTS ${build_tests})
set(SECUREPATH_BUILD_TEST_FRAME ${build_tests})
add_subdirectory(submodules/securepath)

# console is built by securepath only when ncursesw is available
if(TARGET console)
	set(enable_console ON)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/external/json/include)
add_definitions(-DBOOST_JSON_STANDALONE)

# --- compatibility helpers (formerly from sp cmake.main/conf.cmake) ---
function(add_deps)
	if(TARGET ${ARGV0})
		target_link_libraries(${ARGV})
	endif()
endfunction()

function(add_application)
	add_executable(${ARGV})
endfunction()

# test executable from all sources in the calling directory, registered with ctest
function(add_sp_test_application name)
	if(NOT build_tests)
		return()
	endif()
	file(GLOB SRC *.cpp *.hpp)
	add_executable(${name} ${SRC})
	target_link_libraries(${name} ${ARGN} test_frame)
	# empty placeholder suites (e.g. comm) must not fail the run
	add_test(NAME ${name} COMMAND ${name} --allow-running-no-tests)
endfunction()

# --- actual projects ---
add_subdirectory(spsync)
add_subdirectory(groupchat)

# combined library for groupchat (used for mobile)
# note: remote_object and client_common are no longer used
add_library(gc_lib STATIC
	$<TARGET_OBJECTS:groupchat_json_protocol>
	$<TARGET_OBJECTS:groupchat_core>

	$<TARGET_OBJECTS:spsync_client>
	$<TARGET_OBJECTS:spsync_comm>
	$<TARGET_OBJECTS:spsync_core>
	$<TARGET_OBJECTS:spsync_engine>
	$<TARGET_OBJECTS:spsync_protocol>
	$<TARGET_OBJECTS:spsync_util>

	$<TARGET_OBJECTS:packet_transport_client>
	$<TARGET_OBJECTS:packet_transport_protocol>
	$<TARGET_OBJECTS:key_client>

	$<TARGET_OBJECTS:common>
	$<TARGET_OBJECTS:crypto>
	$<TARGET_OBJECTS:database>
	$<TARGET_OBJECTS:event_system>
	$<TARGET_OBJECTS:log>
	$<TARGET_OBJECTS:network>
	$<TARGET_OBJECTS:serialisation>
	$<TARGET_OBJECTS:util>
	)
