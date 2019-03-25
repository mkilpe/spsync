cmake_minimum_required(VERSION 3.10)

if(EXISTS "cmake.config")
	include("cmake.config" OPTIONAL)
endif()

project("SPSync")

include("/home/mikael/dev/sp-backup/src/cmake.main")

# actual projects
add_subdirectory(spsync)
