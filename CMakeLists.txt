cmake_minimum_required(VERSION 3.15)
project(xiloader CXX)

set_property(GLOBAL PROPERTY CXX_STANDARD 20)
set_property(GLOBAL PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(GLOBAL PROPERTY CXX_EXTENSIONS ON)
set_property(GLOBAL PROPERTY LINKER_LANGUAGE CXX)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "CMAKE_SIZEOF_VOID_P == 8: 64-bit build")
    message(FATAL_ERROR "64-bit build is not supported. Please clean your build directory and reconfigure with: cmake .. -A Win32")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "CMAKE_SIZEOF_VOID_P == 4: 32-bit build")
endif()

include(cmake/CPM.cmake)
include(cmake/detours.cmake)
include(cmake/argparse.cmake)
include(cmake/mbedtls.cmake)

# Version info
set(MAJOR_VERSION 2)
set(MINOR_VERSION 0)
set(PATCH_VERSION 0)

add_definitions(-DXILOADER_VERSION_STRING="${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
add_definitions(-DXILOADER_MAJOR_VERSION=${MAJOR_VERSION})
add_definitions(-DXILOADER_MINOR_VERSION=${MINOR_VERSION})
add_definitions(-DXILOADER_PATCH_VERSION=${PATCH_VERSION})

configure_file(
	src/xiloader.rc.in
	src/xiloader.rc
)

# xiloader
add_executable(xiloader
    src/console.cpp
    src/console.h
    src/defines.h
    src/FFXi.h
    src/FFXiMain.h
    src/functions.cpp
    src/functions.h
    src/main.cpp
    src/network.cpp
    src/network.h
    src/polcore.h
    ${CMAKE_CURRENT_BINARY_DIR}/src/xiloader.rc
)

set_target_properties(xiloader PROPERTIES LINK_FLAGS "/LARGEADDRESSAWARE")

target_include_directories(xiloader PUBLIC ${PROJECT_SOURCE_DIR}/xiloader)

target_link_libraries(xiloader PUBLIC
    detours
	argparse
	crypt32
	psapi
	ws2_32
	iphlpapi
	MbedTLS::mbedtls
	MbedTLS::mbedcrypto
	MbedTLS::mbedx509)

message(STATUS "CMAKE_VERSION: ${CMAKE_VERSION}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_COMPILER_VERSION: ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
message(STATUS "CMAKE_GENERATOR_PLATFORM: ${CMAKE_GENERATOR_PLATFORM}")
