# Copyright (c) 2020 Pedro Martelletto. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

project(webauthn_client C)
cmake_minimum_required(VERSION 3.0)
include(FindPkgConfig)

set(CMAKE_COLOR_MAKEFILE OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wbad-function-cast")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic-errors")

pkg_search_module(LIBCURL libcurl REQUIRED)
pkg_search_module(JANSSON jansson REQUIRED)
pkg_search_module(LIBCBOR libcbor REQUIRED)
pkg_search_module(LIBCRYPTO libcrypto REQUIRED)
pkg_search_module(LIBFIDO2 libfido2 REQUIRED)

message(STATUS "LIBCURL_INCLUDE_DIRS: ${LIBCURL_INCLUDE_DIRS}")
message(STATUS "LIBCURL_LIBRARY_DIRS: ${LIBCURL_LIBRARY_DIRS}")
message(STATUS "LIBCURL_LIBRARIES: ${LIBCURL_LIBRARIES}")
message(STATUS "JANSSON_INCLUDE_DIRS: ${JANSSON_INCLUDE_DIRS}")
message(STATUS "JANSSON_LIBRARY_DIRS: ${JANSSON_LIBRARY_DIRS}")
message(STATUS "JANSSON_LIBRARIES: ${JANSSON_LIBRARIES}")
message(STATUS "LIBCBOR_INCLUDE_DIRS: ${LIBCBOR_INCLUDE_DIRS}")
message(STATUS "LIBCBOR_LIBRARY_DIRS: ${LIBCBOR_LIBRARY_DIRS}")
message(STATUS "LIBCBOR_LIBRARIES: ${LIBCBOR_LIBRARIES}")
message(STATUS "LIBCRYPTO_INCLUDE_DIRS: ${LIBCRYPTO_INCLUDE_DIRS}")
message(STATUS "LIBCRYPTO_LIBRARY_DIRS: ${LIBCRYPTO_LIBRARY_DIRS}")
message(STATUS "LIBCRYPTO_LIBRARIES: ${LIBCRYPTO_LIBRARIES}")
message(STATUS "LIBFIDO2_INCLUDE_DIRS: ${LIBFIDO2_INCLUDE_DIRS}")
message(STATUS "LIBFIDO2_LIBRARY_DIRS: ${LIBFIDO2_LIBRARY_DIRS}")
message(STATUS "LIBFIDO2_LIBRARIES: ${LIBFIDO2_LIBRARIES}")

include_directories(${LIBCURL_INCLUDE_DIRS})
include_directories(${JANSSON_INCLUDE_DIRS})
include_directories(${LIBCRYPTO_INCLUDE_DIRS})
include_directories(${LIBCBOR_INCLUDE_DIRS})
include_directories(${LIBFIDO2_INCLUDE_DIRS})

link_directories(${LIBCURL_LIBRARY_DIRS})
link_directories(${JANSSON_LIBRARY_DIRS})
link_directories(${LIBCBOR_LIBRARY_DIRS})
link_directories(${LIBCRYPTO_LIBRARY_DIRS})
link_directories(${LIBFIDO2_LIBRARY_DIRS})

add_executable(webauthn-client
	base64.c
	cbor.c
	clientdata.c
	http.c
	json.c
	webauthn-assert.c
	webauthn-client.c
	webauthn-cred.c
)

target_link_libraries(webauthn-client
	${JANSSON_LIBRARIES}
	${LIBCBOR_LIBRARIES}
	${LIBCRYPTO_LIBRARIES}
	${LIBCURL_LIBRARIES}
	${LIBFIDO2_LIBRARIES}
)
