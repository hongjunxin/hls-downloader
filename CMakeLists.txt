cmake_minimum_required(VERSION 3.7)
project(dhls VERSION 0.0.1)

option(USE_CURL "Use libcurl instead of OpenSSL for https" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)
message("CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")

set(DHLS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/downloader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/epoll.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utility.c)

if(USE_CURL)
    list(APPEND DHLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/mcurl.c)
    find_package(Curl REQUIRED)
endif()

find_package(OpenSSL REQUIRED)
add_executable(dhls ${DHLS_SOURCES})
target_link_libraries(dhls PRIVATE OpenSSL::SSL)
if(USE_CURL)
    target_link_libraries(dhls PRIVATE curl::curl)
endif()