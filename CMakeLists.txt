cmake_minimum_required(VERSION 3.7)
project(dhls VERSION 0.0.1)

option(USE_CURL "Use libcurl instead of OpenSSL for https" OFF)
option(USE_FFMPEG "Use ffmpeg tool" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

set(DHLS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/epoll.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utility.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/media.c)

if(USE_CURL)
    list(APPEND DHLS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/mcurl.c)
    add_compile_definitions(${PROJECT_NAME} PRIVATE USE_CURL=1)
    find_package(Curl REQUIRED)
endif()

if(USE_FFMPEG)
    add_compile_definitions(${PROJECT_NAME} PRIVATE USE_FFMPEG=1)
endif()

find_package(OpenSSL REQUIRED)
add_executable(${PROJECT_NAME} ${DHLS_SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL)
if(USE_CURL)
    target_link_libraries(${PROJECT_NAME} PRIVATE curl::curl)
endif()