cmake_minimum_required(VERSION 3.7)
project(dhls VERSION 0.0.1)

option(USE_CURL "Use libcurl instead of OpenSSL for https" OFF)
option(USE_FFMPEG_TOOL "Use ffmpeg tool" OFF)

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

add_executable(${PROJECT_NAME} ${DHLS_SOURCES})

if(USE_FFMPEG_TOOL)
    add_compile_definitions(${PROJECT_NAME} PRIVATE USE_FFMPEG_TOOL=1)
else()
    find_package(Avformat REQUIRED)
    find_package(Avutil REQUIRED)
    find_package(Avcodec REQUIRED)
    find_package(Swresample REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE avcodec avformat avutil swresample)
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL)
if(USE_CURL)
    target_link_libraries(${PROJECT_NAME} PRIVATE curl::curl)
endif()