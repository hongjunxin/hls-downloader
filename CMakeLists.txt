cmake_minimum_required(VERSION 3.7)
project(dhls VERSION 0.0.1)

option(USE_FFMPEG_TOOL "Use ffmpeg tool" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(DHLS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/epoll.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utility.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/media.c)

add_executable(${PROJECT_NAME} ${DHLS_SOURCES})

if(USE_FFMPEG_TOOL)
    add_compile_definitions(${PROJECT_NAME} PRIVATE USE_FFMPEG_TOOL=1)
else()
    find_package(Avformat REQUIRED)
    find_package(Avutil REQUIRED)
    find_package(Avcodec REQUIRED)
    find_package(Swresample REQUIRED)
    # avformat depends on avcodec, so must before avcodec
    target_link_libraries(${PROJECT_NAME} PRIVATE avformat avcodec avutil swresample)
endif()

find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL m z)
