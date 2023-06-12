cmake_minimum_required(VERSION 3.7)
project(dhls_tests VERSION 0.0.1)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules)

find_package(Avformat REQUIRED)
find_package(Avutil REQUIRED)
find_package(Avcodec REQUIRED)
find_package(Swresample REQUIRED)

add_executable(libav_example libav_example.c)
target_link_libraries(libav_example PRIVATE avformat avcodec avutil swresample m z)
set_target_properties(libav_example PROPERTIES
    OUTPUT_NAME libav_example)

add_executable(remux_example remux_example.c)
target_link_libraries(remux_example PRIVATE avformat avcodec avutil swresample m z)
set_target_properties(remux_example PROPERTIES
    OUTPUT_NAME remux_example)
