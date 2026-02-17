cmake_minimum_required(VERSION 3.20.0)
project(nanolog VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)

add_executable(main main.cpp)
add_executable(spsc_test spsc_test.cpp)