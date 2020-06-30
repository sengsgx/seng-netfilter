cmake_minimum_required(VERSION 3.9) # 3.9 for simplified doxygen command
project(seng_app
        LANGUAGES C
        VERSION 1.0)

# for 3rd party/own cmake find scripts
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})


find_package(SENGNetfilter REQUIRED)

# define executable file that should be build
add_executable(seng_app seng_app.c)

# paths to external header files needed for the executable (beyond standard ones)
target_include_directories(seng_app PRIVATE ../include/ ${SENGNETFLT_INCLUDE_DIRS})

# link libraries (standard libc and co. is auto linked by cmake)
target_link_libraries(seng_app ${SENGNETFLT_LIBRARY})
