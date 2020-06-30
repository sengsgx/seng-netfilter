cmake_minimum_required(VERSION 3.9) # 3.9 for simplified doxygen command
project(seng_netfilter
        LANGUAGES C
        VERSION 1.0)

# for 3rd party/own cmake find scripts
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(LibNL REQUIRED)
find_package(LibGENL REQUIRED)
find_package(Conntrack REQUIRED)

# define library
add_library(sengnetfilter SHARED seng_genl.c seng_netfilter.h seng_conntrack.c)

# paths to external header files needed for the library (beyond standard ones)
target_include_directories(sengnetfilter PUBLIC ../include/
        ${LibNL_INCLUDE_DIRS} ${LibGENL_INCLUDE_DIRS} ${Conntrack_INCLUDE_DIRS})

# link libraries
target_link_libraries(sengnetfilter ${LibNL_LIBRARY} ${LibGENL_LIBRARY} ${Conntrack_LIBRARY})
