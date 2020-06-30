find_path(SENGNETFLT_INCLUDE_DIRS seng_netfilter.h xt_seng.h
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../include/")

find_library(SENGNETFLT_LIBRARY libsengnetfilter.so
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../user-library/build/")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SENGNETFLT DEFAULT_MSG
        SENGNETFLT_INCLUDE_DIRS SENGNETFLT_LIBRARY)

mark_as_advanced(SENGNETFLT_INCLUDE_DIRS SENGNETFLT_LIBRARY)
