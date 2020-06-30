message("Searching for Linux netlink library")

SET( SEARCHPATHS
        /usr/include
        )
FIND_PATH( LibNL_INCLUDE_DIR
        PATH_SUFFIXES
        include/libnl3
        NAMES
        netlink/version.h
        PATHS
        $(SEARCHPATHS)
        )
FIND_LIBRARY(LibNL_LIBRARY
            NAMES
            nl-3 nl libnl-3 libnl
            PATH_SUFFIXES
            lib64 lib
            PATHS
            $(SEARCHPATHS)
            )

if (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)
    set(LibNL_FOUND TRUE)
    message("libnl found!")
endif (LibNL_INCLUDE_DIR AND LibNL_LIBRARY)

if (LibNL_FOUND)
        set(LibNL_LIBRARIES ${LibNL_LIBRARY})
        SET(LibNL_INCLUDE_DIRS ${LibNL_INCLUDE_DIR})
ELSE (LibNL_FOUND)
    if (LibNL_FIND_REQUIRED)
        message("Netlink version 3 development packages cannot be found.")
        message("In Debian/Ubuntu, they may be called:")
        message("libnl-3-dev libnl-genl-3dev libnl-nf-3-dev libnl-route-3-dev")
        message(FATAL_ERROR "Could not find netlink library.")
    endif (LibNL_FIND_REQUIRED)
endif (LibNL_FOUND)