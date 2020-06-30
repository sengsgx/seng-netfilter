message("Searching for Linux generic netlink library")

SET( SEARCHPATHS
        /usr/include
        )
FIND_PATH(LibGENL_INCLUDE_DIR
        PATH_SUFFIXES
        include/libnl3
        NAMES
        netlink/version.h
        PATHS
        $(SEARCHPATHS)
        )

FIND_LIBRARY(LibGENL_LIBRARY
            NAMES
            nl-genl-3 nl-genl libnl-genl-3 libnl-genl
            PATH_SUFFIXES
            include/libnl3/netlink/genl
            # lib64 lib
            PATHS
            $(SEARCHPATHS)
            )

if (LibGENL_INCLUDE_DIR AND LibGENL_LIBRARY)
    set(LibGENL_FOUND TRUE)
    message("Lib-genl found!")
endif (LibGENL_INCLUDE_DIR AND LibGENL_LIBRARY)

if (LibGENL_FOUND)
        set(LibGENL_LIBRARIES ${LibGENL_LIBRARY})
        SET(LibGENL_INCLUDE_DIRS ${LibGENL_INCLUDE_DIR})
ELSE (LibGENL_FOUND)
    if (LibGENL_FIND_REQUIRED)
        message(FATAL_ERROR "Could not find generic netlink library.")
    endif (LibGENL_FIND_REQUIRED)
endif (LibGENL_FOUND)