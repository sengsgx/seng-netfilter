message("Searching for Linux libnetfilter-conntrack-dev")

SET( SEARCHPATHS
        /usr/include/libnetfilter_conntrack
        )
FIND_PATH( Conntrack_INCLUDE_DIR
        NAMES
        libnetfilter_conntrack/libnetfilter_conntrack.h
        PATHS
        $(SEARCHPATHS)
        )
FIND_LIBRARY(Conntrack_LIBRARY
            NAMES
            netfilter_conntrack lnetfilter_conntrack libnetfilter_conntrack
            PATHS
            $(SEARCHPATHS)
            )

if (Conntrack_INCLUDE_DIR AND Conntrack_LIBRARY)
    set(Conntrack_FOUND TRUE)
    message("libnetfilter-conntrack-dev found!")
endif (Conntrack_INCLUDE_DIR AND Conntrack_LIBRARY)

if (Conntrack_FOUND)
        set(Conntrack_LIBRARIES ${Conntrack_LIBRARY})
        SET(Conntrack_INCLUDE_DIRS ${Conntrack_INCLUDE_DIR})
ELSE (Conntrack_FOUND)
    if (Conntrack_FIND_REQUIRED)
        message("Netlink conntrack development packages cannot be found.")
        message("In Debian/Ubuntu, it is called:")
        message("libnetfilter-conntrack-dev")
        message(FATAL_ERROR "Could not find libnetfilter-conntrack-dev.")
    endif (Conntrack_FIND_REQUIRED)
endif (Conntrack_FOUND)