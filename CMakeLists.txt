cmake_minimum_required(VERSION 3.9) # 3.9 for simplified doxygen command
project(seng-extension
        LANGUAGES C
        VERSION 1.0)

find_package(Doxygen
    #REQUIRED dot
        OPTIONAL_COMPONENTS mscgen dia)

set(DOXYGEN_EXTRACT_ALL YES)

doxygen_add_docs(seng_docs
        .
        COMMENT "seng-extension doxygen documentation")
