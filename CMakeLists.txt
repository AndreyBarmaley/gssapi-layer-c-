cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3 -O0 -Wall -Werror -Wno-sign-compare -Wno-unused-function -Wno-unused-variable")
set(CMAKE_CXX_FLAGS_PROFILER "-O2 -pg -Wall -Werror -Wno-sign-compare -Wno-unused-function -Wno-unused-variable")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wall -Wno-sign-compare -Wno-unused-function -Wno-unused-variable")

find_package(PkgConfig)

foreach(PROJ IN ITEMS server client)
    project(${PROJ} VERSION 20221220.1)

    add_executable(${PROJ} test/${PROJ}.cpp test/tools.cpp src/gsslayer.cpp)

    target_include_directories(${PROJ} PRIVATE include test src)

    pkg_search_module(GSSAPI REQUIRED krb5-gssapi)
    target_compile_options(${PROJ} PRIVATE ${GSSAPI_DEFINITIONS})
    target_include_directories(${PROJ} PRIVATE include ${GSSAPI_INCLUDE_DIR})
    target_link_libraries(${PROJ} ${GSSAPI_LIBRARIES})

    set_target_properties(${PROJ} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach()
