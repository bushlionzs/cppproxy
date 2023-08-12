cmake_minimum_required(VERSION 3.18)

project(cppproxy)

include(FetchContent)

FetchContent_Declare(zlib
        GIT_REPOSITORY "ssh://git@git.gizaworks.com:8022/kuaidaili/plugin/zlib.git"
        GIT_TAG main)
FetchContent_GetProperties(zlib)
if(NOT zlib_POPULATED)
  FetchContent_Populate(zlib)
  add_subdirectory(${zlib_SOURCE_DIR} zlib)
endif ()

set(ZLIB_INC_DIR ${zlib_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/zlib)


FetchContent_Declare(dy_network
        GIT_REPOSITORY git@github.com:bushlionzs/dy_network.git
        GIT_TAG main)
FetchContent_GetProperties(dy_network)
if(NOT dy_network_POPULATED)
  FetchContent_Populate(dy_network)
  add_subdirectory(${dy_network_SOURCE_DIR} dy_network)
endif ()



if (WIN32)
set(DYNETWORK_INC_DIR ${dy_network_SOURCE_DIR}/net ${dy_network_SOURCE_DIR}/net/windows ${dy_network_SOURCE_DIR}/common ${dy_network_SOURCE_DIR}/common/windows ${dy_network_SOURCE_DIR}/utility)
else()
set(DYNETWORK_INC_DIR ${dy_network_SOURCE_DIR}/net ${dy_network_SOURCE_DIR}/net/linux ${dy_network_SOURCE_DIR}/common ${dy_network_SOURCE_DIR}/common/linux ${dy_network_SOURCE_DIR}/utility)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

if (WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX -DDY_NETWORK_DISNABLE_SSL)
    add_compile_options("/utf-8")
else()
    if (USE_STATIC_LIBSTDCXX)
        message(STATUS "use static libstdcxx")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")
    endif()

    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()



# 3. add self files


add_executable(${PROJECT_NAME} main.cpp agentServer.cpp agent_server_util.cpp agentSession.cpp targetSession.cpp)

if(MSVC)
set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_include_directories(${PROJECT_NAME}  PRIVATE ${DYNETWORK_INC_DIR} ${PROTOBUF_INC_DIR} ${BORINGSSL_INC_DIR} ${ZLIB_INC_DIR})	

if (WIN32)
target_link_libraries(${PROJECT_NAME} dy_network  zlibstatic winmm)
else()
target_link_libraries(${PROJECT_NAME} dy_network  zlibstatic pcap pthread)
endif()

