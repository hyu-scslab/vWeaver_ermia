# No in-source build
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "In-source builds are not allowed.")
endif("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")

project(ermia)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Woverloaded-virtual -Werror=reorder -Wno-address-of-packed-member")
set(LINK_FLAGS "-libverbs -lnuma -lpthread -pthread -lrt -lglog -lgflags")
link_libraries(${LINK_FLAGS})

# Use masstree for index
add_definitions(-DMASSTREE)

set(MASSTREE_CONFIG "--enable-max-key-len=1024 --with-malloc=malloc")

if(${CMAKE_BUILD_PARAM} STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-debug.h")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Eval1")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -DHYU_EVAL -O3")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Eval2")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -DHYU_EVAL_2 -O3")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Eval2_longchain")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -DHYU_EVAL_2 -DHYU_LONG_CHAIN -O3")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Motivation")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_MOTIVATION -O3")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Motivation_vweaver")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_MOTIVATION -DHYU_VWEAVER -O3")
elseif(${CMAKE_BUILD_PARAM} STREQUAL "Vweaver")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -O3")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()


#if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-debug.h")
#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DHYU_VWEAVER -DHYU_EVAL -g")
#	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
#elseif(${CMAKE_BUILD_TYPE} STREQUAL "Eval1")
#	set(CMAKE_BUILD_TYPE "Release")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
#	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -DHYU_EVAL -O3")
#elseif(${CMAKE_BUILD_TYPE} STREQUAL "Eval2")
#	set(CMAKE_BUILD_TYPE "Release")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
#	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -DHYU_EVAL_2 -O3")
#elseif(${CMAKE_BUILD_TYPE} STREQUAL "Vweaver")
#	set(CMAKE_BUILD_TYPE "Release")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
#	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DHYU_VWEAVER -O3")
#else()
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${CMAKE_CURRENT_SOURCE_DIR}/masstree/config-release.h")
#	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
#endif()

# Assume 64-byte cache line
add_definitions(-DCACHELINE_SIZE=64)

include_directories(dbcore)
include_directories(masstree)
include_directories(third-party/sparsehash/src)

add_subdirectory(benchmarks)
add_subdirectory(dbcore)
add_subdirectory(masstree)

set_property(GLOBAL APPEND PROPERTY ALL_ERMIA_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/ermia.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/tuple.cc
  ${CMAKE_CURRENT_SOURCE_DIR}/txn.cc
)

get_property(LIB_ERMIA_SRC GLOBAL PROPERTY ALL_ERMIA_SRC)

# SI
add_library(ermia_si SHARED ${LIB_ERMIA_SRC})
add_executable(ermia_SI ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/dbtest.cc)
target_link_libraries(ermia_SI ermia_si)

# SI+SSN
add_library(ermia_si_ssn SHARED ${LIB_ERMIA_SRC})
set_target_properties(ermia_si_ssn PROPERTIES COMPILE_FLAGS "-DSSN -DEARLY_SSN_CHECK")

add_executable(ermia_SI_SSN ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/dbtest.cc)
set_target_properties(ermia_SI_SSN PROPERTIES COMPILE_FLAGS "-DSSN -DEARLY_SSN_CHECK")
target_link_libraries(ermia_SI_SSN ermia_si_ssn)

# SSI
add_library(ermia_ssi SHARED ${LIB_ERMIA_SRC})
set_target_properties(ermia_ssi PROPERTIES COMPILE_FLAGS "-DSSI")

add_executable(ermia_SSI ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/dbtest.cc)
set_target_properties(ermia_SSI PROPERTIES COMPILE_FLAGS "-DSSI")
target_link_libraries(ermia_SSI ermia_ssi)

# MVOCC
add_library(ermia_mvocc SHARED ${LIB_ERMIA_SRC})
set_target_properties(ermia_mvocc PROPERTIES COMPILE_FLAGS "-DMVOCC")

add_executable(ermia_MVOCC ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/dbtest.cc)
set_target_properties(ermia_MVOCC PROPERTIES COMPILE_FLAGS "-DMVOCC")
target_link_libraries(ermia_MVOCC ermia_mvocc)

# Benchmark scripts
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run2.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-rdma-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/run-tcp-cluster.sh" DESTINATION ${CMAKE_BINARY_DIR})
