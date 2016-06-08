# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

# Build ops-stpd cli shared libraries.

cmake_minimum_required (VERSION 2.8)

set (OPSSTPD ops-stpd)
project (${OPSSTPD})

set (SRC_DIR src)
set (INCL_DIR include)

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror -ggdb -g3 -O0")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

include_directories (${PROJECT_BINARY_DIR}/${INCL_DIR}
                     ${PROJECT_SOURCE_DIR}/${INCL_DIR}
                     ${PROJECT_SOURCE_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS})

# Source files to build ops-stpd
set (SOURCES ${SRC_DIR}/mstpd.c ${SRC_DIR}/mstpd_ovsdb_if.c
    ${SRC_DIR}/mstpd_ctrl.c ${SRC_DIR}/mqueue.c
    ${SRC_DIR}/mstpd_bdm_sm.c ${SRC_DIR}/mstpd_inlines.c
    ${SRC_DIR}/mstpd_tcm_sm.c ${SRC_DIR}/mstpd_ppm_sm.c
    ${SRC_DIR}/mstpd_prt_sm.c ${SRC_DIR}/mstpd_pti_sm.c
    ${SRC_DIR}/mstpd_prx_sm.c ${SRC_DIR}/mstpd_pim_sm.c
    ${SRC_DIR}/mstpd_prs_sm.c ${SRC_DIR}/mstpd_pst_sm.c
    ${SRC_DIR}/mstpd_ptx_sm.c ${SRC_DIR}/mstpd_show.c
    ${SRC_DIR}/mstpd_debug.c  ${SRC_DIR}/mstpd_init.c
    ${SRC_DIR}/mstpd_recv.c ${SRC_DIR}/mstpd_dyn_reconfig.c
    ${SRC_DIR}/mstpd_util.c ${SRC_DIR}/md5.c )

# Rules to build ops-stpd
add_executable (${OPSSTPD} ${SOURCES})

target_link_libraries (${OPSSTPD} ${OVSCOMMON_LIBRARIES} ${OVSDB_LIBRARIES}
                   -lpthread -lrt -lsupportability)

add_subdirectory(src/cli)

# Build switchd stp plugin shared libraries.
add_subdirectory(plugins)
# Rules to install ops-stpd binary in rootfs
install(TARGETS ${OPSSTPD}
        RUNTIME DESTINATION bin)
