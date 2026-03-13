cmake_minimum_required(VERSION 3.10)
project(pam_parallel_fprint C)

add_library(pam_parallel_fprint MODULE src/pam_parallel_fprint.c)

target_link_libraries(pam_parallel_fprint PRIVATE pam pthread systemd)

set_target_properties(pam_parallel_fprint PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX ""
)

