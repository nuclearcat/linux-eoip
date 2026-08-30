# PACKAGE_VERSION and HAVE_LIBLZO2, the only two macros the sources use.
configure_file(config.h.in config.h @ONLY)

foreach(daemon eoip vip)
    add_executable(${daemon} ${daemon}.c)
    # for the generated config.h
    target_include_directories(${daemon} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(${daemon} PRIVATE minini Threads::Threads)
endforeach()

# Only vip speaks LZO.
if(HAVE_LIBLZO2)
    target_include_directories(vip PRIVATE "${LZO_INCLUDE_DIR}")
    target_link_libraries(vip PRIVATE "${LZO_LIBRARY}")
endif()

install(TARGETS eoip vip RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
