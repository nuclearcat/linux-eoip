# minIni, a small INI parser by ITB CompuPhase, vendored unmodified.
# Apache-2.0, unlike the GPL-3.0-or-later daemons that use it; see the
# license header in minIni.c.
add_library(minini OBJECT minIni.c)

# Consumers get minIni.h and minGlue.h from here.
target_include_directories(minini PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
