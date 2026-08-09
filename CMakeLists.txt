cmake_minimum_required(VERSION 3.16)

# Optional CMake build for OmsiCrashProbe. The simpler build-msvc-x86.bat is the
# main path on Juanjo's machine, but CMake is useful if we later want IDE project
# generation or CI builds.
project(OmsiCrashProbe LANGUAGES CXX)

# Build a Windows DLL from the C++ source and the export-definition file.
add_library(OmsiCrashProbe SHARED
    OmsiCrashProbe.cpp
    OmsiCrashProbe.def
)

# Keep windows.h smaller and avoid min/max macros that can collide with C++ code.
target_compile_definitions(OmsiCrashProbe PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# The code currently uses only modest C++ features, but C++17 is a stable modern
# baseline across Visual Studio 2019+.
target_compile_features(OmsiCrashProbe PRIVATE cxx_std_17)

if (MSVC)
    # /W4 gives useful warnings; /EHsc sets normal C++ exception semantics.
    target_compile_options(OmsiCrashProbe PRIVATE /W4 /EHsc)
endif()
