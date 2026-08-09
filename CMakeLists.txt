cmake_minimum_required(VERSION 3.16)

# Optional CMake build for OmsiCrashProbe. The simpler build-msvc-x86.bat is the
# main path on Juanjo's machine, but CMake is useful if we later want IDE project
# generation or CI builds.
project(OmsiCrashProbe LANGUAGES CXX RC)

add_library(OmsiPatchCore STATIC PatchCore.cpp)
target_include_directories(OmsiPatchCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(OmsiPatchCore PUBLIC cxx_std_17)
target_compile_definitions(OmsiPatchCore PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(OmsiPatchCore PUBLIC bcrypt)

add_executable(OmsiPatchTool OmsiPatchTool.cpp)
target_link_libraries(OmsiPatchTool PRIVATE OmsiPatchCore shell32)
target_compile_features(OmsiPatchTool PRIVATE cxx_std_17)

add_executable(OmsiCrashProbeGui WIN32 OmsiCrashProbeGui.cpp OmsiCrashProbeGui.rc)
set_target_properties(OmsiCrashProbeGui PROPERTIES OUTPUT_NAME OmsiCrashProbe)
target_link_libraries(OmsiCrashProbeGui PRIVATE OmsiPatchCore comctl32 comdlg32 shell32 user32 gdi32)
target_compile_features(OmsiCrashProbeGui PRIVATE cxx_std_17)

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
    target_compile_options(OmsiPatchCore PRIVATE /W4 /EHsc)
    target_compile_options(OmsiPatchTool PRIVATE /W4 /EHsc)
    target_compile_options(OmsiCrashProbeGui PRIVATE /W4 /EHsc)
    target_link_options(OmsiCrashProbeGui PRIVATE /MANIFEST:NO)
    set_property(TARGET OmsiPatchCore PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set_property(TARGET OmsiPatchTool PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set_property(TARGET OmsiCrashProbeGui PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
