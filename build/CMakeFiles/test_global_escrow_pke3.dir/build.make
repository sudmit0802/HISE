# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files\CMake\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files\CMake\bin\cmake.exe" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\sudmi\Desktop\kmzi\HISE

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\sudmi\Desktop\kmzi\HISE\build

# Include any dependencies generated for this target.
include CMakeFiles/test_global_escrow_pke3.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/test_global_escrow_pke3.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/test_global_escrow_pke3.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_global_escrow_pke3.dir/flags.make

CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj: CMakeFiles/test_global_escrow_pke3.dir/flags.make
CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj: CMakeFiles/test_global_escrow_pke3.dir/includes_CXX.rsp
CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj: C:/Users/sudmi/Desktop/kmzi/HISE/test/test_global_escrow_pke3.cpp
CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj: CMakeFiles/test_global_escrow_pke3.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\sudmi\Desktop\kmzi\HISE\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj"
	C:\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj -MF CMakeFiles\test_global_escrow_pke3.dir\test\test_global_escrow_pke3.cpp.obj.d -o CMakeFiles\test_global_escrow_pke3.dir\test\test_global_escrow_pke3.cpp.obj -c C:\Users\sudmi\Desktop\kmzi\HISE\test\test_global_escrow_pke3.cpp

CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.i"
	C:\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\sudmi\Desktop\kmzi\HISE\test\test_global_escrow_pke3.cpp > CMakeFiles\test_global_escrow_pke3.dir\test\test_global_escrow_pke3.cpp.i

CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.s"
	C:\MinGW\bin\g++.exe $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\sudmi\Desktop\kmzi\HISE\test\test_global_escrow_pke3.cpp -o CMakeFiles\test_global_escrow_pke3.dir\test\test_global_escrow_pke3.cpp.s

# Object files for target test_global_escrow_pke3
test_global_escrow_pke3_OBJECTS = \
"CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj"

# External object files for target test_global_escrow_pke3
test_global_escrow_pke3_EXTERNAL_OBJECTS =

test_global_escrow_pke3.exe: CMakeFiles/test_global_escrow_pke3.dir/test/test_global_escrow_pke3.cpp.obj
test_global_escrow_pke3.exe: CMakeFiles/test_global_escrow_pke3.dir/build.make
test_global_escrow_pke3.exe: CMakeFiles/test_global_escrow_pke3.dir/linkLibs.rsp
test_global_escrow_pke3.exe: CMakeFiles/test_global_escrow_pke3.dir/objects1.rsp
test_global_escrow_pke3.exe: CMakeFiles/test_global_escrow_pke3.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\sudmi\Desktop\kmzi\HISE\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_global_escrow_pke3.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\test_global_escrow_pke3.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_global_escrow_pke3.dir/build: test_global_escrow_pke3.exe
.PHONY : CMakeFiles/test_global_escrow_pke3.dir/build

CMakeFiles/test_global_escrow_pke3.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\test_global_escrow_pke3.dir\cmake_clean.cmake
.PHONY : CMakeFiles/test_global_escrow_pke3.dir/clean

CMakeFiles/test_global_escrow_pke3.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\sudmi\Desktop\kmzi\HISE C:\Users\sudmi\Desktop\kmzi\HISE C:\Users\sudmi\Desktop\kmzi\HISE\build C:\Users\sudmi\Desktop\kmzi\HISE\build C:\Users\sudmi\Desktop\kmzi\HISE\build\CMakeFiles\test_global_escrow_pke3.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_global_escrow_pke3.dir/depend

