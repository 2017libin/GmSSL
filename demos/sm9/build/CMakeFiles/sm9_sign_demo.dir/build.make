# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/chase511/code/GmSSL/demos/sm9

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/chase511/code/GmSSL/demos/sm9/build

# Include any dependencies generated for this target.
include CMakeFiles/sm9_sign_demo.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sm9_sign_demo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sm9_sign_demo.dir/flags.make

CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o: CMakeFiles/sm9_sign_demo.dir/flags.make
CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o: ../sm9_sign_demo.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/chase511/code/GmSSL/demos/sm9/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o   -c /home/chase511/code/GmSSL/demos/sm9/sm9_sign_demo.c

CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/chase511/code/GmSSL/demos/sm9/sm9_sign_demo.c > CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.i

CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/chase511/code/GmSSL/demos/sm9/sm9_sign_demo.c -o CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.s

# Object files for target sm9_sign_demo
sm9_sign_demo_OBJECTS = \
"CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o"

# External object files for target sm9_sign_demo
sm9_sign_demo_EXTERNAL_OBJECTS =

sm9_sign_demo: CMakeFiles/sm9_sign_demo.dir/sm9_sign_demo.c.o
sm9_sign_demo: CMakeFiles/sm9_sign_demo.dir/build.make
sm9_sign_demo: CMakeFiles/sm9_sign_demo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/chase511/code/GmSSL/demos/sm9/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable sm9_sign_demo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sm9_sign_demo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sm9_sign_demo.dir/build: sm9_sign_demo

.PHONY : CMakeFiles/sm9_sign_demo.dir/build

CMakeFiles/sm9_sign_demo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sm9_sign_demo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sm9_sign_demo.dir/clean

CMakeFiles/sm9_sign_demo.dir/depend:
	cd /home/chase511/code/GmSSL/demos/sm9/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/chase511/code/GmSSL/demos/sm9 /home/chase511/code/GmSSL/demos/sm9 /home/chase511/code/GmSSL/demos/sm9/build /home/chase511/code/GmSSL/demos/sm9/build /home/chase511/code/GmSSL/demos/sm9/build/CMakeFiles/sm9_sign_demo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sm9_sign_demo.dir/depend

