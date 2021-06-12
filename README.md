# _cygmon_
A sampling process monitor for Cygwin

This project is an experiment in profiling by IP (instruction pointer) sampling.
Cygwin already has a built-in profiler (accessed through _gcc_'s -pg compiler
option), but it has limitations.  One limitation is an inability to record
samples for dynamically linked libraries.  Another limitation is that the
program that processes profiler data files, _gprof_, does not currently support
symbol tables from more than one image at a time (such as dynamic library
symbols in addition to a program's symbols).  There is nothing Cygwin-specific
about these limitations; Linux profilers have the same limitations.

_cygmon_ avoids these limitations by being able to sample multiple text
segments and by writing multiple _gmon.out_ files, one for the program and one
for each dynamic library that had samples recorded.  _cygmon_ can also sample
child processes forked from the initially profiled process.

*Interim build instructions:*
This project assumes you are already set up to build the Cygwin DLL.  In your
Cygwin source tree, navigate to the winsup/utils directory.  Copy cygmon.cc
from this project into that directory.  Merge (carefully) the contents of
mingw/Makefile.am from this project into the version in winsup/utils/mingw.
The effect of the merge is to add _cygmon_ to the list of utilities built as
Windows native programs (like _strace_ and _dumper_) rather than as Cygwin
programs.  Navigate to the corresponding build location and run _make_.  That
will create a cygmon.exe that you can place in /usr/local/bin, for instance.

*Note that this is the final beta release for testing by anybody interested.*
