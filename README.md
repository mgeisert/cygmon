# _cygmon_
A sampling process monitor for Cygwin

This project is an experiment in profiling by PC (program counter) sampling.  Cygwin already has a built-in profiler, but it has limitations.  One limitation is an inability to record samples for dynamically linked libraries.  Another limitation is that the program that processes profiler data files, _gprof_, does not currently support symbol tables from multiple objects such as dynamically linked libraries.  There is nothing Cygwin-specific about these limitations; Linux profilers have the same limitations.

_cygmon_ avoids these limitations by being able to sample multiple text segments and by writing multiple _gmon.out_ files, one for the executable and one for each dynamic library that had samples recorded.  It can also sample child processes forked from the initial process.

*Interim build instructions:*
This project assumes you are already set up to build the Cygwin DLL.  In your Cygwin source tree, find the winsup/utils directory.  Copy cygmon.cc from this project into that directory.  Merge (carefully) the contents of Makefile.in from the project into the version in that directory.  The effect of the merge is to add _cygmon_ to the list of utilities built as Windows executeables (like _strace_ and _dumper_) rather than Cygwin executeables.  Change directory to the corresponding build location and run _make_.  That will create a cygmon.exe that you can place in /usr/local/bin, for instance.

*Note that this is alpha-quality code, not ready for production use.*
