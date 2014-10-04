# airbag_fd

_Drop-in crash handlers for POSIX, particularly embedded Linux._

Copyright 2011-2014 Chuck Coffing <clc@alum.mit.edu>, MIT licensed

https://github.com/ccoffing/airbag_fd

Dumps registers, backtrace, and instruction stream to a file descriptor.
Intended to be self-contained and resilient.  Where possible, will detect and
intelligently handle corrupt state, such as jumping through a bad pointer or a
blown stack.  The harvesting and reporting of the crash log is left as an
exercise for the reader.

## Quick start:

1. Include `airbag_fd.c` and `airbag_fd.h` in your project.
2. If it doesn't build, define the appropriate `DISABLE_*` flag(s).
3. Call one of the `airbag_init_*` functions early, to accept crash data via a
   file descriptor.
4. Post-crash (perhaps in a watchdog or on next startup) harvest crash logs.

## Design

All of airbag_fd's crash-gathering work is intended to be async-signal safe.  In
fact, the fundamental design is influenced by the fact that writing to file
descriptors is async-signal safe, but many higher-level functions are not.
(See http://man7.org/linux/man-pages/man7/signal.7.html.)

One common design may be to exec a watchdog process early, which opens a
crash-handling file descriptor and then fork/execs the main child process,
passing the listening file descriptor to the child process, which then calls
`airbag_init_fd` with that file descriptor.  Even if the child crashes
horribly, the watchdog can gather the crash, report it, and possibly re-exec
the child.

## Compatibility

airbag_fd is intended to compile cleanly under various C and C++ standards and
compilers.  Tested semi-regularly on combinations of:

- C89
- C99
- C++98
- C++03
- clang
- gcc
- x86 Linux
- x64 Linux
- ARM Linux

Rarely tested on:

- MIPS Linux
- FreeBSD
- MacOS
- C++0x
- ...

Help welcome anywhere.

## Notes:

### Linux x86:

(none)

### Linux x64:

Currently no heuristics for trashed stack (x86_64 ABI encourages not saving
FP).

### mips:

(none)

### arm:

Optionally build your application with `-mpoke-function-name` for more readable
backtraces.
