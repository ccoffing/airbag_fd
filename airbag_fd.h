#ifndef AIRBAG_FD_H
#define AIRBAG_FD_H

/**
 * @file  Drop-in crash handlers for POSIX, particularly embedded Linux.
 * @sa https://github.com/ccoffing/airbag_fd
 * @author Chuck Coffing <clc@alum.mit.edu>
 * @copyright Copyright 2011 Chuck Coffing <clc@alum.mit.edu>, MIT licensed
 *
 * Dumps registers, backtrace, and instruction stream to a file descriptor.  Intended to be
 * self-contained and resilient.  Where possible, will detect and intelligently handle corrupt
 * state, such as jumping through a bad pointer or a blown stack.  The harvesting and reporting
 * of the crash log is left as an exercise for the reader.
 *
 * The common case requires no #defines.  Optional defines:
 * - DISABLE_DLADDR
 * - DISABLE_BACKTRACE_SYMBOLS_FD
 * - DISABLE_BACKTRACE
 *
 * Should compile as C or C++.  C++ users are covered; airbag_fd catches SIGABRT.  By default,
 * std::terminate and std::unexpected abort() the program.  Be sure to compile as C++ if you
 * want name demangling.
 *
 * @todo arm: -mpoke-function-name
 * @todo arm: thumb mode
 * @todo arm: http://www.mcternan.me.uk/ArmStackUnwinding/
 * @todo improve GCC's unwind with bad PC, blown stack, etc
 * @todo stop other threads, get their backtraces
 * @todo improve crashes on multiple threads: serialize output
 * @todo if failed to get any backtrace, scan /proc/pid/maps for library offsets
 * @todo test on more OSs: bsd
 * @todo better symbols on x86-64
 * @todo expose airbag_walkstack
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Optional user callback, to print additional state at time of crash (build #, uptime, etc).
 */
typedef void (*airbag_user_callback)(int fd);

/**
 * Extremely simple printf-replacement, which is asynchronous-signal safe.
 * May be used from callback function during crash.  Only supports:
 * - %s for strings,
 * - %x for hex-formatted integers (with optional width specifier),
 * - %u for unsigned integers
 *@return Number of characters written
 */
int airbag_printf(int fd, const char *fmt, ...);

/**
 * Looks up the file name, function name, and offset corresponding to pc.
 * Writes text representation to fd.
 */
void airbag_symbol(int fd, void *pc);

/**
 * Registers crash handlers to output to the file descriptor.
 * @return 0 iff registered; else errno is set.
 */
int airbag_init_fd(int fd, airbag_user_callback cb);

/**
 * Registers crash handlers to output to the named file.  The file is created only if and when
 * a crash occurs.
 * @return 0 iff registered; else errno is set.
 */
int airbag_init_filename(const char *filename, airbag_user_callback cb);

/**
 * Deregisters the crash handlers.
 */
void airbag_deinit();

#ifdef __cplusplus
}
#endif


#endif

