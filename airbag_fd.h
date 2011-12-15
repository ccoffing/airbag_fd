#ifndef AIRBAG_FD_H
#define AIRBAG_FD_H

/**
 * @file  Drop-in crash handlers for POSIX, particularly embedded Linux.
 *
 * @author Chuck Coffing <clc@alum.mit.edu>
 * @copyright Copyright 2011 Chuck Coffing <clc@alum.mit.edu>, MIT licensed
 *
 * Dumps registers, backtrace, and instruction stream to a file descriptor.  Intended to be
 * self-contained and resilient.  Where possible, will detect and intelligently handle corrupt
 * state, such as jumping through a bad pointer or a blown stack.  The harvesting and reporting
 * of the crash log is left as an exercise for the reader.
 *
 * Define any of the following, if your platform is missing that functionality:
 * - DISABLE_DLADDR
 * - DISABLE_BACKTRACE_SYMBOLS_FD
 * - DISABLE_BACKTRACE
 *
 * C++ users are covered; airbag_fd catches SIGABRT.  By default, std::terminate and
 * std::unexpected abort() the program.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Registers crash handlers to output to the file descriptor.
 * @return 0 iff registered; else errno is set.
 */
int airbag_init_fd(int fd);

/**
 * Registers crash handlers to output to the named file.  The file is created only if and when
 * a crash occurs.
 * @return 0 iff registered; else errno is set.
 */
int airbag_init_filename(const char *filename);

/**
 * Deregisters the crash handlers.
 */
void airbag_deinit();

#ifdef __cplusplus
}
#endif


#endif

