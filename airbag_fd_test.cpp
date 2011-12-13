#include <stdio.h>
#include <stdlib.h>
#include <exception>

#include "airbag_fd.h"


/*
 * Test cases:
 * - dereference bad pointer
 * - jump through bad function pointer; PC will be bad; verify can get backtrace
 * - blow the stack; verify still can get backtrace
 * - build without -g; verify can still get backtrace
 * - C++ symbol demangling
 */

typedef void (*CrashPtrT)();

extern int crashFn1(int how);

extern int crashFn3(int how)
{
    if (how < 0)
        crashFn1(how);

    switch (how) {
        case 0: {
            fprintf(stderr, "!!! writing through bad pointer\n");
            *(int *)0x123 = 0xdeadc0de;
            break;
        }
        case 1: {
            fprintf(stderr, "!!! reading through bad pointer\n");
            return *(int *)0x123;
            break;
        }
        case 2: {
            fprintf(stderr, "!!! jumping through bad pointer\n");
            CrashPtrT f = (CrashPtrT)0x1;
            f();
            break;
        }
        case 3: {
            fprintf(stderr, "!!! throwing unhandled std::exception\n");
            throw std::exception();
            break;
        }
    }
    return 42;
}

extern int crashFn2(int how)
{
    return crashFn3(how);
}

extern int crashFn1(int how)
{
    return crashFn2(how);
}

namespace foo
{

int crashMe(int how)
{
    if (how < 0)
        fprintf(stderr, "!!! blowing the stack\n");
    return crashFn1(how);
}

}

void usage()
{
    fprintf(stderr, "airbag_fd_test <crash-number>\n");
    exit(2);
}


int main(int argc, char** argv)
{
    if (argc < 2)
        usage();

    if (airbag_init_fd(2) != 0) {
        perror("airbag_init_fd");
        exit(3);
    }

    foo::crashMe(atoi(argv[1]));

    exit(4);
}


