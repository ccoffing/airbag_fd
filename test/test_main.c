#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#ifdef __cplusplus
#include <exception>
#endif

#include "airbag_fd.h"

#define AFD_THRU_LIBC   0x0100
#define AFD_THRU_STATIC 0x0200
#define AFD_THRU_FORK	0x0400
#define AFD_HANG_CB	0x0800
#define AFD_CRASH_CB	0x1000


typedef void (*CrashPtrT)();

int CrashFn1(int how);

int CrashFn3(int how)
{
	int i;
	if (how < 0)
		CrashFn1(how);

	switch (how) {
		case 0:
			for (i = 0; i < 100; ++i) {
				usleep(1000);
			}
			break;
		case 1:
			CrashFn1(how);
			break;
		case 2:
			fprintf(stderr, "!!! writing through bad pointer\n");
			*(int *)0x123 = 0xdeadc0de;
			break;
		case 3:
			fprintf(stderr, "!!! reading through bad pointer\n");
			return *(int *)0x123;
		case 4: {
			CrashPtrT f = (CrashPtrT)0x1;
			fprintf(stderr, "!!! jumping through bad pointer\n");
			f();
			break;
		}
		case 6:
#ifdef __cplusplus
			fprintf(stderr, "!!! throwing unhandled std::exception\n");
			throw std::exception();
#else
			fprintf(stderr, "!!! not compiled as C++ so not throwing exception\n");
#endif
			break;
		case 7: {
			volatile int n = 1;
			volatile int d = 0;
			fprintf(stderr, "!!! division by 0\n");
			fprintf(stderr, "%d\n", n/d);
			break;
		}
	}
	return 42;
}

int CrashFn2(int how)
{
	return CrashFn3(how);
}

int CrashFn1(int how)
{
	return CrashFn2(how);
}

void CallModifiers(int how);
int HangUserCallback = 0;
int CrashUserCallback = 0;

static void StaticFn(int how)
{
	CallModifiers(how);
}

int CmpInts(const void *p1, const void *p2)
{
	int how = *(int*)p1;
	CallModifiers(how);
	return 0;
}

void ForkModifier(int how)
{
	// TODO
}

void UserCallback(int fd)
{
	while (HangUserCallback)
		usleep(1000);
	if (CrashUserCallback)
		*(int *)0x123 = 0xdeadc0de;
}

void CallModifiers(int how)
{
	if (how & AFD_THRU_STATIC) {
		StaticFn(how & ~AFD_THRU_STATIC);
	} else if (how & AFD_THRU_LIBC) {
		how &= ~AFD_THRU_LIBC;
		int a[] = {how, how};
		qsort(&a[0], 2, sizeof(int), CmpInts);
	} else if (how & AFD_THRU_FORK) {
		how &= ~AFD_THRU_FORK;
		ForkModifier(how);
	} else if (how & AFD_HANG_CB) {
		how &= ~AFD_HANG_CB;
		HangUserCallback = 1;
	} else if (how & AFD_CRASH_CB) {
		how &= ~AFD_CRASH_CB;
		CrashUserCallback = 1;
	} else {
		CrashFn1(how);
	}
}

void *CrashMe(void *test)
{
	int t;
	sscanf((char*)test, "%x", &t);
	CallModifiers(t);
	return NULL;
}

void usage()
{
	fprintf(stderr, "airbag_fd_test <crash-number> ...\n");
	fprintf(stderr, "Multiple crash numbers cause additional threads to be started.  Crash numbers\n");
	fprintf(stderr, "consist of a crash type bitwise OR'd with zero or more modifiers.  For example,\n");
	fprintf(stderr, "this test has two threads racing to corrupt a list, one via a libc callback:\n");
	fprintf(stderr, " ./airbag_fd_test 0x309 0x9\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Crash Types:\n");
	fprintf(stderr, "\t  00 no crash; waste time and exit\n");
	fprintf(stderr, "\t  01 recurse and blow the stack\n");
	fprintf(stderr, "\t  02 write through bad pointer\n");
	fprintf(stderr, "\t  03 read through bad pointer\n");
	fprintf(stderr, "\t  04 jump through bad pointer\n");
	fprintf(stderr, "\t  05 jump through NULL class pointer (C++ only)\n");
	fprintf(stderr, "\t  06 throw unhandled std::exception (C++ only)\n");
	fprintf(stderr, "\t  07 divide by 0\n");
	fprintf(stderr, "\t  08 crash in libc\n");
	fprintf(stderr, "\t  09 data race (use multiple threads)\n");
	fprintf(stderr, "\t  0a unmap code\n");
	fprintf(stderr, "\t  0b unload library\n");
	fprintf(stderr, "Test modifiers:\n");
	fprintf(stderr, "\t0100 run test after calling through libc\n");
	fprintf(stderr, "\t0200 run test after calling through static function\n");
	fprintf(stderr, "\t0400 run test after forking\n");
	fprintf(stderr, "\t0800 hang in callback\n");
	fprintf(stderr, "\t1000 crash in callback\n");
	// Test cases:
	// - fork
	// - call through statics
	// - call through stripped library
	// - unmap library while in use
	// - mprotect, no read priv
	// - dereference bad pointer
	// - jump through bad function pointer; PC will be bad; verify can get backtrace
	// - blow the stack; verify still can get backtrace
	// - build without -g; verify can still get backtrace
	// - C++ symbol demangling
	exit(2);
}

int main(int argc, char** argv)
{
	int i;
	if (argc < 2)
		usage();

	fprintf(stderr, "!!! initializing crash handlers\n");
	if (airbag_init_fd(2, UserCallback) != 0) {
		perror("airbag_init_fd");
		exit(3);
	}

	if (argc == 2)
		CrashMe(argv[1]);
	else {
		pthread_t threads[argc-1];
		for (i = 1; i < argc; ++i) {
			pthread_create(&threads[i-1], NULL, CrashMe, (void*)argv[i]);
		}
		for (i = 1; i < argc; ++i) {
			pthread_join(threads[i-1], NULL);
		}
	}

	fprintf(stderr, "!!! deinitializing crash handlers\n");
	airbag_deinit();

	exit(4);
}


