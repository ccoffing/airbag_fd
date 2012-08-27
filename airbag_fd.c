/*
 * Copyright (C) 2011 Chuck Coffing <clc@alum.mit.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <ucontext.h>
#include <stdio.h>
#include <dlfcn.h>
#include <arpa/inet.h>  /* for htonl */
#ifdef __linux__
#include <sys/prctl.h>
#endif
#if !defined(DISABLE_BACKTRACE)
#include <execinfo.h>
#endif

#if defined(__cplusplus)
#include <cxxabi.h>
/*
 * Theoretically might want to disable this, because __cxa_demangle calls malloc/free, which could
 * deadlock or crash when called from signal inside malloc/free.  But pre-malloc a large buffer
 * ahead of time, and that shouldn't actually happen.
 */
#define USE_GCC_DEMANGLE
#endif
#if defined(__GNUC__) && !defined(__clang__)
#include <unwind.h>
#define USE_GCC_UNWIND
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0  /* Supported starting in Linux 2.6.23 */
#endif


typedef void (*airbag_user_callback)(int fd);

static int s_fd = -1;
static const char* s_filename;
static airbag_user_callback s_cb;


#if defined(USE_GCC_DEMANGLE)
static char* s_demangleBuf;
static size_t s_demangleBufLen;
#endif

#define ALT_STACK_SIZE (MINSIGSTKSZ+256*sizeof(void*))  /* or let it all hang out: SIGSTKSZ */
static void* s_altStackSpace;

static const char comment[] = "# ";
static const char section[] = "=== ";
static const char unknown[] = "\?\?\?";
static const char termBt[] = "terminating backtrace";

#define MAX_SIGNALS 32
static const char *sigNames[MAX_SIGNALS] =
{
    /*[0        ] =*/ NULL,
    /*[SIGHUP   ] =*/ "HUP",
    /*[SIGINT   ] =*/ "INT",
    /*[SIGQUIT  ] =*/ "QUIT",
    /*[SIGILL   ] =*/ "ILL",
    /*[SIGTRAP  ] =*/ "TRAP",
    /*[SIGABRT  ] =*/ "ABRT",
    /*[SIGBUS   ] =*/ "BUS",
    /*[SIGFPE   ] =*/ "FPE",
    /*[SIGKILL  ] =*/ "KILL",
    /*[SIGUSR1  ] =*/ "USR1",
    /*[SIGSEGV  ] =*/ "SEGV",
    /*[SIGUSR2  ] =*/ "USR2",
    /*[SIGPIPE  ] =*/ "PIPE",
    /*[SIGALRM  ] =*/ "ALRM",
    /*[SIGTERM  ] =*/ "TERM",
    /*[SIGSTKFLT] =*/ "STKFLT",
    /*[SIGCHLD  ] =*/ "CHLD",
    /*[SIGCONT  ] =*/ "CONT",
    /*[SIGSTOP  ] =*/ "STOP",
    /*[SIGTSTP  ] =*/ "TSTP",
    /*[SIGTTIN  ] =*/ "TTIN",
    /*[SIGTTOU  ] =*/ "TTOU",
    /*[SIGURG   ] =*/ "URG",
    /*[SIGXCPU  ] =*/ "XCPU",
    /*[SIGXFSZ  ] =*/ "XFSZ",
    /*[SIGVTALRM] =*/ "VTALRM",
    /*[SIGPROF  ] =*/ "PROF",
    /*[SIGWINCH ] =*/ "WINCH",
    /*[SIGIO    ] =*/ "IO",
    /*[SIGPWR   ] =*/ "PWR",
    /*[SIGSYS   ] =*/ "SYS"
};

/*
 * Do not use strsignal; it is not async signal safe.
 */
static const char* _strsignal(int sigNum)
{
    return sigNum < 1 || sigNum >= MAX_SIGNALS ? unknown : sigNames[sigNum];
}


#if defined(__x86_64__)
#define NMCTXREGS NGREG
#define MCTXREG(uc, i) (uc->uc_mcontext.gregs[i])
#define MCTX_PC(uc) MCTXREG(uc, 16)
static const char* mctxRegNames[NMCTXREGS] =
{
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RDI", "RSI", "RBP", "RBX",
    "RDX", "RAX", "RCX", "RSP", "RIP", "EFL", "CSGSFS", "ERR", "TRAPNO", "OLDMASK", "CR2"
};
#elif defined(__i386__)
#define NMCTXREGS NGREG
#define MCTXREG(uc, i) (uc->uc_mcontext.gregs[i])
#define MCTX_PC(uc) MCTXREG(uc, 14)
static const char* mctxRegNames[NMCTXREGS] =
{
    "GS", "FS", "ES", "DS", "EDI", "ESI", "EBP", "ESP", "EBX", "EDX",
    "ECX", "EAX", "TRAPNO", "ERR", "EIP", "CS", "EFL", "UESP", "SS"
};
#elif defined(__arm__)
#define NMCTXREGS 21
#define MCTXREG(uc, i) (((unsigned long*)(&uc->uc_mcontext))[i])
#define MCTX_PC(uc) MCTXREG(uc, 18)
static const char* mctxRegNames[NMCTXREGS] =
{
    "TRAPNO", "ERRCODE", "OLDMASK", "R0", "R1", "R2", "R3", "R4", "R5", "R6",
    "R7", "R8", "R9", "R10", "FP", "IP", "SP", "LR", "PC", "CPSR", "FAULTADDR"
};
static const int gregOffset = 3;
#elif defined(__mips__)
#define NMCTXREGS NGREG
#define MCTXREG(uc, i) (uc->uc_mcontext.gregs[i])
#define MCTX_PC(uc) (uc->uc_mcontext.pc)
static const char* mctxRegNames[NMCTXREGS] =
{
    "ZERO", "AT", "V0", "V1", "A0", "A1", "A2", "A3",
#if _MIPS_SIM == _ABIO32
    "T0", "T1", "T2", "T3",
#else
    "A4", "A5", "A6", "A7",
#endif
    "T4", "T5", "T6", "T7",
    "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "T8", "T9", "K0", "K1", "GP", "SP", "FP", "RA"
};
#endif

#if 0
#if defined(__MACH__)
    #if __DARWIN_UNIX03
        #if defined(__i386__)
            pnt = (void*) uc->uc_mcontext->__ss.__eip;
        #elif defined(__arm__)
            /* don't see mcontext in iphone headers... */
        #else
            /* pnt = (void*) uc->uc_mcontext->__ss.__srr0; */
        #endif
    #else
        #if defined(__i386__)
            pnt = (void*) uc->uc_mcontext->ss.eip;
        #elif defined(__arm__)
            /* don't see mcontext in iphone headers... */
        #else
            pnt = (void*) uc->uc_mcontext->ss.srr0;
        #endif
    #endif
#elif defined(__FreeBSD__)
    #if defined(__i386__)
        pnt = (void*) uc->uc_mcontext.mc_eip;
    #elif defined(__x86_64__)
        pnt = (void*) uc->uc_mcontext.mc_rip;
    #endif
#elif (defined (__ppc__)) || (defined (__powerpc__))
    pnt = (void*) uc->uc_mcontext.regs->nip;
#elif defined(__i386__)
    pnt = (void*) uc->uc_mcontext.gregs[REG_EIP];
#elif defined(__x86_64__)
    pnt = (void*) uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__mips__)
#ifdef CTX_EPC  /* Pre-2007 uclibc */
    pnt = (void*) uc->uc_mcontext.gpregs[CTX_EPC];
#else
    pnt = (void*) uc->uc_mcontext.pc;
#endif
#endif
#endif

static uint8_t load8(const void *_p, uint8_t *v)
{
    static int fds[2] = {-1, -1};
    uint8_t b;
    int r;
    const uint8_t *p = (const uint8_t *)_p;

    if (fds[0] == -1) {
        int r = pipe(fds);
        (void)r; /* even on failure, degrades gracefully if memory is readable */
    }

    if (v)
        *v = 0;
    errno = 0;
    while ((r = write(fds[1], p, 1)) < 1 && errno == EINTR)
        ;
    if (r == 1) {
        while ((r = read(fds[0], v ? v : &b, 1)) < 1 && errno == EINTR)
            ;
        if (r == 1)
            return 0;
    }
    if (errno == EFAULT)
        return 0xff;
    if (v)
        *v = *p;  /* Risk it... */
    return 0;
}

static uint32_t load32(const void *_p, uint32_t *_v)
{
    int i;
    uint32_t r = 0;
    uint32_t v = 0;
    const uint8_t *p = (const uint8_t *)_p;
    for (i = 0; i < 4; ++i) {
        uint8_t b;
        r <<= 8;
        v <<= 8;
        r |= load8(p+i, &b);
        v |= b;
    }
    v = htonl(v);
    r = htonl(r);
    if (_v)
        *_v = v;
    return r;
}

static int airbag_write(int fd, const char* buf, size_t len)
{
    while (write(fd, buf, len) == -1 && errno == EINTR)
        ;
    return len;
}

#if defined(__cplusplus)
extern "C"
#endif
int airbag_printf(int fd, const char *fmt, ...)
{
    int chars = 0;
    const int MAXDIGITS = 32;
    char buf[MAXDIGITS];
    va_list ap;
    va_start(ap, fmt);
    while (*fmt) {
        const char *p = strchr(fmt, '%');
        size_t len = p ? (size_t)(p-fmt) : strlen(fmt);
        chars += airbag_write(fd, fmt, len);
        if (p) {
            int width = -1;
            ++p;
            while (*p >= '0' && *p <= '9') {
                width *= (width < 0) ? 0 : 10;
                width += (*p-'0');
                len ++;
                p ++;
            }
            switch (*p) {
                case 's': {
                    const char *s = va_arg(ap, char*);
                    chars += airbag_write(fd, s, strlen(s));
                    len += 2;
                    break;
                }
                case 'x': {
                    unsigned int n = va_arg(ap, unsigned int);
                    int i = MAXDIGITS;
                    buf[--i] = 0;
                    do {
                        unsigned int digit = (n & 0xf);
                        n >>= 4;
                        buf[--i] = (digit>9) ? (digit-10+'a') : (digit+'0');
                    } while (n || width > MAXDIGITS-i-1);
                    chars += airbag_write(fd, buf+i, MAXDIGITS-i-1);
                    len += 2;
                    break;
                }
                case 'u': {
                    unsigned int n = va_arg(ap, unsigned int);
                    int i = MAXDIGITS;
                    buf[--i] = 0;
                    do {
                        int digit = n % 10;
                        n /= 10;
                        buf[--i] = digit+'0';
                    } while (n);
                    chars += airbag_write(fd, buf+i, MAXDIGITS-i-1);
                    len += 2;
                    break;
                }
                default:
                    chars += airbag_write(fd, p-1, 1);
                    len += 1;
                    break;
            }
        }
        fmt += len;
    }
    va_end(ap);
    return chars;
}


static const char* demangle(const char *mangled)
{
    if (! mangled)
        return unknown;
#if defined(USE_GCC_DEMANGLE)
    int status;
    char *newBuf = abi::__cxa_demangle(mangled, s_demangleBuf, &s_demangleBufLen, &status);
    if (newBuf) {
        s_demangleBuf = newBuf;
    }
    if (status == 0)
        return s_demangleBuf;
#endif
    return mangled;
}

#if defined(__cplusplus)
extern "C"
#endif
void airbag_symbol(int fd, void *pc)
{
    int printed = 0;
#if !defined(DISABLE_DLADDR)
    Dl_info info;
    if (dladdr(pc, &info)) {
        int offset = (ptrdiff_t)pc - (ptrdiff_t)info.dli_saddr;
        airbag_printf(fd, "%s(%s+0x%x)[%x]", info.dli_fname, demangle(info.dli_sname), offset, pc);
        printed = 1;
    }
#endif
#if defined(__arm__)
    if (!printed) {
        /* TODO: -mpoke-function-name */
    }
#endif
    if (!printed) {
        airbag_printf(fd, "%s(%s)[%x]", unknown, unknown, pc);
    }
}

#ifdef USE_GCC_UNWIND
struct trace_arg
{
    void **array;
    int cnt;
    int size;
    ucontext_t const *uc;
};

typedef _Unwind_Ptr (*Unwind_GetIP_T) (struct _Unwind_Context *);
typedef _Unwind_Reason_Code (*Unwind_Backtrace_T) (_Unwind_Trace_Fn, void *);
static Unwind_GetIP_T _unwind_GetIP;
static _Unwind_Reason_Code backtrace_helper(struct _Unwind_Context *ctx, void *a)
{
    struct trace_arg *arg = (struct trace_arg*)a;

    /*  We are first called with address in the __backtrace function. Skip it. */
    if (arg->cnt != -1)
        arg->array[arg->cnt] = (void *)_unwind_GetIP(ctx);
    if (++arg->cnt >= arg->size)
        return _URC_END_OF_STACK;
    return _URC_NO_REASON;
}
#endif

static int airbag_walkstack(int fd, void **buffer, int *repeat, int size, ucontext_t *uc)
{
    memset(repeat, 0, sizeof(int)*size);
#if defined(__mips__)
    /* Algorithm derived from:
     * http://elinux.org/images/6/68/ELC2008_-_Back-tracing_in_MIPS-based_Linux_Systems.pdf
     */
    uint32_t *addr, *pc, *ra, *sp;
    unsigned int raOffset, stackSize;
    uint32_t invalid;

    pc = (uint32_t*)uc->uc_mcontext.pc;
    ra = (uint32_t*)uc->uc_mcontext.gregs[31];
    sp = (uint32_t*)uc->uc_mcontext.gregs[29];

    int depth = 0;
    buffer[depth++] = pc;
    if (size == 1)
        return depth;

    /* Scanning to find the size of the current stack frame */
    raOffset = stackSize = 0;
    for (addr = pc; !raOffset | !stackSize; --addr) {
        uint32_t v;
        if (load32(addr, &v)) {
            airbag_printf(fd, "%sText at %x is not mapped; trying prior frame pointer.\n", comment, addr);
            uc->uc_mcontext.pc = (uint32_t)ra;
            goto backward;
        }
        switch (v & 0xffff0000) {
            case 0x27bd0000:  /* addiu   sp,sp,??? */
                stackSize = abs((short)(v & 0xffff));
                airbag_printf(fd, "%s[%08x]: stack size %u\n", comment, addr, stackSize);
                break;
            case 0xafbf0000:  /* sw      ra,???(sp) */
                raOffset = (v & 0xffff);
                airbag_printf(fd, "%s[%08x]: ra offset %u\n", comment, addr, raOffset);
                break;
            case 0x3c1c0000:  /* lui     gp,??? */
                goto out;
            default:
                break;
        }
    }
out:
    if (raOffset) {
        uint32_t *newRa;
        if (load32((uint32_t*)((uint32_t)sp + raOffset), (uint32_t*)&newRa))
            airbag_printf(fd, "%sText at RA <- SP[raOffset] %x[%x] is not mapped; assuming blown stack.\n", comment, sp, raOffset);
        else
            ra = newRa;
    }
    if (stackSize)
        sp = (uint32_t*)((uint32_t)sp + stackSize);

backward:
    while (depth < size && ra) {
        if (buffer[depth-1] == ra)
            repeat[depth-1] ++;
        else
            buffer[depth++] = ra;
        raOffset = stackSize = 0;
        for (addr = ra; !raOffset || !stackSize; --addr) {
            uint32_t v;
            if (load32(addr, &v)) {
                airbag_printf(fd, "%sText at %x is not mapped; %s.\n", comment, addr, termBt);
                return depth;
            }
            switch (v & 0xffff0000) {
                case 0x27bd0000:  /* addiu   sp,sp,??? */
                    stackSize = abs((short)(v & 0xffff));
                    airbag_printf(fd, "%s[%08x]: stack size %u\n", comment, addr, stackSize);
                    break;
                case 0xafbf0000:  /* sw      ra,???(sp) */
                    raOffset = (v & 0xffff);
                    airbag_printf(fd, "%s[%08x]: ra offset %u\n", comment, addr, raOffset);
                    break;
                case 0x3c1c0000:  /* lui     gp,??? */
                    return depth + 1;
                default:
                    break;
            }
        }
        if (load32((uint32_t*)((uint32_t)sp + raOffset), (uint32_t*)&ra)) {
            airbag_printf(fd, "%sText at RA <- SP[raOffset] %x[%x] is not mapped; %s.\n", comment, sp, raOffset, termBt);
            break;
        }
        sp = (uint32_t*)((uint32_t)sp + stackSize);
    }
    return depth;
#elif defined(__arm__)
    uint32_t pc = MCTX_PC(uc);
    uint32_t fp = MCTXREG(uc, 14);
    uint32_t lr = MCTXREG(uc, 17);
    int depth = 0;

    buffer[depth++] = (void*)pc;
    airbag_printf(fd, "%s", comment);
    airbag_symbol(fd, (void*)pc);
    airbag_printf(fd, "\n");

    if (pc&3 || load32((void*)pc, NULL)) {
        airbag_printf(fd, "%sCalled through bad function pointer; assuming PC <- LR.\n", comment);
        pc = MCTX_PC(uc) = lr;
    }

    /* Heuristic for gcc-generated code:
     *  - Know PC, FP for current frame.
     *  - Scan backwards from PC to find the push of prior FP.  This is the function's prologue.
     *  - Sometimes there's a prior push instruction to account for.
     *  - Load registers from start of frame based on the push instruction(s).
     *  - Leaf functions might not push LR.
     */
    while (depth < size) {
        /*
         * CondOp-PUSWLRn--Register-list---
         * 1110100???101101????????????????
         * Unconditional, op is "load/store multiple", "W" bit because SP is updated,
         * not "L" bit because is store, to SP
         */
        const uint32_t stmBits = 0xe82d0000;
        const uint32_t stmMask = 0xfe3f0000;
        int found = 0;
        int i;
        airbag_printf(fd, "%sSearching frame %u (FP=%x, PC=%x)\n", comment, depth-1, fp, pc);
        for (i = 0; i < 8192 && !found; ++i) {
            uint32_t instr, instr2;
            if (load32((void*)(pc-i*4), &instr2)) {
                airbag_printf(fd, "%sInstruction at %x is not mapped; %s.\n", comment, pc-i*4, termBt);
                return depth;
            }
            if ((instr2 & (stmMask | (1<<11))) == (stmBits | (1<<11))) {
                int pushes = 0, dir, pre;
                uint32_t priorPc = lr;  /* If LR was pushed, will find and use that.  For now assume leaf function. */
                uint32_t priorFp;
                found = 1;
                i++;
                if (load32((void*)(pc-i*4), &instr) == 0 && (instr & stmMask) == stmBits) {
                    int regNum;
checkStm:
                    dir = (instr & (1<<23)) ? 1 : -1;  /* U bit: increment or decrement? */
                    pre = (instr & (1<<24)) ? 1 : 0;  /* P bit: pre  TODO */
                    airbag_printf(fd, "%sPC-%2x[%8x]: %8x stm%s%s sp!\n", comment, i*4, pc-i*4, instr,
                            pre==1?"f":"e", dir==1?"a":"d");
                    for (regNum = 15; regNum >= 0; --regNum) {
                        if (instr & (1<<regNum)) {
                            uint32_t reg;
                            if (load32((void*)(fp+pushes*4*dir), &reg)) {
                                airbag_printf(fd, "%sStack at %x is not mapped; %s.\n", comment,
                                        fp+pushes*4*dir, termBt);
                                return depth;
                            }
                            airbag_printf(fd, "%sFP%s%2x[%8x]: %8x {%s}\n", dir==1?"+":"-", comment, pushes*4,
                                    fp+pushes*4*dir, reg, mctxRegNames[gregOffset + regNum]);
                            pushes++;
                            if (regNum == 11)
                                priorFp = reg;
                            else if (regNum == 14)
                                priorPc = reg;
                        }
                    }
                }
                if (instr2) {
                    i--;
                    instr = instr2;
                    instr2 = 0;
                    goto checkStm;
                }
                pc = priorPc;
                fp = priorFp;
            }
        }

        if (! found) {
            airbag_printf(fd, "%sFailed to find prior stack frame; %s.\n", comment, termBt);
            break;
        } else {
            if (buffer[depth-1] == (void*)pc)
                repeat[depth-1] ++;
            else
                buffer[depth++] = (void*)pc;
            airbag_printf(fd, "%s", comment);
            airbag_symbol(fd, (void*)pc);
            airbag_printf(fd, "\n");
        }
    }
    return depth;
#elif defined(USE_GCC_UNWIND)
    /* Not preferred, because doesn't handle blown stack, etc. */
    static Unwind_Backtrace_T _unwind_Backtrace;
    static void *handle;
    if (!handle)
        handle = dlopen("libgcc_s.so.1", RTLD_LAZY);

    if (handle) {
        if (!_unwind_Backtrace)
            _unwind_Backtrace = (Unwind_Backtrace_T)dlsym(handle, "_Unwind_Backtrace");
        if (!_unwind_GetIP)
            _unwind_GetIP = (Unwind_GetIP_T)dlsym(handle, "_Unwind_GetIP");
        if (_unwind_Backtrace && _unwind_GetIP) {
            struct trace_arg arg = { buffer, -1, size, uc };
            if (load8((void*)(MCTX_PC(uc)), NULL)) {
                airbag_printf(fd, "%sText at %x is not mapped; trying prior frame pointer.\n", comment, MCTX_PC(uc));
#if defined(__mips__)
                MCTX_PC(uc) = MCTXREG(uc, 31);  /* RA */
#elif defined(__arm__)
                MCTX_PC(uc) = MCTXREG(uc, 17);  /* LR */
#elif defined(__i386__)
                /* TODO heuristic for -fomit-frame-pointer? */
                uint8_t* fp = (uint8_t*)MCTXREG(uc, 6) + 4;
                uint32_t eip;
                if (load32((void*)fp, &eip)) {
                    airbag_printf(fd, "%sText at %x is not mapped; cannot get backtrace.\n", comment, fp);
                    size = 0;
                } else {
                    MCTX_PC(uc) = eip;
                }
#elif defined(__x86_64__)
                /* TODO x84_64 abi encourages not saving fp */
                size = 0;
#else
                size = 0;
#endif
            }

            if (size >= 1) {
                /* TODO: setjmp, catch SIGSEGV to longjmp back here, to more gracefully handle
                 * corrupted stack. */
                _unwind_Backtrace(backtrace_helper, &arg);
            }
            return arg.cnt != -1 ? arg.cnt : 0;
        }
    }
#elif !defined(DISABLE_BACKTRACE)
    /*
     * Not preferred, because no way to explicitly start at failing PC, doesn't handle
     * bad PC, doesn't handle blown stack, etc.
     */
    return backtrace(buffer, size);
#endif
    return 0;
}


static void printWhere(void* pc)
{
#if !defined(DISABLE_DLADDR)
    Dl_info info;
    if (dladdr(pc, &info)) {
        airbag_printf(s_fd, " in %s\n", demangle(info.dli_sname));
        return;
    }
#endif
    airbag_printf(s_fd, " at %x\n", pc);
}

static void sigHandler(int sigNum, siginfo_t *si, void *ucontext)
{
    ucontext_t *uc = (ucontext_t*)ucontext;
    const uint8_t* pc = (uint8_t*)MCTX_PC(uc);

    if (s_fd == -1 && s_filename)
        s_fd = open(s_filename, O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC|O_SYNC, 0600);
    if (s_fd == -1)
        s_fd = 2;
    int fd = s_fd;

    airbag_printf(fd, "Caught SIG%s (%u)", _strsignal(sigNum), sigNum);
    if (si->si_code == SI_USER)
        airbag_printf(fd, " sent by user %u from process %u\n", si->si_uid, si->si_pid);
    else if (si->si_code == SI_TKILL)
        airbag_printf(fd, " sent by tkill\n");
    else if (si->si_code == SI_KERNEL) {
        airbag_printf(fd, " sent by kernel");  /* rare; well-behaved kernel gives us a real code, handled below */
        printWhere((void*)pc);
    } else {
        printWhere((void*)pc);

        const char* faultReason = 0;
        switch(sigNum) {
            case SIGABRT:
                break;
            case SIGBUS: {
                switch (si->si_code) {
                    case BUS_ADRALN: faultReason = "invalid address alignment"; break;
                    case BUS_ADRERR: faultReason = "nonexistent physical address"; break;
                    case BUS_OBJERR: faultReason = "object-specific hardware error"; break;
                    default: faultReason = "unknown"; break;
                }
                break;
            }
            case SIGFPE: {
                switch (si->si_code) {
                    case FPE_INTDIV: faultReason = "integer divide by zero"; break;
                    case FPE_INTOVF: faultReason = "integer overflow"; break;
                    case FPE_FLTDIV: faultReason = "floating-point divide by zero"; break;
                    case FPE_FLTOVF: faultReason = "floating-point overflow"; break;
                    case FPE_FLTUND: faultReason = "floating-point underflow"; break;
                    case FPE_FLTRES: faultReason = "floating-point inexact result"; break;
                    case FPE_FLTINV: faultReason = "floating-point invalid operation"; break;
                    case FPE_FLTSUB: faultReason = "subscript out of range"; break;
                    default: faultReason = "unknown"; break;
                }
                break;
            }
            case SIGILL: {
                switch (si->si_code) {
                    case ILL_ILLOPC: faultReason = "illegal opcode"; break;
                    case ILL_ILLOPN: faultReason = "illegal operand"; break;
                    case ILL_ILLADR: faultReason = "illegal addressing mode"; break;
                    case ILL_ILLTRP: faultReason = "illegal trap"; break;
                    case ILL_PRVOPC: faultReason = "privileged opcode"; break;
                    case ILL_PRVREG: faultReason = "privileged register"; break;
                    case ILL_COPROC: faultReason = "coprocessor error"; break;
                    case ILL_BADSTK: faultReason = "stack error"; break;
                    default: faultReason = "unknown"; break;
                }
                break;
            }
            case SIGINT:
                break;
            case SIGQUIT:
                break;
            case SIGTERM:
                break;
            case SIGSEGV: {
                switch (si->si_code) {
                    case SEGV_MAPERR: faultReason = "address not mapped to object"; break;
                    case SEGV_ACCERR: faultReason = "invalid permissions for mapped object"; break;
                    default: faultReason = "unknown"; break;
                }
                break;
            }
        }

        if (faultReason) {
            airbag_printf(fd, "Fault at memory location 0x%x", si->si_addr);
            airbag_printf(fd, " due to %s (%x).\n", faultReason, si->si_code);
        }
    }

#if 0
    /*
     * Usually unset and unused on Linux.  Note that strerror it not guaranteed to
     * be async-signal safe (it deals with the locale) so hit the array directly.
     * And yet the array is deprecated.  Bugger.
     */
    if (si->si_errno)
        airbag_printf(fd, "Errno %u: %s.\n", si->si_errno, sys_errlist[si->si_errno]);
#endif

    airbag_printf(fd, "%sContext:\n", section);
    int width = 0;
    int i;
    for (i = 0; i < NMCTXREGS; ++i) {
        if (! mctxRegNames[i])  /* Can trim junk per-arch by NULL-ing name. */
            continue;
        if (i) {
            if (width > 70) {
                airbag_printf(fd, "\n");
                width = 0;
            } else
                width += airbag_printf(fd, " ");
        }
        width += airbag_printf(fd, "%s:%x", mctxRegNames[i], MCTXREG(uc, i));
    }
    airbag_printf(fd, "\n");
#ifdef __linux__
    /* set your thread name with prctl(PR_SET_NAME, (unsigned long)name); */
    {
        char name[17];
        prctl(PR_GET_NAME, name);
        name[sizeof(name)-1] = 0;
        airbag_printf(fd, "Thread name: %s\n", name);
    }
#endif

    {
        const int size = 32;
        void* buffer[size];
        int repeat[size];
        airbag_printf(fd, "%sBacktrace:\n", section);
        int nptrs = airbag_walkstack(fd, buffer, repeat, size, uc);
        for (i = 0; i < nptrs; ++i) {
            airbag_symbol(fd, buffer[i]);
            if (repeat[i])
                airbag_printf(fd, " (called %u times)", repeat[i]+1);
            airbag_printf(fd, "\n");
        }
        /* Reload PC; walkstack may have discovered better state. */
        pc = (uint8_t*)MCTX_PC(uc);
    }

    width = 0;
    ptrdiff_t bytes = 128;
#if defined(__x86_64__) || defined(__i386__)
    const uint8_t* startPc = pc;
    if (startPc < (uint8_t*)(bytes/2))
        startPc = 0;
    else
        startPc = pc - bytes/2;
    const uint8_t* endPc = startPc + bytes;
    const uint8_t* addr;
#else
    pc = (uint8_t*)(((uint32_t)pc) & ~3);
    const uint32_t* startPc = (uint32_t*)pc;
    if (startPc < (uint32_t*)(bytes/2))
        startPc = 0;
    else
        startPc = (uint32_t*)(pc - bytes/2);
    const uint32_t* endPc = (uint32_t*)((uint8_t*)startPc + bytes);
    const uint32_t* addr;
#endif
    airbag_printf(fd, "%sCode:\n", section);
    for (addr = startPc; addr < endPc; ++addr) {
        if (addr != startPc) {
            if (width > 70) {
                airbag_printf(fd, "\n");
                width = 0;
            } else
                width += airbag_printf(fd, " ");
        }
        if (width == 0) {
            airbag_printf(fd, "%x: ", addr);
        }
#if defined(__x86_64__) || defined(__i386__)
        uint8_t b;
        uint8_t invalid = load8(addr, &b);
        if (invalid)
            airbag_printf(fd, "??");
        else
            airbag_printf(fd, "%02x", b);
        width += 2;
#else
        uint32_t w;
        uint32_t invalid = load32(addr, &w);
        int i;
        for (i = 3; i >= 0; --i) {
            int shift = i*8;
            if ((invalid>>shift) & 0xff)
                airbag_printf(fd, "??");
            else
                airbag_printf(fd, "%02x", (w>>shift) & 0xff);
        }
        width += 8;
#endif
    }
    airbag_printf(fd, "\n");

    if (s_cb)
        s_cb(fd);

    /* Do not use abort(): Would re-raise SIGABRT. */
    /* Do not use exit(): Would run atexit handlers. */
    _exit(EXIT_FAILURE);
}

static int initCrashHandlers()
{
#if defined(USE_GCC_DEMANGLE)
    if (! s_demangleBuf) {
        s_demangleBufLen = 512;
        s_demangleBuf = (char*)malloc(s_demangleBufLen);
        if (! s_demangleBuf)
            return -1;
    }
#endif

    if (! s_altStackSpace) {
        stack_t altStack;
        s_altStackSpace = (void*)malloc(ALT_STACK_SIZE);
        if (! s_altStackSpace)
            return -1;
        altStack.ss_sp = s_altStackSpace;
        altStack.ss_flags = 0;
        altStack.ss_size = ALT_STACK_SIZE;
        if (sigaltstack(&altStack, NULL) != 0) {
            free(s_altStackSpace);
            s_altStackSpace = 0;
            return -1;
        }
    }

    sigset_t sigset;
    sigemptyset(&sigset);

    struct sigaction sa;
    sa.sa_sigaction = sigHandler;
    sa.sa_mask = sigset;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

    sigaction(SIGABRT, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGFPE, &sa, 0);

    return 0;
}


static void deinitCrashHandlers()
{
    sigset_t sigset;
    struct sigaction sa;

    sigemptyset(&sigset);

    sa.sa_handler = SIG_DFL;
    sa.sa_mask = sigset;
    sa.sa_flags = 0;

    sigaction(SIGABRT, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGFPE, &sa, 0);

#if defined(USE_GCC_DEMANGLE)
    if (s_demangleBuf) {
        free(s_demangleBuf);
        s_demangleBuf = 0;
    }
#endif
    if (s_altStackSpace) {
        stack_t altStack;
        altStack.ss_sp = 0;
        altStack.ss_flags = SS_DISABLE;
        altStack.ss_size = 0;
        sigaltstack(&altStack, NULL);
        free(s_altStackSpace);
        s_altStackSpace = 0;
    }
}


#if defined(__cplusplus)
extern "C"
#endif
int airbag_init_fd(int fd, airbag_user_callback cb)
{
    s_fd = fd;
    s_filename = 0;
    s_cb = cb;
    return initCrashHandlers();
}

#if defined(__cplusplus)
extern "C"
#endif
int airbag_init_filename(const char *filename, airbag_user_callback cb)
{
    s_fd = -1;
    s_filename = filename;
    s_cb = cb;
    return initCrashHandlers();
}

#if defined(__cplusplus)
extern "C"
#endif
void airbag_deinit()
{
    s_fd = -1;
    s_filename = 0;
    s_cb = 0;
    deinitCrashHandlers();
}

