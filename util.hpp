#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <cxxabi.h> // for demangle
#include "config.hpp"

namespace monitor {

bool _start = false;
bool _end   = false;

inline bool valid() {
    return _start && !_end;
} 

inline bool invalid() {
    return !_start || _end;
} 

inline void start() {
    _start = true;
}

inline void end() {
    _end = true;
}
} // monitor namespace end

namespace logger {


bool _debug = false;
FILE *_dout = stdout;
bool _verbose = false;
FILE *_vout = stdout;
bool _info = false;
FILE *_iout = stdout;

void setDebug(bool b, FILE *out=stdout) {_debug = b; _dout = out;}
void setVerbose(bool b, FILE *out=stdout) {_verbose = b; _vout = out;}
void setInfo(bool b, FILE *out=stdout) {_info = b; _iout = out;}


void debug(const char *fmt, ...) {
    if (!_debug) return;
    va_list arg;
    va_start(arg, fmt);
    vfprintf(_dout, fmt, arg);
    va_end(arg);
    if (config::isFlush) fflush(_dout);
}

void verbose(const char *fmt, ...) {
    if (!_verbose) return;
    va_list arg;
    va_start(arg, fmt);
    vfprintf(_vout, fmt, arg);
    va_end(arg);
    if (config::isFlush) fflush(_vout);
}

void info(const char *fmt, ...) {
    if (!_info) return;
    va_list arg;
    va_start(arg, fmt);
    vfprintf(_iout, fmt, arg);
    va_end(arg);
    if (config::isFlush) fflush(_iout);
}

void print(const char *fmt, ...) {
    if (!config::print) return;
    va_list arg;
    va_start(arg, fmt);
    vfprintf(stderr, fmt, arg);
    va_end(arg);
    if (config::isFlush) fflush(stdout);
}

void printline(const unsigned char *start, size_t size) {
    if (!config::print) return;
    size = min(size, (size_t)128);
    fprintf(stderr, "size %lx:\t", size);
    for (size_t i = 0; i < size; ++i) {
        fprintf(stderr, "(%x) ", *start++);
    }
    fprintf(stderr, "\n");
}

} // log namespace end


namespace debug {

const char *assembly = NULL;
// char assembly[256];
unsigned long address = 0;

void log(unsigned long address_, const char *assembly_) {
    address = address_;
    assembly = assembly_;
}

void error() {
    printf("error : %lx\t:%s\n", address, assembly);
}

void info() {
    logger::info("error : %lx\t:%s\n", address, assembly);
}

void debug() {
    logger::debug("error : %lx\t:%s\n", address, assembly);
}

} // end of namespace debug


namespace util {

inline ADDRINT Value(UINT64 mem, size_t size) { // a bit weird
    ADDRINT value;
    PIN_SafeCopy((void*)(&value), (void *)mem, sizeof(ADDRINT));
    switch (size) {
        case 1:     value &= 0xff;          break;
        case 2:     value &= 0xffff;        break;
        case 4:     value &= 0xffffffff;    break;
    }
    return value;
}

inline void ValueCopy(void *dst, uint64_t addr, size_t size) {
    PIN_SafeCopy(dst, (void *)addr, size);
}

#define swap16(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define swap32(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define swap64(n) (((((unsigned long long)(n) & 0xFF)) << 56) | \
                  ((((unsigned long long)(n) & 0xFF00)) << 40) | \
                  ((((unsigned long long)(n) & 0xFF0000)) << 24) | \
                  ((((unsigned long long)(n) & 0xFF000000)) << 8) | \
                  ((((unsigned long long)(n) & 0xFF00000000)) >> 8) | \
                  ((((unsigned long long)(n) & 0xFF0000000000)) >> 24) | \
                  ((((unsigned long long)(n) & 0xFF000000000000)) >> 50) | \
                  ((((unsigned long long)(n) & 0xFF00000000000000)) >> 56)) 

uint64_t swap(uint64_t value, int size) {
    if (size == 1) return value;
    if (size == 2) return swap16(value);
    if (size == 3) return swap32(value) >> 8;
    if (size == 4) return swap32(value);
    if (size == 6) return swap64(value) >> 16;
    if (size == 8) return swap64(value);
    printf("error swap value size: %d\n", size);
    return value;
}

const char *nums(int start, int size) {
    static char buf[256];
    int n = snprintf(buf, sizeof(buf), "%d", start);
    for (int i = start + 1; i < start + size; ++i) {
        buf[n++] = ',';
        n += snprintf(buf + n, sizeof(buf) - n, "%d", i);
    }
    buf[n] = 0;
    return buf;
}


void assert(bool a, const char *info=0) {
    if (!a) {
        logger::debug("assert error %s\n", (info > 0) ? info: "");
    }
}


const char *demangle(const char *name) {
    if (!config::demangle) return name;
    const static int maxsize = 256;
    static char buf[maxsize];
    int status;
    char *realname = abi::__cxa_demangle(name, 0, 0, &status);
    if (!status) {
        int size = strlen(realname);
        if (size > maxsize) size = maxsize;
        memcpy(buf, realname, size);
        free(realname);
        return buf;
    } else {
        free(realname);
        return name;
    }
}

const char *displayRegs(CONTEXT *ctx) {
    static char buf[512];
    int n = 0;
    n += sprintf(buf + n, "+--------------------------------------------------------------------------+\n");
    n += sprintf(buf + n, " RAX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX));
    n += sprintf(buf + n, " RBX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX));
    n += sprintf(buf + n, " RCX = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX));
    n += sprintf(buf + n, " RDX = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX));
    n += sprintf(buf + n, " RDI = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI));
    n += sprintf(buf + n, " RSI = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI));
    n += sprintf(buf + n, " RBP = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP));
    n += sprintf(buf + n, " RSP = 0x%-16lx ",  PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP));
    n += sprintf(buf + n, " RIP = 0x%-16lx\n", PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP));
    n += sprintf(buf + n, "+--------------------------------------------------------------------------+\n");
    buf[n] = 0;
    return buf;
}


} // end of namespace util


namespace filter {

const char *entry = "entry";
const char *exit = "exit";

bool read(int fd, uint64_t addr, size_t size) {
    bool ret = (fd <= 2 || fd > 10 || addr <= 0x100 || size <= 2 || size >= 1024) // default pass rule
        || (config::read_size_flag && (size < config::read_size_min || size > config::read_size_max))
        || (config::read_fd_flag && (fd < config::read_fd_min || fd > config::read_fd_max));
    if (ret) {
        logger::print("filter read: fd: %d, addr: %lx, size: %lx\n", fd, addr, size);
    }
    return ret;
}


bool function(const char *name) {
    size_t n = sizeof(config::functions) / sizeof(const char *);

    for (size_t i = 0; i < n; ++i) {
        if (strcmp(config::functions[i], name) == 0) {
            logger::print("filter function: %s\n", name);
            return true;
        }
    }
    return false;
}


bool libs(const std::string &name) {
    size_t n = sizeof(config::libs) / sizeof(const char *);

    for (size_t i = 0; i < n; ++i) {
        if (name.find(config::libs[i]) != std::string::npos) {
            logger::print("filter libs: %s\n", name.c_str());
            return true;
        }
    }
    return false;
}


bool taint_start() {
    if (!config::use_interactive) return true;
    static bool ret = false;
    if (ret) return ret;
    printf("taint start?[y/n]");
    char c = getchar();
    getchar(); // for \n
    if (c == 'y') {
        printf("taint start\n");
        ret = true;
        return true;
    }
    return false;
}

}// end of namespace filter

#endif