#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include "wrapper.hpp"


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
    const bool isFlush = true;
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
        if (isFlush) fflush(_dout);
    }

    void verbose(const char *fmt, ...) {
        if (!_verbose) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_vout, fmt, arg);
        va_end(arg);
        if (isFlush) fflush(_vout);
    }

    void info(const char *fmt, ...) {
        if (!_info) return;
        va_list arg;
        va_start(arg, fmt);
        vfprintf(_iout, fmt, arg);
        va_end(arg);
        if (isFlush) fflush(_iout);
    }

    void print(const char *fmt, ...) {
        va_list arg;
        va_start(arg, fmt);
        vfprintf(stdout, fmt, arg);
        va_end(arg);
        if (isFlush) fflush(stdout);
    }

    void printline(const unsigned char *start, size_t size) {
        size = min(size, (size_t)128);
        printf("size %lx:\t", size);
        for (size_t i = 0; i < size; ++i) {
            printf("(%x) ", *start++);
        }
        printf("\n");
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

uint64_t swap_(uint64_t value, int size) { // rename swap
    if (size == 1) return value;
    if (size == 2) return swap16(value);
    if (size == 3) return swap32(value) >> 8;
    if (size == 4) return swap32(value);
    if (size == 6) return swap64(value) >> 16;
    if (size == 8) return swap64(value);
    printf("error swap value size: %d\n", size); // TODO size = 6
    return value;
}

const char *nums(int start, int size) {
    static char buf[256];
    int n = sprintf(buf, "%d", start);
    for (int i = start + 1; i < start + size; ++i) {
        buf[n++] = ',';
        n += sprintf(buf + n, "%d", i);
    }
    buf[n] = 0;
    return buf;
}

std::string Tag(Ins ins, UINT32 opcount) {
    std::string tag = "";
    for (UINT32 i = 0; i < opcount; ++i) {
        if (ins.isOpReg(i)) {
            tag += "Reg ";
        }
        if (ins.isOpMem(i)) {
            tag += "Mem ";
        }
        if (ins.isOpImm(i)) {
            tag += "Imm ";
        }
        if (ins.isOpImplicit(i)) {
            tag += "Implicit ";
        }
        if (i < opcount - 1)
            tag += ": ";
    }
    return tag;
}

void pp2(Ins ins) {
    printf("%-12lx\t%-32s\tOpCode: %d\tMemOps: %d\tRead: %d Write: %d\t\n", ins.Address(), ins.Name().c_str(), ins.OpCount(), ins.MemCount(), ins.isMemoryRead(), ins.isMemoryWrite());
}

void pp(Ins ins) {
    UINT32 opcount = ins.OpCount();
    OPCODE opcode = ins.OpCode();
    std::string tag = Tag(ins, opcount);
    logger::debug("%-12lx\t%-32s\tOpCode: %d\tMemOps: %d\tRead: %d Write: %d\t", ins.Address(), ins.Name().c_str(), opcode, ins.MemCount(), ins.isMemoryRead(), ins.isMemoryWrite());
    logger::debug("%s ", tag.c_str());
    for (UINT32 i = 0; i < opcount; ++i) {
        if (REG_valid(ins.OpReg(i))) {
            logger::debug("%s\t", REG_StringShort(ins.OpReg(i)).c_str());
        } else {
            logger::debug("---\t");
        }
    }
    REG reg_w = ins.OpReg(0);
    REG reg_r = ins.OpReg(1);
    logger::debug("equal: %d ", reg_w == reg_r);
    logger::debug("\n");
}

#endif