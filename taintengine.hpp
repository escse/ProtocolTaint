#ifndef _TAINTENGINE_H
#define _TAINTENGINE_H

#include <vector>
#include <map>
#include <cstdint>
#include "util.hpp"

namespace TaintEngine {

// Taint Memory
class Inits {
private:
    struct MemI {
        uint64_t start;
        size_t size;
        uint8_t bytes[128];

        uint64_t begin() {
            return start;
        }

        uint64_t end() {
            return start + size;
        }

        bool valid(uint64_t addr) {
            return addr >= start && addr < start + size;
        }

        uint8_t value(size_t pos) {
            return bytes[pos];
        }

        uint64_t value(uint64_t pos, size_t len, bool bigendian) {
            if (pos + len > size) {
                logger::print("length overflow: pos: %lx, len: %lx, size: %lx\n", pos, len, size);
                debug::error();
            }
            uint64_t value = *(uint64_t*)(bytes + pos);
            switch (len) {
                case 1:     value &= 0xff;              break;
                case 2:     value &= 0xffff;            break;
                case 3:     value &= 0xffffff;          break;
                case 4:     value &= 0xffffffff;        break;
                case 6:     value &= 0xffffffffffff;    break;
                case 8:     break;
                default:    logger::print("length unexpected: pos: %lx, len: %lx, size: %lx\n", pos, len, size);
            }
            if (bigendian) value = swap_(value, len);
            return value;
        }
    };

    std::vector<MemI> inits;

    void taintValue(uint64_t start, size_t size) {
        for (size_t i = 0; i < inits.size(); ++i) { // merge continuous taint memory
            if (inits[i].valid(start)) {
                int offset = start - inits[i].start;
                ValueCopy(inits[i].bytes + offset, start, size);
                logger::printline(inits[i].bytes, inits[i].size);
            }
        }
    }

public:
   int offset(uint64_t addr) {
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr))
                return addr - inits[i].start;
        }
        logger::print("address error in offset: addr: %lx\n", addr);
        return -1;
    }

    bool valid(uint64_t addr) {
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr))
                return true;
        }
        return false;
    }

    // use in exit entry function
    void taint(uint64_t start, size_t size) {
        logger::print("start: %lx, size: %lx, len: %lx\n", start, size, inits.size());
        for (size_t i = 0; i < inits.size(); ++i) { // merge continuous taint memory
            if (start == inits[i].begin()) {
                inits[i].size = size; // TODO
                taintValue(start, size);
                return;
            }
            if (start == inits[i].end()) {
                inits[i].size += size; 
                taintValue(start, size);
                return;
            }
        }
        MemI e = {start, size};
        inits.push_back(e);
        taintValue(start, size);
    }

    uint64_t value(uint64_t addr, size_t size, bool bigendian) {
        for (size_t i = 0; i < inits.size(); ++i) {
            if (inits[i].valid(addr)) {
                return inits[i].value(addr - inits[i].begin(), size, bigendian);
            }
        }
        logger::print("address error in value: addr: %lx, size: %lx\n", addr, size);
        return -1;
    }
};

Inits inits;

class Memory {

public:

    struct MemT {
    private:
        uint64_t src_;
        uint16_t offset_;
        uint8_t size_;
        bool bigendian_;
        bool tainted_;

        void set(uint64_t src, size_t size, bool bigendian, bool tainted) {
            src_ = src;
            size_ = size;
            offset_ = 0;
            bigendian_ = bigendian;
            tainted_ = tainted;
        }

        void clear() {
            src_ = 0;
            size_ = 0;
            offset_ = 0;
            tainted_ = false;
            bigendian_ = false;
        }

    public:

        MemT() {}

        void copy(MemT &rhs) {
            tainted_ = rhs.isTainted();
            src_ = rhs.src();
            offset_ = rhs.offset();
            size_ = rhs.size();
            bigendian_ = rhs.isBigendian();
        }

        inline bool isTainted() {
            return tainted_;
        }

        void taint(uint64_t src, size_t size, bool bigendian) {
            set(src, size - 1, bigendian, true); // mark size
        }

        void untaint() {
            clear();
        }

        inline bool isBigendian() {
            return bigendian_;
        }

        inline uint64_t src() {
            return src_;
        }

        inline size_t offset() {
            if (offset_ == 0) {
                offset_ = inits.offset(src_);
            }
            return offset_;
        }

        inline size_t size() {
            return size_ + 1;   // mark size
        }

        inline uint64_t value(size_t s = 0) {
            if (s == 0) s = size();
            if (s > size()) {
                logger::print("size overflow in value: memory size %lx, input size %lx\n", size(), s);
            }
            return inits.value(src_, s, bigendian_);
        }
        
        const char *debug() {
            static char buf[256];
            int n = sprintf(buf, "memory  :\t\tsrc: %lx, size: %lx, offset: %lx, bigendian: %d, value: %lx\n",  src_, size(), offset(), bigendian_, value());
            buf[n] = 0;
            return buf;
        }
    };

    MemT& get(uint64_t addr, bool init=false) {
        if (memories.count(addr) > 0) {
            return memories[addr];
        }
        if (init) {
            // MemT e; // fuck
            memories[addr] = MemT();
            // memories.insert(std::pair<uint64_t, MemT>(addr, MemT()));
            return memories[addr];
        }
        logger::print("memory invalid addr: %lx\n", addr);
        return empty;
    }

    bool isTainted(uint64_t addr) {
        return memories.count(addr) > 0 && memories[addr].isTainted();
    }

    // init
    void taint(uint64_t start, size_t size) {
        for (uint64_t addr = start; addr < start + size; ++addr) {
            get(addr, true).taint(addr, 1, false);
        }
    }

    void taint(uint64_t addr, uint64_t src, size_t size, bool bigendian) {
        if (size > 1 && (size & 0x01)) {
            logger::print("unexpected size in memory taint: %lx\n", size);
        }
        size_t n = 0;
        while (size > n) {
            get(addr + n, true).taint(src + n, size - n, bigendian);
            n += 2;
        }
    }

    void untaint(uint64_t addr) {
        size_t size = get(addr).size();
        size_t n = 0;
        while (size > n) {
            get(addr + n).untaint();
            n += 2;
        }
    }

    uint64_t src(uint64_t addr) {
        return get(addr).src();
    }

    int offset(uint64_t addr) {
        return get(addr).offset();
    }

    size_t size(uint64_t addr) {
        return get(addr).size();
    }

    uint64_t value(uint64_t addr, size_t size = 0) {
        return get(addr).value(size);
    }
    
    const char *offsets(uint64_t addr) {
        MemT &mem = get(addr);
        return nums(mem.offset(), mem.size());
    }

    const char *debug(uint64_t addr) {
        return get(addr).debug();
    }

private:

    MemT empty;
    std::map<uint64_t, MemT> memories;
};

Memory mems;

// REG

REG reglists[] = {
    REG_RAX, REG_EAX, REG_AX, REG_AH, REG_AL,               // 10, 56, 29, 28, 27, 
    REG_RBX, REG_EBX, REG_BX, REG_BH, REG_BL,               //  7, 53, 38, 37, 36, 
    REG_RCX, REG_ECX, REG_CX, REG_CH, REG_CL,               //  9, 55, 32, 31, 30, 
    REG_RDX, REG_EDX, REG_DX, REG_DH, REG_DL,               //  8, 54, 35, 34, 33, 
    REG_RDI, REG_EDI, REG_DI, REG_DIL, REG_INVALID_,        //  3, 45, 41, 46,  0, 
    REG_RSI, REG_ESI, REG_SI, REG_SIL, REG_INVALID_,        //  4, 47, 40, 48,  0, 
    REG_R8, REG_R8D, REG_R8W, REG_R8B, REG_INVALID_,        // 11, 61, 60, 59,  0,
    REG_R9, REG_R9D, REG_R9W, REG_R9B, REG_INVALID_,        // 12, 64, 63, 62,  0,  
    REG_R10, REG_R10D, REG_R10W, REG_R10B, REG_INVALID_,    // 13, 67, 66, 65,  0, 
    REG_R11, REG_R11D, REG_R11W, REG_R11B, REG_INVALID_,    // 14, 70, 69, 68,  0, 
    REG_R12, REG_R12D, REG_R12W, REG_R12B, REG_INVALID_,    // 15, 73, 72, 71,  0, 
    REG_R13, REG_R13D, REG_R13W, REG_R13B, REG_INVALID_,    // 16, 76, 75, 74,  0, 
    REG_R14, REG_R14D, REG_R14W, REG_R14B, REG_INVALID_,    // 17, 79, 78, 77,  0, 
    REG_R15, REG_R15D, REG_R15W, REG_R15B, REG_INVALID_     // 18, 82, 81, 80,  0    
};


const char* regNames[] = { 
    "RAX", "EAX" , "AX"  , "AH"  , "AL",
    "RBX", "EBX" , "BX"  , "BH"  , "BL",
    "RCX", "ECX" , "CX"  , "CH"  , "CL",
    "RDX", "EDX" , "DX"  , "DH"  , "DL",
    "RDI", "EDI" , "DI"  , "DIL" , "Invalid",
    "RSI", "ESI" , "SI"  , "SIL" , "Invalid",
    "R8" , "R8D" , "R8W" , "R8B" , "Invalid",
    "R9" , "R9D" , "R9W" , "R9B" , "Invalid",
    "R10", "R10D", "R10W", "R10B", "Invalid",
    "R11", "R11D", "R11W", "R11B", "Invalid",
    "R12", "R12D", "R12W", "R12B", "Invalid",
    "R13", "R13D", "R13W", "R13B", "Invalid",
    "R14", "R14D", "R14W", "R14B", "Invalid",
    "R15", "R15D", "R15W", "R15B", "Invalid",
};

uint16_t indexOf(REG id) {
    for (uint16_t i = 0; i < sizeof(reglists) / sizeof(REG); ++i) {
        if (reglists[i] == id) {
            return i;
        }
    }
    printf("error index of reg: %d\n", id);
    return -1;
}




class Register {

public:
    struct RegT {
    private:        
        uint64_t src_;
        int8_t shift_;
        uint8_t size_;
        bool tainted_;
        bool bigendian_;
        uint16_t index_;
        uint16_t offset_;

        void set(uint64_t src, size_t size, bool bigendian, int shift, bool tainted) {
            src_ = src;
            size_ = size;
            bigendian_ = bigendian;
            shift_ = shift;
            tainted_ = tainted;
            offset_ = 0;
        }

        void clear() {
            src_ = 0;
            size_ = 0;
            offset_ = 0;
            tainted_ = false;
            bigendian_ = false;
            shift_ = 0;
        }

        int lower() const {
            return shift_;
        }

        int upper() const {
            return shift_ + size_;
        }

        const char *name() {
            return regNames[index_];
        }

    public:

        RegT() {index_ = 3;};

        RegT(uint16_t index): index_(index) {};

        void copy(RegT &rhs) {
            src_ = rhs.src();
            shift_ = rhs.shift();
            size_ = rhs.size() - 1; // mark size
            offset_ = 0;
            tainted_ = rhs.isTainted();
            bigendian_ = rhs.isBigendian();
        }

        void taint(uint64_t src, size_t size,  bool bigendian, int shift) {
            set(src, size - 1, bigendian, shift, true); // mark size
        }

        void untaint() {
            clear();
        }

        inline bool isTainted() {
            return tainted_;
        }

        inline bool isBigendian() {
            return bigendian_;
        }

        void setBigendian(bool b) {
            bigendian_ = b;
        }

        inline uint64_t src() {
            return src_;
        }
        
        inline size_t offset() {
            if (offset_ == 0) {
                offset_ = inits.offset(src_);
            }
            return offset_;
        }

        size_t size() {
            const static size_t table[5] = {8, 4, 2, 1, 1};
            size_t regsize = table[index_ % 5];
            size_t size = size_ + 1;
            if (regsize < size) {
                logger::print("%s reg size unmatch, reg size %lx, size %lx\n", name(), regsize, size);
                return regsize;
            }
            return size;
        }
        
        uint64_t value(size_t s = 0) {
            if (s == 0) s = size();
            if (s > size()) {
                logger::print("reg %s size overflow in value: size %lx, input size %lx\n", name(), size(), s);
            }
            uint64_t ret = inits.value(src_, s, bigendian_);
            if (shift_ > 0) {
                ret <<= 8 * shift_;
            } else if (shift_ < 0) {
                ret >>= 8 * shift_;
            }
            return ret;
        }

        bool adjacent(const RegT &rhs) {
            return (lower() - rhs.upper() == 1 || rhs.lower() - upper() == 1);
        }

        size_t index() {
            return index_;
        }

        int shift() {
            return shift_;
        }

        void setShift(int shift) {
            shift_ = shift;
        }

        void lshift(int8_t s) {
            shift_ += s / 8;
        }

        void rshift(int8_t s) {
            shift_ -= s / 8; // modify minus
        }

        const char *debug() {
            static char buf[256];
            int n = sprintf(buf, "register %s:\tsrc: %lx, size: %lx, offset: %lx, bigendian: %d, value: %lx, shift: %d\n", name(), src_, size(), offset(), bigendian_, value(), shift_);
            buf[n] = 0;
            return buf;
        }
    };

    RegT &get(REG id) {
        if (registers.count(id) > 0) {
            return registers[id];
        }
        RegT e(indexOf(id));
        registers[id] = e;
        return registers[id];
    }

    bool isTainted(REG id) {
        return registers.count(id) > 0 && registers[id].isTainted();
    }

    void taint(REG id, uint64_t src, size_t size, bool bigendian, int shift) {
        get(id).taint(src, size, bigendian, shift);
    }

    void untaint(REG id) {
        int index = get(id).index() / 5 * 5;
        for (int i = 0; i < 5; ++i) {
            id = reglists[index + i];
            if (id == 0) continue;
            get(id).untaint();
        }
    }
  
    uint64_t src(REG id) {
        return get(id).src();
    }

    int offset(REG id) {
        return get(id).offset();
    }

    size_t size(REG id) {
        return get(id).size();
    }

    uint64_t value(REG id, size_t size = 0) {
        return get(id).value(size);
    }
    
    const char *offsets(REG id) {
        RegT &reg = get(id);
        return nums(reg.offset(), reg.size());
    }

    const char *debug(REG id) {
        return get(id).debug();
    }

private:
    
    RegT empty;
    // RegT regs[REG_LAST];
    std::map<REG, RegT> registers;
};

Register regs;

// API

bool isTainted(REG reg) {
    return regs.isTainted(reg);
}

bool isTainted(uint64_t addr) {
    return mems.isTainted(addr);
}

const char *offsets(REG reg) {
    return regs.offsets(reg);
}

const char *offsets(uint64_t addr) {
    return mems.offsets(addr);
}

const char *debug(REG reg) {
    return regs.debug(reg);
}

const char *debug(uint64_t addr) {
    return mems.debug(addr);
}

uint64_t src(REG reg) {
    return regs.src(reg);
}

uint64_t src(uint64_t addr) {
    return mems.src(addr);
}

// init
// use in exit entry point
void Init(size_t start, size_t size) {
    logger::debug("[TAINT]\t %lx bytes tainted from 0x%lx to 0x%lx\n", size, start, start+size);
    inits.taint(start, size);
    mems.taint(start, size);
}

// move
void move(REG w, REG r) {
    int index = regs.get(w).index() / 5 * 5;
    for (int i = 0; i < 5; ++i) {
        REG id = reglists[index + i]; 
        if (id == 0) continue;
        regs.get(id).copy(regs.get(r));
    }
}


void move(REG id, uint64_t addr, size_t size) {
    // if (memories[addr].src != addr) {
    //     size = min(size, Size(addr));
    // }
    Memory::MemT &mem = mems.get(addr, true);
    int index = regs.get(id).index() / 5 * 5;
    if (!inits.valid(addr)) {
        size = min(size, mem.size());
    }
    for (int i = 0; i < 5; ++i) {
        id = reglists[index + i];
        if (id == 0) continue;
        Register::RegT &reg = regs.get(id);
        reg.taint(mem.src(), size, mem.isBigendian(), 0);
    }
}


void move(uint64_t addr, REG id, size_t size) {
    Memory::MemT &mem = mems.get(addr, true);
    Register::RegT &reg = regs.get(id);
    mem.taint(reg.src(), min(size, reg.size()), reg.isBigendian()); // regsize < size
}


void move(uint64_t w, uint64_t r, size_t size) {
    Memory::MemT &mem_w = mems.get(w, true);
    Memory::MemT &mem_r = mems.get(r);
    if (!inits.valid(r)) {
        size = min(size, mem_r.size());
    }
    mem_w.taint(mem_r.src(), size, mem_r.isBigendian());
}


// remove

void remove(uint64_t addr) {
    mems.untaint(addr);
}

void remove(REG id) {
    regs.untaint(id);
}

// add
bool merge(REG w, REG r) {
    if (w == r) return false;
    Register::RegT &lhs = regs.get(w);
    Register::RegT &rhs = regs.get(r);
    int diff_shift = lhs.shift() - rhs.shift();
    int diff_src = lhs.src() - rhs.src();
    if (abs(diff_src) > 3 || !lhs.adjacent(rhs)) {
        return false;
    }
    logger::debug("before\n%s", regs.debug(w));
    logger::debug("%s", regs.debug(r));

    bool bigendian = lhs.isBigendian();
    uint64_t src = min(lhs.src(), rhs.src());
    int shift = min(lhs.shift(), rhs.shift());
    size_t size = lhs.size() + rhs.size();
    if ((diff_src > 0 && diff_shift < 0) || (diff_src < 0 && diff_shift > 0)) {
        bigendian = true;
    }

    int index = regs.get(w).index() / 5 * 5;
    for (int i = 0; i < 5; ++i) {
        REG id = reglists[index + i];
        if (id == 0) continue;
        regs.get(id).taint(src, size, bigendian, shift);
    }
    logger::debug("after\n%s", regs.debug(w));
    return true;
}

void shift(REG id, int offset) { // type
    int index = regs.get(id).index() / 5 * 5;
    for (int i = 0; i < 5; ++i) {
        id = reglists[index + i];
        if (id == 0) continue;
        Register::RegT &reg = regs.get(id);
        if (offset >= 0) {
            reg.lshift(offset);
        } else {
            reg.rshift(-offset);
        }
    }
}

// void and(REG id, size_t mask) { // TODO
//     if (mask == 0xff) {

//     } else if (mask == 0xff00) {

//     } else {
//         printf("unhandle mask %lx\n", mask);
//     }
// }

} // namespace TaintTrackEngine end

#endif