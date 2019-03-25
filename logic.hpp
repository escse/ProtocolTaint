#ifndef _TAINTLOGIC_H
#define _TAINTLOGIC_H

#include "pin.H"
#include "taintengine.hpp"
#include "util.hpp"
#include "pinobject.hpp"

// IARG_MEMORYWRITE_SIZE
// IARG_FUNCARG_ENTRYPOINT_VALUE, 0 函数参数


std::vector<std::vector<std::string> > functraces;
std::vector<int> threadIds;
std::vector<std::string> plts;


void printTrace(int index) {
    std::vector<std::string>::iterator it;
    for (it = functraces[index].begin(); it != functraces[index].end(); ++it) {
        logger::debug("%s -> ", (*it).c_str());
    }
    logger::debug("\n");
}


void function_entry(int threadId, const std::string* name) {
    if (*name == config::start_entry) monitor::start();
    if (monitor::invalid()) return;
    if (name->find("@plt") != std::string::npos) {
        plts.push_back(*name);
        logger::debug("thread id: %d, enter function: %s\n", threadId, util::demangle(name->c_str()));
        logger::debug("thread id: %d, exit function: %s\n", threadId, util::demangle(name->c_str()));
        return;
    }
    const int size = threadIds.size();
    std::vector<int>::iterator it = find(threadIds.begin(), threadIds.end(), threadId);
    int index = it - threadIds.begin();
    if (index == size) {
        threadIds.push_back(threadId);
        functraces.push_back(std::vector<std::string>());
    }
    functraces[index].push_back(*name);
    logger::debug("thread id: %d, enter function: %s\n", threadId, util::demangle(name->c_str()));
    logger::info("enter\t%s\n", util::demangle(name->c_str()));
    // printTrace(index);
}


void function_exit(int threadId, const std::string* name) {
    if (monitor::invalid()) return;
    std::vector<int>::iterator it = find(threadIds.begin(), threadIds.end(), threadId);
    unsigned int index = it - threadIds.begin();
    if (index == threadIds.size()) { logger::debug("error\n"); return;}

    // while (!functraces[index].empty() && functraces[index].back() != *name) {
    //     functraces[index].pop_back();    
    // }

    util::assert(functraces[index].back() == *name);
    functraces[index].pop_back();
    
    logger::debug("thread id: %d, exit  function: %s\n", threadId, util::demangle(name->c_str()));
    logger::info("exit\t%s\n", util::demangle(name->c_str()));
        // printTrace(index);
    if (*name == config::start_entry) monitor::end();
}

const char *printinfo[2][2] = {{ "", "+  taint  +"}, {"- untaint -", "* retaint *"}};


void Syscall_point(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (!monitor::valid()) return;
    const char *point = (const char *)v;
    ADDRINT number = PIN_GetSyscallNumber(ctx, std);
    logger::print("system number: 0x%lx in %s\n", number, point);
    if (number == __NR_read) {
        int fd          = static_cast<int>((PIN_GetSyscallArgument(ctx, std, 0)));
        uint64_t start  = static_cast<uint64_t>((PIN_GetSyscallArgument(ctx, std, 1)));
        size_t size     = static_cast<size_t>((PIN_GetSyscallArgument(ctx, std, 2)));
        if (filter::read(fd, start, size)) return;
        logger::print("%s read: fd: %d, start: 0x%lx, size: 0x%lx\n", point, fd, start, size);
        if (!filter::taint_start()) return;
        logger::debug("[TAINT]\t 0x%lx bytes tainted from 0x%lx to 0x%lx (via read %s fd: %d)\n", size, start, start+size, point, fd);
        TaintEngine::Init(start, size);
    }
}


void read_point(const char *point, int fd, uint64_t buffer, size_t length, ssize_t ret) {
    static int _fd;
    static uint64_t _buffer;
    static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _fd = fd;
        _buffer = buffer;
        _length = length;
    }

    if (filter::read(_fd, _buffer, _length)) return;

    if (point == filter::exit) {
        logger::print("read(fd: %d, buffer: %p, length: 0x%lx) => %zd\n", _fd, _buffer, _length, ret);
        logger::debug("[TAINT]\t 0x%lx bytes tainted from 0x%lx to 0x%lx (via recv socket: %d)\n", _length, _buffer, _buffer+_length, _fd);
        TaintEngine::Init(_buffer, _length);
    }
}


void recv_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, ssize_t ret) {
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }
    if (filter::read(_socket, _buffer, _length)) return;
    
    if (point == filter::exit) {
        logger::print("recv(socket: %d, buffer: %p, length: 0x%lx, flags: %d) => %zd\n", _socket, _buffer, _length, _flags, ret);
        logger::debug("[TAINT]\t 0x%lx bytes tainted from 0x%lx to 0x%lx (via recv socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
        TaintEngine::Init(_buffer, _length);
    }
}


void recvfrom_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len, ssize_t ret){
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }

    if (filter::read(_socket, _buffer, _length)) return;
    
    if (point == filter::exit) {
        logger::print("recvfrom(socket: %d, buffer: %p, length: 0x%lx, flags: %d) => %zd\n", _socket, _buffer, _length, _flags, ret);
        logger::debug("[TAINT]\t 0x%lx bytes tainted from 0x%lx to 0x%lx (via recvfrom socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
        TaintEngine::Init(_buffer, _length);
    }
}


void recvmsg_point(const char *point, int socket, struct msghdr* mhdr, int flags, ssize_t ret) {
    static int _socket;
    static struct msghdr* _mhdr;
    static int _flags;
    static uint64_t _buffer;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _mhdr = mhdr;
        _flags = flags;
        _buffer = (uint64_t) mhdr->msg_iov[0].iov_base;
        // size_t len = message->msg_iovlen;
    }

    if (point == filter::exit) {
        ssize_t _length = ret;
        if (filter::read(_socket, _buffer, _length)) return;
        if (_length > 0) {
            logger::print("recvmsg(socket: %d, mhdr: %p, flags: %d) => %zd\n", _socket, _mhdr, _flags, _length);
            logger::debug("[TAINT]\t 0x%lx bytes tainted from 0x%lx to 0x%lx (via recvmsg socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
            TaintEngine::Init(_buffer, _length);
        }
    }
}


void memcpy_point(const char *point, uint64_t dst, UINT64 src, size_t size) {
    if (!monitor::valid()) return;
    
    for (size_t i = 0; i < size;) {
        if (TaintEngine::isTainted(src + i)) {
            size_t s = i;
            while (i < size && TaintEngine::isTainted(src + i)) ++i;
            logger::print("memcpy(dst: %p, src: %p, size: 0x%lx)\n", dst + s, src + s, i - s);
            logger::debug("[COPY]\t 0x%lx bytes from 0x%lx to 0x%lx (via memcpy)\n", i - s, src + s, dst + s);
            TaintEngine::Init(dst + s, i - s);
        } else {
            ++i;
        }
    }
}


// reg <- mem
void ReadMem(const std::string* assembly, unsigned long address, REG reg, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    ADDRINT value = util::Value(mem, size);
    if (taint_r) { // retaint
        logger::debug("[Reg <- Mem %s]\t0x%lx: %s\t addr: 0x%lx value: (0x%lx, 0x%lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem, TaintEngine::src(mem), value);
        logger::debug("%s", TaintEngine::debug(mem));
        TaintEngine::move(reg, mem, size);
        logger::debug("%s", TaintEngine::debug(reg));

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(mem), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Reg <- Mem %s]\t0x%lx: %s\t addr: 0x%lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem);
        logger::debug("%s", TaintEngine::debug(reg));

        TaintEngine::remove(reg);
    }
    logger::debug("\n");
}

// mem <- reg
void WriteMem(const std::string* assembly, unsigned long address, UINT64 mem, REG reg, ADDRINT value, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    if (taint_r) { // retaint
        logger::debug("[Mem <- Reg %s]\t0x%lx: %s\t addr: 0x%lx value: (0x%lx, 0x%lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem, TaintEngine::src(reg), value);
        logger::debug("%s", TaintEngine::debug(reg));
        TaintEngine::move(mem, reg, size); // change src
        logger::debug("%s", TaintEngine::debug(mem));

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Mem <- Reg %s]\t0x%lx: %s\t addr: 0x%lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem);
        logger::debug("before: %s", TaintEngine::debug(mem));

        TaintEngine::remove(mem);
    }
    logger::debug("\n");
}

// reg <- reg
void spreadReg(const std::string* assembly, unsigned long address, REG reg_w, REG reg_r, ADDRINT value) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    if (taint_r) { // retaint
        logger::debug("[Reg <- Reg %s]\t0x%lx: %s value: (0x%lx, 0x%lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), TaintEngine::src(reg_r), value);
        logger::debug("%s", TaintEngine::debug(reg_r));
        TaintEngine::move(reg_w, reg_r);
        logger::debug("%s", TaintEngine::debug(reg_w));

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg_r), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Reg <- Reg %s]\t0x%lx: %s\n", printinfo[taint_w][taint_r], address, assembly->c_str());
        logger::debug("before: %s", TaintEngine::debug(reg_w));

        TaintEngine::remove(reg_w);
    }
    logger::debug("\n");
}

// mem <- mem
void spreadMem(const std::string* assembly, unsigned long address, UINT64 mem_w, UINT64 mem_r, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(mem_w);
    bool taint_r = TaintEngine::isTainted(mem_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    ADDRINT value = util::Value(mem_r, size);
    if (taint_r) { // retaint
        logger::debug("[Mem <- Mem %s]\t0x%lx: %s\t mem_w: 0x%lx mem_r: 0x%lx value: (0x%lx, 0x%lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem_w, mem_r, TaintEngine::src(mem_r), value);
        logger::debug("%s", TaintEngine::debug(mem_r));
        TaintEngine::move(mem_w, mem_r, size);
        logger::debug("%s", TaintEngine::debug(mem_w));

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(mem_r), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Mem <- Mem %s]\t0x%lx: %s\t mem_w: 0x%lx mem_r: 0x%lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem_w, mem_r);
        logger::debug("%s", TaintEngine::debug(mem_w));

        TaintEngine::remove(mem_w);
    }
    logger::debug("\n");
}

// reg <- imm
void deleteReg(const std::string* assembly, unsigned long address, REG reg) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        logger::debug("[DELETE Reg]\t0x%lx : %s\n", address, assembly->c_str());
        logger::debug("before: %s", TaintEngine::debug(reg));
        logger::debug("\n");

        TaintEngine::remove(reg);
    }
}

// mem <- imm
void deleteMem(const std::string* assembly, unsigned long address, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        ADDRINT value = util::Value(mem, size);

        logger::debug("[DELETE Mem]\t\t0x%lx: %s value: 0x%lx\n", address, assembly->c_str(), value);
        logger::debug("%s", TaintEngine::debug(mem));
        logger::debug("\n");

        TaintEngine::remove(mem);
    }
}


//Insert Logic

// ReadMem
void InsertCall(Ins ins, REG reg, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, 
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// WriteMem
void InsertCall(Ins ins, int mem, REG reg) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, 
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// spreadMem
void InsertCall(Ins ins, int mem_w, int mem_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadMem,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem_w,
        IARG_MEMORYOP_EA, mem_r,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// spreadReg
void InsertCall(Ins ins, REG reg_w, REG reg_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadReg,
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

// delete mem
void InsertCall(Ins ins, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteMem,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// delete reg
void InsertCall(Ins ins, REG reg) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteReg, 
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, reg,
    IARG_END);
}


// 3 Ops

// reg <- reg
void Op3RegReg(const std::string* assembly, unsigned long address, int opcode, REG reg_w, REG reg_r, ADDRINT value_w, ADDRINT value_r) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    logger::debug("[USE RegReg]\t\t0x%lx: %s value: 0x%lx, opcode:%d\n", address, assembly->c_str(), value_w, opcode);
    
    if (taint_w) {
        logger::debug("%s", TaintEngine::debug(reg_w));
        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg_w), value_w);
    }
    if (taint_r) {
        logger::debug("%s", TaintEngine::debug(reg_r));
        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg_r), value_r);
    }            
    if (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR) {
        if (TaintEngine::merge(reg_w, reg_r)) {
            logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg_w), value_w);
        }
    }
    logger::debug("\n");
}

void InsertCallExtra(Ins ins, REG reg_w, REG reg_r) { // Reg Reg
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegReg, 
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_w,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

void Op3RegImm(const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value, int imm) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        if (opcode == XED_ICLASS_SHL) {
            TaintEngine::shift(reg, imm);
        } else if (opcode == XED_ICLASS_SHR || opcode == XED_ICLASS_SAR || opcode == XED_ICLASS_ROR) {
            TaintEngine::shift(reg, -imm); // ror uncheck
        } else if (opcode == XED_ICLASS_AND) { // and uncheck
            TaintEngine::and_(reg, imm);
        }
        logger::debug("[USE RegImm]\t\t0x%lx: %s value: 0x%lx, opcode: %d, imm: %d\n", address, assembly->c_str(), value, opcode, imm);
        logger::debug("%s", TaintEngine::debug(reg));
        logger::debug("\n");

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg), value);
    }   
}

void InsertCallExtra(Ins ins, REG reg) { // Reg Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegImm,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.valueImm(1),
    IARG_END);
}

void Op3RegMem(const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value_w, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    ADDRINT value_r = util::Value(mem, size);
    logger::debug("[USE RegMem]\t\t0x%lx: %s value: 0x%lx, opcode: %d\n", address, assembly->c_str(), value_w, opcode); // TODO
    
    if (taint_w) {
        logger::debug("%s", TaintEngine::debug(reg));
        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(reg), value_w);
    }
    if (taint_r) {
        logger::debug("%s", TaintEngine::debug(mem));
        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(mem), value_r);
    }
    logger::debug("\n");
}

void InsertCallExtra(Ins ins, REG reg, int mem) { // Reg Mem
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegMem,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

void Op3MemImm(const std::string* assembly, unsigned long address, int opcode, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        ADDRINT value = util::Value(mem, size);
        logger::debug("[USE MemImm]\t\t0x%lx: %s value: 0x%lx, opcode: %d\n", address, assembly->c_str(), value, opcode);
        logger::debug("%s", TaintEngine::debug(mem));
        logger::debug("\n");

        logger::info("Instruction 0x%lx: %s\t%s\t0x%lx\n", address, assembly->c_str(), TaintEngine::offsets(mem), value);
    }
}

void InsertCallExtra(Ins ins, int mem) { // Mem Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemImm,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// taint logic end
#endif