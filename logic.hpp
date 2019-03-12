#ifndef _TAINTLOGIC_H
#define _TAINTLOGIC_H

#include "pin.H"
#include "taintengine.hpp"
#include "util.hpp"

// IARG_MEMORYWRITE_SIZE
// IARG_FUNCARG_ENTRYPOINT_VALUE, 0 函数参数

const char *printinfo[2][2] = {{ "", "+  taint  +"}, {"- untaint -", "* retaint *"}};

// taint logic start

// static unsigned int tryksOpen;
static unsigned int tryksClose;


#define TRICKS_CLOSE()                      \
    {                                 \
        if (tryksClose++ == 0) return; \
    }

void Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
                   void *v) {
    // UINT64 start, size;

    // if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    //     TRICKS_OPEN(); /* tricks to ignore the first open */

    //     start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    //     size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

    //     TaintEngine::Init(start, size);
    //     logger::debug("[TAINT]\t %lx bytes tainted from 0x%lx to 0x%lx (via read)\n", size, start, start+size);
    // }
}

void Syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std,
                   void *v) {
    // UINT64 start, size;

    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
        TRICKS_CLOSE(); /* tricks to ignore the first open */

        // start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
        // size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

        // TaintEngine::Init(start, size);
    }
}

void Recv_entry(UINT64 start, size_t size) {
    // TaintEngine::addInit(start, size); // point to self
}

void Recv_exit(UINT64 start, size_t size) {
    TaintEngine::Init(start, size); // point to self
}

void EveryInst(const std::string* assembly) { // # TODO
    if (monitor::invalid()) return;
}

// reg <- mem
void ReadMem(const std::string* assembly, unsigned long address, REG reg, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    ADDRINT value = Value(mem, size);
    if (taint_r) { // retaint
        logger::debug("[Reg <- Mem %s]\t%lx: %s\t addr: %lx value: (%lx, %lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem, TaintEngine::src(mem), value);
        logger::debug("before: %s", TaintEngine::debug(mem));

        TaintEngine::move(reg, mem, size);
        
        logger::debug("after: %s", TaintEngine::debug(reg));
        logger::debug("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value, address);
        logger::info("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value, address);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Reg <- Mem %s]\t%lx: %s\t addr: %lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem);
        logger::debug("before: %s", TaintEngine::debug(reg));

        TaintEngine::remove(reg);
    }
    logger::debug("%s", "\n");
}

// mem <- reg
void WriteMem(const std::string* assembly, unsigned long address, UINT64 mem, REG reg, ADDRINT value, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    if (taint_r) { // retaint
        logger::debug("[Mem <- Reg %s]\t%lx: %s\t addr: %lx value: (%lx, %lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem, TaintEngine::src(reg), value);
        logger::debug("before: %s", TaintEngine::debug(reg));
        
        TaintEngine::move(mem, reg, size); // change src

        logger::debug("after: %s", TaintEngine::debug(mem));
        logger::debug("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value, address);
        logger::info("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value, address);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Mem <- Reg %s]\t%lx: %s\t addr: %lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem);
        logger::debug("before: %s", TaintEngine::debug(mem));

        TaintEngine::remove(mem);
    }
    logger::debug("%s", "\n");
}

// reg <- reg
void spreadReg(const std::string* assembly, unsigned long address, REG reg_w, REG reg_r, ADDRINT value) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    if (taint_r) { // retaint
        logger::debug("[Reg <- Reg %s]\t%lx: %s value: (%lx, %lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), TaintEngine::src(reg_r), value);
        logger::debug("before: %s", TaintEngine::debug(reg_r));

        TaintEngine::move(reg_w, reg_r); // change src

        logger::debug("after: %s", TaintEngine::debug(reg_w));
        logger::debug("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_r), value, address);
        logger::info("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_r), value, address);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Reg <- Reg %s]\t%lx: %s\n", printinfo[taint_w][taint_r], address, assembly->c_str());
        logger::debug("before: %s", TaintEngine::debug(reg_w));

        TaintEngine::remove(reg_w);
    }
    logger::debug("%s", "\n");
}

// mem <- mem
void spreadMem(const std::string* assembly, unsigned long address, UINT64 mem_w, UINT64 mem_r, USIZE size) {
    if (monitor::invalid()) return;
    bool taint_w = TaintEngine::isTainted(mem_w);
    bool taint_r = TaintEngine::isTainted(mem_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    ADDRINT value = Value(mem_r, size);
    if (taint_r) { // retaint
        logger::debug("[Mem <- Mem %s]\t%lx: %s\t mem_w: %lx mem_r: %lx value: (%lx, %lx)\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem_w, mem_r, TaintEngine::src(mem_r), value);
        logger::debug("befroe: %s", TaintEngine::debug(mem_r));

        TaintEngine::move(mem_w, mem_r, size);
        
        logger::debug("after: %s", TaintEngine::debug(mem_w));
        logger::debug("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem_r), value, address);
        logger::info("T\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem_r), value, address);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("[Mem <- Mem %s]\t%lx: %s\t mem_w: %lx mem_r: %lx\n", printinfo[taint_w][taint_r], address, assembly->c_str(), mem_w, mem_r);
        logger::debug("befroe: %s", TaintEngine::debug(mem_w));

        TaintEngine::remove(mem_w);
    }
    logger::debug("%s", "\n");
}

// reg <- imm
void deleteReg(const std::string* assembly, unsigned long address, REG reg) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        logger::debug("[DELETE Reg]\t%lx : %s\n", address, assembly->c_str());
        logger::debug("before: %s", TaintEngine::debug(reg));
        logger::debug("%s", "\n");

        TaintEngine::remove(reg);
    }
}

// mem <- imm
void deleteMem(const std::string* assembly, unsigned long address, UINT64 mem, USIZE size) {
    if (monitor::invalid()) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        ADDRINT value = Value(mem, size);

        logger::debug("[DELETE Mem]\t\t%lx: %s value: %lx\n", address, assembly->c_str(), value);
        logger::debug("befroe: %s", TaintEngine::debug(mem));
        logger::debug("%s", "\n");

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
    logger::debug("[USE RegReg]\t\t%lx: %s value: %lx, opcode:%d\n", address, assembly->c_str(), value_w, opcode);
    
    if (taint_w) {
        logger::debug("%s", TaintEngine::debug(reg_w));
        logger::info("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_w), value_w, address);
        logger::debug("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_w), value_w, address);
    }
    if (taint_r) {
        logger::debug("%s", TaintEngine::debug(reg_r));
        logger::info("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_r), value_r, address);
        logger::debug("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_r), value_r, address);
    }            
    if (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR) {
        if (TaintEngine::merge(reg_w, reg_r)) {
            logger::info("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_w), value_w, address);
            logger::debug("T-RegReg\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg_w), value_w, address);
        }
    }
    logger::debug("%s", "\n");
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
        } else if (opcode == XED_ICLASS_SAR) {
            TaintEngine::shift(reg, -imm);
        } else if (opcode == XED_ICLASS_AND) {
            // TaintEngine::and(reg, imm);
        }
        logger::debug("[USE RegImm]\t\t%lx: %s value: %lx, opcode: %d, imm: %d\n", address, assembly->c_str(), value, opcode, imm);
        logger::debug("%s", TaintEngine::debug(reg));
        logger::debug("T-RegImm\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value, address);
        logger::info("T-RegImm\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value, address);
        logger::debug("%s", "\n");
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
    ADDRINT value_r = Value(mem, size);
    logger::debug("[USE RegMem]\t\t%lx: %s value: %lx, opcode: %d\n", address, assembly->c_str(), value_w, opcode); // TODO
    
    if (taint_w) {
        logger::debug("%s", TaintEngine::debug(reg));
        logger::info("T-RegMem\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value_w, address);
        logger::debug("T-RegMem\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(reg), value_w, address);
    }
    if (taint_r) {
        logger::debug("%s", TaintEngine::debug(mem));
        logger::info("T-RegMem\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value_r, address);
        logger::debug("T-RegMem\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value_r, address);
    }
    logger::debug("%s", "\n");
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
        ADDRINT value = Value(mem, size);
        logger::debug("[USE MemImm]\t\t%lx: %s value: %lx, opcode: %d\n", address, assembly->c_str(), value, opcode);
        logger::debug("%s", TaintEngine::debug(mem));
        logger::debug("T-MemImm\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value, address);
        logger::info("T-MemImm\t%s\t%s\t%lx\t%lx\n", assembly->c_str(), TaintEngine::offsets(mem), value, address);
        logger::debug("%s", "\n");
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