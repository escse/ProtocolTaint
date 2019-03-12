// #include <iomanip>
// #include <iostream>
// #include <string.h>
#include "pin.H"
#include <vector>
#include <asm/unistd.h>
#include "wrapper.hpp"
#include "logic.hpp"
#include "util.hpp"

// const string mode = "debug";
const string mode = "release";


KNOB<string> InputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "./a.out", "binary file name");

KNOB<string> DebugOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "log", "debug.txt", "log file name");

KNOB<string> InfoOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "info", "info.txt", "info file name");

const std::string start_entry = "main";

void assert(bool a, const char *info=0) {
    if (!a) {
        logger::debug("assert error %s\n", (info > 0) ? info: "");
    }
}

// function trace start

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
    if (*name == start_entry) monitor::start();
    if (monitor::invalid()) return;
    if (name->find("@plt") != std::string::npos) {
        plts.push_back(*name);
        logger::debug("thread id: %d, enter function: %s\n", threadId, name->c_str());
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
    logger::debug("thread id: %d, enter function: %s\n", threadId, name->c_str());
    logger::info("enter\t%s\n", name->c_str());
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

    assert(functraces[index].back() == *name);
    functraces[index].pop_back();
    
    logger::debug("thread id: %d, exit  function: %s\n", threadId, name->c_str());
    logger::info("exit\t%s\n", name->c_str());
        // printTrace(index);
    if (*name == start_entry) monitor::end();
}

// function trace end

// INS_OperandImmediate
// INS_OperandRead
// INS_OperandReadAndWritten
// INS_OperandReg
// INS_OperandWritten
// INS_OperandReadOnly
// INS_OperandWrittenOnly

void PushPopTest(const std::string* assembly, unsigned long address, UINT64 mem, const CONTEXT * ctxt) {
    ADDRINT value = Context(ctxt).getReg(REG_STACK_PTR);
    logger::debug("%lx : %s mem: %lx value: %lx\n", address, assembly->c_str(), mem, value);
}

void EveryInst(const std::string* assembly, unsigned long address) {
    // if (monitor::invalid()) return;
    logger::debug("%lx : %s\n", address, assembly->c_str());
}


void Test(Ins ins) {
    UINT32 opcount = ins.OpCount();
    OPCODE opcode = ins.OpCode();
    INT32 ext = ins.Extention();
    if (ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1) return;

    
    if (ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1) return;
    if (ext >= 40) return; // sse TODO

    if (opcount == 2 || (opcode >= 83 && opcode <= 98)) {
        if (ins.isLea()) return;
        if (ins.isOpImplicit(0) || ins.isOpImplicit(1)) return; 
        if (ins.isOpReg(0) && ins.isOpReg(1)) return;
        if (ins.isOpReg(0) && ins.isOpImm(1)) return;
        if (ins.isOpReg(0) && ins.isOpMem(1)) return;
        if (ins.isOpMem(0) && ins.isOpReg(1)) return;
        // if (ins.isOpMem(0) && ins.isOpImm(1)) return;
        // if ((ins.isMemoryWrite() || ins.isMemoryRead())) return;
        
        // pp(ins);

    } else if (opcount == 3) {
        // if (opcode != XED_ICLASS_XOR) return;
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
        pp(ins);
    } else if (opcount == 4) {
        // push pop
        // mul div imul idiv
        // if (opcode == XED_ICLASS_PUSH) 
        if (opcode == XED_ICLASS_POP) {
        }
    } else {
        // pp(ins);
        
    }
}

void Instruction(Ins ins) {
    UINT32 opcount = ins.OpCount();

    if (ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1 || opcount >= 5) return;
    if (ins.Extention() >= 40) return; // TODO sse instructions 
    if (opcount == 2 && (ins.isOpImplicit(0) || ins.isOpImplicit(1))) return; // TODO neg inc, dec cgo setx
    if (ins.isOpReg(0) && (ins.OpReg(0) == REG_RBP || ins.OpReg(0) == REG_RSP || ins.OpReg(0) == REG_RIP)) return;
    if (ins.isOpReg(0) && (ins.OpReg(0) == REG_EBP || ins.OpReg(0) == REG_ESP || ins.OpReg(0) == REG_EIP)) return;

    bool insertFlag = false;

    OPCODE opcode = ins.OpCode();
    
    REG reg_w = ins.OpReg(0);
    REG reg_r = ins.OpReg(1);
    
    if (opcount == 2 || (opcount == 3 && opcode >= 83 && opcode <= 98)) { // condition mov
        if (ins.isLea()) {
            insertFlag = true;
            InsertCall(ins, reg_w); // deleteReg
        }
        if (ins.isOpReg(0) && ins.isOpMem(1)) {
            insertFlag = true;
            InsertCall(ins, reg_w, 0); // ReadMem
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {
            insertFlag = true;
            InsertCall(ins, 0, reg_r); // WriteMem
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            insertFlag = true;
            InsertCall(ins, 0); // deleteMem
        } else if (ins.isOpReg(0) && ins.isOpReg(1)) {
            insertFlag = true;
            InsertCall(ins, reg_w, reg_r); // spreadReg
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            insertFlag = true;
            InsertCall(ins, reg_w); // deleteReg
        }
    } else if (opcount == 3) {
        // cmov in opcode == 2
        if (opcode == XED_ICLASS_XOR && ins.isOpReg(0) && ins.isOpReg(1) && reg_w == reg_r) { // xor
            insertFlag = true;
            InsertCall(ins, reg_w); // deleteReg
        } else if (ins.isOpReg(0) && ins.isOpReg(1)){
            insertFlag = true;
            InsertCallExtra(ins, reg_w, reg_r); // 
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {
            insertFlag = true;
            InsertCallExtra(ins, reg_w, 0); // 
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            insertFlag = true;
            InsertCallExtra(ins, reg_w); // 
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            insertFlag = true;
            InsertCallExtra(ins, 0); // 
        }
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
    } else if (opcount == 4) {
        if (opcode == XED_ICLASS_PUSH) { // push
            if (ins.isOpReg(0)) {
                insertFlag = true;
                InsertCall(ins, 0, reg_w); // WriteMem // note reg_w is the first reg op in push
            } else if (ins.isOpMem(0)) {
                insertFlag = true;
                InsertCall(ins, 0, 1); // spreadMem
            } else if (ins.isOpImm(0)) {
                insertFlag = true;
                InsertCall(ins, 0); // deleteMem
            }
        } else if (opcode == XED_ICLASS_POP) { // pop
            if (ins.isOpReg(0)) {
                insertFlag = true;
                InsertCall(ins, reg_w, 0); // ReadMem
            }
        }
        // mul div imul idiv
    }
    if (!insertFlag) {
        static std::vector<OPCODE> cache;
        if (find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
            logger::debug("assembly not taint included : %s\n", ins.Name().c_str());
        }
    }
}


void Image(IMG img, VOID *v) {
    std::string imgName = IMG_Name(img);
    logger::verbose("%s\n", imgName.c_str());
    if (imgName == InputFile.Value()) {
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
                if (rtn.isArtificial()) continue;
                std::string *rtnName = new std::string(rtn.Name());
                logger::verbose("%s\n", rtnName->c_str());
                rtn.Open();
                if (mode == "release") {
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)function_entry, 
                        IARG_THREAD_ID,
                        IARG_PTR, rtnName, IARG_END);

                    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)function_exit, 
                        IARG_THREAD_ID,
                        IARG_PTR, rtnName, IARG_END);
                
                    for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next()) {
                        Instruction(ins);
                    }
                } else if (mode == "debug") {
                    for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next())
                        Test(ins);
                } else {
                    for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next())
                        pp(ins);
                }
                rtn.Close();
            }
        }
    } else if (imgName.find("libc") != std::string::npos) {
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
                std::string rtnName = rtn.Name();
                logger::verbose("%s\n", rtnName.c_str());
                if (rtnName == "recv") {
                    rtn.Open();
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Recv_entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                        IARG_END);
                    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)Recv_exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                        IARG_END);
                    rtn.Close();
                } 
                // else if (rtnName == "htonl" || rtnName == "ntohl") {
                //     rtn.Open(); // 增加function entry会抱内存问题？？
                //     for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next()) {
                //         Instruction(ins);
                //     }
                //     rtn.Close();
                // }
            }
        }
    }
}

FILE *debug_file;
FILE *info_file;

void Init() {
    debug_file = fopen(DebugOutputFile.Value().c_str(), "w");
    info_file = fopen(InfoOutputFile.Value().c_str(), "w");
    logger::setDebug(true, debug_file);
    logger::setInfo(true, info_file);
}

void Fini(INT32 code, VOID *v) {
    fprintf(debug_file, "#eof\n");
    fclose(debug_file);
    fprintf(info_file, "#eof\n");
    fclose(info_file);
}


INT32 Usage() {
    printf("error\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    Init();
    // logger::setVerbose(true);
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(Image, 0);
    // Rtn::addBlackImageName("libc");
    // Register Routine to be called to instrument rtn
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    PIN_AddSyscallExitFunction(Syscall_exit, 0);

    PIN_StartProgram();

    PIN_AddFiniFunction(Fini, 0);
    return 0;
}