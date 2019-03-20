// #include <iomanip>
// #include <iostream>
// #include <string.h>
#include "pin.H"
#include <vector>
#include <asm/unistd.h>
#include "wrapper.hpp"
#include "logic.hpp"
#include "util.hpp"
#include "config.hpp"


// INS_OperandImmediate
// INS_OperandRead
// INS_OperandReadAndWritten
// INS_OperandReg
// INS_OperandWritten
// INS_OperandReadOnly
// INS_OperandWrittenOnly


void Test(Ins ins) {
    UINT32 opcount = ins.OpCount();
    OPCODE opcode = ins.OpCode();
    INT32 ext = ins.Extention();

    logger::verbose("%s", util::prettify(ins));
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
    } else if (opcount == 3) {
        // if (opcode != XED_ICLASS_XOR) return;
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
    } else if (opcount == 4) {
        // push pop
        // mul div imul idiv
    } else {
    }
}

void Instruction(Ins ins) {
    UINT32 opcount = ins.OpCount();
    
    // filter rules
    if (ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1 || opcount >= 5) return;
    if (ins.Extention() >= 40) return; // TODO sse instructions 
    // if (opcount == 2 && (ins.isOpImplicit(0) || ins.isOpImplicit(1))) return; // TODO neg inc, dec cgo setx
    if (ins.isOpReg(0) && (ins.OpReg(0) == REG_RBP || ins.OpReg(0) == REG_RSP || ins.OpReg(0) == REG_RIP)) return;
    if (ins.isOpReg(0) && (ins.OpReg(0) == REG_EBP || ins.OpReg(0) == REG_ESP || ins.OpReg(0) == REG_EIP)) return;

    bool miss = false;

    OPCODE opcode = ins.OpCode();
    
    REG reg_w = ins.OpReg(0);
    REG reg_r = ins.OpReg(1);
    
    if (opcount == 2 || (opcount == 3 && opcode >= XED_ICLASS_CMOVB && opcode <= XED_ICLASS_CMOVZ)) { // condition mov
        if (ins.isLea()) { // reg calculation
            InsertCall(ins, reg_w); // deleteReg
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {
            InsertCall(ins, reg_w, 0); // ReadMem
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {
            InsertCall(ins, 0, reg_r); // WriteMem
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            InsertCall(ins, 0); // deleteMem
        } else if (ins.isOpReg(0) && ins.isOpReg(1)) {
            InsertCall(ins, reg_w, reg_r); // spreadReg
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            InsertCall(ins, reg_w); // deleteReg
        } else {
            miss = true;
        }
    } else if (opcount == 3) {
        // cmov in opcode == 2
        if (opcode == XED_ICLASS_XOR && ins.isOpReg(0) && ins.isOpReg(1) && reg_w == reg_r) { // xor
            InsertCall(ins, reg_w); // deleteReg
        } else if (ins.isOpReg(0) && ins.isOpReg(1)){
            InsertCallExtra(ins, reg_w, reg_r); // 
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {
            InsertCallExtra(ins, reg_w, 0); // 
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            InsertCallExtra(ins, reg_w); // 
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            InsertCallExtra(ins, 0); // 
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {
            // ADD
        } else {
            miss = false;
        }
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
    } else if (opcount == 4) {
        if (opcode == XED_ICLASS_PUSH) { // push
            if (ins.isOpReg(0)) {
                InsertCall(ins, 0, reg_w); // WriteMem // note reg_w is the first reg op in push
            } else if (ins.isOpMem(0)) {
                InsertCall(ins, 0, 1); // spreadMem
            } else if (ins.isOpImm(0)) {
                InsertCall(ins, 0); // deleteMem
            } else {
                miss = true;
            }
        } else if (opcode == XED_ICLASS_POP) { // pop
            if (ins.isOpReg(0)) {
                InsertCall(ins, reg_w, 0); // ReadMem
            } else {
                miss = true;
            }
        } else {
            miss = true;
        }
        // mul div imul idiv
    }
    if (config::missFlag && miss) {
        static std::vector<OPCODE> cache;
        if (find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
            logger::debug("assembly not taint included : %s\n", ins.Name().c_str());
        }
    }
}



void Image(IMG img, VOID *v) {
    std::string imgName = IMG_Name(img);
    if (config::mode == "release") {
        logger::verbose("image: %s\n", imgName.c_str());
        if (IMG_IsMainExecutable(img)) {
            for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
                for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
                    if (rtn.isArtificial()) continue;
                    std::string *rtnName = new std::string(rtn.Name());
                    if (filter::function(rtnName->c_str())) continue;
                    logger::verbose("function %s\n", rtnName->c_str());
                    
                    rtn.Open();

                    if (rtnName->find("@plt") != std::string::npos) {
                        if (*rtnName == "recv@plt" || *rtnName == "recvfrom@plt") {
                            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Recv_point,
                                IARG_ADDRINT, rtnName,
                                IARG_ADDRINT, util::entry,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // socket
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                                IARG_END);
                            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)Recv_point,
                                IARG_ADDRINT, rtnName,
                                IARG_ADDRINT, util::exit,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // socket
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                                IARG_END);
                        } else if (*rtnName == "memcpy@plt") { // memcpy use xmm registers to copy
                            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Memcpy_point,
                                IARG_ADDRINT, rtnName,
                                IARG_ADDRINT, util::entry,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dest
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // src
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                                IARG_END);
                        }
                        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)function_entry, 
                        IARG_THREAD_ID,
                        IARG_PTR, rtnName, IARG_END);
                    } else {
                        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)function_entry, 
                            IARG_THREAD_ID,
                            IARG_PTR, rtnName, IARG_END);

                        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)function_exit, 
                            IARG_THREAD_ID,
                            IARG_PTR, rtnName, IARG_END);

                        for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next()) {
                            Instruction(ins);
                        }
                    }

                    rtn.Close();
                }
            }
        } else if (imgName.find("libc") != std::string::npos) {
            for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
                for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
                    if (rtn.isArtificial()) continue;
                    std::string *rtnName = new std::string(rtn.Name());
                    if (filter::function(rtnName->c_str())) continue;
                    
                    logger::verbose("function %s\n", rtnName->c_str());

                    rtn.Open();
                    if (*rtnName == "recv"|| *rtnName == "recvfrom") {
                        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Recv_point,
                            IARG_ADDRINT, rtnName,
                            IARG_ADDRINT, util::entry,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // socket
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                            IARG_END);
                        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)Recv_point,
                            IARG_ADDRINT, rtnName,
                            IARG_ADDRINT, util::exit,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // socket
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // buf
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                            IARG_END);
                    } else if (*rtnName == "memcpy") { // memcpy use xmm registers to copy
                        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Memcpy_point,
                            IARG_ADDRINT, rtnName,
                            IARG_ADDRINT, util::entry,
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 0, // dest
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 1, // src
                            IARG_FUNCARG_ENTRYPOINT_VALUE, 2, // len
                            IARG_END);
                    }
                    // else if (*rtnName == "htonl" || *rtnName == "ntohl")
                    rtn.Close();
                }
            }
        }
    } else if (config::mode == "debug") {
        
        logger::verbose("image start: %s\n", imgName.c_str());

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
                if (rtn.isArtificial()) continue;
                std::string *rtnName = new std::string(rtn.Name());
                logger::verbose("function start %s\n", rtnName->c_str());

                rtn.Open();
                for(Ins ins = rtn.InsHead(); ins.Valid(); ins = ins.Next()) {
                    Test(ins);
                }
                rtn.Close();

                logger::verbose("function end %s\n", rtnName->c_str());
            }
        }
        logger::verbose("image end: %s\n", imgName.c_str());
    }
}


FILE *files[3];

void Init() {
    files[0] = fopen(config::filenames[0], "w");
    files[1] = fopen(config::filenames[1], "w");
    files[2] = fopen(config::filenames[2], "w");
    logger::setDebug(config::flags[0], files[0]);
    logger::setInfo(config::flags[1], files[1]);
    logger::setVerbose(config::flags[2], files[2]);
}


void Fini(INT32 code, VOID *v) {
    printf("program end\n");
    fprintf(files[0], "#eof\n");
    fclose(files[0]);
    fprintf(files[1], "#eof\n");
    fclose(files[1]);
    fprintf(files[2], "#eof\n");
    fclose(files[2]);
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
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    // PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(Image, 0);
    if (config::syscall) {
        if (config::use_entry) PIN_AddSyscallEntryFunction(Syscall_point, (void*)util::entry);
        if (config::use_exit)  PIN_AddSyscallExitFunction(Syscall_point , (void*)util::exit);
    }
        
    PIN_StartProgram();
    PIN_AddFiniFunction(Fini, 0);

    return 0;
}