#ifndef _CONFIG_H
#define _CONFIG_H

namespace config {

// run mode
// const string mode = "debug";
const std::string mode = "release";

// entry function name for filter out irrelavant functions
const std::string start_entry = "main"; 
// const std::string start_entry = "init_codecs"; // for python

// flag for print miss assembly
const bool missFlag = true;

// flush immediately after print
const bool isFlush = true; 
const bool print = true;

// debug, info, verbose filenames
const char *filenames[3] = {"debug.txt", "info.txt",  "verbose.txt"};
const bool flags[3] = {true, true, true};

const bool syscall = true;

// read size control
const bool read_size_flag = false;
const int  read_size_max  = 0x100;
const int  read_size_min  = 0x100;

}

#endif