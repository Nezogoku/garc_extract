#include <algorithm>
#include <iostream>
#include <fstream>
#include <string>
#include "defines.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::ifstream;
using std::string;
using std::remove;


void removeQuote(string &arg) {
    arg.erase(remove(arg.begin(), arg.end(), '\"'), arg.end());
}

void printOpts(string prgm) {
    cout << "Usage: " << prgm << " [Options] <infile(s)>\n\n"
         << "Options:\n"
         << "   -h              : print this message\n"
         << "   -d              : activate debug mode\n"
         << "   -l              : output a log file of all extractions\n"
         << "   -T lba.csv      : specify a text file containing LBA table\n"
         << "   -B sector.bin   : specify a binary file containing LBA table\n"
         << endl;
}

void printErr(const char* opt, string arg, int code) {
    switch(code) {
        case 1:     //Missing argument
            cerr << arg << " not specified for option " << opt << "..." << endl;
            break;

        case 2:     //Invalid option
            cerr << opt << " is not a valid option..." << endl;
            break;

        case 3:     //Unexpected end of user inputs
            cerr << "There are not enough arguments..." << endl;
            break;

        case 4:     //Missing file
            cerr << arg << " does not exist..." << endl;
            break;
    }
}

bool fileExists(string fName) {
    bool exists = false;
    ifstream check;

    check.open(fName.c_str());
    if (check.is_open()) {
        check.close();
        exists = true;
    }

    return exists;
}

bool optArgValid(char opt, string arg) {
    bool valid = true;

    //Missing arguments
    if (arg[0] == '-') {
        printErr((const char*)opt, "Text file", 1);
        valid = false;
    }
    //File doesn't exist
    else if (!fileExists(arg)) {
        printErr((const char*)opt, arg, 4);
        valid = false;
    }

    return valid;
}
