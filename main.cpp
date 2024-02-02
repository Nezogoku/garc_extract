#include <algorithm>
#include <cstdio>
#include <string>
#include "garc/garc.hpp"
#include "printpause.hpp"

#define ERR_NO_OPT          0
#define ERR_NO_ARG          1
#define ERR_BAD_OPT         2
#define ERR_NOT_ENOUGH_ARG  3
#define ERR_NO_FILE         4

void removeQuote(std::string &arg) {
    arg.erase(std::remove(arg.begin(), arg.end(), '\"'), arg.end());
}

void printOpts(const char *prgm) {
    fprintf(stderr, "Usage: %s [Options] <infile(s)>\n", prgm);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "   -h              : print this message\n");
    fprintf(stderr, "   -d              : activate debug mode\n");
    fprintf(stderr, "   -L              : output a log file of all extractions\n");
    fprintf(stderr, "   -T lba.csv      : specify a text file containing LBA table\n");
    fprintf(stderr, "   -B sector.bin   : specify a binary file containing LBA table\n");
}

void printErr(const char* opt, const char* arg, int code) {
    switch(code) {
        case ERR_NO_OPT:            // Missing option
            fprintf(stderr, "Option not specified . . .\n");
            break;

        case ERR_NO_ARG:            // Missing argument
            fprintf(stderr, "%s not specified for option %s . . .\n", arg, opt);
            break;

        case ERR_BAD_OPT:           // Invalid option
            fprintf(stderr, "%s not a valid option . . .\n", opt);
            break;

        case ERR_NOT_ENOUGH_ARG:    // Unexpected end of user inputs
            fprintf(stderr, "Not enough arguments . . .\n");
            break;

        case ERR_NO_FILE:           // Missing file
            fprintf(stderr, "%s does not exist . . .\n", arg);
            break;
    }
}


///Main programme thing
int main(int argc, char *argv[]) {
    std::string prgm = argv[0];

    removeQuote(prgm);
    prgm = prgm.substr(prgm.find_last_of("\\/") + 1);
    prgm = prgm.substr(0, prgm.find_last_of('.'));


    if (argc < 2) {
        printOpts(prgm.c_str());
    }
    else {
        std::string binfile, tabfile;
        garc gfile;
        for (int fi = 1, tabtyp; fi < argc; ++fi) {
            if (!binfile.empty()) {
                binfile.clear();
                tabfile.clear();
                tabtyp = 0;
            }

            char opt = 0;
            std::string argin = argv[fi];
            removeQuote(argin);

            if (argin[0] == '-') {
                if (argin.size() < 2) {
                    printErr(0, 0, ERR_NO_OPT);
                    continue;
                }
                else if (argin.size() > 2 || argin.find_first_of("hdLTB") == std::string::npos) {
                    printErr(argin.substr(1).c_str(), 0, ERR_BAD_OPT);
                    continue;
                }

                if (argin.find_first_of("TB") != std::string::npos) {
                    if ((fi + 1) >= argc || argv[fi + 1][0] == '-') {
                        printErr(argin.substr(1).c_str(), "file", ERR_NO_ARG);
                        continue;
                    }
                    else {
                        tabfile = argv[++fi];
                        removeQuote(tabfile);
                        if (tabfile.empty()) {
                            printErr(argin.substr(1).c_str(), "file", ERR_NO_ARG);
                            continue;
                        }
                    }
                }
                opt = argin[1];
            }
            else if (argin.find("sector") != std::string::npos) {
                if (argin.find(".csv") != std::string::npos) opt = 'T';
                else opt = 'B';

                tabfile = argin;
            }
            else binfile = argin;

            switch(opt) {
                case 0:
                    gfile.searchFile(binfile, tabfile, tabtyp);
                    continue;

                case 'h':               // HELP
                    printOpts(prgm.c_str());
                    break;

                case 'd':               // DEBUG MODE
                    gfile.setDebug(true);
                    fprintf(stderr, "Debug mode now active\n");
                    continue;

                case 'L':               // OUTPUT LOG FILE
                    gfile.setLog(true);
                    fprintf(stderr, "Log mode now active\n");
                    continue;

                case 'T':               // INPUT LBA TABLE (CSV)
                    tabtyp = 1;
                    continue;

                case 'B':               // INPUT LBA TABLE (BIN)
                    tabtyp = 2;
                    continue;
            }
            break;
        }
    }

    sleep(10);
    return 0;
}
