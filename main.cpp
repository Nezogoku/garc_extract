#include "defines.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::vector;


///Main programme thing
int main(int argc, char *argv[]) {
    string prgm = argv[0];

    removeQuote(prgm);
    prgm = prgm.substr(prgm.find_last_of("\\/") + 1);
    prgm = prgm.substr(0, prgm.find_last_of('.'));


    if (argc < 2) {
        printOpts(prgm);
    }
    else {
        int fileIndex = 1;
        vector<lbaSpec> lbaTable;
        bool isDebug = false,
             hasLog = false;

        while (fileIndex < argc) {
            string argin = argv[fileIndex++];
            removeQuote(argin);

            if (argin[0] == '-') {
                //If option too long or missing
                if (argin.size() != 2) {
                    printErr(argin.c_str(), "", 1);
                    continue;
                }

                char opt = argin[1];
                switch(opt) {
                    case 'h':               //HELP
                        printOpts(prgm);
                        break;

                    case 'd':               //DEBUG MODE
                        isDebug = true;
                        continue;

                    case 'l':               //OUTPUT LOG FILE
                        hasLog = true;
                        continue;

                    case 'T':               //INPUT LBA TABLE (CSV)
                        //End of inputs
                        if (fileIndex == argc) {
                            printErr((const char*)opt, "", 2);
                            break;
                        }

                        argin = argv[fileIndex++];
                        removeQuote(argin);

                        if (optArgValid(opt, argin)) {
                            lbaTable.clear();
                            lbaTable = getTableCSV(argin);
                        }
                        continue;

                    case 'B':               //INPUT LBA TABLE (BIN)
                        //End of inputs
                        if (fileIndex == argc) {
                            printErr((const char*)opt, "", 2);
                            break;
                        }

                        argin = argv[fileIndex++];
                        removeQuote(argin);

                        if (optArgValid(opt, argin)) {
                            lbaTable.clear();
                            lbaTable = getTableBIN(argin);
                        }
                        continue;

                    default:                //UNKNOWN OPTION
                        printErr((const char*)opt, "", 2);
                        continue;
                }
            }
            else searchGARC(lbaTable, argin, isDebug, hasLog);
        }
    }

    return 0;
}
