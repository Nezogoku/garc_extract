#include <iostream>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <vector>
#include <string>
#include <direct.h>
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif


using std::cout;
using std::cerr;
using std::endl;
using std::fstream;
using std::ifstream;
using std::ios;
using std::ofstream;
using std::string;
using std::to_string;
using std::vector;
using std::remove;

#define GARC 0x47415243
#define FILE 0x46494C45

#define SGXD 0x53475844
#define NAME 0x4E414D45

#define XUI_ 0x58554900
#define TIMP 0x54494D50
#define TIPM 0x01000100


bool hasLog = false;


void printOpts(string prgm) {
    cout << "Usage: " << prgm << " [Options] <infile(s)>\n\n"
         << "Options:\n"
         << "   -h      prints this message\n"
         << "   -l      creates a log file of all extractions"
         << endl;
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


int extractTIMP(ofstream &extraction_log, ifstream &file, int secdex, string name) {
    string timpName = (name == "") ? "unknown_timp_" : name;
    static int iter = 0;
    uint32_t chunk;


    file.seekg(secdex);
    file.read((char*)(&chunk), sizeof(uint32_t));
    if (htonl(chunk) != TIMP) return 0x01;

    file.seekg(secdex + 0x04);
    file.read((char*)(&chunk), sizeof(uint32_t));
    if (htonl(chunk) != TIPM) return 0x04;

    if (name == "") timpName += to_string(iter++);
    timpName += ".tip";

    if (fileExists(timpName)) return 0x04;


    uint32_t pal_data, px_data,
             px_length = 0x00,
             file_length = 0x00;
    uint16_t width, height;

    int chunk_w, chunk_h,
        pal_colors = 16;


    file.seekg(secdex + 0x12);
    file.read((char*)(&width), sizeof(uint16_t));

    file.seekg(secdex + 0x14);
    file.read((char*)(&height), sizeof(uint16_t));

    file.seekg(secdex + 0x20);
    file.read((char*)(&pal_data), sizeof(uint32_t));

    file.seekg(secdex + 0x24);
    file.read((char*)(&px_data), sizeof(uint32_t));


    if (pal_data != 0x00) pal_colors = (px_data - 0x30) / 0x04;
    else pal_colors = pal_data;

    switch(pal_colors) {
        case 0:
            chunk_w = 4;
            chunk_h = 8;
            break;

        case 16:
        case 32:
        case 48:
        case 96:
        case 112:
            chunk_w = 32;
            chunk_h = 8;
            break;

        case 64:
        case 236:
        case 256:
            chunk_w = 16;
            chunk_h = 8;
            break;

        default:
            chunk_w = 4;
            chunk_h = 8;
            break;
    }


    px_length = width * height;
    if (!(width % chunk_w == 0 && height % chunk_h == 0)) {
        int amntX = std::ceil((double)width / chunk_w);
        int amntY = std::ceil((double)height / chunk_h);

        px_length = (chunk_w * amntX) * (chunk_h * amntY);
    }

    file_length += px_data;
    file_length += px_length;

    ofstream extr_out(timpName.c_str(), ios::binary);
    file.seekg(secdex);
    for(int ind = 0; ind < file_length; ++ind) {
        char buff;
        file.get(buff);
        extr_out.put(buff);
    }
    extr_out.close();

    cout << "Extracted " << timpName << endl;

    if (hasLog) extraction_log << timpName << "\n\t" <<
                                  "\tFile type: tip\n\t" <<
                                  "\tFile address: 0x" << std::hex << secdex << std::dec << "\n\t" <<
                                  "\tFile size: " << file_length << " bytes\n";

    return file_length;
}

int timpFromXUI(ofstream &extraction_log, ifstream &file, int secdex) {
    bool timpFound = false;
    uint32_t nameSize, chunk;

    file.seekg(secdex + 0x08);
    file.read((char*)(&nameSize), sizeof(uint32_t));

    int tempdex = 0x14;

    file.seekg(secdex + tempdex);
    string timpName = "";
    for(int ind = 0; ind < secdex + nameSize; ++ind) {
        char buff;
        file.get(buff);

        if (buff == 0x00) {
            if (timpName.find_last_of(".tip") != string::npos) {
                break;
            }

            timpName = "";
        }
        else timpName += buff;
    }

    tempdex = 0x0;
    while (tempdex < 0x60) {
        file.seekg(secdex + nameSize + tempdex++);
        file.read((char*)(&chunk), sizeof(uint32_t));

        if (htonl(chunk) == TIMP) {
            timpFound = true;
            break;
        }
    }

    if (!(timpFound) || fileExists(timpName)) return tempdex + nameSize;

    return nameSize + tempdex + extractTIMP(extraction_log, file, secdex + nameSize + tempdex, timpName);
}

int extractSGXD(ofstream &extraction_log, ifstream &file, int secdex) {
    string sgxdName = "";
    uint32_t name_offset;                                                       // Address to bank name
    uint32_t data_offset;                                                       // Address to start of sample data
    uint32_t data_length;                                                       // Length of data + 2147483648 (0x80000000) bytes, zero-padded

    file.seekg(secdex + 0x04);
    file.read((char*)(&name_offset), sizeof(uint32_t));
    file.seekg(secdex + 0x08);
    file.read((char*)(&data_offset), sizeof(uint32_t));
    file.seekg(secdex + 0x0C);
    file.read((char*)(&data_length), sizeof(uint32_t));

    file.seekg(secdex + name_offset);
    while(true) {
        char buff;
        file.get(buff);
        if (buff == 0x00) break;
        sgxdName += buff;
    }

    if (data_length < 0x80000000) {
        data_length = 0x00;
        sgxdName += ".sgh";
    }
    else {
        data_length -= 0x80000000;
        sgxdName += ".sgd";
    }

    if (fileExists(sgxdName)) return data_offset + data_length;

    ofstream extr_out(sgxdName.c_str(), ios::binary);
    file.seekg(secdex);
    for(int i = 0; i < (data_offset + data_length); ++i) {
        char buff;
        file.get(buff);
        extr_out.put(buff);
    }
    extr_out.close();

    cout << "Extracted " << sgxdName << endl;
    if (hasLog) extraction_log << "\t" << sgxdName << "\n\t" <<
                                  "\tFile type: sgd\n\t" <<
                                  "\tFile address: 0x" << std::hex << secdex << std::dec << "\n\t" <<
                                  "\tFile size: " << data_offset + data_length << " bytes\n";

    return data_offset + data_length;
}

int fromGARC(ofstream &extraction_log, ifstream &file, int secdex) {
    uint32_t chunk;

    uint32_t cfileAddr;                                                         // 32 bit le, FILE chunk location
    uint32_t numFiles;                                                          // 32 bit le, number of stored files
    uint32_t cfileSize;                                                         // 32 bit le, FILE chunk size
    uint32_t cfileStart;                                                        // 32 bit le, start of FILE

    uint32_t cnameAddr;                                                         // 32 bit le, NAME chunk location
    uint32_t numNames;                                                          // 32 bit le, number of stored names
    uint32_t cnameSize;                                                         // 32 bit le, NAME chunk size
    uint32_t cnameStart;                                                        // 32 bit le, start of NAME

    uint32_t cdataAddr;                                                         // 32 bit le, DATA chunk location
    uint32_t numData;                                                           // 32 bit le, number of stored data
    uint32_t cdataSize;                                                         // 32 bit le, DATA chunk size
    uint32_t cdataStart;                                                        // 32 bit le, start of DATA

    uint32_t termAddr;                                                          // 32 bit le, TERM location


    file.seekg(secdex + 0x14);
    file.read((char*)(&cfileAddr), sizeof(uint32_t));

    file.seekg(secdex + cfileAddr + 0x04);
    file.read((char*)(&cnameAddr), sizeof(uint32_t));
    file.seekg(secdex + cfileAddr + 0x08);
    file.read((char*)(&numFiles), sizeof(uint32_t));
    file.seekg(secdex + cfileAddr + 0x0C);
    file.read((char*)(&cfileSize), sizeof(uint32_t));
    file.seekg(secdex + cfileAddr + 0x10);
    file.read((char*)(&cfileStart), sizeof(uint32_t));

    file.seekg(secdex + cnameAddr + 0x04);
    file.read((char*)(&cdataAddr), sizeof(uint32_t));
    file.seekg(secdex + cnameAddr + 0x08);
    file.read((char*)(&numNames), sizeof(uint32_t));
    file.seekg(secdex + cnameAddr + 0x0C);
    file.read((char*)(&cnameSize), sizeof(uint32_t));
    file.seekg(secdex + cnameAddr + 0x10);
    file.read((char*)(&cnameStart), sizeof(uint32_t));

    file.seekg(secdex + cdataAddr + 0x04);
    file.read((char*)(&termAddr), sizeof(uint32_t));
    file.seekg(secdex + cdataAddr + 0x08);
    file.read((char*)(&numData), sizeof(uint32_t));
    file.seekg(secdex + cdataAddr + 0x0C);
    file.read((char*)(&cdataSize), sizeof(uint32_t));
    file.seekg(secdex + cdataAddr + 0x10);
    file.read((char*)(&cdataStart), sizeof(uint32_t));


    file.seekg(secdex + cfileAddr);
    file.read((char*)(&chunk), sizeof(uint32_t));
    if (htonl(chunk) != FILE) return 0x00;


    if (hasLog) cout << numFiles << " files discovered" << endl;
    if (hasLog) extraction_log << "\tOffset: 0x" << std::hex << secdex << std::dec << "\n";
    if (hasLog) extraction_log << "\t" + to_string(numFiles) + " file descriptions in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numNames) + " file names in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numData) + " file data in current archive\n";

    uint32_t workAddr = secdex + cfileStart;
    int fileFound = 0;

    while (fileFound++ < numFiles && workAddr < (secdex + cfileStart) + cfileSize) {
        char buff;

        // Get extension of file being extracted
        file.seekg(workAddr);
        string temp_ext = "";
        while(temp_ext.length() < 4) {
            file.get(buff);
            if (buff == 0x00) break;
            temp_ext += buff;
        }
        workAddr += 0x04;

        // Get size of file being extracted (32 bit le)
        file.seekg(workAddr);
        uint32_t temp_size;
        file.read((char*)(&temp_size), sizeof(uint32_t));
        workAddr += 0x04;

        // Get location of file being extracted (32 bit le)
        file.seekg(workAddr);
        uint32_t temp_data_addr;
        file.read((char*)(&temp_data_addr), sizeof(uint32_t));
        workAddr += 0x04;

        // Get location of name of file being extracted (32 bit le)
        file.seekg(workAddr);
        uint32_t temp_name_addr;
        file.read((char*)(&temp_name_addr), sizeof(uint32_t));
        workAddr += 0x0C;


        // Get name of file being extracted
        file.seekg(secdex + temp_name_addr);
        string temp_name = "";
        while(true) {
            file.get(buff);
            if (buff == 0x00) break;
            temp_name += buff;
        }

        // Get data of file being extracted
        file.seekg(secdex + temp_data_addr);

        // Extract file
        if (fileExists(temp_name)) continue;

        ofstream extr_out(temp_name.c_str(), ios::binary);
        file.seekg(secdex + temp_data_addr);
        for(int ind = 0; ind < temp_size; ++ind) {
            file.get(buff);
            extr_out.put(buff);
        }
        extr_out.close();

        cout << "Extracted " << temp_name << endl;

        // Saves info to log file
        if (hasLog) extraction_log << "\t" << temp_name << "\n\t" <<
                                      "\tFile type: " << temp_ext << "\n\t" <<
                                      "\tFile address: 0x" << std::hex << secdex + temp_data_addr << std::dec << "\n\t" <<
                                      "\tFile size: " << temp_size << " bytes\n";
    }

    if (hasLog) extraction_log << '\n';

    return termAddr;
}

void searchGARC(string garc_filename) {
    ifstream file;
    ofstream extraction_log;

    string extracted_folder = "";
    string garc_index = "";
    string log_file = "";

    char buff;

    uint32_t sizeofsect = 0x00,
             index = sizeofsect;

    int num_garc = 0;

    extracted_folder = garc_filename.substr(0, garc_filename.find_last_of("\\/") + 1);

    _chdir(extracted_folder.c_str());

    garc_filename = garc_filename.substr(garc_filename.find_last_of("\\/") + 1);

    file.open(garc_filename.c_str(), ios::binary);
    if (!file.is_open()) {
        cerr << "Unable to open \"" << garc_filename << "\"" << endl;
        return;
    }

    file.seekg(0x00);

    extracted_folder += garc_filename.substr(0, garc_filename.find_last_of('.')) + "_extracted";

    _mkdir(extracted_folder.c_str());
    _chdir(extracted_folder.c_str());

    extracted_folder = "@" + garc_filename.substr(0, garc_filename.find_last_of('.'));

    log_file = garc_filename.substr(0, garc_filename.find_last_of('.')) + "_log.txt";
    if (hasLog) extraction_log.open(log_file.c_str());
    if (hasLog) if (hasLog) cout << "Saving extraction log to " << log_file << "\n" << endl;

    if (hasLog) cout << "Extracting from \"" << garc_filename << "\"" << endl;
    if (hasLog) extraction_log << "Files in " + garc_filename + ":\n";

    while (file.get(buff)) {
        uint32_t chunk;

        garc_index = "000";
        garc_index += to_string(num_garc);
        garc_index = garc_index.substr(garc_index.size() - 3);
        garc_index = "_" + garc_index;

        file.seekg(index);
        file.read((char*)(&chunk), sizeof(uint32_t));

        if (htonl(chunk) == GARC) {
            if (hasLog) cout << "\n" << (char*)(&chunk) << endl;
            if (num_garc < 1) garc_index = "";

            _mkdir((extracted_folder + garc_index).c_str());
            _chdir((extracted_folder + garc_index).c_str());
            if (hasLog) extraction_log << "Current folder: " + (extracted_folder + garc_index) + "\n";

            num_garc += 1;

            sizeofsect = fromGARC(extraction_log, file, index);

            if (sizeofsect > 0) {
                index += sizeofsect;
                _chdir("..");
            }
            else {
                remove((extracted_folder + garc_index).c_str());
                num_garc -= 1;
                index += 0x04;
            }
            continue;
        }
        else if (htonl(chunk) == SGXD) {
            if (hasLog) cout << "\n" << (char*)(&chunk) << endl;
            sizeofsect = extractSGXD(extraction_log, file, index);
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            continue;
        }
        else if (htonl(chunk) == XUI_) {
            if (hasLog) cout << "\n" << (char*)(&chunk) << " to TIMP" << endl;
            sizeofsect = timpFromXUI(extraction_log, file, index);
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            continue;
        }
        else if (htonl(chunk) == TIMP) {
            if (hasLog) cout << "\n" << (char*)(&chunk) << endl;
            sizeofsect = extractTIMP(extraction_log, file, index, "");
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            continue;
        }
        else {
            index += 0x01;
        }

        if (hasLog && index % 0x500 == 0) cout << '.' << endl;
    }
    file.close();

    if (hasLog) cout << num_garc << " arc file structures found and extracted\n" << endl;

    if (hasLog) extraction_log << "End of file\n";
    if (hasLog) extraction_log.close();
}

int main(int argc, char *argv[]) {
    string prgm = argv[0];
    prgm.erase(remove(prgm.begin(), prgm.end(), '\"'), prgm.end());
    prgm = prgm.substr(prgm.find_last_of("\\/") + 1, prgm.find_last_of('.'));


    if (argc < 2) {
        printOpts(prgm);
    }
    else {
        for (int fileIndex = 1; fileIndex < argc; ++fileIndex) {
            string argin = argv[fileIndex];
            argin.erase(remove(argin.begin(), argin.end(), '\"'), argin.end());

            if (argin == "-h") {
                printOpts(prgm);
                break;
            }
            else if (argin == "-l") {
                hasLog = true;
                continue;
            }

            searchGARC(argin);
        }
    }

    return 0;
}
