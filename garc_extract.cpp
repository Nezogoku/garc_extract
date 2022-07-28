#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <vector>
#include <string>
#include <direct.h>

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

#define GPRS 0x47505253
#define GARC 0x47415243
#define FILE 0x46494C45

#define SGXD 0x53475844
#define NAME 0x4E414D45

#define XUI_ 0x58554900
#define TIMP 0x54494D50
#define TIPM 0x01000100

#define LRMD 0x4C524D44


bool hasLog = false;

int extractTIMP(ofstream &extraction_log, ifstream &file, int secdex, string name);
int fromXUI(ofstream &extraction_log, ifstream &file, int secdex);
int extractSGXD(ofstream &extraction_log, ifstream &file, int secdex);
int fromGARC(ofstream &extraction_log, ifstream &file, int secdex, string name);
int DecryptGPRS(ofstream &extraction_log, ifstream &section, int index, string name);


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

void setReverse(uint32_t &tmpInt) {
    uint32_t buffer = 0x00;
    for (int b = 0; b < 4; ++b) {
        buffer |= uint8_t((tmpInt >> (0x00 + (8 * b))) & 0xFF);
        if (b != 3) buffer <<= 8;
    }
    tmpInt = buffer;
}

int extractTIMP(ofstream &extraction_log, ifstream &file, int secdex, string name) {
    if (hasLog) extraction_log << "TIMP\n";
    if (hasLog) cout << "TIMP" << endl;

    static int iter = 0;
    string timpName = (name == "") ? "unknown_timp_" + to_string(iter++): name;

    uint32_t chunk;


    file.seekg(secdex + 0x04);
    file.read((char*)(&chunk), sizeof(uint32_t));
    setReverse(chunk);
    if (chunk != TIPM) {
        if (hasLog) extraction_log << "\tThis is not a TIMP file\n";
        if (hasLog) cout << "Not a TIMP file" << endl;
        return 0x04;
    }

    timpName += ".tip";

    if (fileExists(timpName)) {
        cout << timpName << " already exists" << endl;
        return 0x04;
    }

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

/* Don't feel like writing this out...
int fromXUI(ofstream &extraction_log, ifstream &file, int secdex) {
    static struct data_def {
        uint32_t offset_name;
        string name;
        uint32_t offset_data;
        char type;              //P for PATH, F for FILE NAME
    };

    vector<data_def> xuiBank;

    if (hasLog) extraction_log << "XUI \n";
    if (hasLog) cout << "XUI to misc. files" << endl;

    uint32_t offsetDefs = 0x00,
             offsetNames = 0x00,
             offsetTemp = 0x00,
             chunk;
    int miscCounter = 0;

    file.seekg(secdex + 0x08);
    file.read((char*)(&offsetDefs), sizeof(uint32_t));

    file.seekg(secdex + 0x10);
    file.read((char*)(&offsetNames), sizeof(uint32_t));


    while (offsetTemp < offsetDefs) {
        data_def temp;

        offsetTemp = secdex + offsetDefs + (0x04 * miscCounter++);
        file.seekg(offsetTemp);
        file.read((char*)(&temp.offset_name), sizeof(uint32_t));

        if ((temp.offset_name >= offsetNames) && (temp.offset_name < offsetDefs)) {
            file.seekg(temp.offset_name);
            temp.name = "";

            while(true) {
                char buff;
                file.get(buff);
                if (buff == 0x00) break;
                temp.name += buff;
            }

            temp.offset_data = temp.offset_name + temp.name.size() + 0x01;
            temp.type = 'P';
            xuiBank.push_back(temp);
        }
    }
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

        if (setReverse(chunk) == TIMP) {
            timpFound = true;
            break;
        }
    }

    if (!(timpFound) || fileExists(timpName)) return tempdex + nameSize;

    return nameSize + tempdex + extractTIMP(extraction_log, file, secdex + nameSize + tempdex, timpName);
}
*/

int extractSGXD(ofstream &extraction_log, ifstream &file, int secdex) {
    if (hasLog) extraction_log << "SGXD\n";
    if (hasLog) cout << "\nSGXD" << endl;

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

    if (fileExists(sgxdName)) {
        cout << sgxdName << " already exists" << endl;
        return data_offset + data_length;
    }

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

int extractLRMD(ofstream &extraction_log, ifstream &file, int secdex, string name) {
    if (hasLog) extraction_log << "LRMD\n";
    if (hasLog) cout << "\nLRMD" << endl;

    static int iter_l = 0;
    string lrmdName = (name == "") ? "unknown_lrmd_" + std::to_string(iter_l++): name;

    uint32_t data_offset;                                                       // Address to start of sample data
    uint32_t data_length;                                                       // Length of data

    file.seekg(secdex + 0x08);
    file.read((char*)(&data_offset), sizeof(uint32_t));
    file.seekg(secdex + 0x0C);
    file.read((char*)(&data_length), sizeof(uint32_t));

    if (true) {
        data_length = 0x00;
        lrmdName += ".lrmh";
    }
    else {}

    if (fileExists(lrmdName)) {
        cout << lrmdName << " already exists" << endl;
        return data_offset + data_length;
    }

    ofstream extr_out(lrmdName.c_str(), ios::binary);
    file.seekg(secdex);
    for(int i = 0; i < (data_offset + data_length); ++i) {
        char buff;
        file.get(buff);
        extr_out.put(buff);
    }
    extr_out.close();

    cout << "Extracted " << lrmdName << endl;
    if (hasLog) extraction_log << "\t" << lrmdName << "\n\t" <<
                                  "\tFile type: lrmd\n\t" <<
                                  "\tFile address: 0x" << std::hex << secdex << std::dec << "\n\t" <<
                                  "\tFile size: " << data_offset + data_length << " bytes\n";

    return data_offset + data_length;
}

int fromGARC(ofstream &extraction_log, ifstream &file, int secdex, string name) {
    static int num_garc = 0;
    string garc_file;
    if (name == "") {
        garc_file = "000";
        if (num_garc < 1) {
            garc_file = "";
        }
        else {
            garc_file += to_string(num_garc);
            garc_file = garc_file.substr(garc_file.size() - 3);
        }

        garc_file = "garc_" + garc_file;
    }
    else garc_file = name;
    garc_file = garc_file.substr(garc_file.find_last_of("\\/") + 1, garc_file.find_last_of('.'));


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
    setReverse(chunk);
    if (chunk != FILE) {
        return 0x04;
    }


    if (hasLog) extraction_log << "GARC\n";
    if (hasLog) cout << "GARC" << endl;
    if (hasLog) cout << numFiles << " files discovered" << endl;
    if (hasLog) extraction_log << "\tOffset: 0x" << std::hex << secdex << std::dec << "\n";
    if (hasLog) extraction_log << "\t" + to_string(numFiles) + " file descriptions in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numNames) + " file names in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numData) + " file data in current archive\n";

    _mkdir(garc_file.c_str());
    _chdir(garc_file.c_str());
    if (hasLog) extraction_log << "Current folder: " << garc_file << "\n";
    if (hasLog) cout << "Current folder: " << garc_file << endl;

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

        //Check if compressed or GARC
        bool delFile = true;

        ifstream test_file;
        test_file.open(temp_name.c_str(), ios::binary);
        test_file.seekg(0x00);
        test_file.read((char*)(&chunk), sizeof(uint32_t));
        setReverse(chunk);

        if (chunk == GPRS) DecryptGPRS(extraction_log, test_file, 0x00, temp_name);
        else if (chunk == GARC) {
            if (hasLog) extraction_log << "\tExtracting " << temp_name << " as ";
            fromGARC(extraction_log, test_file, 0x00, temp_name);
        }
        else delFile = false;

        test_file.close();
        if (delFile) remove(temp_name.c_str());


        cout << "Extracted " << temp_name << endl;

        // Saves info to log file
        if (hasLog) extraction_log << "\t" << temp_name << "\n\t" <<
                                      "\tFile type: " << temp_ext << "\n\t" <<
                                      "\tFile address: 0x" << std::hex << secdex + temp_data_addr << std::dec << "\n\t" <<
                                      "\tFile size: " << temp_size << " bytes\n";
    }

    cout << '\n';
    if (hasLog) extraction_log << '\n';
    num_garc += 1;
    _chdir("..");

    return termAddr;
}

//More code from that owocek person
//Would this be considered decryption or decoding?
//I assumed these were basically zip files using some algorithm but...
int DecryptGPRS(ofstream &extraction_log, ifstream &section, int index, string name) {
    if (hasLog) extraction_log << "\tGPRS\n";
    if (hasLog) cout << "GPRS" << endl;

    static int num_gprs = 0;
    string dat_file;
    if (name == "") {
        dat_file = "000";
        dat_file += to_string(num_gprs++);
        dat_file = "gprs_" + dat_file.substr(dat_file.size() - 3) + ".out";
    }
    else dat_file = name;


    uint32_t GPRS_start = 0x00;
    uint32_t GARC_start = 0xA210D0;

    uint32_t v0 = 0x80;         //0x1CFD8;
    uint32_t v1 = 0x00;         //0x00;
    uint32_t a0 = GARC_start;   //GARC_start;
    uint32_t a1 = 0x09;         //0x08;
    uint32_t a2 = 0x0A;         //0x00;
    uint32_t a3 = 0x08;         //0x08;
    uint32_t t0 = 0x01;         //0x00;
    uint32_t t1 = 0x00;         //0x00;
    uint32_t t2 = -0x0100;      //0x00;
    uint32_t t3 = 0x00;         //0x00;
    uint32_t t4 = 0x00;         //0x00;
    uint32_t at = 0x00;         //0x00;

    bool running = true,
         jump = false;

    int jump_count = 0;

    uint32_t curr_addr = 0x00,
             jump_addr = 0x00,
             end_addr = 0x00;


    vector<uint32_t> MAGIC_file = {0x350,0x348,0x340,0x338,
                                   0x330,0x328,0x320,0x318,
                                   0x86C,0x864,0x85C,0x854,
                                   0x84C,0x844,0x83C,0x834};
    vector<char> temp_file;

    while (running) {
        uint32_t t_addr;
        char buff;

        switch(curr_addr) {
            case 0x00:
                section.seekg(index + 0x08);
                section.get(buff);
                a3 = buff;

                if (0x08 > end_addr) end_addr = 0x08;
                curr_addr = 0x18;
                break;

            case 0x18:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0x34;
                }

                curr_addr += 0x04;
                break;

            case 0x1C:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x20:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    a3 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                a1 = a2;
                v0 = int32_t(0x80);
                a2 = a1 + int32_t(0x01);
                t1 = a3 & v0;

                curr_addr += 0x14;
                break;

            case 0x34:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0x48;
                }

                curr_addr += 0x04;
                break;

            case 0x38:
                t3 = v0 >> 0x01;
                v0 = t3;

                curr_addr += 0x08;
                break;

            case 0x40:
                jump = true;
                jump_addr = 0x50;
                curr_addr += 0x04;
                break;

            case 0x44:
                t1 = t0;
                curr_addr += 0x04;
                break;

            case 0x48:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x4C:
                t1 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0x50:
                if (t1 != 0x00) {
                    jump = true;
                    jump_addr = 0x70;
                }

                curr_addr += 0x04;
                break;

            case 0x54:
                curr_addr += 0x04;
                break;

            case 0x58:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x5C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x60:
                if (a0 >= GARC_start) {
                    buff = t1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x64:
                a0 += int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x68:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x6C:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x70:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x8C;
                }

                curr_addr += 0x04;
                break;

            case 0x74:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x78:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    a3 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x7C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x80:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x84:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x88:
                t1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x8C:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0xA0;
                }

                curr_addr += 0x04;
                break;

            case 0x90:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x94:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x98:
                jump = true;
                jump_addr = 0xA8;
                curr_addr += 0x04;
                break;

            case 0x9C:
                t1 = t0;
                curr_addr += 0x04;
                break;

            case 0xA0:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0xA4:
                t1 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0xA8:
                if (t1 != t0) {
                    jump = true;
                    jump_addr = 0x01A4;
                }

                curr_addr += 0x04;
                break;

            case 0xAC:
                curr_addr += 0x04;
                break;

            case 0xB0:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0xB4:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0xB8:
                t1 = t1 | t2;
                curr_addr += 0x04;
                break;

            case 0xBC:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0xD4;
                }

                curr_addr += 0x04;
                break;

            case 0xC0:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0xC4:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0xC8:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0xCC:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0xD0:
                v1 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0xD4:
                t3 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0xD8:
                if (t3 == 0x00) {
                    jump = true;
                    jump_addr = 0xEC;
                }

                curr_addr += 0x04;
                break;

            case 0xDC:
                v1 = v1 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0xE0:
                t3 = v1;
                curr_addr += 0x04;
                break;

            case 0xE4:
                jump = true;
                jump_addr = 0xF4;
                curr_addr += 0x04;
                break;

            case 0xE8:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0xEC:
                t3 = v1;
                curr_addr += 0x04;
                break;

            case 0xF0:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0xF4:
                if (v1 != 0x00) {
                    jump = true;
                    jump_addr = 0x010C;
                }

                curr_addr += 0x04;
                break;

            case 0xF8:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0xFC:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x100:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x104:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x108:
                t3 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x10C:
                v0 = a3 & t3;
                curr_addr += 0x04;
                break;

            case 0x110:
                if (v0 == 0x00) {
                    jump = true;
                    jump_addr = 0x0124;
                }

                curr_addr += 0x04;
                break;

            case 0x114:
                t3 = t3 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x118:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x11C:
                jump = true;
                jump_addr = 0x012C;
                curr_addr += 0x04;
                break;

            case 0x120:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x124:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x128:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x12C:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x0144;
                }

                curr_addr += 0x04;
                break;

            case 0x130:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x134:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x138:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x13C:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x140:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x144:
                v1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x148:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x015C;
                }

                curr_addr += 0x04;
                break;

            case 0x14C:
                t3 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x150:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x154:
                jump = true;
                jump_addr = 0x0164;
                curr_addr += 0x04;
                break;

            case 0x158:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x15C:
                v0 = t3;
                curr_addr += 0x04;
                break;

            case 0x160:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x164:
                if (t3 != 0x00) {
                    jump = true;
                    jump_addr = 0x017C;
                }

                curr_addr += 0x04;
                break;

            case 0x168:
                t1 = t1 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x16C:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x170:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x174:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x178:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x17C:
                t3 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x180:
                if (t3 == 0x00) {
                    jump = true;
                    jump_addr = 0x0194;
                }

                curr_addr += 0x04;
                break;

            case 0x184:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x188:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x18C:
                jump = true;
                jump_addr = 0x019C;
                curr_addr += 0x04;
                break;

            case 0x190:
                t1 = t1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x194:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x198:
                t1 = t1;
                curr_addr += 0x04;
                break;

            case 0x19C:
                jump = true;
                jump_addr = 0x01C0;
                curr_addr += 0x04;
                break;

            case 0x1A0:
                t1 = t1 + int32_t(-0xFF);
                curr_addr += 0x04;
                break;

            case 0x1A4:
                if ((a1 >= GPRS_start) && (a1 < GARC_start)) {
                    section.seekg(index + a1);
                    section.get(buff);
                    t1 = buff;

                    if (a1 > end_addr) end_addr = a1;
                }

                if (a1 >= GARC_start) {
                    t_addr = a1 - GARC_start;

                    t1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x1A8:
                if (t1 == 0x00) {
                    jump = true;
                    jump_addr = 0x01B8;
                }

                curr_addr += 0x04;
                break;

            case 0x1AC:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x1B0:
                jump = true;
                jump_addr = 0x01C0;
                curr_addr += 0x04;
                break;

            case 0x1B4:
                t1 = t1 | t2;
                curr_addr += 0x04;
                break;

            case 0x1B8:
                jump = true;
                jump_addr = 0x036C;
                curr_addr += 0x04;
                break;

            case 0x1BC:
                curr_addr += 0x04;
                break;

            case 0x1C0:
                t3 = t0;
                curr_addr += 0x04;
                break;

            case 0x1C4:
                if (v0 != 0x00) {
                    jump = true;
                    jump_addr = 0x01E0;
                }

                curr_addr += 0x04;
                break;

            case 0x1C8:
                v0 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0x1CC:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x1D0:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x1D4:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x1D8:
                v1 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x1DC:
                v0 = a3 & v1;
                curr_addr += 0x04;
                break;

            case 0x1E0:
                if (v0 == 0x00) {
                    jump = true;
                    jump_addr = 0x01F4;
                }

                curr_addr += 0x04;
                break;

            case 0x1E4:
                v1 = v1 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x1E8:
                v0 = v1;
                curr_addr += 0x04;
                break;

            case 0x1EC:
                jump = true;
                jump_addr = 0x01FC;
                curr_addr += 0x04;
                break;

            case 0x1F0:
                t4 = t0;
                curr_addr += 0x04;
                break;

            case 0x1F4:
                v0 = v1;
                curr_addr += 0x04;
                break;

            case 0x1F8:
                t4 = int32_t(0x00);
                curr_addr += 0x04;
                break;

            case 0x1FC:
                if (t4 != t0) {
                    jump = true;
                    jump_addr = 0x0244;
                }

                curr_addr += 0x04;
                break;

            case 0x200:
                curr_addr += 0x04;
                break;

            case 0x204:
                if (v1 != 0x00) {
                    jump = true;
                    jump_addr = 0x021C;
                }

                curr_addr += 0x04;
                break;

            case 0x208:
                t3 = t3 << 0x01;
                curr_addr += 0x04;
                break;

            case 0x20C:
                if ((a2 >= GPRS_start) && (a2 < GARC_start)) {
                    section.seekg(index + a2);
                    section.get(buff);
                    a3 = buff;

                    if (a2 > end_addr) end_addr = a2;
                }

                if (a2 >= GARC_start) {
                    t_addr = a2 - GARC_start;

                    a3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x210:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x214:
                a1 = a2;
                curr_addr += 0x04;
                break;

            case 0x218:
                v0 = int32_t(0x80);
                curr_addr += 0x04;
                break;

            case 0x21C:
                v1 = a3 & v0;
                curr_addr += 0x04;
                break;

            case 0x220:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x0234;
                }

                curr_addr += 0x04;
                break;

            case 0x224:
                v0 = v0 >> 0x01;
                curr_addr += 0x04;
                break;

            case 0x228:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x22C:
                jump = true;
                jump_addr = 0x023C;
                curr_addr += 0x04;
                break;

            case 0x230:
                t3 = t3 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x234:
                v1 = v0;
                curr_addr += 0x04;
                break;

            case 0x238:
                t3 = t3;
                curr_addr += 0x04;
                break;

            case 0x23C:
                jump = true;
                jump_addr = 0x01C4;
                curr_addr += 0x04;
                break;

            case 0x240:
                curr_addr += 0x04;
                break;

            case 0x244:
                if (t3 < 0x7) a2 = 1;
                else a2 = 0;

                curr_addr += 0x04;
                break;

            case 0x248:
                if (a2 == 0x00) {
                    jump = true;
                    jump_addr = 0x0278;
                    curr_addr += 0x04;
                }
                else curr_addr += 0x08;
                break;

            case 0x24C:
                t3 = t3 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x250:
                if (t3 < 0) {
                    jump = true;
                    jump_addr = 0x364;
                }

                curr_addr += 0x04;
                break;

            case 0x254:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x258:
                v1 = a0 + t1;
                curr_addr += 0x04;
                break;

            case 0x25C:
                if ((v1 >= GPRS_start) && (v1 < GARC_start)) {
                    section.seekg(index + v1);
                    section.get(buff);
                    v1 = buff;

                    if (v1 > end_addr) end_addr = v1;
                }
                if (v1 >= GARC_start) {
                    t_addr = v1 - GARC_start;

                    v1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x260:
                t3 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x264:
                if (a0 >= GARC_start) {
                    buff = v1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x268:
                if ((int32_t)t3 >= 0) {
                    jump = true;
                    jump_addr = 0x0258;
                }

                curr_addr += 0x04;
                break;

            case 0x26C:
                a0 = a0 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x270:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x274:
                curr_addr += 0x04;
                break;

            case 0x278:
                a2 = t3 >> 0x3;
                curr_addr += 0x04;
                break;

            case 0x27C:
                t3 = t3 & 0x7;
                curr_addr += 0x04;
                break;

            case 0x280:
                v1 = t3 + int32_t(-0x08);
                curr_addr += 0x04;
                break;

            case 0x284:
                a0 = a0 + v1;
                curr_addr += 0x04;
                break;

            case 0x288:
                if (t3 < 0x08) v1 = 1;
                else v1 = 0;

                curr_addr += 0x04;
                break;

            case 0x28C:
                if (v1 == 0x00) {
                    jump = true;
                    jump_addr = 0x02AC;
                }

                curr_addr += 0x04;
                break;

            case 0x290:
                t1 = a0 + t1;
                curr_addr += 0x04;
                break;

            case 0x294:
                t3 = t3 << 0x02;
                curr_addr += 0x04;
                break;

            case 0x298:
                at = 0x00;
                curr_addr += 0x04;
                break;

            case 0x29C:
                at = at + t3;
                curr_addr += 0x04;
                break;

            case 0x2A0:
                at = MAGIC_file[at / 4];
                curr_addr += 0x04;
                break;

            case 0x2A4:
                jump = true;
                jump_addr = at;
                curr_addr += 0x04;
                break;

            case 0x2A8:
                curr_addr += 0x04;
                break;

            case 0x2AC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    section.seekg(index + t1);
                    section.get(buff);
                    t3 = buff;

                    if (t1 > end_addr) end_addr = t1;
                }

                if (t1 >= GARC_start) {
                    t_addr = t1 - GARC_start;
                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2B0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2B4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x01 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x01 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2B8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2BC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x02 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x02 + t1 - GARC_start;
                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2C0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2C4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x3 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x3 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2C8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2CC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x04 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x04 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2D0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2D4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x05 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x05 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2D8:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2DC:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x6 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x6 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2E0:
                if (a0 >= GARC_start) {
                    buff = t3;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2E4:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x7 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    v1 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x7 + t1 - GARC_start;

                    v1 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x2E8:
                t3 = a2;
                curr_addr += 0x04;
                break;

            case 0x2EC:
                a2 = a0 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x2F0:
                if (a0 >= GARC_start) {
                    buff = v1;
                    temp_file.push_back(buff);
                }

                curr_addr += 0x04;
                break;

            case 0x2F4:
                t1 = t1 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x2F8:
                a0 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x2FC:
                t3 = a0;
                curr_addr += 0x04;
                break;

            case 0x300:
                a0 = a2;
                curr_addr += 0x04;
                break;

            case 0x304:
                a2 = t3;
                curr_addr += 0x04;
                break;

            case 0x308:
                if ((int32_t)a2 >= 0) {
                    jump = true;
                    jump_addr = 0x02AC;
                }

                curr_addr += 0x04;
                break;

            case 0x30C:
                curr_addr += 0x04;
                break;

            case 0x310:
                jump = true;
                jump_addr = 0x0364;
                curr_addr += 0x04;
                break;

            case 0x314:
                a2 = a1 + int32_t(0x01);
                curr_addr += 0x04;
                break;

            case 0x318:
                jump = true;
                jump_addr = 0x02B8;
                curr_addr += 0x04;
                break;

            case 0x31C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x01 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x01 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x320:
                jump = true;
                jump_addr = 0x02C0;
                curr_addr += 0x04;
                break;

            case 0x324:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x02 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x02 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x328:
                jump = true;
                jump_addr = 0x02C8;
                curr_addr += 0x04;
                break;

            case 0x32C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x3 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x3 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x330:
                jump = true;
                jump_addr = 0x02D0;
                curr_addr += 0x04;
                break;

            case 0x334:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x04 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x04 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x338:
                jump = true;
                jump_addr = 0x02D8;
                curr_addr += 0x04;
                break;

            case 0x33C:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x05 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x05 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x340:
                jump = true;
                jump_addr = 0x02E0;
                curr_addr += 0x04;
                break;

            case 0x344:
                if ((t1 >= GPRS_start) && (t1 < GARC_start)) {
                    t_addr = 0x6 + t1;

                    section.seekg(index + t_addr);
                    section.get(buff);
                    t3 = buff;

                    if (t_addr > end_addr) end_addr = t_addr;
                }

                if (t1 >= GARC_start) {
                    t_addr = 0x6 + t1 - GARC_start;

                    t3 = (int32_t)temp_file[t_addr];
                }

                curr_addr += 0x04;
                break;

            case 0x348:
                jump = true;
                jump_addr = 0x02E4;
                curr_addr += 0x04;
                break;

            case 0x34C:
                curr_addr += 0x04;
                break;

            case 0x350:
                t3 = a2;
                curr_addr += 0x04;
                break;

            case 0x354:
                a2 = a0 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x358:
                t1 = t1 + int32_t(0x08);
                curr_addr += 0x04;
                break;

            case 0x35C:
                jump = true;
                jump_addr = 0x02FC;
                curr_addr += 0x04;
                break;

            case 0x360:
                a0 = t3 + int32_t(-0x01);
                curr_addr += 0x04;
                break;

            case 0x364:
                jump = true;
                jump_addr = 0x18;
                curr_addr += 0x04;
                break;

            case 0x368:
                curr_addr += 0x04;
                break;

            case 0x36C:
                running = false;
                break;
        }

        if(jump_count >= 1) {
            jump_count = 0;
            curr_addr = jump_addr;
        }

        if(jump) {
            jump = false;
            jump_count = 1;
        }
    }

    cout << "Size of decompressed section: " << temp_file.size() / 1024 << "kB" << endl;
    if (hasLog) extraction_log << "\tSize of compressed section: " << (end_addr - index) / 1024 << "kB\n";
    if (hasLog) extraction_log << "\tSize of decompressed section: " << temp_file.size() / 1024 << "kB\n";

    ofstream out_file;
    out_file.open(dat_file, ios::binary);
    out_file.write((const char*)(temp_file.data()), temp_file.size());
    out_file.close();
    vector<char> ().swap(temp_file);

    bool delFile = true;
    uint32_t chunk;

    ifstream test_file;
    test_file.open(dat_file, ios::binary);
    test_file.seekg(0x00);
    test_file.read((char*)(&chunk), sizeof(uint32_t));
    setReverse(chunk);


    if (hasLog) extraction_log << "\tDecompressed file to type ";

    if (chunk == GPRS) DecryptGPRS(extraction_log, test_file, 0x00, dat_file);
    else if (chunk == GARC) fromGARC(extraction_log, test_file, 0x00, dat_file);
    else if (chunk == SGXD) extractSGXD(extraction_log, test_file, 0x00);
    else if (chunk == TIMP) extractTIMP(extraction_log, test_file, 0x00, "");
    //else if (chunk == XUI_) timpFromXUI(extraction_log, test_file, 0x00);
    else if (chunk == LRMD) extractLRMD(extraction_log, test_file, 0x00, "");
    else delFile = false;

    test_file.close();

    if (delFile) remove(dat_file.c_str());

    return end_addr;
}

void searchGARC(string garc_filename) {
    if (hasLog) cout << std::setfill('0') << std::right;

    ifstream file;
    ofstream extraction_log;

    string extracted_folder = "";
    string log_file = "";

    char buff;

    uint32_t sizeofsect = 0x00,
             index = sizeofsect;

    extracted_folder = garc_filename.substr(0, garc_filename.find_last_of("\\/") + 1);

    _chdir(extracted_folder.c_str());

    garc_filename = garc_filename.substr(garc_filename.find_last_of("\\/") + 1);

    file.open(garc_filename.c_str(), ios::binary);
    if (!file.is_open()) {
        cerr << "Unable to open \"" << garc_filename << "\"" << endl;
        return;
    }

    file.seekg(0x00);

    extracted_folder += garc_filename.substr(0, garc_filename.find_last_of('.'));

    _mkdir(extracted_folder.c_str());
    _chdir(extracted_folder.c_str());

    extracted_folder = garc_filename.substr(0, garc_filename.find_last_of('.'));

    log_file = garc_filename.substr(0, garc_filename.find_last_of('.')) + "_log.txt";
    if (hasLog) extraction_log.open(log_file.c_str());
    if (hasLog) if (hasLog) cout << "Saving extraction log to " << log_file << "\n" << endl;

    if (hasLog) cout << "Extracting from \"" << garc_filename
                     << "\" to \"" << extracted_folder << "\"" << endl;
    if (hasLog) extraction_log << "Files in " + garc_filename + ":\n";

    while (file.get(buff)) {
        uint32_t chunk;

        file.seekg(index);
        file.read((char*)(&chunk), sizeof(uint32_t));
        setReverse(chunk);

        if (chunk == GARC) {
            sizeofsect = fromGARC(extraction_log, file, index, "");

            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        else if (chunk == SGXD) {
            sizeofsect = extractSGXD(extraction_log, file, index);
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        /*
        else if (chunk == XUI_) {
            sizeofsect = timpFromXUI(extraction_log, file, index);
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        */
        else if (chunk == TIMP) {
            sizeofsect = extractTIMP(extraction_log, file, index, "");
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        else if (chunk == LRMD) {
            sizeofsect = extractLRMD(extraction_log, file, index, "");
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        else if (chunk == GPRS) {
            sizeofsect = DecryptGPRS(extraction_log, file, index, "");
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
        }
        else {
            index += 0x01;
        }

        if (hasLog && (index % 0x800) == 0) cout << "Offset 0x" << std::hex << std::setw(8) << index << std::dec << endl;
    }
    file.close();

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
