#include <iomanip>
#include <iostream>
#include <cstdint>
#include <direct.h>
#include <fstream>
#include <string>
#include <vector>
#include "defines.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::ifstream;
using std::ios;
using std::ofstream;
using std::string;
using std::to_string;
using std::vector;
using std::remove;


void setReverse(uint32_t &tmpInt) {
    uint32_t buffer = 0x00;
    for (int b = 0; b < 4; ++b) {
        buffer |= uint8_t((tmpInt >> (0x00 + (8 * b))) & 0xFF);
        if (b != 3) buffer <<= 8;
    }
    tmpInt = buffer;
}


void searchGARC(vector<lbaSpec> table, string garc_filename, bool isDebug, bool hasLog) {
    if (isDebug) cout << std::setfill('0') << std::right;

    ifstream file;
    ofstream extraction_log;

    string extracted_folder = "";
    string log_file = "";

    bool hasTable = (table.empty()) ? false : true;

    uint32_t sizeofsect = 0x00,
             index = 0x00,
             lbns = table.size(),
             lbni = 0;

    if (hasTable) {
        while (table[lbni].file_name == "FILE_NAME") lbni += 1;
    }

    if (hasTable) cout << "This binary file has " << (table.size() - lbni) << " files" << endl;
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
    if (hasLog) cout << "Saving extraction log to " << log_file << "\n" << endl;

    if (isDebug) cout << "Extracting from \"" << garc_filename
                      << "\" to \"" << extracted_folder << "\"" << endl;
    if (hasLog) extraction_log << "Files in " + garc_filename + ":\n";


    char buff;
    while (true) {
        uint32_t chunk, lbSize = 0;
        string lbName = "";

        if (hasTable && (lbni < lbns)) {
            index = table[lbni].file_rlbn * 0x0800;
            lbSize = table[lbni].file_size;
            lbName = table[lbni].file_name;

            lbni += 1;
        }

        file.seekg(index);
        file.read((char*)(&chunk), sizeof(uint32_t));
        setReverse(chunk);

        if (chunk == GARC) {
            sizeofsect = fromGARC(extraction_log, file, isDebug, hasLog, index, lbSize, lbName);

            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
            continue;
        }
        else if (chunk == GPRS) {
            sizeofsect = DecryptGPRS(extraction_log, file, isDebug, hasLog, index, lbSize, lbName);
            if (sizeofsect > 0) {
                index += sizeofsect;
            }
            else {
                index += 0x04;
            }
        }
        else if (hasTable) {
            ofstream extr_out(lbName.c_str(), ios::binary);
            file.seekg(index);
            for(int ind = 0; ind < lbSize; ++ind) {
                file.get(buff);
                extr_out.put(buff);
            }
            extr_out.close();
        }
        else {
            index += 0x01;
        }

        if (isDebug && (index % 0x800) == 0) cout << "Offset 0x"
                                                  << std::hex
                                                  << std::setw(8) << index << std::dec
                                                  << endl;

        //Check if reached end of table-less file or lba table
        if ((!hasTable && !file.get(buff)) || (hasTable && lbni >= lbns)) break;
    }
    file.close();

    if (hasLog) extraction_log << "End of file\n";
    if (hasLog) extraction_log.close();
}

int fromGARC(ofstream &extraction_log, ifstream &file, bool isDebug, bool hasLog, int secdex, int seclen, string name) {
    static int num_garc = 0;
    string garc_file;
    if (name.empty()) {
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

    garc_file = garc_file.substr(0, garc_file.find_last_of('.'));


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


    if (hasLog) extraction_log << "\tGARC\n";
    if (isDebug) cout << "GARC" << endl;
    if (isDebug) cout << numFiles << " files discovered" << endl;
    if (hasLog) extraction_log << "\tOffset: 0x" << std::hex << secdex << std::dec << "\n";
    if (hasLog) extraction_log << "\t" + to_string(numFiles) + " file descriptions in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numNames) + " file names in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numData) + " file data in current archive\n";

    _mkdir(garc_file.c_str());
    _chdir(garc_file.c_str());
    if (hasLog) extraction_log << "Current folder: " << garc_file << "\n";
    if (isDebug) cout << "Current folder: " << garc_file << endl;

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

        //Check if compressed or GARC or sector.bin
        bool delFile = true;

        ifstream test_file;
        test_file.open(temp_name.c_str(), ios::binary);
        test_file.seekg(0x00);
        test_file.read((char*)(&chunk), sizeof(uint32_t));
        setReverse(chunk);

        if (chunk == GPRS) DecryptGPRS(extraction_log, test_file, isDebug, hasLog, 0x00, temp_size, temp_name);
        else if (chunk == GARC) {
            if (hasLog) extraction_log << "\tExtracting " << temp_name;
            fromGARC(extraction_log, test_file, isDebug, hasLog, 0x00, temp_size, temp_name);
        }
        else if (chunk == GIMG) {
            if (hasLog) extraction_log << "\tRecording LBA values from " << temp_name << '\n';
            test_file.close();

            vector<lbaSpec> lba = getTableBIN(temp_name);

            string csv_file = temp_name.substr(0, temp_name.find_last_of('.')) + ".csv";

            ofstream csv_out(csv_file.c_str());
            csv_out << "FILE_NAME,FILE_RLBN,FILE_SIZE\n";

            for (int line = 0; line < lba.size(); ++line) {
                csv_out << lba[line].file_name + ','
                        << to_string(lba[line].file_rlbn) + ','
                        << to_string(lba[line].file_size) + '\n';
            }
            csv_out.close();

            delFile = false;
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

    if (seclen == 0) seclen = termAddr + 0x04;

    return seclen;
}
