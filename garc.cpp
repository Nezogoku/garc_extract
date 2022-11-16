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


void searchGARC(string garc_filename) {
    if (isDebug) cout << std::setfill('0') << std::right;

    ifstream file;
    ofstream extraction_log;

    string extracted_folder = "";
    string log_file = "";

    //Checks if global LBA table has elements
    bool hasTable = (lbaTable.empty()) ? false : true;

    uint32_t sizeofsect = 0x00,
             sizeoffile = 0,
             index = 0x00,
             lbns = lbaTable.size(),
             lbni = 0;

    if (hasTable) {
        while (lbaTable[lbni].file_name == "FILE_NAME") lbni += 1;
        cout << "This binary file has " << (lbaTable.size() - lbni) << " files" << endl;
    }

    extracted_folder = garc_filename.substr(0, garc_filename.find_last_of("\\/") + 1);
    _chdir(extracted_folder.c_str());

    garc_filename = garc_filename.substr(garc_filename.find_last_of("\\/") + 1);

    file.open(garc_filename.c_str(), ios::binary);
    if (!file.is_open()) {
        cerr << "Unable to open \"" << garc_filename << "\"" << endl;
        return;
    }

    file.seekg(0x00, ios::end);
    sizeoffile = file.tellg();

    uchar *temp_src = new uchar[sizeoffile];
    file.seekg(0x00, ios::beg);
    file.read((char*)(temp_src), sizeoffile);
    file.close();

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


    while (true) {
        uint32_t chunk, lbSize;
        string lbName = "";

        if (hasTable && (lbni < lbns)) {
            index = lbaTable[lbni].file_rlbn * 0x0800;
            lbSize = lbaTable[lbni].file_size;
            lbName = lbaTable[lbni].file_name;

            lbni += 1;
        }
        else lbSize = sizeoffile - index;

        getBeInt(temp_src, chunk, index, 0x04);
        if (chunk == GARC) {
            sizeofsect = fromGARC(extraction_log, (temp_src + index), lbSize, lbName);

            if (sizeofsect > 0) index += sizeofsect;
            else index += 0x04;

            continue;
        }
        else if (chunk == GPRS) {
            sizeofsect = inflateGPRS(extraction_log, (temp_src + index), lbSize, lbName);

            if (sizeofsect > 0) index += sizeofsect;
            else index += 0x04;
        }
        else if (hasTable) {
            ofstream extr_out(lbName.c_str(), ios::binary);
            extr_out.write((const char*)(&temp_src[index]), lbSize);
            extr_out.close();
        }
        else index += 0x01;

        if (isDebug && (index % 0x800) == 0) cout << "Offset 0x"
                                                  << std::hex
                                                  << std::setw(8) << index << std::dec
                                                  << endl;

        //Check if reached end of table-less file or lba table
        if ((!hasTable && (index >= sizeoffile)) || (hasTable && lbni >= lbns)) break;
    }

    if (hasLog) extraction_log << "End of file\n";
    if (hasLog) extraction_log.close();

    delete[] temp_src;
}

int fromGARC(ofstream &extraction_log, uchar* src, int seclen, string name) {
    string garc_file;
    if (name.empty()) {
        if (num_garc < 1) {
            garc_file = "";
        }
        else {
            garc_file = "000";
            garc_file = garc_file + to_string(num_garc);
            garc_file = garc_file.substr(garc_file.size() - 3);
            garc_file = "_" + garc_file;
        }
        garc_file = "garc" + garc_file;
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


    getLeInt(src, cfileAddr, 0x14, 0x04);

    getBeInt(src, chunk, cfileAddr, 0x04);
    if (chunk != FILE) return 0x04;
    getLeInt(src, cnameAddr, cfileAddr + 0x04, 0x04);
    getLeInt(src, numFiles, cfileAddr + 0x08, 0x04);
    getLeInt(src, cfileSize, cfileAddr + 0x0C, 0x04);
    getLeInt(src, cfileStart, cfileAddr + 0x10, 0x04);

    getBeInt(src, chunk, cnameAddr, 0x04);
    if (chunk != NAME) return 0x04;
    getLeInt(src, cdataAddr, cnameAddr + 0x04, 0x04);
    getLeInt(src, numNames, cnameAddr + 0x08, 0x04);
    getLeInt(src, cnameSize, cnameAddr + 0x0C, 0x04);
    getLeInt(src, cnameStart, cnameAddr + 0x10, 0x04);

    getBeInt(src, chunk, cdataAddr, 0x04);
    if (chunk != DATA) return 0x04;
    getLeInt(src, termAddr, cdataAddr + 0x04, 0x04);
    getLeInt(src, numData, cdataAddr + 0x08, 0x04);
    getLeInt(src, cdataSize, cdataAddr + 0x0C, 0x04);
    getLeInt(src, cdataStart, cdataAddr + 0x10, 0x04);


    if (hasLog) extraction_log << "\tGARC\n";
    if (isDebug) cout << "GARC" << endl;
    if (isDebug) cout << numFiles << " files discovered" << endl;
    if (hasLog) extraction_log << "\t" + to_string(numFiles) + " file descriptions in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numNames) + " file names in current archive\n";
    if (hasLog) extraction_log << "\t" + to_string(numData) + " file data in current archive\n";

    _mkdir(garc_file.c_str());
    _chdir(garc_file.c_str());
    if (hasLog) extraction_log << "Current folder: " << garc_file << "\n";
    if (isDebug) cout << "Current folder: " << garc_file << endl;

    uint32_t workAddr = cfileStart;
    int fileFound = 0;

    while (fileFound++ < numFiles && workAddr < (cfileStart) + cfileSize) {
        bool save_file = false;

        // Get extension of file being extracted
        string temp_ext = "";
        for(int e = 0; e < 4; ++e) temp_ext += src[workAddr + e];
        workAddr += 0x04;

        // Get size of file being extracted (32 bit le)
        uint32_t temp_size;
        getLeInt(src, temp_size, workAddr, 0x04);
        workAddr += 0x04;

        // Get location of file being extracted (32 bit le)
        uint32_t temp_data_addr;
        getLeInt(src, temp_data_addr, workAddr, 0x04);
        workAddr += 0x04;

        // Get location of name of file being extracted (32 bit le)
        uint32_t temp_name_addr;
        getLeInt(src, temp_name_addr, workAddr, 0x04);
        workAddr += 0x0C;


        // Get name of file being extracted
        string temp_name = "";
        while(true) {
            if (!src[temp_name_addr]) break;
            temp_name += src[temp_name_addr++];
        }


        // Check if file exists
        if (fileExists(temp_name)) continue;

        //Check if compressed or GARC or sector.bin
        getBeInt(src, chunk, temp_data_addr, 0x04);
        if (chunk == GPRS) inflateGPRS(extraction_log, (src + temp_data_addr), temp_size, temp_name);
        else if (chunk == GARC) {
            if (hasLog) extraction_log << "\tExtracting " << temp_name;
            fromGARC(extraction_log, (src + temp_data_addr), temp_size, temp_name);
        }
        else if (chunk == GIMG) {
            if (hasLog) extraction_log << "\tRecording LBA values from " << temp_name << '\n';

            vector<lbaSpec> lba = getTableBIN((src + temp_data_addr));
            string csv_file = temp_name.substr(0, temp_name.find_last_of('.')) + ".csv";
            ofstream csv_out(csv_file.c_str());
            csv_out << "FILE_NAME,FILE_RLBN,FILE_SIZE\n";

            for (int line = 0; line < lba.size(); ++line) {
                csv_out << lba[line].file_name + ','
                        << to_string(lba[line].file_rlbn) + ','
                        << to_string(lba[line].file_size) + '\n';
            }
            csv_out.close();

            //Set global LBA table to local LBA table
            lbaTable.swap(lba);

            save_file = true;
        }
        else save_file = true;

        // Get data of file being extracted
        if (save_file) {
            ofstream extr_out(temp_name.c_str(), ios::binary);
            extr_out.write((const char*)(&src[temp_data_addr]), temp_size);
            extr_out.close();

            cout << "Extracted " << temp_name << endl;
            // Saves info to log file
            if (hasLog) extraction_log << "\t" << temp_name << "\n\t" <<
                                          "\tFile type: " << temp_ext << "\n\t" <<
                                          "\tFile address: 0x" << std::hex << temp_data_addr << std::dec << "\n\t" <<
                                          "\tFile size: " << temp_size << " bytes\n";
        }
    }

    cout << '\n';
    if (hasLog) extraction_log << '\n';
    num_garc += 1;
    _chdir("..");

    if (seclen == 0) seclen = termAddr + 0x04;

    return seclen;
}
