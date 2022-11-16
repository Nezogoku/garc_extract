#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>
#include "defines.hpp"

using std::cerr;
using std::endl;
using std::getline;
using std::ifstream;
using std::ios;
using std::ofstream;
using std::string;
using std::vector;


vector<lbaSpec> getTableCSV(string csv_filename) {
    vector<lbaSpec> out;
    string inLine;
    int nameLine = 0,
        sizeLine = 1,
        rlbnLine = 2;

    ifstream csv(csv_filename.c_str());
    if (!csv.is_open()) {
        cerr << "Unable to open \"" << csv_filename << "\"" << endl;
        return {};
    }

    csv.seekg(0x00);
    while (getline(csv, inLine)) {
        lbaSpec temp;

        for (int sect = 0; sect < 3; ++sect) {
            int pos = inLine.find_first_of(',');

            string tempSub = inLine.substr(0, pos);
            inLine = inLine.substr(pos + 1);

            if (tempSub == "FILE_NAME") nameLine = sect;
            else if (tempSub == "FILE_SIZE") sizeLine = sect;
            else if (tempSub == "FILE_RLBN") rlbnLine = sect;
            else {
                if (sect == nameLine) {
                    temp.file_name = tempSub;
                }
                else if (sect == sizeLine) {
                    try { temp.file_size = std::stoi(tempSub); }
                    catch(std::exception &e) {
                        cerr << tempSub << " is not a valid size" << endl;
                        csv.close();
                        return {};
                    }
                }
                else if (sect == rlbnLine) {
                    try { temp.file_rlbn = std::stoi(tempSub); }
                    catch(std::exception &e) {
                        cerr << tempSub << " is not a valid logical block number" << endl;
                        csv.close();
                        return {};
                    }
                }
            }


        }
        out.push_back(temp);
    }
    csv.close();

    return out;
}


vector<lbaSpec> getTableBIN(string bin_filename) {
    ifstream bin(bin_filename.c_str(), ios::binary);
    if (!bin.is_open()) {
        cerr << "Unable to open \"" << bin_filename << "\"" << endl;
        return {};
    }

    uint32_t binSize;
    bin.seekg(0x00, ios::end);
    binSize = bin.tellg();

    uchar temp_bin[binSize];
    bin.seekg(0x00);
    bin.read((char*)(temp_bin), binSize);
    bin.close();

    return getTableBIN(temp_bin);
}

vector<lbaSpec> getTableBIN(uchar* src) {
    vector<lbaSpec> out;
    uint32_t chunk, num_sects,
             index = 0x00;

    getBeInt(src, chunk, index, 0x04);
    index += 0x08;

    if (chunk != GIMG) {
        cerr << "This file does not store LBA info" << endl;
        return {};
    }

    getLeInt(src, num_sects, index, 0x04);
    index += 0x04;

    for (int s = 0; s < num_sects; ++s) {
        index = 0x0C + (s * 0x10);
        lbaSpec temp;

        getLeInt(src, chunk, index, 0x04);
        index += 0x04;
        getLeInt(src, temp.file_rlbn, index, 0x04);
        index += 0x04;
        getLeInt(src, temp.file_unkn, index, 0x04);
        index += 0x04;
        getLeInt(src, temp.file_size, index, 0x04);
        index += 0x04;


        temp.file_name = "";
        while(true) {
            if (!src[chunk]) break;
            temp.file_name += src[chunk++];
        }
        out.push_back(temp);
    }

    return out;
}
