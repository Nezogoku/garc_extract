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
    vector<lbaSpec> out;
    uint32_t chunk, num_sects,
             index = 0x00;

    ifstream bin(bin_filename.c_str(), ios::binary);
    if (!bin.is_open()) {
        cerr << "Unable to open \"" << bin_filename << "\"" << endl;
        return {};
    }

    bin.seekg(index);
    bin.read((char*)(&chunk), sizeof(uint32_t));
    setReverse(chunk);

    if (chunk != GIMG) {
        cerr << "This file does not store LBA info" << endl;
        bin.close();
        return {};
    }

    bin.seekg(index + 0x08);
    bin.read((char*)(&num_sects), sizeof(uint32_t));

    for (int s = 0; s < num_sects; ++s) {
        index = 0x0C + (s * 0x10);
        lbaSpec temp;

        bin.seekg(index + 0x00);
        bin.read((char*)(&chunk), sizeof(uint32_t));

        bin.seekg(index + 0x04);
        bin.read((char*)(&temp.file_rlbn), sizeof(uint32_t));

        bin.seekg(index + 0x08);
        bin.read((char*)(&temp.file_unkn), sizeof(uint32_t));

        bin.seekg(index + 0x0C);
        bin.read((char*)(&temp.file_size), sizeof(uint32_t));


        bin.seekg(chunk);
        temp.file_name = "";
        while(true) {
            char buff;
            bin.get(buff);
            if (buff == 0x00) break;
            temp.file_name += buff;
        }
        out.push_back(temp);
    }
    bin.close();

    return out;
}
