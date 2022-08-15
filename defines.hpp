#ifndef DEFINES_HPP
#define DEFINES_HPP

#include <iostream>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#define GPRS 0x47505253
#define GIMG 0x47494D47
#define GARC 0x47415243
#define FILE 0x46494C45
#define NAME 0x4E414D45


///Logical Block Access info stuffs
struct lbaSpec {
    std::string file_name; //Name of file
    uint32_t    file_rlbn; //Relative logical block number of file
    uint32_t    file_unkn; //I dunno
    uint32_t    file_size; //Size of file
};

///Reverse byte order (32 bits)
void setReverse(uint32_t &tmpInt);

///Remove quotation marks from file name
void removeQuote(std::string &arg);

///Print options
void printOpts(std::string prgm);

///Print error message
void printErr(const char* opt, std::string arg, int code);

///Check if file exists
bool fileExists(std::string fName);

///Extract files from LocoRoco archive
int fromGARC(std::ofstream &extraction_log, std::ifstream &file, bool isDebug, bool hasLog, int secdex, int seclen, std::string name);

///Inflate file
int DecryptGPRS(std::ofstream &extraction_log, std::ifstream &section, bool isDebug, bool hasLog, int index, int length, std::string name);

///Searches binary file for (compressed) LocoRoco archive(s)
void searchGARC(std::vector<lbaSpec> table, std::string garc_filename, bool isDebug, bool hasLog);

///Retrieves LBA table from comma-separated text file
std::vector<lbaSpec> getTableCSV(std::string csv_filename);

///Retrieves LBA table from binary file
std::vector<lbaSpec> getTableBIN(std::string bin_filename);

///Checks if argument for option is valid
bool optArgValid(char opt, std::string arg);


#endif
