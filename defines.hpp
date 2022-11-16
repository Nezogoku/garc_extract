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
#define DATA 0x44415441

typedef unsigned char uchar;

///Logical Block Access info stuffs
struct lbaSpec {
    std::string file_name; //Name of file
    uint32_t    file_rlbn; //Relative logical block number of file
    uint32_t    file_unkn; //I dunno
    uint32_t    file_size; //Size of file
};

static bool isDebug;                   // Whether or not to print messages to console
static bool hasLog;                    // Whether or not to create log
static int num_garc;                   // GARC counter
static int num_gprs;                   // GPRS counter
static std::vector<lbaSpec> lbaTable;  // Stores LBA information

///Check if bit from array is set
bool cmpBits(uchar data, int &shift);

///Gets absolute value of variable int from array
void getAbsInt(int in, int &out);

///Gets LE variable int from array
void getLeInt(uchar *data, unsigned int &out, int pos, int len);

///Gets BE variable int from array
void getBeInt(uchar *data, unsigned int &out, int pos, int len);

///Remove quotation marks from file name
void removeQuote(std::string &arg);

///Print options
void printOpts(std::string prgm);

///Print error message
void printErr(const char* opt, std::string arg, int code);

///Check if file exists
bool fileExists(std::string fName);

///Extract files from LocoRoco archive
int fromGARC(std::ofstream &extraction_log, uchar* src, int seclen, std::string name);

///Inflate file
int inflateGPRS(std::ofstream &extraction_log, uchar* src, int seclen, std::string name);

///Searches binary file for (compressed) LocoRoco archive(s)
void searchGARC(std::string garc_filename);

///Retrieves LBA table from comma-separated text file
std::vector<lbaSpec> getTableCSV(std::string csv_filename);

///Retrieves LBA table from binary file
std::vector<lbaSpec> getTableBIN(std::string bin_filename);
std::vector<lbaSpec> getTableBIN(uchar* src);

///Checks if argument for option is valid
bool optArgValid(char opt, std::string arg);


#endif
