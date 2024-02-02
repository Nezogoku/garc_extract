#include <cstdio>
#include <string>
#include "directory.hpp"
#include "stringstream.hpp"
#include "lba_shared.hpp"


void lbat::reset() {
    this->amnt_glba = 0;
    if (this->info) delete[] this->info; this->info = 0;
}


int lbat::setTableCSV(const char *csv_filename) {
    if (this->isDebug) fprintf(stderr, "Attempt to open CSV file\n");
    return setTable(csv_filename, 1);
}
int lbat::setTableBIN(const char *bin_filename) {
    if (this->isDebug) fprintf(stderr, "Attempt to open BIN file\n");
    return setTable(bin_filename, 2);
}
int lbat::setTable(const char *filename, int tabletyp) {
    int ret = 0;
    unsigned char *fdata = 0;
    unsigned fdata_size = 0;

    if (!getFileData(filename, fdata, fdata_size)) {
        fprintf(stderr, "Unable to open file\n");
    }
    else {
        if (tabletyp == 1) ret = setTableCSV(fdata, fdata_size);
        else ret = setTableBIN(fdata, fdata_size);

        delete[] fdata;
    }
    return ret;
}


int lbat::setTableCSV(unsigned char *src, unsigned src_size) {
    reset();
    sstream lbalog(src, src_size);

    if (this->isDebug) fprintf(stderr, "    Check LBA for maximum file amount\n");

    this->amnt_glba = lbalog.getUnsigned(":", "GIMG_AMNT");
    if ((int)this->amnt_glba < 0) { reset(); return 0; }

    if (this->isDebug) fprintf(stderr, "    Get LBA table info order\n");
    int nID = -1, rID = -1, sID = -1;
    for (int t = 0, pos = lbalog.tellPos(); t < 3;) {
        std::string tmp = lbalog.getString(",");
        
        if (tmp.empty()) break;
        if (this->isDebug) fprintf(stderr, "    Log header: %s\n", tmp.c_str());
        
             if (tmp == "FILE_NAME") nID = t++;
        else if (tmp == "FILE_RLBN") rID = t++;
        else if (tmp == "FILE_SIZE") sID = t++;
        
        if (!t) { nID = 0; rID = 1; sID = 2; lbalog.seekPos(pos); break; }
    }

    if (this->isDebug) fprintf(stderr, "    Name ID %i, Block ID %i, Size ID %i\n", nID, rID, sID);
    if ((nID + rID + sID) < 3) { reset(); return 0; }

    if (this->isDebug) fprintf(stderr, "    Resize LBA table to %d\n", this->amnt_glba);
    this->info = new lbainf[this->amnt_glba] {};
    if (this->isDebug) fprintf(stderr, "    Update LBA table\n");
    if (this->isDebug) fprintf(stderr, "    Search at position 0x%08X\n", lbalog.tellPos());
    for (int m = 0; m < this->amnt_glba; ++m) {
        for (int t = 0; t < 3; ++t) {
            if (t == nID) {
                this->info[m].info_name = lbalog.getString(",");
                if (this->info[m].info_name.empty()) { this->amnt_glba = m; return 0; }
            }
            else if (t == rID) {
                this->info[m].info_rlbn = lbalog.getUnsigned(",");
                if ((int)this->info[m].info_rlbn < 0) { this->amnt_glba = m; return 0; }
            }
            else if (t == sID) {
                this->info[m].info_size = lbalog.getUnsigned(",");
                if ((int)this->info[m].info_size < 0) { this->amnt_glba = m; return 0; }
            }
        }

        if (this->isDebug) fprintf(stderr, "        Set %-*s with size 0x%08X to entry %d\n",
                                           27, this->info[m].info_name.c_str(),
                                           this->info[m].info_size,
                                           m);
    }

    return 1;
}

int lbat::setTableBIN(unsigned char *src, unsigned src_size) {
    reset();
    
    unsigned char *src_start = src, *src_end = src_start + src_size;
    auto cmp_str = [&](const char *in1, int length) -> bool {
        while ((*(src++) == (unsigned char)(*(in1++))) && --length);
        return !length;
    };
    auto get_int = [&]() -> unsigned {
        unsigned out = 0;
        for (int i = 0; src < src_end && i < 4; ++i) {
            out |= (unsigned)*(src++) << (8 * (3 - i));
        }
        return out;
    };
    
    if (this->isDebug) fprintf(stderr, "    Check LBA for header\n");
    if (!cmp_str("GIMG", 4)) return 0;
    else src += 4;
    if ((int)(this->amnt_glba = get_int()) < 0) return 0;

    if (this->isDebug) fprintf(stderr, "    Resize LBA table to %d\n", this->amnt_glba);
    this->info = new lbainf[this->amnt_glba] {};

    if (this->isDebug) fprintf(stderr, "    Update LBA table\n");
    for (int m = 0, tmp; src < src_end && m < this->amnt_glba; ++m) {
        this->info[m].info_name = (char*)(src_start + get_int());
        this->info[m].info_rlbn = get_int();
        src += 4;
        this->info[m].info_size = get_int();

        if (this->isDebug) fprintf(stderr, "        Set %-*s with size 0x%08X to entry %d\n",
                                           27, this->info[m].info_name.c_str(),
                                           this->info[m].info_size,
                                           m);
    }

    return 1;
}


std::string lbat::getTableCSV(unsigned char *src, unsigned src_size) {
    if (this->isDebug) fprintf(stderr, "Attempt to create CSV file\n");

    std::string gimg = "";

    if (src && src_size) setTableBIN(src, src_size);
    
    if (this->info && this->amnt_glba) {
        gimg += "GIMG_AMNT: " + std::to_string(this->amnt_glba) + "\n";
        gimg += "FILE_NAME, FILE_RLBN, FILE_SIZE\n";
        for (int g = 0; g < this->amnt_glba; ++g) {
            gimg += this->info[g].info_name + ", ";
            gimg += std::to_string(this->info[g].info_rlbn) + ", ";
            gimg += std::to_string(this->info[g].info_size) + "\n";
        }
    }

    return gimg;
}
