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
    for (int t = 0; t < 3; ++t) {
        std::string tmp = lbalog.getString(",");
        
        if (tmp.empty()) break;
        if (this->isDebug) fprintf(stderr, "    Log header: %s\n", lbalog.ssub.c_str());

        if (tmp == "FILE_NAME")      nID = t;
        else if (tmp == "FILE_RLBN") rID = t;
        else if (tmp == "FILE_SIZE") sID = t;
    }

    if (this->isDebug) fprintf(stderr, "    Check if LBA table info order valid\n");
    if (nID < 0 && rID < 0 && sID < 0) { nID = 0; rID = 1; sID = 2; }
    if (this->isDebug) fprintf(stderr, "    Name ID %i, Block ID %i, Size ID %i\n", nID, rID, sID);
    if (nID < 0 || rID < 0 || sID < 0) return 0;

    if (this->isDebug) fprintf(stderr, "    Resize LBA table to %d\n", tmp.glba_amnt);
    tmp.glba_info = new lbaSpec::lbainf[tmp.glba_amnt] {};

    if (this->isDebug) fprintf(stderr, "    Update LBA table\n");
    if (this->isDebug) fprintf(stderr, "    Search at position 0x%08X\n", lbalog.str_cur - lbalog.str_beg);
    for (int m = 0; lbalog.str_beg && m < tmp.glba_amnt; ++m) {
        bool is_valid = true;

        for (int t = 0; is_valid && t < 3; ++t) {
            is_valid = lbalog.getStream(",");
            if (!is_valid) break;

            if (t == nID) tmp.glba_info[m].file_name = lbalog.ssub;
            else if (t == rID && (int)lbalog.isub >= 0) tmp.glba_info[m].file_rlbn = lbalog.isub;
            else if (t == sID && (int)lbalog.isub >= 0) tmp.glba_info[m].file_size = lbalog.isub;
            else is_valid = false;
        }
        if (!is_valid) { tmp.glba_amnt = m; break; }

        if (this->isDebug) fprintf(stderr, "        Set %-*s with size 0x%08X to entry %d\n",
                                           27, tmp.glba_info[m].file_name.c_str(),
                                           tmp.glba_info[m].file_size,
                                           m);
    }
    this->table = tmp;

    return 1;
}

int lbat::setTableBIN(unsigned char *src, unsigned src_size) {
    unsigned char *src_start = src, *src_end = src_start + src_size;
    auto get_int = [&]() -> unsigned int {
        unsigned int out = 0, i = 0;
        while (i < 4) out |= (unsigned int)*(src++) << (8 * i++);
        return out;
    };
    
    if (this->isDebug) fprintf(stderr, "    Check LBA for header\n");
    this->table = {};
    if (std::string(src, src + 4) != "GIMG") return 0;
    else src += 4;

    lbaSpec tmp;
    src += 4;
    tmp.glba_amnt = get_int();

    if (this->isDebug) fprintf(stderr, "    Resize LBA table to %d\n", tmp.glba_amnt);
    tmp.glba_info = new lbaSpec::lbainf[tmp.glba_amnt] {};

    if (this->isDebug) fprintf(stderr, "    Update LBA table\n");
    for (int m = 0; src < src_end && m < tmp.glba_amnt; ++m) {
        tmp.glba_info[m].file_name = (char*)(src_start + get_int());
        tmp.glba_info[m].file_rlbn = get_int();
        src += 4;
        tmp.glba_info[m].file_size = get_int();

        if (this->isDebug) fprintf(stderr, "        Set %-*s with size 0x%08X to entry %d\n",
                                           27, tmp.glba_info[m].file_name.c_str(),
                                           tmp.glba_info[m].file_size,
                                           m);
    }
    this->table = tmp;

    return 1;
}


std::string lbat::getTableCSV(unsigned char *src, unsigned src_size) {
    if (this->isDebug) fprintf(stderr, "Attempt to create CSV file\n");

    std::string gimg = "";

    if (setTableBIN(src, src_size)) {
        gimg += "GIMG_AMNT: " + std::to_string(table.glba_amnt) + "\n";
        gimg += "FILE_NAME, FILE_RLBN, FILE_SIZE\n";
        for (int g = 0; g < table.glba_amnt; ++g) {
            gimg += table.glba_info[g].file_name + ", ";
            gimg += std::to_string(table.glba_info[g].file_rlbn) + ", ";
            gimg += std::to_string(table.glba_info[g].file_size) + "\n";
        }
    }

    return gimg;
}
