#include <cstdio>
#include <string>
#include <variant>
#include "directory.hpp"
#include "lba_shared.hpp"
#include "gprs_shared.hpp"
#include "garc.hpp"


bool garc::cmpStr(unsigned char *in0, const char *in1, int length) {
    while ((unsigned char)(*(in1++)) == *(in0++) && --length > 0);
    return !length;
}

unsigned int garc::getInt(unsigned char *&in, int length) {
    unsigned int out = 0;
    for (int i = 0; i < length; ++i) out |= (unsigned int)*(in++) << (8 * i);
    return out;
}

template<typename... Args>
std::string garc::formatStr(const char *in, Args... args) {
    std::string stmp = "";
    std::variant<std::string, unsigned int, int> ftmp[] = {args...};

    while (in[0]) {
        if (in[0] == '{') {
            int p = in[1] - '0';
            switch(ftmp[p].index()) {
                case 0:
                    stmp += std::get<0>(ftmp[p]);
                    break;
                case 1:
                    if (in[2] == 'X') {
                        const char HEX[] = "0123456789ABCDEF";
                        std::string tmp = "";
                        unsigned num = std::get<1>(ftmp[p]);
                        while (num) {
                            tmp = HEX[num % 16] + tmp;
                            num /= 16;
                        }
                        num = in[3] - '0';
                        if (!tmp.empty()) num = ((num - (tmp.length() % num)) % num);
                        stmp += "0x" + std::string(num, '0') + tmp;

                        in += 2;
                    }
                    else if (in[2] == 'D') {
                        std::string tmp = std::to_string(std::get<1>(ftmp[p]));
                        unsigned num = in[3] - '0';
                        num = ((num - (tmp.length() % num)) % num);
                        stmp += std::string(num, '0') + tmp;

                        in += 2;
                    }
                    else stmp += std::to_string(std::get<1>(ftmp[p]));
                    break;
                case 2:
                    stmp += std::to_string(std::get<2>(ftmp[p]));
                    break;
                default:
                    stmp += *(in++);
                    continue;
            }
            in += 3;
        }
        else stmp += *(in++);
    }
    return stmp;
}


int garc::unpackGARC(unsigned char *src, std::string root, std::string name) {
    struct garc_info {
        //const char garc[4] {'G','A','R','C'};
        unsigned crc;
        unsigned align;

        unsigned resrv;
        unsigned foffs;

        //const char file[4] {'F','I','L','E'};
        unsigned noffs;
        unsigned fdnum;
        unsigned fdsiz;
        unsigned fdoffs;

        //const char name[4] {'N','A','M','E'};
        unsigned doffs;
        unsigned ndnum;
        unsigned ndsiz;
        unsigned ndoffs;

        //const char data[4] {'D','A','T','A'};
        unsigned toffs;
        unsigned ddnum;
        unsigned ddsiz;
        unsigned ddoffs;

        //const char term[4] {'T','E','R','M'};
    } ginfo;

    unsigned char *gbeg = src, *gend;
    if (!cmpStr(src, "GARC", 4)) {
        if (this->isDebug) fprintf(stdout, "Missing GARC\n");
        return 0;
    }
    else src += 4;
    ginfo.crc = getInt(src, 4);
    ginfo.align = getInt(src, 4);

    src = gbeg + ginfo.align;
    ginfo.resrv = getInt(src, 4);
    ginfo.foffs = getInt(src, 4);

    src = gbeg + ginfo.foffs;
    if (!cmpStr(src, "FILE", 4)) {
        if (this->isDebug) fprintf(stdout, "Missing FILE\n");
        return 0;
    }
    else src += 4;
    ginfo.noffs = getInt(src, 4);
    ginfo.fdnum = getInt(src, 4);
    ginfo.fdsiz = getInt(src, 4);
    ginfo.fdoffs = getInt(src, 4);

    src = gbeg + ginfo.noffs;
    if (!cmpStr(src, "NAME", 4)) {
        if (this->isDebug) fprintf(stdout, "Missing NAME\n");
        return 0;
    }
    else src += 4;
    ginfo.doffs = getInt(src, 4);
    ginfo.ndnum = getInt(src, 4);
    ginfo.ndsiz = getInt(src, 4);
    ginfo.ndoffs = getInt(src, 4);

    src = gbeg + ginfo.doffs;
    if (!cmpStr(src, "DATA", 4)) {
        if (this->isDebug) fprintf(stdout, "Missing DATA\n");
        return 0;
    }
    else src += 4;
    ginfo.toffs = getInt(src, 4);
    ginfo.ddnum = getInt(src, 4);
    ginfo.ddsiz = getInt(src, 4);
    ginfo.ddoffs = getInt(src, 4);

    if ((ginfo.fdnum != ginfo.ndnum) || (ginfo.ndnum != ginfo.ddnum)) {
        if (this->isDebug) fprintf(stdout, "Entry amounts not equal\n");
        return 0;
    }

    src = gbeg + ginfo.toffs;
    if (!cmpStr(src, "TERM", 4)) {
        if (this->isDebug) fprintf(stdout, "Missing TERM\n");
        return 0;
    }
    else gend = gbeg + ginfo.toffs;


    if (!name.empty()) name = "@" + name.substr(0, name.find_last_of('.')) + "/";
    if (this->isDebug) fprintf(stdout, "    Root folder:    %s\n", root.c_str());
    if (this->isDebug) fprintf(stdout, "    Subroot folder: %s\n", (!name.empty() ? name.c_str() : "(none)"));
    if (this->isDebug) fprintf(stderr, "    Amount entries: %d\n", ginfo.fdnum);

    if (!createFolder((root + name).c_str())) {
        fprintf(stderr, "Unable to create subroot folder\n");
        return 0;
    }

    this->debugLog += formatStr("Subroot folder:   {0}\n", (!name.empty() ? name.c_str() : "(none)"));
    this->debugLog += formatStr("    Amount files: {0}\n", ginfo.fdnum);
    this->debugLog += formatStr("    Amount names: {0}\n", ginfo.ndnum);
    this->debugLog += formatStr("    Amount data:  {0}\n", ginfo.ddnum);


    struct file_info {
        std::string fext;
        unsigned fdsiz;
        unsigned fdoffs;
        unsigned fnoffs;
        unsigned funk;
        unsigned fflag;

        std::string fnam;
    } finfo[ginfo.fdnum] {};

    src = gbeg + ginfo.fdoffs;
    for (auto &inf : finfo) {
        inf.fext = {src, src + 4}; src += 4;
        inf.fdsiz = getInt(src, 4);
        inf.fdoffs = getInt(src, 4);
        inf.fnoffs = getInt(src, 4);
        inf.funk = getInt(src, 4);
        inf.fflag = getInt(src, 4);
        inf.fnam = (char*)(gbeg + inf.fnoffs);
    }

    for (auto &inf : finfo) {
        src = gbeg + inf.fdoffs;
        if (src >= gend || (src + inf.fdsiz) > gend) continue;

        unsigned char *fTmp = 0;
        unsigned fSiz;

        if (!cmpStr(src, "GPRS", 4)) {
            fTmp = src;
            fSiz = inf.fdsiz;
        }
        else decompress(src, inf.fdsiz, fTmp, fSiz);

        if (!fTmp);
        if (cmpStr(fTmp, "GARC", 4)) {
            fprintf(stdout, "    UNPACK %s\n", inf.fnam.c_str());
            if (!unpackGARC(fTmp, root + name, inf.fnam)) {
                fprintf(stderr, "    Unable to unpack embedded GARC\n");
            }
            else fprintf(stdout, "    UNPACKED %s\n", inf.fnam.c_str());
        }
        else if (!createFile((root + name + inf.fnam).c_str(), fTmp, fSiz)) {
            fprintf(stderr, "    Unable to save %s\n", inf.fnam.c_str());
        }
        else {
            fprintf(stdout, "    EXTRACTED %s\n", inf.fnam.c_str());
            this->debugLog += formatStr("        FILE_TYPE:              {0}\n", inf.fext.c_str());
            this->debugLog += formatStr("        FILE_NAME:              {0}\n", inf.fnam.c_str());
            this->debugLog += formatStr("        FILE_OFFSET:            {0X8}\n", inf.fdoffs);
            this->debugLog += formatStr("        FILE_COMPRESSED_SIZE:   {0X8}\n", inf.fdsiz);
            this->debugLog += formatStr("        FILE_DECOMPRESSED_SIZE: {0X8}\n\n", fSiz);

            if (cmpStr(fTmp, "GIMG", 4)) {
                setDebug(false);
                std::string fTab = getTableCSV(fTmp, fSiz);
                if (!this->amnt_glba) setTableBIN(fTmp, fSiz);
                setDebug(this->isDebug);

                if (createFile((root + name + inf.fnam + ".csv").c_str(), fTab.c_str(), fTab.length())) {
                    fprintf(stdout, "    CREATED sector log file %s\n", (inf.fnam + ".csv").c_str());
                }
            }
        }

        if (fSiz != inf.fdsiz) delete[] fTmp;
    }

    this->debugLog.resize(this->debugLog.length() - 1);
    this->debugLog += "End of GARC\n\n";
    return ginfo.toffs + 4;
}

int garc::searchLBAT(std::string root, unsigned char *src, const unsigned char *src_end) {
    if (this->isDebug) fprintf(stderr, "Extract with LBA table\n");

    for (int a = 0; a < this->amnt_glba; ++a) {
        std::string tmp_nam = this->info[a].info_name, tmp_ext;
        unsigned tmp_siz = this->info[a].info_size, gSiz = 0;
        unsigned char *tmp_dat = src + (this->info[a].info_rlbn * 0x0800),
                      *gTmp = 0;

        if (tmp_dat >= src_end || (tmp_dat + tmp_siz) > src_end) {
            fprintf(stderr, "Entry outside range of file\n");
            continue;
        }

        if (!cmpStr(tmp_dat, "GPRS", 4)) {
            gTmp = tmp_dat;
            gSiz = tmp_siz;
        }
        else {
            if (this->isDebug) fprintf(stderr, "DECOMPRESS GPRS\n");
            decompress(tmp_dat, tmp_siz, gTmp, gSiz);
        }

        if (!gTmp) continue;
        else if (cmpStr(gTmp, "GARC", 4)) {
            fprintf(stdout, "UNPACK %s\n", tmp_nam.c_str());
            if (!unpackGARC(gTmp, root, tmp_nam)) fprintf(stderr, "Unable to unpack GARC\n");
            else fprintf(stdout, "UNPACKED %s\n", tmp_nam.c_str());
        }
        else if (!createFile((root + tmp_nam).c_str(), gTmp, gSiz)) {
            fprintf(stderr, "Unable to save %s\n", tmp_nam.c_str());
        }
        else {
            fprintf(stdout, "EXTRACTED %s\n", tmp_nam.c_str());
            tmp_ext = tmp_nam.substr(tmp_nam.find_last_of('.') + 1);
            this->debugLog += formatStr("    FILE_TYPE:              {0}\n", tmp_ext.c_str());
            this->debugLog += formatStr("    FILE_NAME:              {0}\n", tmp_nam.c_str());
            this->debugLog += formatStr("    FILE_OFFSET:            {0X8}\n", unsigned(tmp_dat - src));
            this->debugLog += formatStr("    FILE_COMPRESSED_SIZE:   {0X8}\n", tmp_siz);
            this->debugLog += formatStr("    FILE_DECOMPRESSED_SIZE: {0X8}\n\n", gSiz);
        }

        if (tmp_siz != gSiz) delete[] gTmp;
    }
    reset();

    return 1;
}

int garc::searchBIN(std::string root, unsigned char *src, const unsigned char *src_end) {
    if (this->isDebug) fprintf(stderr, "Extract without LBA table\n");

    //unsigned char *src_beg = src;
    unsigned gnum = 0;
    while (src < src_end) {
        unsigned tmp_siz = src_end - src;
        unsigned char *gTmp = 0;
        unsigned gSiz;
        
        //if (this->isDebug) fprintf(stderr, "ADDRESS 0x%08X\n", src - src_beg);

        if (!cmpStr(src, "GPRS", 4)) {
            gTmp = src;
            gSiz = tmp_siz;
        }
        else {
            if (this->isDebug) fprintf(stderr, "DECOMPRESS GPRS\n");
            tmp_siz = decompress(src, tmp_siz, gTmp, gSiz);
        }

        if (gTmp && cmpStr(gTmp, "GARC", 4)) {
            fprintf(stdout, "UNPACK GARC\n");
            std::string subroot = (!gnum && (src + tmp_siz + 0x10) >= src_end) ? "" :
                                  formatStr("garc_{0D3}.arc", gnum);
            if (!(tmp_siz = unpackGARC(gTmp, root, subroot))) {
                fprintf(stderr, "Unable to unpack GARC\n");
            }
            else fprintf(stdout, "UNPACKED GARC\n");
            gnum += 1;
        }

        if (tmp_siz != gSiz) delete[] gTmp;
        tmp_siz += (0x0800 - (tmp_siz % 0x0800)) % 0x0800;
        src += tmp_siz;
    }

    return 1;
}

void garc::searchFile(std::string filename) { searchFile(filename, "", 0); }
void garc::searchFile(std::string filename, std::string tablename, int tablet) {
    int ret = 0;
    unsigned char *fdat = 0;
    unsigned fsiz = 0;
    std::string root = filename.substr(0, filename.find_last_of('.')) + "/",
                name = filename.substr(filename.find_last_of("\\/") + 1);


    if (this->isDebug && this->hasLog) fprintf(stderr, "Setup log\n");
    this->debugLog = formatStr("Files in {0}\n", name.c_str());

    if (!getFileData(filename.c_str(), fdat, fsiz)) {
        fprintf(stderr, "Unable to open file\n");
    }
    else if (!createFolder(root.c_str())) {
        fprintf(stderr, "Unable to create root folder\n");
    }
    else {
        if (!this->amnt_glba && ((!tablet && tablename.empty()) || !setTable(tablename.c_str(), tablet))) {
            ret = searchBIN(root, fdat, fdat + fsiz);
        }
        else ret = searchLBAT(root, fdat, fdat + fsiz);
    }
    if (fdat) delete[] fdat;

    if (!ret) fprintf(stderr, "Unable to completely search file\n");
    else fprintf(stderr, "Data unpacked successfully\n");

    this->debugLog += formatStr("End of {0}\n", name.c_str());

    if (this->hasLog) {
        root.resize(root.length() - (name.substr(0, name.find_last_of('.')).length() + 1));
        name += ".glog";

        if (this->isDebug) fprintf(stderr, "Save log to %s\n", name.c_str());
        if (!createFile((root + name).c_str(), this->debugLog.c_str(), this->debugLog.length())) {
            fprintf(stderr, "Unable to save log\n");
        }
    }
    this->debugLog.clear();
}
