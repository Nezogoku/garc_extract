#ifndef GARC_HPP
#define GARC_HPP

#include "gprs_shared.hpp"
#include "lba_shared.hpp"

class garc : public lzgprs, public lbat {
    public:
        garc(bool debug = false, bool log = false) : isDebug(debug), hasLog(log) {}

        void setDebugging(bool debug, bool log) { this->isDebug = debug; this->hasLog = log; }
        void searchFile(std::string filename);
        void searchFile(std::string filename, std::string tablename, int tablet);

    private:
        bool cmpStr(unsigned char *in0, const char *in1, int length);
        unsigned int getInt(unsigned char *&in, int length);
        template<typename... Args>
        std::string formatStr(const char *in, Args... args);
        int unpackGARC(unsigned char *src, std::string root, std::string name);
        int searchLBAT(std::string root, unsigned char *src, const unsigned char *src_end);
        int searchBIN(std::string root, unsigned char *src, const unsigned char *src_end);

        bool hasLog;
        std::string debugLog;
};


#endif
