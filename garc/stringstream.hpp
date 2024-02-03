#ifndef STRINGSTREAM_HPP
#define STRINGSTREAM_HPP

#include <string>

///Struct for custom stringstream
struct sstream {
    sstream() :
        str_beg(""), ssub(""), isub(-1), str_pos(0) {}
    sstream(const std::string str) :
        str_beg(str), ssub(""), isub(-1), str_pos(0) {}
    sstream(const unsigned char *str, const unsigned siz) :
        str_beg(std::string((char*)str, siz)), ssub(""), isub(-1), str_pos(0) {}
    sstream(const sstream &s)
        { copy(s); }
    sstream(sstream &&s) :
        sstream{s} { s.~sstream(); }
    ~sstream() { reset(); }

    sstream& operator=(const sstream &s) { copy(s); return *this; }
    sstream& operator=(sstream &&s) { copy((const sstream)s); s.~sstream(); return *this; }
    
    int tellPos() { return str_pos; }
    
    void seekPos(int p) { str_pos = p; }

    int getStream(const char *delim = 0) {
        bool quotes = 0;
        int pos0, pos1;
        
        if (!ssub.empty()) ssub.clear();
        isub = -1;
        if (str_beg.empty()) return 0;
        
        auto get_whitespace = [](std::string str, int pos = 0) -> int {
            return str.find_first_of(" \"\t\r\n\v\f", pos);
        };
        auto get_not_whitespace = [](std::string str, int pos = 0) -> int {
            return str.find_first_not_of(" \t\r\n\v\f", pos);
        };
        
        pos0 = pos1 = get_not_whitespace(str_beg, str_pos);
        if (pos0 == std::string::npos) { reset(); return 0; }
        
        if (delim) {
            int tmp = get_whitespace(str_beg, pos0);
            pos1 = str_beg.find(delim, str_pos);
            if (tmp < pos1) pos1 = tmp;
        }
        else {
            while ((pos1 = get_whitespace(str_beg, pos1)) != std::string::npos) {
                if (str_beg[pos1] == '\"') quotes = !quotes;
                else if (quotes);
                else break;
                
                pos1 += 1;
            }
        }
        if (pos1 == std::string::npos) pos1 = str_beg.length() - 1;
        ssub = str_beg.substr(pos0, pos1 - pos0);
        str_pos = pos1 + ((!delim) ? 1 : std::string(delim).length());
        
        pos0 = get_whitespace(ssub);
        while ((pos1 = get_whitespace(ssub, pos0)) != std::string::npos) {
            if (ssub[pos1] == '\"') {
                quotes = !quotes;
                ssub.erase(pos1, 1);
                if (!quotes) pos0 = pos1;
            }
            else if (!quotes && delim) {
                ssub.erase(pos1, 1);
            }
            else if (quotes) pos0 += 1;
        }
        
        if (!ssub.empty()) {
            auto is_dec = [&]() -> bool {
                return ssub.find_first_not_of("0123456789") == std::string::npos;
            };
            auto is_hex = [&]() -> bool {
                return ssub.find("0x") == 0 &&
                       ssub.find_first_not_of("0123456789ABCDEFabcdef", 2) == std::string::npos;
            };
            
            if (is_dec()) { isub = std::stol(ssub, nullptr, 10); }
            else if (is_hex()) { isub = std::stol(ssub, nullptr, 16); }
            return 1;
        }
        else {
            reset();
            return 0;
        }
    }

    std::string getString(const char *delim = 0, std::string str = "") {
        if (!str.empty() && (!getStream(delim) || ssub != str || !getStream())) return "";
        else if (str.empty() && !getStream(delim)) return "";
        else return ssub;
    }

    int getUnsigned(const char *delim = 0, std::string str = "") {
        if (!str.empty() && (!getStream(delim) || ssub != str || !getStream())) return -1;
        else if (str.empty() && !getStream(delim)) return -1;
        else return isub;
    }


    private:
        std::string str_beg, ssub; unsigned int isub;
        int str_pos;

        void reset() {
            if (!str_beg.empty()) str_beg.clear();
            if (!ssub.empty()) ssub.clear();
            str_pos = 0; isub = -1;
        }
        
        void copy(const sstream &s) {
            reset();
            str_beg = s.str_beg;
            ssub = s.ssub;
            isub = s.isub;
            str_pos = s.str_pos;
        }
};


#endif
