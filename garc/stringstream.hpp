#ifndef STRINGSTREAM_HPP
#define STRINGSTREAM_HPP

#include <string>

///Struct for custom stringstream
struct sstream {
    unsigned char *str_beg, *str_end, *str_cur;
    unsigned ssize;
    std::string ssub; unsigned isub;

    sstream(unsigned char *str = 0, unsigned siz = 0) : ssize(0), ssub(""), isub(-1) {
        copy(str, str_beg, siz, 1);
        str_cur = str_beg;
        str_end = str_beg + siz;
    }
    ~sstream() { reset(); }

    int getStream(const char *delim = 0) {
        int ret = 0;
        bool quotes = 0;
        char sep = (!delim) ? '\0' : delim[0];

        if (!ssub.empty()) ssub.clear();
        isub = -1;

        if (!str_beg) return ret;

        str_cur += ssize;
        while (true) {
            if (str_cur >= str_end) break;

            if (*str_cur == '\"') { quotes = !quotes; str_cur += 1; }
            else if (isgraph(*str_cur)) break;
            else str_cur += 1;
        }

        ssize = 0;
        while (true) {
            if (str_cur + ssize >= str_end) break;

            if (*(str_cur + ssize) == '\"') { quotes = !quotes; ssize += 1; }
            else if (isspace(*(str_cur + ssize)) && !quotes) break;
            else if (*(str_cur + ssize) == sep && !quotes) { ssize += 1; break; }
            else ssize += 1;
        }

        for (int c = 0; c < ssize; ++c) {
            if (*(str_cur + c) == '\"' || *(str_cur + c) == sep) continue;
            else ssub += *(str_cur + c);
        }

        if (!ssub.empty()) {
            bool isnum = true;
            for (auto &c : ssub) if (!isdigit(c)) { isnum = false; break; }
            if (isnum) { isub = stol(ssub, 0, 10); ssub.clear(); }

            ret = 1;
        }
        else reset();

        return ret;
    }


    private:
        void reset() {
            if (str_beg) { delete[] str_beg; str_beg = 0; }
            if (str_end) str_end = 0;
            if (str_cur) str_cur = 0;
        }
        template <typename T0, typename T1>
        void copy(const T0 *in, T1 *&out, const int S, const int a) {
            if (in) {
                if (S > 0) out = new T1[S + a] {};
                for (int i = 0; i < S; ++i) out[i] = T1(in[i]);
            }
        }
};


#endif
