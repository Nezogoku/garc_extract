#include <algorithm>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <fstream>
#include <string>
#include "defines.hpp"

using std::cout;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::to_string;

//Took it upon myself to rewrite bnnm's LZGPRS thing
void decompress_lzgprs(uchar *dst, int dst_size, uchar *src, int *src_size) {
    if (isDebug) cout << "Entered decompress_lzgprs" << endl;

    uchar *dst_start = dst;
    uchar *dst_end = dst + dst_size;
    uchar *dst_next = dst;
    uchar *src_start = src;
    uchar *src_end = src + *src_size;
    uchar *src_next = src + 1;

    int shift, addr;
    uint8_t cur;

    cur = *(src++);
    shift = 7;
    do {
        while (true) {
            if (shift < 0) {
                cur = *src;
                shift = 7;
                src_next = src + 1;
            }
            else src_next = src;

            if (cmpBits(cur, shift)) break;
            /* else if (isDebug) cout << "Bit unset" << endl; */

            *(dst++) = *src_next;
            src = src_next + 1;

            /*
            if (isDebug) cout << "Out raw byte 0x" << std::hex
                             << int(*src_next)
                             << " to dst 0x"
                             << ((dst - 1) - dst_start) << std::dec
                             << endl;
            */
        }
        /* if (isDebug) cout << "Bit set" << endl; */

        if (shift < 0) {
            cur = *(src_next++);
            shift = 7;
        }

        if (!cmpBits(cur, shift)) {
            src = src_next + 1;

            if (!(*src_next)) break;

            addr = 0xFFFFFF00 | (*src_next);
            /*
            if (isDebug) cout << "Addr when unset "
                             << addr
                             << endl;
            */
        }
        else {
            uint32_t src_temp = (*src_next);
            uint8_t nib_temp = 0;

            src = src_next + 1;

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = cmpBits(cur, shift);

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmpBits(cur, shift);

            addr = (0xFFFFFF00 | src_temp);
            addr = (addr << 4) | nib_temp;
            addr -= 0xFF;

            /*
            if (isDebug) cout << "Address when set "
                             << addr
                             << endl;
            */
        }

        int count = 1;
        while (true) {
            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            if (!cmpBits(cur, shift)) break;

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            count = count * 2 + cmpBits(cur, shift);
        }

        /* if (isDebug) cout << "Count " << count << endl; */
        if (count < 7) {
            count += 1;
            /* if (isDebug) cout << "Get " << count << " bytes from dst" << endl; */
            /* if (isDebug) cout << "Add " << addr << " to dst" << endl; */

            dst_next = dst + addr;
            while (count--) {
                *dst = *dst_next;
                /*
                if (isDebug) cout << "Out byte 0x" << std::hex
                                 << unsigned(*dst)
                                 << " from dst 0x"
                                 << (dst_next - dst_start)
                                 << " to dst 0x"
                                 << (dst - dst_start) << std::dec
                                 << endl;
                */
                dst += 1;
                dst_next += 1;
            }
        }
        else {
            int add = ++count & 0x07;
            count = (count >> 3) + 1;

            dst += (add - 8);

            /* if (isDebug) cout << "Repeat " << count << " times" << endl; */
            /* if (isDebug) cout << "Add " << (add - 8) << " to dst" << endl; */
            /* if (isDebug) cout << "Add " << addr << " to dst" << endl; */

            dst_next = dst + addr;
            while (true) {
                int a;

                if (!add) {
                    a = add;
                    dst += 8;
                    dst_next += 8;
                    if (!(--count)) break;
                }
                else a = (~add & 0x07) + 1;

                for (; a < 8; ++a) {
                    dst[a] = dst_next[a];
                    /*
                    if (isDebug) cout << "Out byte 0x" << std::hex
                                     << unsigned(dst_next[a])
                                     << " from dst 0x"
                                     << ((dst_next + a) - dst_start)
                                     << " to dst 0x"
                                     << ((dst + a) - dst_start) << std::dec
                                     << endl;
                    */
                }
                if (add) add = 0;
            }
        }
    } while (src_next < src_end && dst < dst_end);

    *src_size = src_next - src_start;
}

int inflateGPRS(std::ofstream &extraction_log, uchar* src, int seclen, std::string name) {
    if (seclen < 0) return 0x01;

    if (hasLog) extraction_log << "\tGPRS\n";
    if (isDebug) cout << "GPRS" << endl;

    string dat_file = name;
    if (dat_file.empty()) {
        dat_file = "000";
        dat_file += to_string(num_gprs++);
        dat_file = "gprs_" + dat_file.substr(dat_file.size() - 3) + ".out";
    }


    uint32_t finSize;
    getBeInt(src, finSize, 0x04, 0x04);

    uchar *temp_file = new uchar[finSize];

    seclen -= 0x08;
    decompress_lzgprs(temp_file, finSize, (src + 0x08), &seclen);

    cout << "Decompressed file: " << dat_file << endl;
    cout << "Size of decompressed section: " << finSize / 1024 << "kB" << endl;
    if (hasLog) extraction_log << "\tSize of compressed section: " << seclen / 1024 << "kB\n";
    if (hasLog) extraction_log << "\tSize of decompressed section: " << finSize / 1024 << "kB\n";

    bool save_file = false;
    uint32_t chunk;

    getBeInt(temp_file, chunk, 0x00, 0x04);
    if (chunk == GPRS) inflateGPRS(extraction_log, temp_file, finSize, dat_file);
    else if (chunk == GARC) fromGARC(extraction_log, temp_file, finSize, dat_file);
    else save_file = true;

    if (save_file) {
        ofstream out_file(dat_file.c_str(), ios::binary);
        out_file.write((const char*)(temp_file), finSize);
        out_file.close();
    }
    cout << endl;

    delete[] temp_file;

    return seclen;
}
