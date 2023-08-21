//#include <cstdio>
#include "gprs_shared.hpp"

//Took it upon myself to rewrite bnnm's LZGPRS thing
int lzgprs::decompress(unsigned char *src, unsigned src_size, unsigned char *&dst, unsigned &dst_size) {
    unsigned char *src_start = src, *src_end = src + src_size, *src_next = 0,
                  *dst_start = 0, *dst_end = 0, *dst_next = 0,
                  cur = 0;
    int shift = 7, addr;
    auto cmp_bit = [&]() -> bool { return (cur >> shift--) & 0x01; };
    dst_size = 0;

    src += 4;
    for (int s = 0; s < 4; ++s) dst_size = (dst_size << 8) | *(src++);
    dst = new unsigned char[dst_size] {};
    dst_start = dst;
    dst_next = dst;
    dst_end = dst + dst_size;

    src_next = src + 1;
    cur = *(src++);
    do {
        while (true) {
            if (shift < 0) {
                cur = src[0];
                shift = 7;
                src_next = src + 1;
            }
            else src_next = src;

            if (cmp_bit()) break;
            //fprintf(stderr, "Bit unset\n");

            *(dst++) = src_next[0];
            src = src_next + 1;
            //fprintf(stderr, "Raw byte 0x%02X to dst[%d]\n", src_next[0], ((dst - 1) - dst_start));
        }
        //fprintf(stderr, "Bit set\n");

        if (shift < 0) {
            cur = *(src_next++);
            shift = 7;
        }

        if (!cmp_bit()) {
            src = src_next + 1;

            if (!src_next[0]) break;

            addr = 0xFFFFFF00 | src_next[0];
            //fprintf(stderr, "Addr when unset %d\n", addr);
        }
        else {
            unsigned src_temp = src_next[0];
            unsigned char nib_temp = 0;

            src = src_next + 1;

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = cmp_bit();

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmp_bit();

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmp_bit();

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            nib_temp = (nib_temp << 1) | cmp_bit();

            addr = (0xFFFFFF00 | src_temp);
            addr = (addr << 4) | nib_temp;
            addr -= 0xFF;
            //fprintf(stderr, "Addr when set %d\n", addr);
        }

        int count = 1;
        while (true) {
            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            if (!cmp_bit()) break;

            if (shift < 0) {
                cur = *(src++);
                shift = 7;
            }
            count = count * 2 + cmp_bit();
        }

        //fprintf(stderr, "Count %d\n", count);
        if (count < 7) {
            count += 1;
            //fprintf(stderr, "Get %d bytes from dst\n", count);
            //fprintf(stderr, "Add %d to dst\n", addr);

            dst_next = dst + addr;
            while (count--) {
                dst[0] = dst_next[0];
                /*
                fprintf(stderr, "Out byte 0x%02X from dst[%d] to dst[%d]\n",
                                dst[0], (dst_next - dst_start), (dst - dst_start));
                */
                dst += 1;
                dst_next += 1;
            }
        }
        else {
            int add = ++count & 0x07;
            count = (count >> 3) + 1;

            dst += (add - 8);

            //fprintf(stderr, "Repeat %d times\n", count);
            //fprintf(stderr, "Add %d to dst\n", (add - 8));
            //fprintf(stderr, "Add %d to dst\n", addr);

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
                    fprintf(stderr, "Out byte 0x%02X from dst[%d] to dst[%d]\n",
                                    dst_next[a], ((dst_next + a) - dst_start), ((dst + a) - dst_start));
                    */
                }
                if (add) add = 0;
            }
        }
    } while (src_next < src_end && dst < dst_end);

    dst = dst_start;
    return (src_next - src_start);
}
