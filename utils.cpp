#include "defines.hpp"

bool cmpBits(uchar data, int &shift) {
    return (data >> shift--) & 0x01;
}

void getAbsInt(int in, int &out) {
    int mask = in >> sizeof(int) * 7;
    out = (in + mask) ^ mask;
}

void getLeInt(uchar *data, unsigned int &out, int pos, int len) {
    out = 0;
    for (int s = len; s > 0; --s) {
        out <<= 8;
        out |= data[pos + (s - 1)];
    }

    pos += len;
}

void getBeInt(uchar *data, unsigned int &out, int pos, int len) {
    out = 0;
    for (int s = 0; s < len; ++s) {
        out <<= 8;
        out |= data[pos + s];
    }

    pos += len;
}

