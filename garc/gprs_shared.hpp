#ifndef GPRS_SHARED_HPP
#define GPRS_SHARED_HPP

class lzgprs {
    public:
        int decompress(unsigned char *src, unsigned src_size, unsigned char *&dst, unsigned &dst_size);
};

#endif
