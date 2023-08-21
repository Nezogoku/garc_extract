#ifndef DIRECTORY_HPP
#define DIRECTORY_HPP

#include <cstdio>
#include <errno.h>
#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) \
                      || defined(WIN64) || defined(_WIN64) || defined(__WIN64__)
    #include <direct.h>
    #define mkdir(filename) _mkdir(filename)
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #define mkdir(filename) mkdir(filename, 0777)
#endif


///Create a folder
static int createFolder(const char *folder) {
    int ret = 1;
    if (mkdir(folder) < 0) ret = (errno == EEXIST);

    return ret;
}

///Write binary to a file
static int createFile(const char *file, unsigned char *data, unsigned data_size) {
    int ret = 1;

    FILE *out = fopen(file, "wb");
    if (!out) ret = 0;
    else {
        fseek(out, 0, SEEK_SET);
        fflush(out);
        if (!fwrite(data, 1, data_size, out) || fclose(out)) ret = 0;
    }

    return ret;
}

///Write C-style string to a file
static int createFile(const char *file, const char *data, unsigned data_size) {
    return createFile(file, (unsigned char*)data, data_size);
}

///Delete a file
static int removeFile(const char *file) {
    int ret = 1;
    if (remove(file) < 0) ret = (errno == ENOENT);

    return ret;
}

///Get data from a file
static int getFileData(const char *file, unsigned char *&data, unsigned &data_size) {
    int ret = 1;

    FILE *in = fopen(file, "rb");
    if (!in) ret = 0;
    else {
        if (!data_size) {
            fseek(in, 0, SEEK_END);
            data_size = ftell(in);
        }
        fseek(in, 0, SEEK_SET);

        data = new unsigned char[data_size] {};

        if (!fread(data, 1, data_size, in) || fclose(in)) ret = 0;
    }

    return ret;
}


#endif
