#ifndef LBA_SHARED_HPP
#define LBA_SHARED_HPP

#include <string>

class lbat {
    public:
        lbat() : reset() {}
        ~lbat() : reset() {}
        
        std::string getTableCSV(unsigned char *src, unsigned src_size);
        int setTableCSV(unsigned char *src, unsigned src_size);
        int setTableCSV(const char *csv_filename);
        int setTableBIN(unsigned char *src, unsigned src_size);
        int setTableBIN(const char *bin_filename);

    protected:
        int setTable(const char *filename, int tabletyp);
        
        bool isDebug;
        unsigned amnt_glba;
        struct lbainf {
            std::string info_name;  // Name of file
            unsigned info_rlbn;     // Relative logical block number of file
            //unsigned info_unkn;   // Unknown
            unsigned info_size;     // Size of file
        } *info;

    private:
        void reset();
};


#endif
