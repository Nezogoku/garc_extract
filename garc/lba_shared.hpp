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
            std::string file_name;  // Name of file
            unsigned file_rlbn;     // Relative logical block number of file
            //unsigned file_unkn;   // Unknown
            unsigned file_size;     // Size of file
        } *info;

    private:
        void reset();
};


#endif
