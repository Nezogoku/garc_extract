#ifndef LBA_SHARED_HPP
#define LBA_SHARED_HPP

#include <string>

class lbat {
    public:
        lbat(bool debug = false) : isDebug(debug) {}
        ~lbat() { table = {}; }

        void setDebug(bool debug) { this->isDebug = debug; }
        int setTableCSV(unsigned char *src, unsigned src_size);
        int setTableCSV(const char *csv_filename);
        int setTableBIN(unsigned char *src, unsigned src_size);
        int setTableBIN(const char *bin_filename);

        int getTableNum() { return table.glba_amnt; }
        std::string getTableEntName(int id) { return table.glba_info[id].file_name; }
        unsigned getTableEntRlbn(int id) { return table.glba_info[id].file_rlbn; }
        unsigned getTableEntSize(int id) { return table.glba_info[id].file_size; }
        std::string getTableCSV(unsigned char *src, unsigned src_size);

    protected:
        int setTable(const char *filename, int tabletyp);
        void resetTable() { this->table = {}; }

    private:
        bool isDebug;
        struct lbaSpec {
            //unsigned glba_crc;    // CRC
            unsigned glba_amnt;     // Amount LB
            struct lbainf {
                std::string file_name;  // Name of file
                unsigned file_rlbn;     // Relative logical block number of file
                //unsigned file_unkn;   // Unknown
                unsigned file_size;     // Size of file
            } *glba_info;

            lbaSpec() : glba_amnt(0), glba_info(0) {}
            ~lbaSpec() { reset(); }

            lbaSpec& operator=(const lbaSpec &s) {
                reset();
                glba_amnt = s.glba_amnt;
                copy(s.glba_info, glba_info, s.glba_amnt, 0);
                return *this;
            }

            private:
                void reset() { if (glba_info) delete[] glba_info; }
                template <typename T0, typename T1>
                void copy(const T0 *in, T1 *&out, const int S, const int a) {
                    if (in) {
                        if (S > 0) out = new T1[S + a] {};
                        for (int i = 0; i < S; ++i) out[i] = T1(in[i]);
                    }
                }
        } table;
};


#endif
