# garc_extract
A program that unpacks and decompresses files found in LocoRoco games.
Each LocoRoco game contains a main .arc file and a DATA.BIN file.
        
        Usage: garc_extract [option(s)] <infile(s)>
            options:
                -h              Prints help message
                -d              Activates debug mode
                -L              Outputs a log file
                -T lba.csv      Accepts a text file containing the corresponding LBA table
                -B sector.bin   Accepts a binary file containing the corresponding LBA table


# .arc files
All arcs are LocoRoco archive files containing one or more embedded files.
Archives may or may not be compressed using a custom LZ compression algorithm.
The main .arc file is a singular compressed archive,
one entry being a .bin file with information for the DATA.BIN file.
If a main .arc file is preceded by its corresponding DATA.BIN file (eg. garc_extract first_usa.arc DATA.BIN),
then all files specified in the former will be extracted from the latter.


# .csv files
All csvs produced by this program are text files storing file information for the corresponding DATA.BIN file.
New files will be produced from the sector.bin file found in the main .arc file.
These text files are read when the -T option is specified and will store the following information:
    
    Table initializer:
        'GIMG_AMNT' followed by a colon and the number of entries in the file
    
    Table headers:
        'FILE_NAME' indicating the name of an entry
        'FILE_RLBN' indicating the relative logical block number of an entry
        'FILE_SIZE' indicating the size (in bytes) of an entry
        These headers are all on one line, seperated by commas, and may be in any order
    
    Entry info:
        The names, relative logical block numbers, and sizes of each entry are all on one line,
        seperated by commas, and ordered according to the previous headers


# .glog files
All glogs are text files storing file extraction information for an extracted file.
New files will share a name with their corresponding file.
These text files are created when the -L option is specified and will likely store the following information:
    
    Log initializer:
        A line containing the name of the file
    
    Entry info:
        'FILE_TYPE' followed by a colon and the extension of the entry
        'FILE_NAME' followed by a colon and the name (plus extension) of the entry
        'FILE_OFFSET' followed by a colon and the relative address (in hex bytes) of the entry
        'FILE_COMPRESSED_SIZE' followed by a colon and the raw size (in hex bytes) of the entry
        'FILE_DECOMPRESSED_SIZE' followed by a colon and the final size (in hex bytes) of the entry
    
    Archive info:
        A line containing either the name of the subroot folder or '(none)' if the root folder is used
        Three lines, each containing the number of files, names, and data found in the archive
        Variable lines containing info for each entry
        A line indicating the end of the archive after the final entry


# decompression
Heavily-edited LZ decompression algorithm, originally created by bnnm and some other folks I can't remember the name of.
