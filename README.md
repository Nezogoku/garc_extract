# garc_extract
A program that extracts files from LocoRoco GARC files.

Capable of extracting all files when LBA table specified.

    Usage: garc_extract [Options] <infile(s)>
         Options:
            -h              Prints help message
            -d              Activates debug mode
            -l              Outputs a log file
            -T lba.csv      Accepts a text file containing the corresponding LBA table
            -B sector.bin   Accepts a binary file containing the corresponding LBA table

If a sector.bin file is found, the programme will create a csv containing the LBA table automatically.

If multiple files are dragged onto the program and the first contains the LBA table for the second,
then all listed files in the table will be extracted from the second file automatically.
