/* Exists purely for the sleep() function */

#ifndef PRINTPAUSE_HPP
#define PRINTPAUSE_HPP

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) \
                      || defined(WIN64) || defined(_WIN64) || defined(__WIN64__)
    #include <windows.h>
    #define sleep(secs) Sleep(secs * 1000)
#else
    #include <unistd.h>
#endif


#endif
