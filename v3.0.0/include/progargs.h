/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
    Header file of library that process user arguments from terminal

    Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
    Start date: 08/03/2022  (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef PROGARGS_H
#define PROGARGS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct args
{
    bool     InFileFlag;
    bool     ChRoundFlag;
    bool     FileKeyFlag;
    bool     VerboseFlag;
    bool     HelpFlag;
    
    uint8_t  InFilePathIndex;
    uint8_t  NumRoundsIndex;
    uint8_t  FileKeyPathIndex;
};
typedef struct args args_t;

char *HelpMsg = 
" \n\nNAME\n\
        cha - encrypt and decrypt files using the chacha algorithm.\n\
\n\
 USE\n\
        cha [options] <input_file>\n\
\n\
 OPTIONS\n\
\n\
    -r \033[4mNumber\033[0m\n\
        Even number that set the amount of chacha rounds to be performed.(default=20)\n\
\n\
    -k \033[4mPathToKeyfile\033[0m\n\
        Use any file as key.(if not used will prompt for password)\n\
\n\
    -v\n\
        Verbose (display extra info).\n\
\n\
    -h\n\
        Display this help and exit.\n\
\n\
 AUTHOR\n\
    Written by Vitor Henrique Andrade Helfensteller Straggiotti Silva.\n\
\n";

/*######################### FUNTIONS ########################################*/

/* Receive arguments from terminal and initializes ArgConf structure */
void process_arguments(int argc, char *argv[], args_t *ArgConf);

#endif
