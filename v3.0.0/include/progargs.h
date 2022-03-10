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
    
    uint8_t  InFilePathIndex;
    uint8_t  NumRoundsIndex;
    uint8_t  FileKeyPathIndex;
};
typedef struct args args_t;

/*######################### FUNTIONS ########################################*/

/* Receive arguments from terminal and initializes ArgConf structure */
void process_arguments(int argc, char *argv[], args_t *ArgConf);

#endif
