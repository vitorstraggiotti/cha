/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
    Library that process user arguments from terminal

    Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
    Start date: 08/03/2022  (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "../include/progargs.h"

static char *HelpMsg = 
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


void process_arguments(int argc, char *argv[], args_t *ArgConf)
{
    /* Inicialize argument structure to default values*/
    ArgConf->InFileFlag = false;
    ArgConf->ChRoundFlag = false;
    ArgConf->FileKeyFlag = false;
    ArgConf->VerboseFlag = false;
   
    ArgConf->InFilePathIndex = 0;
    ArgConf->NumRoundsIndex = 0;
    ArgConf->FileKeyPathIndex = 0;

    /* Program called with no arguments */
    if(argc == 1)
    {
    	printf("\nError: too few arguments.\n");
    	printf("%s", HelpMsg);
    }
    
    /* Find and set options and input file from arguments */
    for(uint8_t i = 1; i < argc; i++)
    {
        if(argv[i][0] == '-') /* If argument start with "-". It is an option */
        {
            switch(argv[i][1])
            {
                case 'r':

                    if(ArgConf->ChRoundFlag == false)
                    {
                        ArgConf->ChRoundFlag = true;

                        if(argv[i+1][0] != '-') /* if next string is not an option */
                        {
                            ArgConf->NumRoundsIndex = ++i;
                        }
                        else
                        {
                        	printf("Error: option \"-r\" have no argument.\n\n");
                        	printf("%s", HelpMsg);
                        	exit(EXIT_FAILURE);
                        }
                    }
                    else
                    {
                        printf("Error: repeated option \"-r\"\n\n");
                        printf("%s", HelpMsg);
                        exit(EXIT_FAILURE);
                    }
                    break;

                case 'k':

                    if(ArgConf->FileKeyFlag == false)
                    {
                        ArgConf->FileKeyFlag = true;

                        if(argv[i+1][0] != '-') /* if next string is not an option */
                        {
                            ArgConf->FileKeyPathIndex = ++i;
                        }
                        else
                        {
                        	printf("Error: option \"-k\" have no argument.\n\n");
                        	printf("%s", HelpMsg);
                        	exit(EXIT_FAILURE);
                        }
                    }
                    else
                    {
                        printf("Error: repeated option \"-k\"\n\n");
                        printf("%s", HelpMsg);
                        exit(EXIT_FAILURE);
                    }
                    break;

                case 'v':

                    if(ArgConf->VerboseFlag == false)
                    {
                        ArgConf->VerboseFlag = true;
                    }
                    else
                    {
                        printf("Error: repeated option \"-v\"\n\n");
                        printf("%s", HelpMsg);
                        exit(EXIT_FAILURE);
                    }
                    break;

                case 'h':

                    printf("%s", HelpMsg);
                    exit(EXIT_SUCCESS);
                    break;

                default:

                    printf("Error: invalid option.\n\n");
                    exit(EXIT_FAILURE);
            }
        }
        else /* Argument does not start with "-". It is not an option */
        {
            if(ArgConf->InFileFlag == false)
            {
                ArgConf->InFileFlag = true;
                ArgConf->InFilePathIndex = i;
            }
            else
            {
                printf("Error: too much input file paths.\n");
                printf("Note: input \"%s\" already set.\n\n", argv[i]);
                printf("%s", HelpMsg);
                exit(EXIT_FAILURE);
            }
        }
    }
}
