/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
    Library that process user arguments from terminal

    Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
    Start date: 08/03/2022  (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "../include/progargs.h"

void process_arguments(int argc, char *argv[], args_t *ArgConf)
{
    /* Inicialize argument structure to default values*/
    ArgConf->InFileFlag = false;
    ArgConf->ChRoundFlag = false;
    ArgConf->FileKeyFlag = false;
    ArgConf->VerboseFlag = false;
    ArgConf->HelpFlag = false;

    ArgConf->InFilePathIndex = 0;
    ArgConf->NumRoundsIndex = 0;
    ArgConf->FileKeyPathIndex = 0;

    /* Program called with no arguments */
    if(argc == 1)
    {
    	printf("Error: too few arguments\n\n");
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

                    if(ArgConf->HelpFlag == false)
                    {
                        ArgConf->HelpFlag = true;
                    }
                    else
                    {
                        printf("Error: repeated option \"-h\"\n\n");
                        printf("%s", HelpMsg);
                        exit(EXIT_FAILURE);
                    }
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
