/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Data encryption software using chacha20 algorithm
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 
// On future change hash algorithm to something like:
//	Argon2, PBKDF2, scrypt, bcrypt ...

#include <stdio.h>      //Input/output operations
#include <stdlib.h>     //Memory allocation and program termination
#include <stdint.h>     //For precise variable types
#include <stdbool.h>    //To use boolean variables
#include <unistd.h>     //System information
#include <termios.h>    //Terminal manipulation (buffer and echo)
#include <sys/stat.h>   //Find filesize
#include <time.h>       //Use system time for pseudo random number generator

#include "../include/chacha20.h"    //Generate cipher block
#include "../include/sha256.h"      //Generate hash digest
#include "../include/prog_bar.h"    //Draw progress bar
#include "../include/progargs.h"    //Process arguments from terminal


#define MAJOR_PROG_VERSION      3

//flag to compile with debug code
#define DEBUG                   1

//Encryption/decryption constants (bytes)
#define MAX_PASSWORD_LENGTH     500
#define CIPHER_LENGTH           64
#define DATA_BLOCK_SIZE         CIPHER_LENGTH
#define KEY_LENGTH              32

//Passwords lengths for diferent color characters
#define SMALL_PASSWORD          8
#define MEDIUM_PASSWORD         20

//ANSI scape codes
#define RED_CHAR                "\033[91m"
#define YELLOW_CHAR             "\033[93m"
#define GREEN_CHAR              "\033[92m"
#define RESET_COLOR             "\033[0m"
#define RED_BG                  "\033[101m"

//Progress bar info
#define PROG_BAR_SIZE           50
#define PROG_BAR_PRECISION      1

//ASCII printable values limits
#define LOW_PRINT_ASCII         0x20
#define HIGH_PRINT_ASCII        0x7E

#pragma pack(push, 1)
struct header
{
uint8_t     Signature[8];   // File signature = "chachaXX"
uint32_t    MajProgVer;     // Major prog version
uint32_t    NumRounds;      // Number of rounds
uint64_t    Nonce;          // Number used once
uint64_t    DataSize;       // Encrypted data size in bytes
};
#pragma pack(pop)

typedef struct header header_t;

static FILE *open_read_file(const char *Filename);
static FILE *open_write_file(const char *Filename);
//Create the encrypted output filename by appending ".cha20" extension to input filename
static char *create_encrypted_out_filename(const char *InputFilename);
//test for ".cha20" extension. Return 1 if true
static uint8_t input_is_encrypted(const char *InputFilename);
//Create the decrypted output filename by removing ".cha20" extension of input filename
static char *create_decrypted_out_filename(const char *InputFilename);
static uint64_t filesize(const char *Filename);
//Set a null terminated pointer to char containing user password
static void get_password(uint32_t *PasswordLength, uint8_t *Password);


int main(int argc, char *argv[])
{	
    uint64_t    InFileSizeByte;             //Input filesize in bytes
    uint8_t     *Key;                       //32 byte key for chacha20 cipher

    uint8_t     CipherKey[CIPHER_LENGTH];   //64 byte chacha20 block to be XOR'ed with data
    uint64_t    Nonce = 0;                  //8 byte "number used once" for chacha20
    uint64_t    BlockCounter = 0;           //8 byte block counter for chacha20 cipher
    uint32_t    Rounds = 20;                //Number of chacha rounds to generate cipher stream

    uint8_t     Password[MAX_PASSWORD_LENGTH] = {0};//Password from user to be transformed into key
    uint32_t    PasswordLength = 0;

    uint8_t     InDataBlock[DATA_BLOCK_SIZE];       //Data block from file to be encrypted
    uint8_t     OutEncryptedBlock[DATA_BLOCK_SIZE]; //Encrypted data to be saved into a file
	
    header_t	FileHeader;
    args_t      ArgConf;    //Hold info from terminal arguments about path and options
	
    bar_t       *Bar;       //Hold info for progress bar drawing
    bar_graph_t *Graph;     //Hold graphical info for progress bar representation
	
	
    //Validate input ------------------------------------------------------------
    process_arguments(argc, argv, &ArgConf);
    #error implement ArgConf on the rest of the program

    /* Geting user input (password) ------------------------------------------- */
    get_password(&PasswordLength, Password);


    /* Initialising file variables. Header manipulation ------------------------*/

    FILE *InDataFile, *OutDataFile;
    char *OutFilename;

    InDataFile = open_read_file(argv[1]);

    if(input_is_encrypted(argv[1]))
    {
        fread(&FileHeader, sizeof(header_t), 1, InDataFile);

        /* Checking compatibility */
        if(FileHeader.MajProgVer != MAJOR_PROG_VERSION)
        {
            printf("Error: file incompatible with current program version.\n");
            printf("Note: File version:    %u\n", FileHeader.MajProgVer);
            printf("      Program version: %u\n", MAJOR_PROG_VERSION);
            exit(EXIT_FAILURE);
        }

        Rounds = FileHeader.NumRounds;
        Nonce = FileHeader.Nonce;
        InFileSizeByte = FileHeader.DataSize;

        /* Create output file */
        OutFilename = create_decrypted_out_filename(argv[1]);
        OutDataFile = open_write_file(OutFilename);

    }
    else /* Not encrypted */
    {
        FileHeader.Signature[0] = 'c';
        FileHeader.Signature[1] = 'h';
        FileHeader.Signature[2] = 'a';
        FileHeader.Signature[3] = 'c';
        FileHeader.Signature[4] = 'h';
        FileHeader.Signature[5] = 'a';
        FileHeader.Signature[6] = 'X';
        FileHeader.Signature[7] = 'X';
        FileHeader.MajProgVer = MAJOR_PROG_VERSION;
        FileHeader.NumRounds = Rounds;

        /* Generating number used once (nonce) */
        srand((unsigned int) time(NULL));
        Nonce = (uint8_t) rand();
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        Nonce = ((uint8_t) rand()) | (Nonce << 8);
        FileHeader.Nonce = Nonce;

        InFileSizeByte = filesize(argv[1]);
        FileHeader.DataSize = InFileSizeByte;

        /* Create output file */
        OutFilename = create_encrypted_out_filename(argv[1]);
        OutDataFile = open_write_file(OutFilename);

        /* Write file header to output file */
        if(fwrite(&FileHeader, sizeof(header_t), 1, OutDataFile) != 1)
        {
            printf("Error: Could not write header to output file.");
            exit(EXIT_FAILURE);
        }
    }

    free(OutFilename);

    /* Generating key --------------------------------------------------------- */
    Key = sha256_data(Password, (uint64_t)PasswordLength, SHA256_NOT_VERBOSE);

/*###########################################################################*/
#if DEBUG
    printf("------------------------- DEBUG INFO -------------------------------\n");
	/* Print password */
    printf("Password (first 60 characters): [%%c(%%02x)]");
    for(uint32_t i = 0; i < 60; i++)
    {
        if((i % 8) == 0)
            printf("\n");
        printf("%c(%02x) ", Password[i], Password[i]);
    }
    printf("\n\nFormated password:\n");
    for(uint32_t i = 0; i < PasswordLength; i++)
    {
        printf("%c", Password[i]);
    }

    /* Print key and nonce */
    printf("\n\nKey:    ");
    for(uint32_t i = 0; i < KEY_LENGTH; i++)
    {
        printf("%02x", Key[i]);
    }
    printf("\nNonce: ");
    printf(" %lx\n\n", Nonce);

    /* Print file header */
    printf("File header\n");
    printf("  Signature ................. %s\n", FileHeader.Signature);
    printf("  Major program version ..... %u\n", FileHeader.MajProgVer);
    printf("  Number of chacha rounds ... %u\n", FileHeader.NumRounds);
    printf("  File size ................. %lu\n", FileHeader.DataSize);

    printf("--------------------------------------------------------------------\n\n");        
#endif
/*###########################################################################*/

    //Encryption routine -------------------------------------------------------
    printf("Encrypting/decrypting...\n");
    Bar = init_bar(0, (InFileSizeByte / CIPHER_LENGTH)-1, PROG_BAR_SIZE, PROG_BAR_PRECISION);
    Graph = init_bar_graph('|', '#', ' ', '|');

    //Encryption on full size blocks (64 bytes)
    BlockCounter = 0;
    for(uint64_t Block = 0; Block < (InFileSizeByte / CIPHER_LENGTH); Block++)
    {
        fread(InDataBlock, sizeof(uint8_t), CIPHER_LENGTH, InDataFile);
        BlockCounter++;

        generate_chacha_cipher_key(Key, BlockCounter, Nonce, Rounds, CipherKey);

        for(uint32_t i = 0; i < CIPHER_LENGTH; i++)
        {
            OutEncryptedBlock[i] = CipherKey[i] ^ InDataBlock[i];
        }
        fwrite(OutEncryptedBlock, sizeof(uint8_t), CIPHER_LENGTH, OutDataFile);

        //Print progress bar
        update_bar(Bar, Graph, (int64_t)Block);
    }

    //Dealocate progress bar objects
    destroy_bar(Bar);
    destroy_graph(Graph);

    //Encryption on last partial size block
    if((InFileSizeByte % CIPHER_LENGTH) != 0)
    {
        fread(InDataBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), InDataFile);
        BlockCounter++;
        
        generate_chacha_cipher_key(Key, BlockCounter, Nonce, Rounds, CipherKey);

        for(uint32_t i = 0; i < (InFileSizeByte % CIPHER_LENGTH); i++)
        {
            OutEncryptedBlock[i] = CipherKey[i] ^ InDataBlock[i];
        }
        fwrite(OutEncryptedBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), OutDataFile);
    }


    //Close files
    fclose(InDataFile);
    fclose(OutDataFile);

    //Destroy key and deallocate
    for(uint8_t i = 0; i < KEY_LENGTH; i++)
        Key[i] = 0x0;
    free(Key);

    return 0;
}
//==============================================================================
//    HELPER FUNCTIONS
//==============================================================================
/*******************************************************************************/
static FILE *open_read_file(const char *Filename)
{
    FILE *ReadFile;

    ReadFile = fopen(Filename, "rb");
    if(ReadFile == NULL)
    {
        printf("Error: could not open \"%s\" file.\n", Filename);
        exit(EXIT_FAILURE);
    }
    return ReadFile;
}
/*******************************************************************************/
static FILE *open_write_file(const char *Filename)
{
    FILE *WriteFile;

    WriteFile = fopen(Filename, "wb");
    if(WriteFile == NULL)
    {
        printf("Error: could not create output file.\n");
        exit(EXIT_FAILURE);
    }
    return WriteFile;
}
/*******************************************************************************/
//Create the encrypted output filename by appending ".cha" extension to input filename
static char *create_encrypted_out_filename(const char *InputFilename)
{	
    char        *OutputFilename;
    uint32_t    NumChar = 0;
    uint8_t     HaveExtensionFlag = 0;

    /* Count number of characters in input filename */
    for(uint32_t i = 0;; i++)
    {
        if(InputFilename[i] != '\0')
            NumChar++;
        else
            break;
    }

    /* Check for the existence of the ".cha" extension */
    if(InputFilename[NumChar - 4] == '.')
        if(InputFilename[NumChar - 3] == 'c')
            if(InputFilename[NumChar - 2] == 'h')
                if(InputFilename[NumChar - 1] == 'a')
                    HaveExtensionFlag = 1;

    if(HaveExtensionFlag == 0)
    {
        //Allocate memory, copy input filename and append extension
        OutputFilename = (char *)malloc((NumChar + 5) * sizeof(char));

        for(uint32_t i = 0; i < (NumChar + 1); i++)
        {
            if(i == NumChar) //if in the last char of InputFilename
            {
                OutputFilename[NumChar] = '.';
                OutputFilename[NumChar + 1] = 'c';
                OutputFilename[NumChar + 2] = 'h';
                OutputFilename[NumChar + 3] = 'a';
                OutputFilename[NumChar + 4] = '\0';
            }
            else
            {
                OutputFilename[i] = InputFilename[i];
            }
        }
    }
    else
    {
        printf("Warning: File was not recognized to be encrypted but have \".cha\" extension.\n");

        //Allocate memory, copy input filename
        OutputFilename = (char *)malloc((NumChar+1) * sizeof(char));

        for(uint32_t i = 0; i < (NumChar + 1); i++)
        {
            OutputFilename[i] = InputFilename[i];
        }
    }

    return OutputFilename;
}
/******************************************************************************/
/* test for "chacha" file signature. Return 1 if true. */
static uint8_t input_is_encrypted(const char *InputFilename)
{
    FILE        *InputFile;
    header_t    Header;
    uint8_t     Signature[] = "chachaXX";

    InputFile = fopen(InputFilename, "rb");

    if(fread(&Header, sizeof(header_t), 1, InputFile) == 1)
    {
        for(uint8_t i = 0; i < 8; i++)
        {
            if(Header.Signature[i] != Signature[i])
            {
                fclose(InputFile);
                return 0;
            }
        }

        fclose(InputFile);
        return 1;
    }
    else
    {
        fclose(InputFile);
        return 0;
    }
}
/******************************************************************************/
//Create the decrypted output filename by removing ".cha20" extension of input filename
static char *create_decrypted_out_filename(const char *InputFilename)
{
    char        *OutputFilename;
    uint32_t    NumChar = 0;
    uint8_t     HaveExtensionFlag = 0;

    //Count number of characters in input filename
    for(uint32_t i = 0;; i++)
    {
        if(InputFilename[i] != '\0')
            NumChar++;
        else
        break;
    }

    /* Check for the existence of the ".cha" extension */
    if(InputFilename[NumChar - 4] == '.')
        if(InputFilename[NumChar - 3] == 'c')
            if(InputFilename[NumChar - 2] == 'h')
                if(InputFilename[NumChar - 1] == 'a')
                    HaveExtensionFlag = 1;

    if(HaveExtensionFlag)
    {
        //Allocate memory, copy input filename until ".cha20" extension
        OutputFilename = (char *)malloc((NumChar - 3) * sizeof(char));

        for(uint32_t i = 0; i < (NumChar - 4); i++)
        {
            OutputFilename[i] = InputFilename[i];
        }
        OutputFilename[NumChar - 4] = 0x0;
    }
    else
    {
        //Allocate memory, copy input filename until ".cha20" extension
        OutputFilename = (char *)malloc((NumChar+1) * sizeof(char));

        for(uint32_t i = 0; i < (NumChar +1); i++)
        {
            OutputFilename[i] = InputFilename[i];
        }		
    }

    return OutputFilename;
}
/******************************************************************************/
static uint64_t filesize(const char *Filename)
{
    struct stat Status;

    stat(Filename, &Status);

    return Status.st_size;
}
/******************************************************************************/
//Return a null terminated pointer to char containing user password
static void get_password(uint32_t *PassLength, uint8_t *Password)
{
    struct termios OldTerminal, NewTerminal;    //terminal info

    uint32_t    PasswordLength = 0; //size of user password
    uint8_t     TmpChar = 0;        //Temporary char to use on password acquisition


    //acquiring terminal information
    tcgetattr(STDIN_FILENO, &OldTerminal);
    NewTerminal = OldTerminal;
    //configure terminal: turn off buffering and echo
    NewTerminal.c_lflag &= ~(ICANON | ECHO);
    //Set new terminal configuration
    tcsetattr(STDIN_FILENO, TCSANOW, &NewTerminal);

    printf("Password:\n");
    for(int32_t i = 0; i < MAX_PASSWORD_LENGTH;)
    {
        //Get char and filter input
        TmpChar = getc(stdin);
        while(((TmpChar < LOW_PRINT_ASCII) || (TmpChar > HIGH_PRINT_ASCII)) && 
               (TmpChar != '\n')  && (TmpChar != '\b') &&
               (TmpChar != 0x7f))
        {
            TmpChar = getc(stdin);
        }

        //End user input if new line
        if(TmpChar == '\n')
            break;

        //Set terminal char color
        if(i < SMALL_PASSWORD)
            printf(RED_CHAR);
        else if(i < MEDIUM_PASSWORD)
            printf(YELLOW_CHAR);
        else
            printf(GREEN_CHAR);

        fflush(stdout);

        //Back space password
        if((TmpChar == '\b') || (TmpChar == 0x7f))
        {	
            if(i > 0)
            {
                i--;
                PasswordLength--;
                Password[i] = 0x0;
                //printf(CURSOR_BACK " " CURSOR_BACK);
                printf("\b \b");
            }
        }
        else //Save printable char
        {
            Password[i] = TmpChar;
            i++;
            PasswordLength++;

            putc('\r', stdout);
            for(uint32_t i = 0; i < PasswordLength; i++)
            {
                putc('#', stdout);
            }
        }

    }
    printf("\n\n"RESET_COLOR);

    //Set terminal to old configuration
    tcsetattr(STDIN_FILENO, TCSANOW, &OldTerminal);

    if(PasswordLength == 0)
    {
        printf("Error: no password entered.\n");
        exit(EXIT_FAILURE);
    }

    *PassLength = PasswordLength;
}









