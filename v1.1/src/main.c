/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Data encryption software using chacha20 chiper
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 
// On future change hash algorithm to something like:
//	Argon2, PBKDF2, scrypt, bcrypt ...

#include <stdio.h>		//input/output operations
#include <stdlib.h>		//memory allocation and program termination
#include <stdint.h>		//for precise variable types
#include <string.h>		//string manipulation
#include <unistd.h>		//system information
#include <termios.h>	//terminal manipulation (buffer and echo)
#include <sys/stat.h>	//find filesize

#include "../include/chacha20.h"	//generate cipher block
#include "../include/sha256.h"		//generate hash digest

//flag to compile with debug code
#define DEBUG  0

//Encryption/decryption constants
#define MAX_PASSWORD_LENGTH		500
#define CIPHER_LENGTH			64
#define DATA_BLOCK_SIZE			CIPHER_LENGTH
#define KEY_LENGTH				32
#define NONCE_LENGTH			12

//Passwords lengths for diferent color characters
#define SMALL_PASSWORD			8
#define MEDIUM_PASSWORD			25

//ANSI scape codes
#define RED_CHAR				"\033[91m"
#define YELLOW_CHAR				"\033[93m"
#define GREEN_CHAR				"\033[92m"
#define RESET_COLOR				"\033[0m"
#define RED_BG					"\033[101m"

#define PROGRESS_BAR_SIZE		50

#define LOW_PRINT_ASCII		0x20
#define HIGH_PRINT_ASCII	0x7E

static FILE *open_read_file(char *Filename);
static FILE *open_write_file(char *Filename);
static uint8_t input_is_encrypted(char *InputFilename);
static char *create_encrypted_out_filename(char *InputFilename);
static char *create_decrypted_out_filename(char *InputFilename);
void print_progress(uint32_t CurrState, uint32_t Min, uint32_t Max, uint32_t BarSize);


int main(int argc, char *argv[])
{
	static		struct termios OldTerminal, NewTerminal;	//terminal info
	
	uint32_t	InFileSizeByte;	//Input filesize in bytes
	uint8_t		*Key;			//32 byte key for chacha20 cipher

	uint8_t		Cipher[CIPHER_LENGTH];	//64 byte chacha20 block to be XOR'ed with data
	uint8_t		Nonce[NONCE_LENGTH];	//12 byte "number used once" for chacha20
	uint32_t	BlockCounter;		//4 byte block counter for chacha20 cipher

	uint8_t		Password[MAX_PASSWORD_LENGTH];	//Password from user to be transformed into key
	uint32_t	PasswordLength;	//size of user password
	uint8_t		TmpChar;		//Temporary char to use on password acquisition

	uint8_t 	InDataBlock[DATA_BLOCK_SIZE];	//Data block from file to be encrypted
	uint8_t 	OutEncryptedBlock[DATA_BLOCK_SIZE]; //Encrypted data to be saved into a file
	
	
	//Validate input ------------------------------------------------------------
	if(argc != 2)
	{
		printf("Error: wrong number of arguments.\n");
		printf("Use: %s <file_path>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	
	//Initialising file variables ----------------------------------------------
	
	FILE *InDataFile, *OutEncryptedFile;
	
	//Find input file size
	struct stat Status;
	stat(argv[1], &Status);
	InFileSizeByte = Status.st_size;
	
	//Open file to encrypt on read only mode
	InDataFile = open_read_file(argv[1]);
	
	//Creating encrypted/decrypted output filename
	char *OutputFilename;
	
	if(input_is_encrypted(argv[1]))
	{
		OutputFilename = create_decrypted_out_filename(argv[1]);
	}
	else
	{
		OutputFilename = create_encrypted_out_filename(argv[1]);
	}
	
	OutEncryptedFile = open_write_file(OutputFilename);
	free(OutputFilename);

	//Geting user input --------------------------------------------------------
	//acquiring terminal information
	tcgetattr(STDIN_FILENO, &OldTerminal);
	NewTerminal = OldTerminal;
	//configure terminal: turn off buffering and echo
	NewTerminal.c_lflag &= ~(ICANON | ECHO);
	//Set new terminal configuration
	tcsetattr(STDIN_FILENO, TCSANOW, &NewTerminal);

	//Clear password related variables
	for(uint32_t i = 0; i < MAX_PASSWORD_LENGTH; i++)
	{
		Password[i] = 0x0;
	}
	PasswordLength = 0;
	
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
		if(i <= SMALL_PASSWORD)
		{
			printf(RED_CHAR);
		}
		else if(i <= MEDIUM_PASSWORD)
		{
			printf(YELLOW_CHAR);
		}
		else
		{
			printf(GREEN_CHAR);
		}
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
			for(int32_t i = 0; i < PasswordLength; i++)
			{
				putc('#', stdout);
			}
		}
		
	}
	putc('\n', stdout);
	
	//Set terminal to old configuration
	tcsetattr(STDIN_FILENO, TCSANOW, &OldTerminal);

	if(PasswordLength == 0)
	{
		printf(RESET_COLOR "Error: no password entered.\n");
		exit(EXIT_FAILURE);
	}
	

#if DEBUG
	//****************** for debug ***********************************
	printf("\nPassword (first 60 characters):");
	for(uint32_t i = 0; i < 60; i++)
	{
		if((i % 8) == 0)
			printf("\n");
		printf("%c(%02x) ", Password[i], Password[i]);
	}
	printf("\nFormated password:");
	for(uint32_t i = 0; i < PasswordLength; i++)
	{
		if((i % 8) == 0)
			printf("\n");
		printf("%c(%02x) ", Password[i], Password[i]);
	}
	//*****************************************************************
#endif	

	//Allocating and initialising cryptographic variables ----------------------
	BlockCounter = 0;
	Key = sha256(Password, (uint64_t)PasswordLength);

	for(uint32_t i = 0; i < (2 * NONCE_LENGTH); i += 2)
	{
		Nonce[i/2] = Key[i] + Key[i+1];
	}

#if DEBUG	
	//****************** for debug ************************************
	printf("\nsha256 (key): ");
	for(uint32_t i = 0; i < KEY_LENGTH; i++)
	{
		printf("%02x", Key[i]);
	}
	printf("\nsha256 (nonce): ");
	for(uint32_t i = 0; i < NONCE_LENGTH; i++)
	{
		printf("%02x", Nonce[i]);
	}
	printf("\n");
	//***************************************************************
#endif

	//Encryption routine -------------------------------------------------------

	//Encryption on full size blocks (64 bytes)
	for(uint32_t Block = 0; Block < (InFileSizeByte / CIPHER_LENGTH); Block++)
	{
		fread(InDataBlock, sizeof(uint8_t), CIPHER_LENGTH, InDataFile);
		BlockCounter++;

		chacha20_block(Key, BlockCounter, Nonce, Cipher);

		for(uint32_t i = 0; i < CIPHER_LENGTH; i++)
		{
			OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
		}
		fwrite(OutEncryptedBlock, sizeof(uint8_t), CIPHER_LENGTH, OutEncryptedFile);
		
		//Print progress bar
		if(InFileSizeByte < (CIPHER_LENGTH * 500))
		{
			print_progress(Block+1, 0, (InFileSizeByte / CIPHER_LENGTH), PROGRESS_BAR_SIZE);
		}
		else if((Block % (InFileSizeByte / (CIPHER_LENGTH * 500))) == 0)
		{
			print_progress(Block+1, 0, (InFileSizeByte / CIPHER_LENGTH), PROGRESS_BAR_SIZE);
		}
			
		if(Block == (InFileSizeByte / CIPHER_LENGTH)-1)
			print_progress(Block+1, 0, (InFileSizeByte / CIPHER_LENGTH), PROGRESS_BAR_SIZE);
	}
	putc('\n', stdout);
	
	//Encryption on last partial size block
	if((InFileSizeByte % CIPHER_LENGTH) != 0)
	{
		fread(InDataBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), InDataFile);
		BlockCounter++;

		chacha20_block(Key, BlockCounter, Nonce, Cipher);

		for(uint32_t i = 0; i < (InFileSizeByte % CIPHER_LENGTH); i++)
		{
			OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
		}
		fwrite(OutEncryptedBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), OutEncryptedFile);
	}


	
	//Close files
	fclose(InDataFile);
	fclose(OutEncryptedFile);
	
	//Deallocate variables
	free(Key);
	
	return 0;
}
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
//		HELPER FUNCTIONS
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/*******************************************************************************/
void print_progress(uint32_t CurrState, uint32_t Min, uint32_t Max, uint32_t BarSize)
{
	uint32_t BarPosition;
	float Percentage;
	
	//Calculating progress
	BarPosition = ((BarSize * (CurrState - Min)) / (Max - Min));
	Percentage = 100.0 * ((float)(CurrState - Min) / (float)(Max - Min));
	
	//Drawing progress bar
	fputs("\r|", stdout);
	for(uint32_t i = 0; i < BarSize; i++)
	{
		if(i < BarPosition)
		{
			printf(RED_BG " ");
		}else
		{
			printf(RESET_COLOR " ");
		}
	}
	printf(RESET_COLOR "| %.1f %%", Percentage);
	fflush(stdout);

}
/*******************************************************************************/
static FILE *open_read_file(char *Filename)
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
static FILE *open_write_file(char *Filename)
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
//Create the encrypted output filename by appending ".cha20" extension to input filename
static char *create_encrypted_out_filename(char *InputFilename)
{	
	char *OutputFilename;
	uint32_t NumChar = 0;

	//Count number of characters in input filename
	for(uint32_t i = 0;; i++)
	{
		if(InputFilename[i] != '\0')
		{
			NumChar++;
		}
		else
		{
			break;
		}
	}

	//Allocate memory, copy input filename and append extension
	OutputFilename = (char *)malloc((NumChar + 7) * sizeof(char));
	
	for(uint32_t i = 0; i < NumChar; i++)
	{
		if(i == (NumChar - 1)) //if in the last char of InputFilename
		{
			OutputFilename[NumChar] = '.';
			OutputFilename[NumChar + 1] = 'c';
			OutputFilename[NumChar + 2] = 'h';
			OutputFilename[NumChar + 3] = 'a';
			OutputFilename[NumChar + 4] = '2';
			OutputFilename[NumChar + 5] = '0';
			OutputFilename[NumChar + 6] = '\0';
		}
		else
		{
			OutputFilename[i] = InputFilename[i];
		}
	}
	
	return OutputFilename;
}
/******************************************************************************/
//test for ".cha20" extension. Return 1 if true
static uint8_t input_is_encrypted(char *InputFilename)
{
	for(uint32_t i =0;; i++)
	{
		if(InputFilename[i] == '\0')
			return 0;
			
		if(InputFilename[i] == '.')
			if(InputFilename[i+1] == 'c')
				if(InputFilename[i+2] == 'h')
					if(InputFilename[i+3] == 'a')
						if(InputFilename[i+4] == '2')
							if(InputFilename[i+5] == '0')
								if(InputFilename[i+6] == '\0')
									return 1;
	}
}
/******************************************************************************/
//Create the decrypted output filename by removing ".cha20" extension of input filename
static char *create_decrypted_out_filename(char *InputFilename)
{
	char *OutputFilename;
	uint32_t NumChar = 0;

	//Count number of characters in input filename
	for(uint32_t i = 0;; i++)
	{
		if(InputFilename[i] != '\0')
		{
			NumChar++;
		}
		else
		{
			break;
		}
	}

	//Allocate memory, copy input filename until ".cha20" extension
	OutputFilename = (char *)malloc((NumChar - 5) * sizeof(char));
	
	for(uint32_t i = 0; i < (NumChar - 6); i++)
	{
		OutputFilename[i] = InputFilename[i];
	}
	OutputFilename[NumChar - 6] = 0x0;
	
	return OutputFilename;
}











