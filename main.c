/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Data encryption software using chacha20 chiper
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "chacha20.h"
#include "sha256.h"

#define DEBUG  1	//flag to compile with debug code

#define MAX_PASSWORD_LENGTH   4000000000
#define CIPHER_LENGTH         64
#define KEY_LENGTH            32
#define NONCE_LENGTH          12


static FILE *open_read_file(char *Filename);
static uint32_t find_size_file(char *Filename);
static FILE *open_write_file(char *Filename);
static uint8_t input_is_encrypted(char *InputFilename);
static char *create_encrypted_out_filename(char *InputFilename);
static char *create_decrypted_out_filename(char *InputFilename);


int main(int argc, char *argv[])
{
	uint32_t InFileSizeByte;	//Input file size in bytes
	
	uint8_t *Cipher;			//64 byte chacha20 block to be XOR'ed with data
	uint8_t *Key;				//32 byte key for chacha20 cipher
	uint8_t *Nonce;				//12 byte "number used once" for chacha20
	uint32_t Counter;			//4 byte block counter for chacha20 cipher

	uint8_t *Password;			//Password from user to be transformed into key
	uint32_t PasswordLength;	//size of user password
	uint8_t *InDataBlock;		//Data block from file to be encrypted
	uint8_t *OutEncryptedBlock; //Encrypted data to be saved into a file
	
	
	//Parsing input ------------------------------------------------------------
	if(argc != 2)
	{
		printf("Error: wrong number of arguments.\n");
		printf("Use: %s <file_path>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	
	//Initialising file variables ----------------------------------------------
	
	FILE *InDataFile, *OutEncryptedFile;
	
	//Find input file size
	printf("Finding file size ...\n");
	InFileSizeByte = find_size_file(argv[1]);
	
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
	Password = (uint8_t *)malloc(MAX_PASSWORD_LENGTH * sizeof(uint8_t));
	printf("Password: ");
	uint8_t tmp; 
	PasswordLength = 0;
	//NÃO ESTA FUNCIONANDO A AQUISIÇÃO DE SENHA. TENTAR OUTRA COISA.
	for(uint32_t i = 0; i <= MAX_PASSWORD_LENGTH; i++)
	{
		tmp = getc(stdin);
		if((i == MAX_PASSWORD_LENGTH) && (tmp != '\n'))
		{
			printf("Warning: password exceed size limits. ");
			printf("Max password length: %lu\n", MAX_PASSWORD_LENGTH);
			printf("Note: password truncated to max length\n");
			break;	
		}
		if(tmp != '\n')
		{
			Password[i] = tmp;
			PasswordLength++;
		}
		else
		{
			break;
		}
	}

#if DEBUG
	//****************** for debug ***********************************
	printf("Password (first 60 characters):");
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
	Key    = (uint8_t *)malloc(KEY_LENGTH * sizeof(uint8_t));
	Nonce  = (uint8_t *)malloc(NONCE_LENGTH * sizeof(uint8_t));
	
	Counter = 0;
	Key = sha256(Password, (uint64_t)PasswordLength);
	free(Password);
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
	
	//Allocating working blocks ------------------------------------------------
	InDataBlock       = (uint8_t *)malloc(CIPHER_LENGTH * sizeof(uint8_t));
	OutEncryptedBlock = (uint8_t *)malloc(CIPHER_LENGTH * sizeof(uint8_t));

	//Encryption routine -------------------------------------------------------
	//Encryption on full size blocks (64 bytes)
	for(uint32_t Block = 0; Block < (InFileSizeByte / CIPHER_LENGTH); Block++)
	{
		fread(InDataBlock, sizeof(uint8_t), CIPHER_LENGTH, InDataFile);
		Counter++;
		Cipher = chacha20_block(Key, Counter, Nonce);
		for(uint32_t i = 0; i < CIPHER_LENGTH; i++)
		{
			OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
		}
		fwrite(OutEncryptedBlock, sizeof(uint8_t), CIPHER_LENGTH, OutEncryptedFile);
		free(Cipher);
	}
	
	//Encryption on last partial size block
	fread(InDataBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), InDataFile);
	Counter++;
	Cipher = chacha20_block(Key, Counter, Nonce);
	for(uint32_t i = 0; i < (InFileSizeByte % CIPHER_LENGTH); i++)
	{
		OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
	}
	fwrite(OutEncryptedBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), OutEncryptedFile);
	free(Cipher);


	
	//Close files
	fclose(InDataFile);
	fclose(OutEncryptedFile);
	
	//Deallocate variables
	free(Key);
	free(Nonce);
	free(InDataBlock);
	free(OutEncryptedBlock);
	
	return 0;
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
static uint32_t find_size_file(char *Filename)
{
	FILE *InDataFile;
	uint32_t InFileSizeByte = 0;
	uint8_t *TrashPointer;
	
	InDataFile = fopen(Filename, "rb");
	if(InDataFile == NULL)
	{
		printf("Error: could not open \"%s\" file.\n", Filename);
		exit(EXIT_FAILURE);
	}
	
	TrashPointer = (uint8_t *)malloc(sizeof(uint8_t));
	while(1)
	{
		fread(TrashPointer, sizeof(uint8_t), 1, InDataFile);
		if(feof(InDataFile))
			break;
		InFileSizeByte++;
	}
	
	free(TrashPointer);
	fclose(InDataFile);
	
	return InFileSizeByte;
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
	strcpy(OutputFilename, InputFilename);
	strcat(OutputFilename, ".cha20");
	
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
	
	return OutputFilename;
}











