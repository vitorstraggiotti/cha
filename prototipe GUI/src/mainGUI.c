/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Data encryption software with GUI and using chacha20 chiper
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 23/11/2021 (DD/MM/YYYY)
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
#include <gtk/gtk.h>	//functions for graphical user interface

#include "../include/chacha20.h"	//generate cipher block
#include "../include/sha256.h"		//generate hash digest

//flag to compile with debug code
#define DEBUG  0

//Encryption/decryption constants (bytes)
#define MAX_PASSWORD_LENGTH		500
#define CIPHER_LENGTH			64
#define DATA_BLOCK_SIZE			CIPHER_LENGTH
#define KEY_LENGTH				32

//Passwords lengths for diferent color characters
#define SMALL_PASSWORD			8
#define MEDIUM_PASSWORD			20

//ANSI scape codes
#define RED_CHAR				"\033[91m"
#define YELLOW_CHAR				"\033[93m"
#define GREEN_CHAR				"\033[92m"
#define RESET_COLOR				"\033[0m"
#define RED_BG					"\033[101m"

//Progress bar info
#define PROG_BAR_SIZE		50
#define PROG_BAR_PRECISION  1

//ASCII printable values limits
#define LOW_PRINT_ASCII		0x20
#define HIGH_PRINT_ASCII	0x7E

// Global variables ------------------------------------------------------------
char		*InFilePath = NULL;	//Path to the input file

uint8_t		*Password = NULL;		//Password from user to be transformed into key
uint32_t	PasswordLength = 0;

// Helper functions ------------------------------------------------------------
static FILE *open_read_file(char *Filename);
static FILE *open_write_file(char *Filename);
//Create the encrypted output filename by appending ".cha20" extension to input filename
static char *create_encrypted_out_filename(char *InputFilename);
//test for ".cha20" extension. Return 1 if true
static uint8_t input_is_encrypted(char *InputFilename);
//Create the decrypted output filename by removing ".cha20" extension of input filename
static char *create_decrypted_out_filename(char *InputFilename);
static uint64_t filesize(const char *Filename);
//Return a null terminated pointer to char containing user password
static uint8_t *get_password(uint32_t *PasswordLength);
// Encrypt and decrypt files
void cryptcha(uint32_t Rounds);

// Main functions --------------------------------------------------------------

// Callback functions ----------------------------------------------------------
void destroy_main_window(GtkWidget *widget, gpointer data)
{
	gtk_main_quit();
}

void button_select_file(GtkWidget *widget, gpointer data)
{
	GtkBuilder	*Builder = (GtkBuilder *)data;
	GtkWidget	*DialogFileChoose = GTK_WIDGET(gtk_builder_get_object(Builder, "DialogFileChoose"));
	
	gtk_widget_show_all(DialogFileChoose);
}

void button_cancel_file_choose(GtkWidget *widget, gpointer data)
{
	GtkBuilder	*Builder = (GtkBuilder *)data;
	GtkWidget	*DialogFileChoose = GTK_WIDGET(gtk_builder_get_object(Builder, "DialogFileChoose"));
	GtkWidget	*LabelFilePathPrint = GTK_WIDGET(gtk_builder_get_object(Builder, "LabelFilePathPrint"));
	
	gtk_widget_hide(DialogFileChoose);
	gtk_label_set_text(GTK_LABEL(LabelFilePathPrint), (const gchar *)"arquivo não selecionado");
	InFilePath = NULL;
}

void button_ok_file_choose(GtkWidget *widget, gpointer data)
{
	GtkBuilder	*Builder = (GtkBuilder *)data;
	GtkWidget	*DialogFileChoose = GTK_WIDGET(gtk_builder_get_object(Builder, "DialogFileChoose"));
	GtkWidget	*LabelFilePathPrint = GTK_WIDGET(gtk_builder_get_object(Builder, "LabelFilePathPrint"));
	
	gtk_widget_hide(DialogFileChoose);
	InFilePath = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(DialogFileChoose));
	gtk_label_set_text(GTK_LABEL(LabelFilePathPrint), InFilePath);
}

void button_start_crypt(GtkWidget *widget, gpointer data)
{
	GtkBuilder	*Builder = (GtkBuilder *)data;
	GtkWidget	*EntryPassword = GTK_WIDGET(gtk_builder_get_object(Builder, "EntryPassword"));
	GtkWidget	*LabelInfoOutput = GTK_WIDGET(gtk_builder_get_object(Builder, "LabelInfoOutput"));
	
	// Get password and password length
	Password = gtk_entry_get_text(GTK_ENTRY(EntryPassword));
	PasswordLength = 0;
	for(uint8_t i = 0;; i++)
	{
		if(Password[i] == '\0')
			break;
		PasswordLength++;
	}
	
	// Check for valid inputs
	if(InFilePath == NULL)
	{
		gtk_label_set_text(GTK_LABEL(LabelInfoOutput), (const gchar *)"Error: No file selected for encryption/decryption !!");
		return;
	}
	else if(PasswordLength == 0)
	{
		gtk_label_set_text(GTK_LABEL(LabelInfoOutput), (const gchar *)"Error: No password entered !!");
		return;
	}
	
	gtk_label_set_text(GTK_LABEL(LabelInfoOutput), (const gchar *)"Running encryption/decryption");
	
	cryptcha(20);
	
	gtk_label_set_text(GTK_LABEL(LabelInfoOutput), (const gchar *)"Finished !");
}


int main(int argc, char *argv[])
{	
	GtkBuilder	*Builder;
	
	GtkWidget	*MainWindow;	
	
	gtk_init(&argc, &argv);
	Builder = gtk_builder_new_from_file("interface.glade");
	gtk_builder_add_callback_symbols(Builder,
										(const gchar *)"on_MainWindow_destroy", G_CALLBACK(destroy_main_window),
										(const gchar *)"on_ButtonSelectFile_clicked", G_CALLBACK(button_select_file),
										(const gchar *)"on_ButtonStartCrypt_clicked", G_CALLBACK(button_start_crypt),
										(const gchar *)"on_ButtonCancelFileChoose_clicked", G_CALLBACK(button_cancel_file_choose),
										(const gchar *)"on_ButtonOkFileChoose_clicked", G_CALLBACK(button_ok_file_choose), NULL);
	gtk_builder_connect_signals(Builder, (gpointer *)Builder);
	
	MainWindow = GTK_WIDGET(gtk_builder_get_object(Builder, "MainWindow"));
	
	gtk_widget_show_all(MainWindow);
	
	gtk_main();	
	
	//Geting user input --------------------------------------------------------
	// Password			--> uint8*
	// PasswordLength	--> uint32
//	#error "aquire user password"
	
	// InFilePath		--> char*
//	#error "aquire input file path"
	
		
	return 0;
}
//==============================================================================
//		HELPER FUNCTIONS
//==============================================================================
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
	
	for(uint32_t i = 0; i < (NumChar + 1); i++)
	{
		if(i == NumChar) //if in the last char of InputFilename
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
/******************************************************************************/
static uint64_t filesize(const char *Filename)
{
	struct stat Status;
	
	stat(Filename, &Status);
	
	return Status.st_size;
}
/******************************************************************************/
//Return a null terminated pointer to char containing user password
static uint8_t *get_password(uint32_t *PassLength)
{
	struct termios OldTerminal, NewTerminal;	//terminal info

	uint8_t		*Password;
	uint32_t	PasswordLength = 0;	//size of user password
	uint8_t		TmpChar = 0;		//Temporary char to use on password acquisition
	
	//Allocating and erasing memory for password
	Password = (uint8_t *)malloc(MAX_PASSWORD_LENGTH * sizeof(uint8_t));
	for(uint32_t i = 0; i < MAX_PASSWORD_LENGTH; i++)
	{
		Password[i] = '\0';
	}
	
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
			for(int32_t i = 0; i < PasswordLength; i++)
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
	
	return Password;
}
/******************************************************************************/
// Encrypt and decrypt files
// Rounds --> number of chacha rounds to generate cipher stream
void cryptcha(uint32_t Rounds)
{
	uint64_t	InFileSizeByte = 0;			//Input filesize in bytes
	uint8_t		*Key = NULL;			//32 byte key for chacha20 cipher
	uint8_t		Cipher[CIPHER_LENGTH];	//64 byte chacha20 block to be XOR'ed with data
	
	uint64_t	Nonce = 0;				//8 byte "number used once" for chacha20
	uint64_t	BlockCounter = 0;		//8 byte block counter for chacha20 cipher
	
	uint8_t 	InDataBlock[DATA_BLOCK_SIZE];	//Data block from file to be encrypted
	uint8_t 	OutEncryptedBlock[DATA_BLOCK_SIZE]; //Encrypted data to be saved into a file
	
	char		*OutputFilename;

	FILE *InDataFile, *OutEncryptedFile;
	
	//Find input filesize
	InFileSizeByte = filesize(InFilePath);
	
	//Open file to encrypt on read only mode
	InDataFile = open_read_file(InFilePath);
	
	//Creating encrypted/decrypted output filename	
	if(input_is_encrypted(InFilePath))
	{
		OutputFilename = create_decrypted_out_filename(InFilePath);
	}
	else
	{
		OutputFilename = create_encrypted_out_filename(InFilePath);
	}
	
	OutEncryptedFile = open_write_file(OutputFilename);
	free(OutputFilename);	

	//Allocating and initialising cryptographic variables ----------------------
	Key = sha256_data(Password, (uint64_t)PasswordLength, NOT_VERBOSE);

	for(uint8_t i = 0; i <= 24; i += 8)
	{
		Nonce ^= (((uint64_t)Key[i])   << 56) |
				 (((uint64_t)Key[i+1]) << 48) |
				 (((uint64_t)Key[i+2]) << 40) |
				 (((uint64_t)Key[i+3]) << 32) |
				 (((uint64_t)Key[i+4]) << 24) |
				 (((uint64_t)Key[i+5]) << 16) |
				 (((uint64_t)Key[i+6]) << 8) |
				 ((uint64_t)Key[i+7]);
	}


	//Encryption routine -------------------------------------------------------	
	//Encryption on full size blocks (64 bytes)
	BlockCounter = 0;
	for(uint64_t Block = 0; Block < (InFileSizeByte / CIPHER_LENGTH); Block++)
	{
		fread(InDataBlock, sizeof(uint8_t), CIPHER_LENGTH, InDataFile);
		BlockCounter++;

		generate_chacha_cipher(Key, BlockCounter, Nonce, Rounds, Cipher);

		for(uint32_t i = 0; i < CIPHER_LENGTH; i++)
		{
			OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
		}
		fwrite(OutEncryptedBlock, sizeof(uint8_t), CIPHER_LENGTH, OutEncryptedFile);
	}
	
	//Encryption on last partial size block
	if((InFileSizeByte % CIPHER_LENGTH) != 0)
	{
		fread(InDataBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), InDataFile);
		BlockCounter++;

		generate_chacha_cipher(Key, BlockCounter, Nonce, Rounds, Cipher);

		for(uint32_t i = 0; i < (InFileSizeByte % CIPHER_LENGTH); i++)
		{
			OutEncryptedBlock[i] = Cipher[i] ^ InDataBlock[i];
		}
		fwrite(OutEncryptedBlock, sizeof(uint8_t), (InFileSizeByte % CIPHER_LENGTH), OutEncryptedFile);
	}


	//Close files
	fclose(InDataFile);
	fclose(OutEncryptedFile);

	//Destroy key and deallocate
	for(uint8_t i = 0; i < KEY_LENGTH; i++)
		Key[i] = 0x0;
	free(Key);

}
