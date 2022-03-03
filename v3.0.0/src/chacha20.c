/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Library for implementing chacha20 cipher
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "../include/chacha20.h"

//==============================================================================
//                         HELPER FUNCTIONS
//==============================================================================

static void quarter_round(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t *ChachaBlock)
{
	ChachaBlock[a] += ChachaBlock[b];
	ChachaBlock[d] ^= ChachaBlock[a];
	ChachaBlock[d] = (ChachaBlock[d] << 16) | (ChachaBlock[d] >> 16);

	ChachaBlock[c] += ChachaBlock[d];
	ChachaBlock[b] ^= ChachaBlock[c];
	ChachaBlock[b] = (ChachaBlock[b] << 12) | (ChachaBlock[b] >> 20);
	
	ChachaBlock[a] += ChachaBlock[b];
	ChachaBlock[d] ^= ChachaBlock[a];
	ChachaBlock[d] = (ChachaBlock[d] << 8) | (ChachaBlock[d] >> 24);
	
	ChachaBlock[c] += ChachaBlock[d];
	ChachaBlock[b] ^= ChachaBlock[c];
	ChachaBlock[b] = (ChachaBlock[b] << 7) | (ChachaBlock[b] >> 25);
	
}
/******************************************************************************/
static void shuffle_block(uint32_t *ChachaBlock)
{
	//Column shuffle
	quarter_round(0, 4, 8, 12, ChachaBlock);
	quarter_round(1, 5, 9, 13, ChachaBlock);
	quarter_round(2, 6, 10, 14, ChachaBlock);
	quarter_round(3, 7, 11, 15, ChachaBlock);
	
	//Diagonal shuffle
	quarter_round(0, 5, 10, 15, ChachaBlock);
	quarter_round(1, 6, 11, 12, ChachaBlock);
	quarter_round(2, 7, 8, 13, ChachaBlock);
	quarter_round(3, 4, 9, 14, ChachaBlock);
}
/******************************************************************************/
static void serialize(uint32_t *ChachaBlock, uint8_t *CipherStream)
{
	for(uint32_t i = 0; i < 64; i += 4)
	{
		CipherStream[i]   = (uint8_t)(ChachaBlock[i / 4] & 0x000000FF);
		CipherStream[i+1] = (uint8_t)((ChachaBlock[i / 4] >> 8) & 0x000000FF);
		CipherStream[i+2] = (uint8_t)((ChachaBlock[i / 4] >> 16) & 0x000000FF);
		CipherStream[i+3] = (uint8_t)(ChachaBlock[i / 4] >> 24);
	}
}
//==============================================================================
//                   MAIN FUNCTIONS
//==============================================================================
//(in) Key --> pointer to 8 bytes array used as key to generate the output cipher stream
//(in) Counter --> 8 byte value meant to start at 0 and be incremented by 1 on each call
//(in) Nonce --> 8 byte value used as "Number Used Once"
//(in) Rounds --> Number of chacha rounds to be performed. Is an even number. If odd number
//            is used it will be rounded to nearest smallest even number
//(out) OutCipher --> pointer to 64 bytes array of cipher to be XOR'ed with data
void generate_chacha_cipher_key(uint8_t *Key, uint64_t Counter, uint64_t Nonce, uint32_t Rounds, uint8_t *OutCipherStream)
{
	uint32_t ChachaBlock[16], WorkingChachaBlock[16];
	
	//Adding constants to chacha block
	ChachaBlock[0] = 0x61707865;
	ChachaBlock[1] = 0x3320646e;
	ChachaBlock[2] = 0x79622d32;
	ChachaBlock[3] = 0x6b206574;
	
	//Adding key to chacha block
	for(uint32_t i = 0; i < 32; i += 4)
	{
		ChachaBlock[(i / 4) + 4] =  (uint32_t)Key[i]           |
									((uint32_t)Key[i+1] << 8)  |
									((uint32_t)Key[i+2] << 16) |
									((uint32_t)Key[i+3] << 24);
	}
	
	//Adding counter to chacha block
	ChachaBlock[12] = (uint32_t)(Counter >> 32);
	ChachaBlock[13] = (uint32_t)Counter;
	
	//Adding nonce to chacha block
	ChachaBlock[14] = (uint32_t)(Nonce >> 32);
	ChachaBlock[15] = (uint32_t)Nonce;
	
	//Creating work copy of chacha block to be shuffled
	for(uint8_t i = 0; i < 16; i++)
	{
		WorkingChachaBlock[i] = ChachaBlock[i];
	}
	
	//Shuffling rounds and generating key block ---------------------------------
	for(uint32_t i = 0; i < Rounds/2; i++)
	{
		shuffle_block(WorkingChachaBlock);
	}
	for(uint32_t i = 0; i < 16; i++)
	{
		ChachaBlock[i] += WorkingChachaBlock[i];
	}
	
	//Serialize chacha block into cipher ---------------------------------------
	serialize(ChachaBlock, OutCipherStream);
	
}







