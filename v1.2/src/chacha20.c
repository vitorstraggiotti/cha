/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Library for implementing chacha20 cipher
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdint.h>
#include <stdlib.h>
#include "../include/chacha20.h"

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
static void serialize(uint32_t *ChachaBlock, uint8_t *Cipher)
{
	for(uint32_t i = 0; i < 64; i += 4)
	{
		Cipher[i]   = (uint8_t)(ChachaBlock[i / 4] & 0x000000FF);
		Cipher[i+1] = (uint8_t)((ChachaBlock[i / 4] >> 8) & 0x000000FF);
		Cipher[i+2] = (uint8_t)((ChachaBlock[i / 4] >> 16) & 0x000000FF);
		Cipher[i+3] = (uint8_t)(ChachaBlock[i / 4] >> 24);
	}
}
/******************************************************************************/
void chacha20_block(uint8_t *Key, uint32_t Counter, uint8_t *Nonce, uint8_t *OutCipher)
{
	uint32_t ChachaBlock[16], WorkingChachaBlock[16];
	
	//Constants
	ChachaBlock[0] = 0x61707865; WorkingChachaBlock[0] = 0x61707865;
	ChachaBlock[1] = 0x3320646e; WorkingChachaBlock[1] = 0x3320646e;
	ChachaBlock[2] = 0x79622d32; WorkingChachaBlock[2] = 0x79622d32;
	ChachaBlock[3] = 0x6b206574; WorkingChachaBlock[3] = 0x6b206574;
	//Key
	for(uint32_t i = 0; i < 32; i += 4)
	{
		ChachaBlock[(i / 4) + 4] =  (uint32_t)Key[i]           |
									((uint32_t)Key[i+1] << 8)  |
									((uint32_t)Key[i+2] << 16) |
									((uint32_t)Key[i+3] << 24);

		WorkingChachaBlock[(i / 4) + 4] = ChachaBlock[(i / 4) + 4];
	}
	//Counter
	ChachaBlock[12] = Counter; WorkingChachaBlock[12] = Counter;
	//Nonce
		for(uint32_t i = 0; i < 12; i += 4)
	{
		ChachaBlock[(i / 4) + 13] = (uint32_t)Nonce[i]           |
									((uint32_t)Nonce[i+1] << 8)  |
									((uint32_t)Nonce[i+2] << 16) |
									((uint32_t)Nonce[i+3] << 24);

		WorkingChachaBlock[(i / 4) + 13] = ChachaBlock[(i / 4) + 13];
	}
	
	//Shuffling rounds ---------------------------------------------------------
	for(uint32_t i = 0; i < 10; i++)
	{
		shuffle_block(WorkingChachaBlock);
	}
	
	for(uint32_t i = 0; i < 16; i++)
	{
		ChachaBlock[i] += WorkingChachaBlock[i];
	}
	
	//Serialize chacha block into cipher ---------------------------------------
	serialize(ChachaBlock, OutCipher);
	
}







