/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
	Library for implementing chacha20 cipher
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Date: 30/06/2021 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef CHACHA20_H
#define CHACHA20_H


//Return a 64byte cipher. 32byte key, 4byte counter, 12byte nonce
void chacha20_block(uint8_t *Key, uint32_t Counter, uint8_t *Nonce, uint8_t *OutCipher);

#endif
