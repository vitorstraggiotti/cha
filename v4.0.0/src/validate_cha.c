/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **
	Program to validate chacha cypher using test vectors
	
	Author: Vitor Henrique Andrade Helfensteller Straggiotti Silva
	Start date: 29/05/2022 (DD/MM/YYYY)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Chacha test vectors:
https://datatracker.ietf.org/doc/html/draft-strombergson-chacha-test-vectors-00
   Chacha algorithm:
https://datatracker.ietf.org/doc/html/rfc7539 */

#include <stdio.h>
#include <stdint.h>

#include "validate_cha.h"
#include "../include/chacha20.h"

uint64_t array_uint8_to_uint64(uint8_t *ByteArray);
uint8_t keystream_is_equal(uint8_t *Array1, uint8_t *Array2);

int main(void)
{
	uint8_t  Keystream[BYTES_PER_BLOCK];
	uint8_t  *Key256;
	uint8_t  *Key128;
	uint64_t BlockNum;
	uint64_t Nonce;
	uint32_t Rounds;

	/* ====================== Testing local functions =========================== */
	uint8_t test1[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	uint64_t test1_64bit = 0;
	test1_64bit = array_uint8_to_uint64(test1);
	printf("\nuint8_t array: ");
	for (int i = 0; i < 8; i++)
	{
		printf("%.2x ", test1[i]);
	}
	printf("\nArray converted to uint64_t: %lx\n\n", test1_64bit);

	uint8_t TestBlock1[BYTES_PER_BLOCK] =
	{
		0xe2, 0x8a, 0x5f, 0xa4, 0xa6, 0x7f, 0x8c, 0x5d,
		0xef, 0xed, 0x3e, 0x6f, 0xb7, 0x30, 0x34, 0x86,
		0xaa, 0x84, 0x27, 0xd3, 0x14, 0x19, 0xa7, 0x29,
		0x57, 0x2d, 0x77, 0x79, 0x53, 0x49, 0x11, 0x20,
		0xb6, 0x4a, 0xb8, 0xe7, 0x2b, 0x8d, 0xeb, 0x85,
		0xcd, 0x6a, 0xea, 0x7c, 0xb6, 0x08, 0x9a, 0x10,
		0x18, 0x24, 0xbe, 0xeb, 0x08, 0x81, 0x4a, 0x42,
		0x8a, 0xab, 0x1f, 0xa2, 0xc8, 0x16, 0x08, 0x1b
    };
    
	uint8_t TestBlock2[BYTES_PER_BLOCK] =
	{
		0x8a, 0x26, 0xaf, 0x44, 0x8a, 0x1b, 0xa9, 0x06,
		0x36, 0x8f, 0xd8, 0xc8, 0x38, 0x31, 0xc1, 0x8c,
		0xec, 0x8c, 0xed, 0x81, 0x1a, 0x02, 0x8e, 0x67,
		0x5b, 0x8d, 0x2b, 0xe8, 0xfc, 0xe0, 0x81, 0x16,
		0x5c, 0xea, 0xe9, 0xf1, 0xd1, 0xb7, 0xa9, 0x75,
		0x49, 0x77, 0x49, 0x48, 0x05, 0x69, 0xce, 0xb8,
		0x3d, 0xe6, 0xa0, 0xa5, 0x87, 0xd4, 0x98, 0x4f,
		0x19, 0x92, 0x5f, 0x5d, 0x33, 0x8e, 0x43, 0x0d  
	};

	printf("Test 1 of keystream_is_equal() ... ");
	if (keystream_is_equal(TestBlock1, TestBlock1))
	{
		printf("OK\n");
	}
	else
	{
		printf("FAIL\n");
	}

	printf("Test 2 of keystream_is_equal() ... ");
	if (keystream_is_equal(TestBlock1, TestBlock2))
	{
		printf("FAIL\n");
	} 
	else
	{
		printf("OK\n");
	}


	printf("\n\n");
	/*================================= Testing TC1 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 1 (TC1) ==========\n");
	printf("     ===============================================\n\n");
	
	Nonce = array_uint8_to_uint64(Nonce_64[TC1]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC1];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC1];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC1_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC1_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC2 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 2 (TC2) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC2]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC2];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC2];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC2_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC2_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC3 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 3 (TC3) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC3]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC3];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC3];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC3_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC3_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC4 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 4 (TC4) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC4]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC4];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC4];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC4_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC4_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC5 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 5 (TC5) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC2]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC5];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC5];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC5_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC5_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC7 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 7 (TC7) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC7]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC7];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC7];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC7_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC7_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	/*================================= Testing TC8 =========================*/
	printf("     ===============================================\n");
	printf("     ========== TEST VECTOR GROUP 8 (TC8) ==========\n");
	printf("     ===============================================\n\n");

	Nonce = array_uint8_to_uint64(Nonce_64[TC8]);
	
	/* 128 bits key */
	printf("++++++++++ 128 BIT KEYS ++++++++++\n\n");
	Key128 = Key_128[TC8];

		/* NEED TO WRITE VALIDATION FOR 128 BIT KEY */

	/* 256 bits key*/
	printf("++++++++++ 256 BIT KEYS ++++++++++\n\n");
	Key256 = Key_256[TC8];

	Rounds = 8;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_8 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_8 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_8][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 12;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_12 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_12 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_12][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");

	Rounds = 20;

	BlockNum = 0;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_20 on Block 0 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n");
	else
		printf("FAIL\n");

	BlockNum = 1;
	generate_chacha_cipher_key(Key256, BlockNum, Nonce, Rounds, Keystream);
	printf("  Test TC8_Key_256_Nonce_64_Rounds_20 on Block 1 ... ");
	if(keystream_is_equal(Keystream, KeystreamRef[TC8_Key_256_Nonce_64_Rounds_20][BlockNum]))
		printf("OK\n\n");
	else
		printf("FAIL\n\n");



    return 0;
}

/*===========================================================================*/
uint64_t array_uint8_to_uint64(uint8_t *ByteArray)
{
	uint64_t Result = 0;

	Result = ByteArray[0];
	for(uint8_t i = 1; i < 8; i++)
	{
		Result = (Result << 8) | ByteArray[i];
	}

	return Result;
}

/*---------------------------------------------------------------------------*/
uint8_t keystream_is_equal(uint8_t *Array1, uint8_t *Array2)
{
	for(uint8_t i = 0; i < BYTES_PER_BLOCK; i++)
	{
		if(Array1[i] != Array2[i])
			return 0;
	}

	return 1;
}