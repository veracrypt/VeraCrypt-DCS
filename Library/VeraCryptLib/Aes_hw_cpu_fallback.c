/** @file
ARM64 software fallback for VeraCrypt AES hardware entry points.

Copyright (c) 2026. VeraCrypt, Mounir IDRASSI

This program and the accompanying materials
are licensed and made available under the terms and conditions
of the Apache License, Version 2.0.

The full text of the license may be found at
https://opensource.org/licenses/Apache-2.0
**/

#include "crypto/Aes_hw_cpu.h"
#include "crypto/Aes.h"

#if !defined(CRYPTOPP_DISABLE_ARM_AES)
#error The ARM64 software fallback must not be linked when ARM AES is enabled.
#endif

void aes_hw_cpu_decrypt (const uint8 *ks, uint8 *data)
{
	aes_decrypt (data, data, (const aes_decrypt_ctx *) ks);
}

void VC_CDECL aes_hw_cpu_decrypt_32_blocks (const uint8 *ks, uint8 *data)
{
	int i;

	for (i = 0; i < 32; ++i)
	{
		aes_decrypt (data, data, (const aes_decrypt_ctx *) ks);
		data += AES_BLOCK_SIZE;
	}
}

void aes_hw_cpu_encrypt (const uint8 *ks, uint8 *data)
{
	aes_encrypt (data, data, (const aes_encrypt_ctx *) ks);
}

void VC_CDECL aes_hw_cpu_encrypt_32_blocks (const uint8 *ks, uint8 *data)
{
	int i;

	for (i = 0; i < 32; ++i)
	{
		aes_encrypt (data, data, (const aes_encrypt_ctx *) ks);
		data += AES_BLOCK_SIZE;
	}
}
