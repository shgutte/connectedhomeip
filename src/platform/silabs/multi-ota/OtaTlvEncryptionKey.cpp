#include "OtaTlvEncryptionKey.h"
#include <lib/support/CodeUtils.h>
#include <platform/silabs/SilabsConfig.h>
#include <stdio.h>
#include <string.h>

#ifndef USE_MBDTLS
#include <sl_psa_crypto.h>
#else
#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"
#include "mbedtls/aes.h"
#endif

namespace chip {
namespace DeviceLayer {
namespace Silabs {
namespace OtaTlvEncryptionKey {

uint8_t sValue[128] = { 0 };
size_t sSize = 0;
uint8_t mKey[16]; // Add a member variable to store the key

using SilabsConfig = chip::DeviceLayer::Internal::SilabsConfig;

#ifdef USE_MBDTLS
void UpdateIV(unsigned char *iv, uint32_t &mIVOffset)
{
    // Combine the last four bytes of the IV into a single 32-bit integer
    uint32_t u32IVCount = (static_cast<uint32_t>(iv[12]) << 24) |
                          (static_cast<uint32_t>(iv[13]) << 16) |
                          (static_cast<uint32_t>(iv[14]) << 8) |
                          iv[15];
    
    // Increment the IV count by the offset divided by 16
    u32IVCount += (mIVOffset >> 4);

    // Split the 32-bit integer back into the last four bytes of the IV
    iv[12] = static_cast<uint8_t>((u32IVCount >> 24) & 0xff);
    iv[13] = static_cast<uint8_t>((u32IVCount >> 16) & 0xff);
    iv[14] = static_cast<uint8_t>((u32IVCount >> 8) & 0xff);
    iv[15] = static_cast<uint8_t>(u32IVCount & 0xff);
}

CHIP_ERROR Decrypt(MutableByteSpan &block, uint32_t &mIVOffset)
{
    unsigned char *input = block.data();
    size_t input_len = block.size();
    unsigned char *output = new unsigned char[input_len]; // Allocate memory for the output
    constexpr uint8_t initial_iv[] = { 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x00, 0x00, 0x00 };
    uint8_t iv[16];
    mbedtls_aes_context aes;
    unsigned char stream_block[16];
    size_t nc_off = 0;
    size_t offset = 0;

    mbedtls_aes_init(&aes); // Initialize the AES context

    // Set the AES decryption key
    if (mbedtls_aes_setkey_dec(&aes, key, 128U) != 0)
    {
        mbedtls_aes_free(&aes);
        delete[] output; // Free allocated memory
        return CHIP_ERROR_INTERNAL;
    }

    // Copy the initial IV to the mutable iv array
    memcpy(iv, initial_iv, sizeof(initial_iv));
    UpdateIV(iv, mIVOffset); // Update the IV with the offset

    // Process the input in 16-byte blocks
    while (offset + 16 <= input_len)
    {
        // Decrypt the current block
        if (mbedtls_aes_crypt_ctr(&aes, 16, &nc_off, iv, stream_block, input + offset, output + offset) != 0)
        {
            mbedtls_aes_free(&aes);
            delete[] output; // Free allocated memory
            return CHIP_ERROR_INTERNAL;
        }

        // Increment the IV for the next block
        mIVOffset += 16;
        UpdateIV(iv, mIVOffset);

        offset += 16; // Increment the buffer offset
    }

    // Decrypt any remaining bytes
    if (offset < input_len)
    {
        if (mbedtls_aes_crypt_ctr(&aes, input_len - offset, &nc_off, iv, stream_block, input + offset, output + offset) != 0)
        {
            mbedtls_aes_free(&aes);
            delete[] output; // Free allocated memory
            return CHIP_ERROR_INTERNAL;
        }
    }

    // Copy the decrypted output back to the block
    memcpy(block.data(), output, input_len);
    delete[] output; // Free allocated memory
    mbedtls_aes_free(&aes); // Free the AES context

    return CHIP_NO_ERROR;
}

#else

int destroyAESKey(uint32_t kid)
{
    psa_key_handle_t key_handle;

    int err = psa_open_key(kid, &key_handle);
    if (err)
    {
        psa_close_key(kid);
    }
    else
    {
        err = psa_destroy_key(kid);
    }
    return err;
}

CHIP_ERROR OtaTlvEncryptionKey::Import(const uint8_t * key, size_t key_len)
{
    destroyAESKey(mId);

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_key_id_t key_id;
    psa_set_key_id(&attributes, mId);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS)
    {
        printf("Failed to import a key error:%ld\n", status);
        return CHIP_ERROR_INTERNAL;
    }

    return CHIP_NO_ERROR;
}


CHIP_ERROR OtaTlvEncryptionKey::Decrypt(MutableByteSpan & block, uint32_t & mIVOffset)
{
    constexpr uint8_t au8Iv[] = { 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x00, 0x00, 0x00, 0x00 };
    uint8_t iv[16];
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    psa_status_t status;
    uint8_t output[PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES)];
    size_t output_len;
    size_t total_output;
    uint32_t u32IVCount;
    uint32_t Offset = 0;

    memcpy(iv, au8Iv, sizeof(au8Iv));

    u32IVCount = (((uint32_t) iv[12]) << 24) | (((uint32_t) iv[13]) << 16) | (((uint32_t) iv[14]) << 8) | (iv[15]);
    u32IVCount += (mIVOffset >> 4);

    iv[12] = (uint8_t) ((u32IVCount >> 24) & 0xff);
    iv[13] = (uint8_t) ((u32IVCount >> 16) & 0xff);
    iv[14] = (uint8_t) ((u32IVCount >> 8) & 0xff);
    iv[15] = (uint8_t) (u32IVCount & 0xff);

    while (Offset + 16 <= block.size())
    {
        status = psa_cipher_decrypt_setup(&operation, static_cast<psa_key_id_t>(mId), PSA_ALG_CTR);
        if (status != PSA_SUCCESS)
        {
            printf("Failed to begin cipher operation error:%ld\n", status);
            return CHIP_ERROR_INTERNAL;
        }

        status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
        if (status != PSA_SUCCESS)
        {
            printf("Failed to set IV error:%ld\n", status);
            return CHIP_ERROR_INTERNAL;
        }

        status = psa_cipher_update(&operation, static_cast<uint8_t *>(&block[Offset]), 16, output, sizeof(output), &output_len);
        if (status != PSA_SUCCESS)
        {
            printf("Failed to update cipher operation error:%ld\n", status);
            return CHIP_ERROR_INTERNAL;
        }

        /* increment the IV for the next block  */
        u32IVCount++;

        iv[12] = (uint8_t) ((u32IVCount >> 24) & 0xff);
        iv[13] = (uint8_t) ((u32IVCount >> 16) & 0xff);
        iv[14] = (uint8_t) ((u32IVCount >> 8) & 0xff);
        iv[15] = (uint8_t) (u32IVCount & 0xff);

        memcpy((void *) &block[Offset], &output, output_len);

        Offset += 16; /* increment the buffer offset */
        mIVOffset += 16;
        status = psa_cipher_finish(&operation, output + total_output, sizeof(output) - total_output, &total_output);
        if (status != PSA_SUCCESS)
        {
            printf("Failed to finish cipher operation\n");
            return CHIP_ERROR_INTERNAL;
        }
    }

    printf("Decrypted ciphertext\n");

    psa_cipher_abort(&operation);

    return CHIP_NO_ERROR;
}
#endif // SL_WIFI
} // namespace OtaTlvEncryptionKey
} // namespace Silabs
} // namespace DeviceLayer
} // namespace chip
