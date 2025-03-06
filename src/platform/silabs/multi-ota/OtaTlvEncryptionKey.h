#pragma once

#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>
#include <platform/silabs/multi-ota/OTATlvProcessor.h>
#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

namespace chip {
namespace DeviceLayer {
namespace Silabs {
namespace OtaTlvEncryptionKey {

static constexpr uint32_t kAES_KeyId_Default = (PSA_KEY_ID_USER_MIN + 2);

class OtaTlvEncryptionKey
{
public:
    OtaTlvEncryptionKey(uint32_t id = 0) { mId = (id > 0) ? id : kAES_KeyId_Default; }
#ifdef SL_MBEDTLS_USE_TINYCRYPT
OtaTlvEncryptionKey(const uint8_t * key, size_t key_len) {
        mKey = key;
        mKeyLen = key_len;
    }
#endif // SL_MBEDTLS_USE_TINYCRYPT
~OtaTlvEncryptionKey() = default;

    uint32_t GetId() { return mId; }
    CHIP_ERROR Import(const uint8_t * key, size_t key_len);
#ifdef SL_MBEDTLS_USE_TINYCRYPT
    void UpdateIV(unsigned char *iv, uint32_t &mIVOffset);
#endif // SL_MBEDTLS_USE_TINYCRYPT
    CHIP_ERROR Decrypt(MutableByteSpan & block, uint32_t & mIVOffset);
protected:
uint32_t mId = 0;
#ifdef SL_MBEDTLS_USE_TINYCRYPT
    const uint8_t * mKey = nullptr;
    size_t mKeyLen = 0;
#endif // SL_MBEDTLS_USE_TINYCRYPT
};

} // namespace OtaTlvEncryptionKey
} // namespace Silabs
} // namespace DeviceLayer
} // namespace chip
