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
    OtaTlvEncryptionKey(uint32_t id = 0, const uint8_t * key, size_t key_len) {
        mId = (id > 0) ? id : kAES_KeyId_Default; 
        this->key = key;
        this->key_len = key_len;
    }
    ~OtaTlvEncryptionKey() = default;

    uint32_t GetId() { return mId; }
    CHIP_ERROR Import(const uint8_t * key, size_t key_len);
#ifdef USE_MBDTLS
    void UpdateIV(unsigned char *iv, uint32_t &mIVOffset);
    CHIP_ERROR Decrypt(MutableByteSpan &block, uint32_t &mIVOffset);
#else
    CHIP_ERROR Decrypt(MutableByteSpan & block, uint32_t & mIVOffset);
#endif
protected:
    const uint8_t * key;
    size_t key_len;
    uint32_t mId = 0;
};

} // namespace OtaTlvEncryptionKey
} // namespace Silabs
} // namespace DeviceLayer
} // namespace chip
