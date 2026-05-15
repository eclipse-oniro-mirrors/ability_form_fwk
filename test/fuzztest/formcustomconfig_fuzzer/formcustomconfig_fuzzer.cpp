/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "formcustomconfig_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_custom_config.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    // Fuzz Marshalling
    FormCustomConfig config;
    config.bundleName = std::string(data, std::min(size, static_cast<size_t>(32)));
    config.moduleName = std::string(data, std::min(size, static_cast<size_t>(16)));
    config.abilityName = std::string(data, std::min(size, static_cast<size_t>(16)));
    config.formName = std::string(data, std::min(size, static_cast<size_t>(16)));
    config.relatedBundleName = std::string(data, std::min(size, static_cast<size_t>(32)));
    config.isShowInFormCenter = (data[0] % 2) == 0;
    config.isRepeatAdditionSupported = (data[0] % 2) == 1;

    Parcel parcel;
    config.Marshalling(parcel);

    // Fuzz Unmarshalling with fuzz data parcel
    Parcel fuzzParcel;
    fuzzParcel.WriteBuffer(data, size);
    fuzzParcel.RewindRead(0);
    FormCustomConfig destConfig;
    destConfig.ReadFromParcel(fuzzParcel);

    // Fuzz Unmarshalling static method
    Parcel fuzzParcel2;
    fuzzParcel2.WriteBuffer(data, size);
    fuzzParcel2.RewindRead(0);
    FormCustomConfig *result = FormCustomConfig::Unmarshalling(fuzzParcel2);
    if (result != nullptr) {
        delete result;
    }

    // Fuzz round trip
    Parcel roundParcel;
    if (config.Marshalling(roundParcel)) {
        FormCustomConfig *roundResult = FormCustomConfig::Unmarshalling(roundParcel);
        if (roundResult != nullptr) {
            delete roundResult;
        }
    }

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }
    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
