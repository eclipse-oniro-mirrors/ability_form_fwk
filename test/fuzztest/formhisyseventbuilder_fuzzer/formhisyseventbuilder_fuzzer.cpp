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

#include "formhisyseventbuilder_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_hisysevent_wrapper.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;

static std::string ConsumeKey(FuzzedDataProvider *fdp)
{
    return fdp->ConsumeRandomLengthString(MAX_LENGTH);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormHiSysEventBuilder builder;

    // InsertParam(key, int64_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<int64_t>());

    // InsertParam(key, uint64_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<uint64_t>());

    // InsertParam(key, int32_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<int32_t>());

    // InsertParam(key, uint32_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<uint32_t>());

    // InsertParam(key, int8_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<int8_t>());

    // InsertParam(key, uint8_t)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeIntegral<uint8_t>());

    // InsertParam(key, bool)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeBool());

    // InsertParam(key, float)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeFloatingPoint<float>());

    // InsertParam(key, double)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeFloatingPoint<double>());

    // InsertParam(key, const char *)
    std::string charStr = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    builder.InsertParam(ConsumeKey(fdp), charStr.c_str());

    // InsertParam(key, const std::string &)
    builder.InsertParam(ConsumeKey(fdp), fdp->ConsumeRandomLengthString(MAX_LENGTH));

    // InsertParam(key, const std::vector<int64_t> &)
    {
        std::vector<int64_t> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeIntegral<int64_t>());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<uint64_t> &)
    {
        std::vector<uint64_t> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeIntegral<uint64_t>());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<int32_t> &)
    {
        std::vector<int32_t> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeIntegral<int32_t>());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<uint32_t> &)
    {
        std::vector<uint32_t> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeIntegral<uint32_t>());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<uint8_t> &)
    {
        std::vector<uint8_t> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeIntegral<uint8_t>());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<bool> &)
    {
        std::vector<bool> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeBool());
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // InsertParam(key, const std::vector<std::string> &)
    {
        std::vector<std::string> vec;
        int32_t sz = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < sz; i++) {
            vec.push_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        }
        builder.InsertParam(ConsumeKey(fdp), vec);
    }

    // Test Write to exercise the final serialization path
    std::string domain = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string eventName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    builder.Write(domain, eventName, HISYSEVENT_BEHAVIOR);

    // Test Clear to exercise cleanup path
    builder.Clear();

    // Test with empty builder (edge case)
    FormHiSysEventBuilder emptyBuilder;
    emptyBuilder.Write(domain, eventName, HISYSEVENT_BEHAVIOR);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
