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

#include "signtools_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <fstream>

#define private public
#define protected public
#include "feature/param_update/sign_tools.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    std::string pubKeyPath = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string signPath = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string digestPath = fdp->ConsumeRandomLengthString(MAX_LENGTH);

    SignTools::VerifyFileSign(pubKeyPath, signPath, digestPath);

    std::string fpath = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    auto [err, digest] = SignTools::CalcFileSha256Digest(fpath);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
