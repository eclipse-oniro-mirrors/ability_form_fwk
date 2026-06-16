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

#include "paramreader_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "form_constants.h"
#define private public
#define protected public
#include "feature/param_update/param_reader.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_NUM = 15;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    std::string path1 = fdp->ConsumeRandomLengthString(MAX_NUM);
    std::string path2 = fdp->ConsumeRandomLengthString(MAX_NUM);
    ParamReader::GetInstance().GetPathVersion(Constants::FORM_MGR_CONFIG_DIR);
    ParamReader::GetInstance().VerifyCertSfFile();
    ParamReader::GetInstance().VerifyParamFile(path1);
    ParamReader::GetInstance().GetParamInfoStr(path2);
    ParamReader::GetInstance().GetManifestSha256Digest();

    std::string fileName = fdp->ConsumeRandomLengthString(MAX_NUM);
    std::string fileName1 = fdp->ConsumeRandomLengthString(MAX_NUM);
    ParamReader::GetInstance().GetSha256Digest(fileName);
    ParamReader::GetInstance().CalcFileSha256Digest(fileName1);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}