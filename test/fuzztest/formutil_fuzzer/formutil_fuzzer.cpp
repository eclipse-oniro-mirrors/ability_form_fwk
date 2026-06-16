/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/util/form_util.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int64_t udidHash = fdp->ConsumeIntegral<int64_t>();
    int64_t formId = FormUtil::GenerateFormId(udidHash);
    FormUtil::DeleteFormId(formId);

    int64_t formId2 = fdp->ConsumeIntegral<int64_t>();
    uint64_t udidHash2 = fdp->ConsumeIntegral<uint64_t>();
    FormUtil::PaddingUdidHash(formId2, udidHash2);
    
    int64_t &udidHashRef = udidHash;
    FormUtil::GenerateUdidHash(udidHashRef);

    FormUtil::GetCurrentNanosecond();
    FormUtil::GetCurrentMillisecond();
    FormUtil::GetCurrentSteadyClockMillseconds();

    struct tm timeStruct;
    timeStruct.tm_year = fdp->ConsumeIntegralInRange(0, 100);
    timeStruct.tm_mon = fdp->ConsumeIntegralInRange(0, 12);
    timeStruct.tm_mday = fdp->ConsumeIntegralInRange(0, 31);
    timeStruct.tm_hour = fdp->ConsumeIntegralInRange(0, 23);
    timeStruct.tm_min = fdp->ConsumeIntegralInRange(0, 59);
    timeStruct.tm_sec = fdp->ConsumeIntegralInRange(0, 59);
    FormUtil::GetMillisecondFromTm(timeStruct);

    FormUtil::GetCurrentAccountId();
    FormUtil::IsSACall();

    std::string permissionName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormUtil::VerifyCallingPermission(permissionName);

    std::string strInfo = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int64_t int64Value = fdp->ConsumeIntegral<int64_t>();
    FormUtil::ConvertStringToInt64(strInfo, int64Value);

    std::string strInfo2 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int radix = fdp->ConsumeIntegralInRange(2, 36);
    FormUtil::ConvertStringToInt(strInfo2, radix);

    std::string strInfo3 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int radix2 = fdp->ConsumeIntegralInRange(2, 36);
    FormUtil::ConvertStringToLongLong(strInfo3, radix2);

    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    FormUtil::IsActiveUser(userId);

    std::vector<int32_t> activeList;
    int32_t numActive = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numActive; i++) {
        activeList.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    FormUtil::GetActiveUsers(activeList);

    std::vector<int32_t> foregroundList;
    int32_t numForeground = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numForeground; i++) {
        foregroundList.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    FormUtil::GetForegroundUsers(foregroundList);

    int32_t callingUid = fdp->ConsumeIntegral<int32_t>();
    FormUtil::GetCallerUserId(callingUid);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
