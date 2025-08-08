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

#include "formdatamgrfour_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_data_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::vector<int64_t> removedFormIds;
    removedFormIds.emplace_back(formId);
    FormDataMgr::GetInstance().DeleteFormsByUserId(userId, removedFormIds);
    FormDataMgr::GetInstance().ClearFormRecords();
    int32_t callingUid = fdp->ConsumeIntegral<int32_t>();
    std::set<int64_t> matchedFormIds;
    matchedFormIds.insert(formId);
    std::string bundleName = fdp->ConsumeRandomLengthString();
    std::string abilityName = fdp->ConsumeRandomLengthString();
    FormIdKey formIdKey(bundleName, abilityName);
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    noHostTempFormsMap.emplace(formIdKey, matchedFormIds);
    std::map<int64_t, bool> foundFormsMap;
    bool flag = fdp->ConsumeBool();
    foundFormsMap.emplace(formId, flag);
    FormDataMgr::GetInstance().GetNoHostInvalidTempForms(userId,
        callingUid, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    FormDataMgr::GetInstance().BatchDeleteNoHostTempForms(callingUid, noHostTempFormsMap, foundFormsMap);
    FormDataMgr::GetInstance().DeleteInvalidTempForms(userId, callingUid, matchedFormIds, foundFormsMap);
    FormDataMgr::GetInstance().DeleteInvalidPublishForms(userId, bundleName, matchedFormIds);
    FormDataMgr::GetInstance().ClearHostDataByInvalidForms(callingUid, foundFormsMap);
    Want want;
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    FormDataMgr::GetInstance().AddRequestPublishFormInfo(formId, want, formProviderData);
    FormDataMgr::GetInstance().RemoveRequestPublishFormInfo(formId);
    FormDataMgr::GetInstance().IsRequestPublishForm(formId);
    FormDataMgr::GetInstance().GetRequestPublishFormInfo(formId, want, formProviderData);
    FormRecord record;
    BundlePackInfo bundlePackInfo;
    AbilityFormInfo abilityFormInfo;
    FormDataMgr::GetInstance().GetPackageForm(record, bundlePackInfo, abilityFormInfo);
    FormDataMgr::GetInstance().IsSameForm(record, abilityFormInfo);
    bool isNeedFreeInstall = fdp->ConsumeBool();
    FormDataMgr::GetInstance().SetRecordNeedFreeInstall(formId, isNeedFreeInstall);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
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

    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    free(ch);
    ch = nullptr;
    return 0;
}