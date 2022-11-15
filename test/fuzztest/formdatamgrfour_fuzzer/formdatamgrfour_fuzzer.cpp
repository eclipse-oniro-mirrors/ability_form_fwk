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

#define private public
#define protected public
#include "form_data_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormDataMgr formDataMgr;
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    std::vector<int64_t> removedFormIds;
    removedFormIds.emplace_back(formId);
    formDataMgr.DeleteFormsByUserId(userId, removedFormIds);
    formDataMgr.ClearFormRecords();
    int32_t callingUid = static_cast<int32_t>(GetU32Data(data));
    std::set<int64_t> matchedFormIds;
    matchedFormIds.insert(formId);
    std::string bundleName(data, size);
    std::string abilityName(data, size);
    FormIdKey formIdKey(bundleName, abilityName);
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    noHostTempFormsMap.emplace(formIdKey, matchedFormIds);
    std::map<int64_t, bool> foundFormsMap;
    bool flag = *data % ENABLE;
    foundFormsMap.emplace(formId, flag);
    formDataMgr.GetNoHostInvalidTempForms(userId, callingUid, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    formDataMgr.BatchDeleteNoHostTempForms(callingUid, noHostTempFormsMap, foundFormsMap);
    formDataMgr.DeleteInvalidTempForms(userId, callingUid, matchedFormIds, foundFormsMap);
    formDataMgr.DeleteInvalidPublishForms(userId, bundleName, matchedFormIds);
    formDataMgr.ClearHostDataByInvalidForms(callingUid, foundFormsMap);
    Want want;
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    formDataMgr.AddRequestPublishFormInfo(formId, want, formProviderData);
    formDataMgr.RemoveRequestPublishFormInfo(formId);
    formDataMgr.IsRequestPublishForm(formId);
    formDataMgr.GetRequestPublishFormInfo(formId, want, formProviderData);
    FormRecord record;
    BundlePackInfo bundlePackInfo;
    AbilityFormInfo abilityFormInfo;
    formDataMgr.GetPackageForm(record, bundlePackInfo, abilityFormInfo);
    formDataMgr.IsSameForm(record, abilityFormInfo);
    bool isNeedFreeInstall = *data % ENABLE;
    formDataMgr.SetRecordNeedFreeInstall(formId, isNeedFreeInstall);
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

