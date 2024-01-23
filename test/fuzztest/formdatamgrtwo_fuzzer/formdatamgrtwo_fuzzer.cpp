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

#include "formdatamgrtwo_fuzzer.h"

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
    FormHostRecord record;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    std::vector<int64_t> recordTempForms;
    recordTempForms.emplace_back(formId);
    formDataMgr.HandleHostDiedForTempForms(record, recordTempForms);
    formDataMgr.PaddingUdidHash(formId);
    formDataMgr.GenerateFormId();
    formDataMgr.GenerateUdidHash();
    formDataMgr.GetUdidHash();
    int64_t udidHash = static_cast<int64_t>(GetU32Data(data));
    formDataMgr.SetUdidHash(udidHash);
    sptr<IRemoteObject> callerToken = nullptr;
    formDataMgr.GetMatchedHostClient(callerToken, record);
    bool needRefresh = *data % ENABLE;
    formDataMgr.SetNeedRefresh(formId, needRefresh);
    bool countTimerRefresh = *data % ENABLE;
    formDataMgr.SetCountTimerRefresh(formId, countTimerRefresh);
    FormRecord records;
    std::vector<FormInfo> targetForms;
    FormInfo updatedForm;
    targetForms.emplace_back(updatedForm);
    formDataMgr.GetUpdatedForm(records, targetForms, updatedForm);
    bool enableUpdate = *data % ENABLE;
    formDataMgr.SetEnableUpdate(formId, enableUpdate);
    long updateDuration = static_cast<long>(GetU32Data(data));
    int updateAtHour = static_cast<int>(GetU32Data(data));
    int updateAtMin = static_cast<int>(GetU32Data(data));
    formDataMgr.SetUpdateInfo(formId, enableUpdate, updateDuration, updateAtHour, updateAtMin);
    formDataMgr.IsSameForm(records, updatedForm);
    std::string bundleName(data, size);
    std::set<int64_t> removedForms;
    removedForms.insert(formId);
    formDataMgr.CleanRemovedFormRecords(bundleName, removedForms);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formDataMgr.CleanRemovedTempFormRecords(bundleName, userId, removedForms);
    formDataMgr.GetReCreateFormRecordsByBundleName(bundleName, removedForms);
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

