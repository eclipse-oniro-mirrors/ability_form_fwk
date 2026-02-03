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

#include "formdatamgrthree_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "data_center/form_data_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
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
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    bool versionUpgrade = *data % ENABLE;
    formDataMgr.SetVersionUpgrade(formId, versionUpgrade);
    FormRecord formRecord;
    formDataMgr.UpdateHostForm(formId, formRecord);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    bool flag = *data % ENABLE;
    bool isOnlyEnableUpdate = *data % ENABLE;
    FormHostRecord formHostRecord;
    std::vector<int64_t> refreshForms;
    refreshForms.emplace_back(formId);
    formDataMgr.HandleUpdateHostFormFlag(formIds, flag, isOnlyEnableUpdate, formHostRecord, refreshForms);
    sptr<IRemoteObject> callerToken = nullptr;
    formDataMgr.UpdateHostFormFlag(formIds, callerToken, flag, isOnlyEnableUpdate, refreshForms);
    formDataMgr.FindMatchedFormId(formId);
    int uId = static_cast<int>(GetU32Data(data));
    formDataMgr.ClearHostDataByUId(uId);
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    std::string bundleName(data, size);
    std::string abilityName(data, size);
    FormIdKey formIdKey(bundleName, abilityName);
    std::set<int64_t> aa;
    aa.insert(formId);
    noHostTempFormsMap.emplace(formIdKey, aa);
    std::map<int64_t, bool> foundFormsMap;
    foundFormsMap.emplace(formId, flag);
    formDataMgr.GetNoHostTempForms(uId, noHostTempFormsMap, foundFormsMap);
    FormItemInfo info;
    formDataMgr.ParseUpdateConfig(formRecord, info);
    int configDuration = static_cast<int>(GetU32Data(data));
    formDataMgr.ParseIntervalConfig(formRecord, configDuration);
    formDataMgr.ParseAtTimerConfig(formRecord, info);
    formDataMgr.IsFormCached(formRecord);
    std::string provider(data, size);
    int callingUid = static_cast<int>(GetU32Data(data));
    formDataMgr.CreateFormStateRecord(provider, info, callerToken, callingUid);
    bool isVisible = *data % ENABLE;
    int32_t userId = static_cast<int>(GetU32Data(data));
    formDataMgr.NotifyFormsVisible(formIds, isVisible, callerToken, userId);
    int64_t matchedFormId = static_cast<int64_t>(GetU32Data(data));
    formDataMgr.SetRecordVisible(matchedFormId, isVisible);
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

    char* ch = reinterpret_cast<char *>(malloc(size + 1));
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

