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

#include "formprovidermgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "form_item_info.h"
#define private public
#define protected public
#include "form_provider_mgr.h"
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
    FormItemInfo formItemInfo;
    bool isFormVisibleNotify = *data % ENABLE;
    formItemInfo.SetFormVisibleNotify(isFormVisibleNotify);
    std::string formSrc(data, size);
    formItemInfo.SetFormSrc(formSrc);
    formItemInfo.GetFormSrc();
    FormWindow formWindow;
    formItemInfo.SetFormWindow(formWindow);
    formItemInfo.GetFormWindow();
    uint32_t versionCode = static_cast<uint32_t>(GetU32Data(data));
    formItemInfo.SetVersionCode(versionCode);
    formItemInfo.GetVersionCode();
    std::string versionName(data, size);
    formItemInfo.SetVersionName(versionName);
    formItemInfo.GetVersionName();
    uint32_t compatibleVersion = static_cast<uint32_t>(GetU32Data(data));
    formItemInfo.SetCompatibleVersion(compatibleVersion);
    formItemInfo.GetCompatibleVersion();
    formItemInfo.GetIcon();
    std::string deviceId(data, size);
    formItemInfo.SetDeviceId(deviceId);
    formItemInfo.GetDeviceId();
    FormType type = FormType::JS;
    formItemInfo.SetType(type);
    formItemInfo.GetType();
    FormProviderMgr formProviderMgr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    FormProviderInfo formProviderInfo;
    formProviderMgr.AcquireForm(formId, formProviderInfo);
    Want want;
    bool isVisibleToFresh = *data % ENABLE;
    formProviderMgr.RefreshForm(formId, want, isVisibleToFresh);
    FormRecord record;
    bool isTimerRefresh = *data % ENABLE;
    formProviderMgr.ConnectAmsForRefresh(formId, record, want, isTimerRefresh);
    formProviderMgr.NotifyProviderFormDelete(formId, record);
    std::string bundleName(data, size);
    std::string abilityName(data, size);
    std::set<int64_t> formIds;
    formIds.insert(formId);
    formProviderMgr.NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds);
    formProviderMgr.UpdateForm(formId, formProviderInfo);
    FormProviderData formProviderData;
    formProviderMgr.UpdateForm(formId, record, formProviderData);
    formProviderMgr.MessageEvent(formId, record, want);
    formProviderMgr.IncreaseTimerRefreshCount(formId);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    std::string provider(data, size);
    Want wantArg;
    formProviderMgr.AcquireFormStateBack(state, provider, wantArg);
    formProviderMgr.IsNeedToFresh(record, formId, isVisibleToFresh);
    formProviderMgr.GetFormAbilityInfo(record);
    formProviderMgr.IsFormCached(record);
    sptr<AAFwk::IAbilityConnection> formRefreshConnection = nullptr;
    return formProviderMgr.RebindByFreeInstall(record, want, formRefreshConnection);
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

