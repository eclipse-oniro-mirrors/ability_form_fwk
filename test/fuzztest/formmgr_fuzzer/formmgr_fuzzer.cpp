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

#include "formmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr.h"
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
    FormMgr formMgr;
    int errorCode = static_cast<int>(GetU32Data(data));
    formMgr.GetErrorMsg(errorCode);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    formMgr.AddForm(formId, want, callerToken, formInfo);
    formMgr.DeleteForm(formId, callerToken);
    bool delCache = *data % ENABLE;
    formMgr.ReleaseForm(formId, callerToken, delCache);
    FormProviderData formBindingData;
    formMgr.UpdateForm(formId, formBindingData);
    formMgr.RequestForm(formId, callerToken, want);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    int32_t formVisibleType = static_cast<int32_t>(GetU32Data(data));
    formMgr.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
    formMgr.CastTempForm(formId, callerToken);
    std::string stringData(data);
    formMgr.DumpStorageFormInfos(stringData);
    std::string bundleName(data);
    std::string formInfos(data);
    formMgr.DumpFormInfoByBundleName(bundleName, formInfos);
    formMgr.DumpFormInfoByFormId(formId, stringData);
    formMgr.DumpFormTimerByFormId(formId, stringData);
    formMgr.MessageEvent(formId, want, callerToken);
    formMgr.RouterEvent(formId, want, callerToken);
    int64_t nextTime = static_cast<int64_t>(GetU32Data(data));
    formMgr.SetNextRefreshTime(formId, nextTime);
    std::unique_ptr<FormProviderData> formBindingDatas = nullptr;
    formMgr.RequestPublishForm(want, delCache, formBindingDatas, formId);
    formMgr.LifecycleUpdate(formIds, callerToken, delCache);
    formMgr.GetRecoverStatus();
    formMgr.SetRecoverStatus(errorCode);
    formMgr.GetErrorMessage(errorCode);
    std::shared_ptr<FormCallbackInterface> formDeathCallback = nullptr;
    formMgr.RegisterDeathCallback(formDeathCallback);
    formMgr.UnRegisterDeathCallback(formDeathCallback);
    formMgr.GetDeathRecipient();
    formMgr.CheckIsDeathCallbackRegistered(formDeathCallback);
    return formMgr.Reconnect();
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

