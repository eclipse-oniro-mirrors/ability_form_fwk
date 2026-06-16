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

#include "formsharemgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "feature/form_share/form_share_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormShareMgr formShareMgr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    std::string deviceId(data, size);
    sptr<IRemoteObject> callerToken = nullptr;
    int64_t requestCode = static_cast<int64_t>(GetU32Data(data));
    formShareMgr.ShareForm(formId, deviceId, callerToken, requestCode);
    FormShareInfo info;
    int32_t userId = static_cast<int64_t>(GetU32Data(data));
    formShareMgr.HandleRecvFormShareInfoFromRemoteTask(info, userId);
    formShareMgr.CheckFormShareInfo(info);
    formShareMgr.MakeFormShareInfoKey(info);
    Want want;
    formShareMgr.MakeFormShareInfoKey(want);
    formShareMgr.StartFormUser(info, userId);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formShareMgr.IsExistFormPackage(bundleName, moduleName, userId);
    std::string formShareInfoKey(data, size);
    formShareMgr.RemoveFormShareInfo(formShareInfoKey);
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    formShareMgr.FinishFreeInstallTask(freeInstallOperator);
    int32_t resultCode = static_cast<int32_t>(GetU32Data(data));
    formShareMgr.OnInstallFinished(freeInstallOperator, resultCode, formShareInfoKey, userId);
    int64_t eventId = static_cast<int64_t>(GetU32Data(data));
    formShareMgr.HandleFormShareInfoTimeout(eventId);
    formShareMgr.HandleFreeInstallTimeout(eventId);
    WantParams wantParams;
    formShareMgr.AddProviderData(want, wantParams);
    formShareMgr.IsShareForm(want);
    int64_t msg = static_cast<int64_t>(GetU32Data(data));
    formShareMgr.OnEventTimeoutResponse(msg, eventId);
    formShareMgr.RecvFormShareInfoFromRemote(info, userId);
    formShareMgr.CheckFormPackage(info, formShareInfoKey, userId);
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

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

