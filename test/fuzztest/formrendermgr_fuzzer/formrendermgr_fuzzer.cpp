/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "formrendermgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_render/form_render_mgr.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t MAIN_CALLING_USER_ID = 100 * 200000;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRenderMgr.RenderForm(formRecord, wantParams, hostToken);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    FormProviderData formProviderData;
    bool mergeData = *data % ENABLE;
    formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData);
    std::vector<FormRecord> formRecords;
    formRecords.emplace_back(formRecord);
    std::string bundleName(data, size);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId);
    std::string compId(data, size);
    formRenderMgr.StopRenderingForm(formId, formRecord, compId);
    Want want;
    formRenderMgr.RenderFormCallback(formId, want);
    formRenderMgr.StopRenderingFormCallback(formId, want);
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.AddConnection(formId, connection, formRecord);
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.CleanFormHost(host, OHOS::MAIN_CALLING_USER_ID);
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgr.AddRenderDeathRecipient(remoteObject, formRecord);
    formRenderMgr.IsNeedRender(formId);
    int32_t errorCode = static_cast<int32_t>(GetU32Data(data));
    formRenderMgr.HandleConnectFailed(formId, errorCode);
    formRenderMgr.IsRerenderForRenderServiceDied(formId);
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

