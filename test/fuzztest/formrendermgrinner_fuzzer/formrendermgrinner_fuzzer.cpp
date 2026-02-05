/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "formrendermgrinner_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_render/form_render_mgr_inner.h"
#undef private
#undef protected
#include "message_parcel.h"
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
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    sptr<IRemoteObject> hostToken = nullptr;
    formRenderMgrInner.RenderForm(formRecord, want, hostToken);
    WantParams wantParams;
    bool mergeData = *data % ENABLE;
    FormProviderData formProviderData;
    formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    std::string compId(data, size);
    formRenderMgrInner.StopRenderingForm(formId, formRecord, compId);
    std::vector<FormRecord> formRecords;
    formRecords.emplace_back(formRecord);
    std::string bundleName(data, size);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formRenderMgrInner.ReloadForm(std::move(formRecords), bundleName, userId);
    formRenderMgrInner.StopRenderingFormCallback(formId, want);
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.AddConnection(formId, connection);
    formRenderMgrInner.RemoveConnection(formId);
    sptr<IRemoteObject> renderRemoteObj = nullptr;
    formRenderMgrInner.AddRenderDeathRecipient(renderRemoteObj);
    formRenderMgrInner.RerenderAllForms();
    sptr<IRemoteObject> host = nullptr;
    formRenderMgrInner.CleanFormHost(host);
    formRenderMgrInner.OnRenderingBlock(bundleName);
    formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId);
    formRenderMgrInner.PostOnUnlockTask();
    formRenderMgrInner.PostSetVisibleChangeTask(formId, true);
    formRenderMgrInner.GetReRenderCount();
    formRenderMgrInner.GetRenderRemoteObj();
    sptr<IFormRender> remoteObject = nullptr;
    formRenderMgrInner.SetRenderRemoteObj(remoteObject);
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    formRenderMgrInner.RecycleForms(formIds, want, remoteObjectOfHost);
    formRenderMgrInner.RecoverForms(formIds, wantParams);
    formRenderMgrInner.DisconnectRenderService(connection, size);
    formRenderMgrInner.RemoveHostToken(host);
    formRenderMgrInner.NotifyHostRenderServiceIsDead();
    formRenderMgrInner.FillBundleInfo(want, bundleName, userId);
    formRenderMgrInner.CheckIfFormRecycled(formRecord, want);
    formRenderMgrInner.GetConnectionAndRenderForm(formRecord, want);
    sptr<IRemoteObject> renderObj = nullptr;
    formRenderMgrInner.GetRenderObject(renderObj);
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

