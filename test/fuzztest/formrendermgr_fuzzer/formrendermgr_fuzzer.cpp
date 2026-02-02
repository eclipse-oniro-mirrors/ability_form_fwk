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

#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_render/form_render_mgr.h"
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t MAX_LENGTH = 5;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    formRecord.formId = formId;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRenderMgr.RenderForm(formRecord, wantParams, hostToken);
 
    FormProviderData formProviderData;
    bool mergeData = fdp->ConsumeBool();
    formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData);
    std::vector<FormRecord> formRecords;
    formRecords.emplace_back(formRecord);
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId);
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formRenderMgr.StopRenderingForm(formId, formRecord, compId);
    Want want;
    formRenderMgr.RenderFormCallback(formId, want);
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgr.AddRenderDeathRecipient(remoteObject, formRecord);
    formRenderMgr.IsNeedRender(formId);
    int32_t errorCode = fdp->ConsumeIntegral<int32_t>();
    formRenderMgr.HandleConnectFailed(formId, errorCode);
    formRenderMgr.IsRerenderForRenderServiceDied(formId);
    return true;
}
}
 
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

