/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "facrconnectionFourth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "form_constants.h"
#include "form_supply_stub.h"
#include "form_surface_info.h"

#define private public
#define protected public
#include "form_render_service_mgr.h"
#include "status_mgr_center/form_render_status_mgr.h"
#include "status_mgr_center/form_render_status_task_mgr.h"
#include "data_center/form_basic_info_mgr.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
class FormSupplyStubFuzzTest : public FormSupplyStub {
public:
    FormSupplyStubFuzzTest() = default;
    virtual ~FormSupplyStubFuzzTest() = default;
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return 0;
    }
    int OnEventHandle(const Want &want) override
    {
        return 0;
    }
    int OnAcquireStateResult(FormState state, const std::string &provider,
        const Want &wantArg, const Want &want) override
    {
        return 0;
    }
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override
    {}
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return ERR_OK;
    }
};

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    Want want;
    std::string statusData = fdp->ConsumeRandomLengthString(5);
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, FormFsmEvent::RENDER_FORM_DONE, "", formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, FormFsmEvent::RECOVER_FORM_DONE, "", formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, FormFsmEvent::DELETE_FORM_DONE, "", formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, FormFsmEvent::RECYCLE_FORM_DONE, "", formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, FormFsmEvent::RECYCLE_DATA_DONE, statusData, want, formSupplyClient);
    std::string eventId = fdp->ConsumeRandomLengthString(5);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, FormFsmEvent::RENDER_FORM_DONE, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, FormFsmEvent::RECOVER_FORM_DONE, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, FormFsmEvent::DELETE_FORM_DONE, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, FormFsmEvent::RECYCLE_FORM_DONE, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, FormFsmEvent::RECYCLE_DATA_DONE, statusData, want, formSupplyClient);
    std::string queueStr = "FormRenderSerialQueue";
    std::shared_ptr<FormRenderSerialQueue> serialQueue = std::make_unique<FormRenderSerialQueue>(queueStr);
    FormRenderStatusTaskMgr::GetInstance().SetSerialQueue(serialQueue);
    FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);
    FormRenderStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId);
    FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);
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