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
#include "ffrt.h"

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

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

constexpr int32_t MAX_STR_LEN = 64;
constexpr int32_t MAX_FSM_EVENT = 18; // INVALID_EVENT

FormFsmEvent ConsumeFsmEvent(FuzzedDataProvider *fdp)
{
    return static_cast<FormFsmEvent>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FSM_EVENT));
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    Want want;
    std::string statusData = fdp->ConsumeRandomLengthString(MAX_STR_LEN);
    std::string eventId = fdp->ConsumeRandomLengthString(MAX_STR_LEN);
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, ConsumeFsmEvent(fdp), statusData, want, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, ConsumeFsmEvent(fdp), eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, ConsumeFsmEvent(fdp), statusData, want, formSupplyClient);
    std::string queueStr = fdp->ConsumeRandomLengthString(MAX_STR_LEN);
    std::shared_ptr<Common::FormBaseSerialQueue> serialQueue = std::make_shared<Common::FormBaseSerialQueue>(queueStr);
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