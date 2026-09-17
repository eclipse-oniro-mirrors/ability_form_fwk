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

#include "facrconnectionTwo_fuzzer.h"

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

constexpr int32_t MAX_FSM_EVENT = 18; // INVALID_EVENT
constexpr int32_t MAX_FSM_STATUS = 8;  // UNPROCESSABLE

FormFsmEvent ConsumeFsmEvent(FuzzedDataProvider *fdp)
{
    return static_cast<FormFsmEvent>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FSM_EVENT));
}

FormFsmStatus ConsumeFsmStatus(FuzzedDataProvider *fdp)
{
    return static_cast<FormFsmStatus>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FSM_STATUS));
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string str1 = fdp->ConsumeRandomLengthString();
    FormRenderServiceMgr::GetInstance().FormRenderGCTask(str1);
    FormRenderServiceMgr::GetInstance().FormRenderGC(str1);
    FormRenderServiceMgr::GetInstance().IsRenderRecordExist(str1);
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();
    FormRenderServiceMgr::GetInstance().OnUnlock();
    FormRenderServiceMgr::GetInstance().GetFormSupplyClient();
    FormRenderServiceMgr::GetInstance().OnConfigurationUpdatedInner();
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    FormFsmEvent event = ConsumeFsmEvent(fdp);
    int32_t funcRet = fdp->ConsumeIntegral<int32_t>();
    std::function<int32_t()> func = [funcRet]() { return funcRet; };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, func);
    FormFsmStatus status = ConsumeFsmStatus(fdp);
    FormFsmProcessType processType = fdp->ConsumeBool() ? FormFsmProcessType::PROCESS_TASK_DELETE
        : FormFsmProcessType::PROCESS_TASK_DIRECT;
    FormRenderStatusMgr::GetInstance().ExecFormTask(processType, formId, event, status, func);
    FormRenderStatusMgr::GetInstance().ProcessTaskDirect(func);
    FormRenderStatusMgr::GetInstance().ProcessTaskDelete(formId);
    FormRenderStatusMgr::GetInstance().PrintTaskInfo(formId, event, status);
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
