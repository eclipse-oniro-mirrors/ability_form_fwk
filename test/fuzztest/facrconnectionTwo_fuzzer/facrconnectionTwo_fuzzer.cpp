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

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
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
    FormFsmEvent event = FormFsmEvent::RELOAD_FORM;
    std::function<int32_t()> func = []() { return 1; };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, func);
    FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    std::string eventId = fdp->ConsumeRandomLengthString();
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormFsmStatus status = FormFsmStatus::UNPROCESSABLE;
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