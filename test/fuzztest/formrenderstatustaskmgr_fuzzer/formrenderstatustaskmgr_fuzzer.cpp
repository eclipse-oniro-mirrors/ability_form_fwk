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

#include "formrenderstatustaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "status_mgr_center/form_render_status_task_mgr.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
constexpr int64_t MAX_NUM = 10000;
constexpr int64_t MIN_NUM = 0;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int64_t formId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    int32_t eventValue = fdp->ConsumeIntegral<int32_t>();
    FormFsmEvent event = static_cast<FormFsmEvent>(eventValue);
    std::string eventId = fdp->ConsumeRandomLengthString(100);
    sptr<IFormSupply> formSupplyClient = nullptr;
    
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(formId, event, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(formId, event, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(formId, event, eventId, formSupplyClient);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(formId, event, eventId, formSupplyClient);
    
    std::string statusData = fdp->ConsumeRandomLengthString(100);
    Want want;
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(formId, event, statusData, want, formSupplyClient);
    
    FormRenderStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId);
    FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);
    
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
