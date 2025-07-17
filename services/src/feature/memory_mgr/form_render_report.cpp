/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "feature/memory_mgr/form_render_report.h"
#include "common/event/form_event_report.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormRenderReady
 * FormRenderReady is used to call frs report.
 */
FormRenderReport::FormRenderReport()
{
    HILOG_INFO("init isFirstLoad:%{public}d", isFirstLoad_.load());
}

FormRenderReport::~FormRenderReport() {}

bool FormRenderReport::IsFirstLoad()
{
    if (isFirstLoad_.load()) {
        HILOG_INFO("isFirstLoad");
        isFirstLoad_.store(false);
        return true;
    }
    return isFirstLoad_.load();
}

void FormRenderReport::FirstStartReport()
{
    HILOG_INFO("call");
    if (IsFirstLoad()) {
        int64_t formCount;
        GetAllFormCount(formCount);
        FormEventReport::SendFrsStateEvent(FormEventName::FORM_RENDER_SERVICE_START, formCount,
            FormDataMgr::GetInstance().IsLowMemory());
    }
}

void FormRenderReport::DeadReport()
{
    HILOG_INFO("call");
    isFirstLoad_.store(true);
    int64_t formCount;
    GetAllFormCount(formCount);
    FormEventReport::SendFrsStateEvent(FormEventName::FORM_RENDER_SERVICE_DEAD, formCount,
        FormDataMgr::GetInstance().IsLowMemory());
}

void FormRenderReport::GetAllFormCount(int64_t &formCount)
{
    int32_t tempFormsCount;
    FormDataMgr::GetInstance().GetTempFormsCount(tempFormsCount);
    int32_t castFormsCount;
    FormDataMgr::GetInstance().GetCastFormsCount(castFormsCount);
    formCount = tempFormsCount + castFormsCount;
}
}
}
