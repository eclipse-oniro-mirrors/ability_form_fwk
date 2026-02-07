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

#include "form_status_print.h"
#include <unordered_map>
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {

class FormMapInfoTable {
public:
    std::unordered_map<FormFsmStatus, std::string> FORM_STATUS_STRING_MAP;
    std::unordered_map<FormFsmEvent, std::string> FORM_EVENT_STRING_MAP;

    FormMapInfoTable()
    {
        this->FORM_STATUS_STRING_MAP = {
            { FormFsmStatus::INIT, "[INIT]" },
            { FormFsmStatus::RENDERED, "[RENDERED]" },
            { FormFsmStatus::RECYCLED, "[RECYCLED]" },
            { FormFsmStatus::RENDERING, "[RENDERING]" },
            { FormFsmStatus::RECYCLING_DATA, "[RECYCLING_DATA]" },
            { FormFsmStatus::RECYCLING, "[RECYCLING]" },
            { FormFsmStatus::RECOVERING, "[RECOVERING]" },
            { FormFsmStatus::DELETING, "[DELETING]" },
            { FormFsmStatus::UNPROCESSABLE, "[UNPROCESSABLE]" },
        };
        this->FORM_EVENT_STRING_MAP = {
            { FormFsmEvent::RENDER_FORM, "[RENDER_FORM]" },
            { FormFsmEvent::RENDER_FORM_DONE, "[RENDER_FORM_DONE]" },
            { FormFsmEvent::RENDER_FORM_FAIL, "[RENDER_FORM_FAIL]" },
            { FormFsmEvent::RECYCLE_DATA, "[RECYCLE_DATA]" },
            { FormFsmEvent::RECYCLE_DATA_DONE, "[RECYCLE_DATA_DONE]" },
            { FormFsmEvent::RECYCLE_DATA_FAIL, "[RECYCLE_DATA_FAIL]" },
            { FormFsmEvent::RECYCLE_FORM, "[RECYCLE_FORM]" },
            { FormFsmEvent::RECYCLE_FORM_DONE, "[RECYCLE_FORM_DONE]" },
            { FormFsmEvent::RECYCLE_FORM_FAIL, "[RECYCLE_FORM_FAIL]" },
            { FormFsmEvent::RECOVER_FORM, "[RECOVER_FORM]" },
            { FormFsmEvent::RECOVER_FORM_DONE, "[RECOVER_FORM_DONE]" },
            { FormFsmEvent::RECOVER_FORM_FAIL, "[RECOVER_FORM_FAIL]" },
            { FormFsmEvent::DELETE_FORM, "[DELETE_FORM]" },
            { FormFsmEvent::DELETE_FORM_DONE, "[DELETE_FORM_DONE]" },
            { FormFsmEvent::DELETE_FORM_FAIL, "[DELETE_FORM_FAIL]" },
            { FormFsmEvent::DELETE_FORM_FINISH, "[DELETE_FORM_FINISH]" },
            { FormFsmEvent::EXECUTION_TIMEOUT, "[EXECUTION_TIMEOUT]" },
            { FormFsmEvent::RELOAD_FORM, "[RELOAD_FORM]" },
        };
    }
};

const static FormMapInfoTable FORM_MAP_INFO_TBL;
}

std::string FormStatusPrint::FormStatusToString(const FormFsmStatus status)
{
    std::string value = std::to_string(static_cast<int>(status));
    const auto iter = FORM_MAP_INFO_TBL.FORM_STATUS_STRING_MAP.find(status);
    if (iter != FORM_MAP_INFO_TBL.FORM_STATUS_STRING_MAP.end()) {
        value = iter->second;
    }
    return value;
}

std::string FormStatusPrint::FormEventToString(const FormFsmEvent event)
{
    std::string value = std::to_string(static_cast<int>(event));
    const auto iter = FORM_MAP_INFO_TBL.FORM_EVENT_STRING_MAP.find(event);
    if (iter != FORM_MAP_INFO_TBL.FORM_EVENT_STRING_MAP.end()) {
        value = iter->second;
    }
    return value;
}
}  // namespace AppExecFwk
}  // namespace OHOS