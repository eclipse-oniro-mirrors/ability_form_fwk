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

#include "status_mgr_center/form_render_status_table.h"
#include <unordered_map>
#include "fms_log_wrapper.h"
#include "form_status_print.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_INIT = {
    // INIT
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RENDERING = {
    // RENDERING
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RENDER_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RENDER_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RENDERED = {
    // RENDERED
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RECYCLED = {
    // RECYCLED
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RECYCLING_DATA = {
    // RECYCLING_DATA
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_DATA_DONE,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_DATA_FAIL,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RECYCLING = {
    // RECYCLING
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECYCLE_FORM_DONE,
        FormFsmStatus::RECYCLED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECYCLE_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_RECOVERING = {
    // RECOVERING
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECOVER_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECOVER_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_DELETING = {
    // DELETING
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_FINISH,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::vector<FormRenderStatusMachineInfo> FORM_STATUS_TABLE_UNPROCESSABLE = {
    // UNPROCESSABLE
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
    },
};

const std::unordered_map<FormFsmStatus, std::vector<FormRenderStatusMachineInfo>> FORM_STATUS_TABLE = {
    {FormFsmStatus::INIT, FORM_STATUS_TABLE_INIT},
    {FormFsmStatus::RENDERING, FORM_STATUS_TABLE_RENDERING},
    {FormFsmStatus::RENDERED, FORM_STATUS_TABLE_RENDERED},
    {FormFsmStatus::RECYCLED, FORM_STATUS_TABLE_RECYCLED},
    {FormFsmStatus::RECYCLING_DATA, FORM_STATUS_TABLE_RECYCLING_DATA},
    {FormFsmStatus::RECYCLING, FORM_STATUS_TABLE_RECYCLING},
    {FormFsmStatus::RECOVERING, FORM_STATUS_TABLE_RECOVERING},
    {FormFsmStatus::DELETING, FORM_STATUS_TABLE_DELETING},
    {FormFsmStatus::UNPROCESSABLE, FORM_STATUS_TABLE_UNPROCESSABLE},
};
}  // namespace

FormRenderStatusTable::FormRenderStatusTable()
{
    HILOG_INFO("create FormRenderStatusTable");
}

FormRenderStatusTable::~FormRenderStatusTable()
{
    HILOG_DEBUG("destroy FormRenderStatusTable");
}

bool FormRenderStatusTable::GetFormStatusInfo(
    FormFsmStatus curStatus, FormFsmEvent event, FormRenderStatusMachineInfo &info)
{
    auto iter = FORM_STATUS_TABLE.find(curStatus);
    if (iter == FORM_STATUS_TABLE.end()) {
        HILOG_ERROR("not find table, curStatus is %{public}s, event is %{public}s.",
            FormStatusPrint::FormStatusToString(curStatus).c_str(),
            FormStatusPrint::FormEventToString(event).c_str());
        return false;
    }

    auto tableInfo = iter->second;
    for (size_t i = 0; i < tableInfo.size(); i++) {
        if (tableInfo[i].event == event) {
            info = tableInfo[i];
            return true;
        }
    }

    HILOG_ERROR("form status error, curStatus is %{public}s, event is %{public}s.",
        FormStatusPrint::FormStatusToString(curStatus).c_str(),
        FormStatusPrint::FormEventToString(event).c_str());
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
