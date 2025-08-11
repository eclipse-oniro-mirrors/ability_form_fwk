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

#include "status_mgr_center/form_status_table.h"
#include <unordered_map>
#include "fms_log_wrapper.h"
#include "form_status_print.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_INIT = {
    // INIT
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::INIT,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RENDERING = {
    // RENDERING
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_UNIQUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RENDER_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_FROM_QUEUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RENDER_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_UNIQUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RENDERING,
        FormFsmEvent::EXECUTION_TIMEOUT,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RENDERED = {
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RENDERED,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RECYCLED = {
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RECYCLED,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RECYCLING_DATA = {
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_DATA_DONE,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_DATA_FAIL,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING_DATA,
        FormFsmEvent::EXECUTION_TIMEOUT,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RECYCLING = {
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECYCLE_FORM_DONE,
        FormFsmStatus::RECYCLED,
        FormFsmProcessType::PROCESS_TASK_FROM_QUEUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECYCLE_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECYCLING,
        FormFsmEvent::EXECUTION_TIMEOUT,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_RECOVERING = {
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_UNIQUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECOVER_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_FROM_QUEUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::RECOVER_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::RECOVERING,
        FormFsmEvent::EXECUTION_TIMEOUT,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_DELETING = {
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_DONE,
        FormFsmStatus::RENDERED,
        FormFsmProcessType::PROCESS_TASK_FROM_QUEUE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_FAIL,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::DELETE_FORM_FINISH,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_DELETE,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
    {
        FormFsmStatus::DELETING,
        FormFsmEvent::EXECUTION_TIMEOUT,
        FormFsmStatus::UNPROCESSABLE,
        FormFsmProcessType::PROCESS_TASK_RETRY,
        FormEventTimeout::TIMEOUT_NO_NEED,
    },
};

const std::vector<FormStatusMachineInfo> FORM_STATUS_TABLE_UNPROCESSABLE = {
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RENDER_FORM,
        FormFsmStatus::RENDERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECYCLE_DATA,
        FormFsmStatus::RECYCLING_DATA,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECYCLE_FORM,
        FormFsmStatus::RECYCLING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::RECOVER_FORM,
        FormFsmStatus::RECOVERING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
    {
        FormFsmStatus::UNPROCESSABLE,
        FormFsmEvent::DELETE_FORM,
        FormFsmStatus::DELETING,
        FormFsmProcessType::PROCESS_TASK_DIRECT,
        FormEventTimeout::TIMEOUT_3_S,
    },
};

const std::unordered_map<FormFsmStatus, std::vector<FormStatusMachineInfo>> FORM_STATUS_TABLE = {
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

FormStatusTable::FormStatusTable()
{
    HILOG_INFO("create FormStatusTable");
}

FormStatusTable::~FormStatusTable()
{
    HILOG_DEBUG("destroy FormStatusTable");
}

bool FormStatusTable::GetFormStatusInfo(FormFsmStatus curStatus, FormFsmEvent event, FormStatusMachineInfo &info)
{
    auto iter = FORM_STATUS_TABLE.find(curStatus);
    if (iter == FORM_STATUS_TABLE.end()) {
        HILOG_ERROR("form status error, curStatus is %{public}s, event is %{public}s.",
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
