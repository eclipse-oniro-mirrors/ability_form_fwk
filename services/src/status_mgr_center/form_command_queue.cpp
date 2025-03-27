/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "status_mgr_center/form_command_queue.h"
#include "fms_log_wrapper.h"
#include "status_mgr_center/form_command_process_strategy.h"
#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_status_queue.h"

namespace OHOS {
namespace AppExecFwk {
FormCommandQueue::FormCommandQueue(const int64_t &formId) : formId_(formId)
{
    HILOG_INFO("create FormCommandQueue, formId :%{public}" PRId64 ". ", formId_);
}

FormCommandQueue::~FormCommandQueue()
{
    HILOG_INFO("destroy FormCommandQueue, formId :%{public}" PRId64 ". ", formId_);
}

void FormCommandQueue::PushFormCommand(FormCommand formCommand)
{
    std::lock_guard<std::mutex> lock(formCommandQueueMutex_);
    HILOG_INFO("PushFormCommand, formId :%{public}" PRId64 ". ", formId_);
    CommandQueue.push(formCommand);

    // Process the command queue after adding a new command.
    ProcessCommandQueue();
}

bool FormCommandQueue::PopFormCommand(FormCommand &formCommand)
{
    std::lock_guard<std::mutex> lock(formCommandQueueMutex_);
    if (CommandQueue.empty()) {
        HILOG_INFO("empty CommandQueue, formId :%{public}" PRId64 ". ", formId_);
        return false;
    }
    formCommand = CommandQueue.front();
    CommandQueue.pop();
    return true;
}

bool FormCommandQueue::IsCommondQueueEmpty()
{
    std::lock_guard<std::mutex> lock(formCommandQueueMutex_);
    if (CommandQueue.empty()) {
        HILOG_INFO("empty CommandQueue, formId :%{public}" PRId64 ". ", formId_);
        return true;
    }
    HILOG_INFO("CommandQueue not empty, formId :%{public}" PRId64 ". ", formId_);
    return false;
}

void FormCommandQueue::ProcessCommandQueue()
{
    if (CommandQueue.empty()) {
        HILOG_ERROR("empty CommandQueue, formId :%{public}" PRId64 ". ", formId_);
        return;
    }

    FormCommand latestFormCommand = CommandQueue.back();
    FormStatus currentFormStatus;
    if (!FormStatusMgr::GetInstance().GetFormStatus(latestFormCommand.getFormId(), currentFormStatus)) {
        HILOG_ERROR("GetFormStatus fail, formId :%{public}" PRId64 ". ", formId_);
        return;
    }

    auto strategy = CommandProcessStrategyFactory::CreateStrategy(
        latestFormCommand.getEventMsg().first, currentFormStatus);
    if (!strategy) {
        HILOG_ERROR("strategy fail, formId :%{public}" PRId64 ". ", formId_);
        return;
    }
 
    strategy->ProcessCommandQueue(CommandQueue, formId_);
}
} // namespace AppExecFwk
}  // namespace OHOS
