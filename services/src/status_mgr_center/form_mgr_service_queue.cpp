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

#include "form_mgr_service_queue.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_MGR_SERVICE_QUEUE = "FormMgrServiceQueue";
} // namespace
FormMgrServiceQueue::FormMgrServiceQueue()
{
    HILOG_INFO("create FormMgrServiceQueue, queueName :%{public}s", FORM_MGR_SERVICE_QUEUE.c_str());
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_MGR_SERVICE_QUEUE.c_str());
}

FormMgrServiceQueue::~FormMgrServiceQueue()
{
    HILOG_INFO("destroy FormMgrServiceQueue");
}

bool FormMgrServiceQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    return serialQueue_->ScheduleTask(ms, func);
}
} // namespace AppExecFwk
} // namespace OHOS