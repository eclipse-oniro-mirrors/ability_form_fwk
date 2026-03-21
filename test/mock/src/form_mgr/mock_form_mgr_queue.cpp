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

#include "form_mgr/mock_form_mgr_queue.h"
#include <gtest/gtest.h>
#include "form_mgr/form_mgr_queue.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormMgrQueue> MockFormMgrQueue::obj = nullptr;

FormMgrQueue::FormMgrQueue() {}
FormMgrQueue::~FormMgrQueue() {}

bool FormMgrQueue::ScheduleTask(uint64_t ms, std::function<void()> task)
{
    GTEST_LOG_(INFO) << "FormMgrQueue::ScheduleTask called with delay " << ms;
    if (MockFormMgrQueue::obj) {
        return MockFormMgrQueue::obj->ScheduleTask(ms, task);
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
