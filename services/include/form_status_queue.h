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

#ifndef OHOS_FORM_FWK_FORM_STATUS_QUEUE_H
#define OHOS_FORM_FWK_FORM_STATUS_QUEUE_H

#include <map>
#include <unordered_map>
#include <shared_mutex>
#include <string>

#include <singleton.h>
#include "ffrt.h"
#include "iremote_object.h"
#include "form_command_queue.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_MAX_TIME_OUT = 5000; // ms
}

class FormStatusQueue final : public DelayedRefSingleton<FormStatusQueue> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatusQueue)

public:
    DISALLOW_COPY_AND_MOVE(FormStatusQueue);
    bool ScheduleTask(uint64_t ms, std::function<void()> func);
    void ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg, uint32_t ms, std::function<void()> func);
    void CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg);

    void AddFormStatusQueue(const int64_t formId, const sptr<IRemoteObject> &remoteObjectOfHost);
    void DeleteFormStatusQueue(const int64_t formId);
    
    void PostFormStatusTask(FormCommand formCommand);
    void PostFormDeleteTask(FormCommand formCommand);

    void PostFormCommandTaskByFormId(const int64_t formId);
    void ProcessTask(FormCommand &formCommand);

    void PostTimeOutReAddForm(const int64_t formId);
    void CancelTimeOutReAddForm(const int64_t &formId);

private:
    void TimeOutReAddForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost);

    //<formid, CommandQueue>
    std::shared_mutex formCommandQueueMapMutex_;
    std::unordered_map<int64_t, std::shared_ptr<FormCommandQueue>> formCommandQueueMap_;
    // <formId, hostToken>
    std::unordered_map<int64_t, sptr<IRemoteObject>> formHostTokenMap_;

    std::shared_mutex mutex_;
    std::map<std::pair<int64_t, int64_t>, ffrt::task_handle> taskMap_;
    ffrt::queue queue_;
};
}
}
#endif // OHOS_FORM_FWK_FORM_STATUS_QUEUE_H
