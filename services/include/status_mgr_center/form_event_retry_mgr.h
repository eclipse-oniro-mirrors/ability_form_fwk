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

#ifndef OHOS_FORM_FWK_FORM_EVENT_RETRY_MGR_H
#define OHOS_FORM_FWK_FORM_EVENT_RETRY_MGR_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "status_mgr_center/form_status_common.h"
#include "status_mgr_center/form_event_queue.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t FORM_EVENT_RETRY_MAX = 1;
}

class FormEventRetryMgr final : public DelayedRefSingleton<FormEventRetryMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormEventRetryMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormEventRetryMgr);

    /**
     * @brief Get the last form event from map
     * @param formId Form ID
     * @param formEventInfo Form event task information
     * @return Returns true if successful, false otherwise
     */
    bool GetLastFormEvent(const int64_t formId, FormEventTaskInfo &formEventInfo);

    /**
     * @brief Set the last form event to map
     * @param formId Form ID
     * @param formEventInfo Form event task information
     */
    void SetLastFormEvent(const int64_t formId, const FormEventTaskInfo formEventInfo);

    /**
     * @brief Delete the last form event from map
     * @param formId Form ID
     */
    void DeleteLastFormEvent(const int64_t formId);

    /**
     * @brief Get the retry count from map
     * @param formId Form ID
     * @param retryCount Retry count
     * @return Returns true if successful, false otherwise
     */
    bool GetRetryCount(const int64_t formId, int32_t &retryCount);

    /**
     * @brief Set the retry count to map
     * @param formId Form ID
     * @param retryCount Retry count
     */
    void SetRetryCount(const int64_t formId, const int32_t retryCount);

    /**
     * @brief Delete the retry count from map
     * @param formId Form ID
     */
    void DeleteRetryCount(const int64_t formId);

private:
    // <formId, FormEventTaskInfo>
    std::shared_mutex lastFormEventMutex_;
    std::unordered_map<int64_t, FormEventTaskInfo> lastFormEventMap_;

    // <formId, retryCount>
    std::shared_mutex retryCountMutex_;
    std::unordered_map<int64_t, int32_t> retryCountMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_EVENT_RETRY_MGR_H
