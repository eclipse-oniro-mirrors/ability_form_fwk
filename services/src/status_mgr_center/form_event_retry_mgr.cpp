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

#include "status_mgr_center/form_event_retry_mgr.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormEventRetryMgr::FormEventRetryMgr()
{
    HILOG_DEBUG("create FormEventRetryMgr");
}

FormEventRetryMgr::~FormEventRetryMgr()
{
    HILOG_DEBUG("destroy FormEventRetryMgr");
}

bool FormEventRetryMgr::GetLastFormEvent(const int64_t formId, FormEventTaskInfo &formEventInfo)
{
    std::shared_lock<std::shared_mutex> lock(lastFormEventMutex_);
    auto iter = lastFormEventMap_.find(formId);
    if (iter == lastFormEventMap_.end()) {
        HILOG_ERROR("lastFormEvent not exist, formId:%{public}" PRId64 ". ", formId);
        return false;
    }

    formEventInfo = iter->second;
    return true;
}

void FormEventRetryMgr::SetLastFormEvent(const int64_t formId, const FormEventTaskInfo formEventInfo)
{
    std::unique_lock<std::shared_mutex> lock(lastFormEventMutex_);
    auto iter = lastFormEventMap_.find(formId);
    if (iter == lastFormEventMap_.end()) {
        HILOG_INFO("set new lastFormEvent, formId:%{public}" PRId64 ".", formId);
        lastFormEventMap_.emplace(formId, formEventInfo);
        return;
    }

    iter->second = formEventInfo;
    HILOG_DEBUG("set lastFormEvent, formId:%{public}" PRId64 ".", formId);
}

void FormEventRetryMgr::DeleteLastFormEvent(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(lastFormEventMutex_);
    auto iter = lastFormEventMap_.find(formId);
    if (iter != lastFormEventMap_.end()) {
        HILOG_INFO("delete last form event, formId:%{public}" PRId64 ". ", formId);
        lastFormEventMap_.erase(iter);
    }
}

bool FormEventRetryMgr::GetRetryCount(const int64_t formId, int32_t &retryCount)
{
    std::shared_lock<std::shared_mutex> lock(retryCountMutex_);
    auto iter = retryCountMap_.find(formId);
    if (iter == retryCountMap_.end()) {
        HILOG_ERROR("retryCount not exist, formId:%{public}" PRId64 ". ", formId);
        return false;
    }

    retryCount = iter->second;
    return true;
}

void FormEventRetryMgr::SetRetryCount(const int64_t formId, const int32_t retryCount)
{
    std::unique_lock<std::shared_mutex> lock(retryCountMutex_);
    auto iter = retryCountMap_.find(formId);
    if (iter == retryCountMap_.end()) {
        HILOG_INFO("set new retryCount, formId:%{public}" PRId64 ".", formId);
        retryCountMap_.emplace(formId, retryCount);
        return;
    }

    iter->second = retryCount;
    HILOG_INFO("set retryCount, formId:%{public}" PRId64 ".", formId);
}

void FormEventRetryMgr::DeleteRetryCount(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(retryCountMutex_);
    auto iter = retryCountMap_.find(formId);
    if (iter != retryCountMap_.end()) {
        HILOG_INFO("delete retry count, formId:%{public}" PRId64 ". ", formId);
        retryCountMap_.erase(iter);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
