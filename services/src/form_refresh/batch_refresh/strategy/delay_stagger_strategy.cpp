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

#include <unordered_set>
#include <vector>
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_queue.h"
#include "form_refresh/batch_refresh/strategy/delay_stagger_strategy.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
void RefreshBatch(size_t startIdx, size_t endIdx, std::vector<RefreshData> &batch, int32_t refreshType)
{
    auto &formRenderMgr = FormRefreshMgr::GetInstance();
    for (size_t j = startIdx; j < endIdx; ++j) {
        int32_t ret = formRenderMgr.RequestRefresh(batch[j], refreshType);
        if (ret != ERR_OK) {
            HILOG_WARN("DelayStaggerStrategy::ExecuteRefresh: refresh failed for form %{public}" PRId64 ","
                "err = %{public}d", batch[j].formId, ret);
        }
    }
}
}

int32_t DelayStaggerStrategy::ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType)
{
    std::vector<std::vector<RefreshData>> batches;
    std::unordered_set<int32_t> currentBatchUids;
    std::vector<RefreshData> currentBatch;

    for (const auto &data : batch) {
        int32_t uid = data.record.uid;

        // Check if adding this data would exceed the batch size by unique uid count
        if (currentBatchUids.count(uid) == 0 && currentBatchUids.size() >= static_cast<size_t>(batchSize_)) {
            // Current batch is full, save it and start a new one
            batches.push_back(std::move(currentBatch));
            currentBatch.clear();
            currentBatchUids.clear();
        }

        currentBatch.push_back(data);
        currentBatchUids.insert(uid);
    }

    // Last batch
    if (!currentBatch.empty()) {
        batches.push_back(std::move(currentBatch));
    }

    // Execute batches
    for (size_t i = 0; i < batches.size(); ++i) {
        if (i == 0) {
            // First batch: execute immediately
            RefreshBatch(0, batches[i].size(), batches[i], refreshType);
            continue;
        }

        // Subsequent batches: schedule with delay
        auto refreshBatch = [
            batch = std::move(batches[i]),
            refreshType
        ]() mutable {
            RefreshBatch(0, batch.size(), batch, refreshType);
        };
        FormMgrQueue::GetInstance().ScheduleTask(delayMs_ * static_cast<int32_t>(i), std::move(refreshBatch));
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
