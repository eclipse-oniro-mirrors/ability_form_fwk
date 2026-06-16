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
 * * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "form_refresh/batch_refresh/batch_refresh_mgr.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {

std::weak_ptr<IStaggerStrategy> BatchRefreshMgr::GetStaggerStrategy(const StaggerStrategyType strategyType)
{
    std::lock_guard<std::mutex> lock(strategyMutex_);

    switch (strategyType) {
        case StaggerStrategyType::DEFAULT:
            if (defaultStrategy_ == nullptr) {
                defaultStrategy_ = std::make_shared<DefaultStaggerStrategy>();
            }
            return defaultStrategy_;

        case StaggerStrategyType::DELAY:
            if (delayStrategy_ == nullptr) {
                delayStrategy_ = std::make_shared<DelayStaggerStrategy>();
            }
            return delayStrategy_;

        case StaggerStrategyType::VISIBLE_DELAY:
            if (visibleDelayStrategy_ == nullptr) {
                visibleDelayStrategy_ = std::make_shared<VisibleDelayStaggerStrategy>();
            }
            return visibleDelayStrategy_;

        default:
            HILOG_ERROR("BatchRefreshMgr::GetStaggerStrategy: unknown strategyType = %{public}d",
                static_cast<int>(strategyType));
            return std::weak_ptr<IStaggerStrategy>();
    }
}

int32_t BatchRefreshMgr::BatchRequestRefresh(const int32_t refreshType,
    const StaggerStrategyType strategyType, std::vector<RefreshData> &batch)
{
    if (batch.empty()) {
        return ERR_OK;
    }

    std::weak_ptr<IStaggerStrategy> weakStrategy = GetStaggerStrategy(strategyType);
    std::shared_ptr<IStaggerStrategy> strategy = weakStrategy.lock();
    if (strategy == nullptr) {
        HILOG_ERROR("BatchRefreshMgr::BatchRequestRefresh: strategy is nullptr for strategyType = %{public}d",
            static_cast<int>(strategyType));
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    strategy->Filter(batch, refreshType);
    int32_t ret = strategy->ExecuteRefresh(batch, refreshType);
    if (ret != ERR_OK) {
        HILOG_ERROR("BatchRefreshMgr::BatchRequestRefresh: ExecuteRefresh failed, ret = %{public}d", ret);
    }

    return ret;
}
} // namespace AppExecFwk
} // namespace OHOS
