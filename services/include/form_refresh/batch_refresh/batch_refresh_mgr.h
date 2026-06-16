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

#ifndef OHOS_FORM_FWK_BATCH_REFRESH_MGR_H
#define OHOS_FORM_FWK_BATCH_REFRESH_MGR_H

#include <memory>
#include <mutex>
#include <vector>

#include "form_refresh/refresh_impl/form_refresh_interface.h"
#include "form_refresh/batch_refresh/strategy/stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/default_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/delay_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/visible_delay_stagger_strategy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @enum StaggerStrategyType
 * StaggerStrategy type enumeration.
 */
enum class StaggerStrategyType {
    DEFAULT = 0,
    DELAY = 1,
    VISIBLE_DELAY = 2,
};

/**
 * @class BatchRefreshMgr
 * BatchRefreshMgr manages batch refresh operations with configurable stagger strategies.
 */
class BatchRefreshMgr {
public:
    BatchRefreshMgr() = default;
    ~BatchRefreshMgr() = default;
    DISALLOW_COPY_AND_MOVE(BatchRefreshMgr);

    /**
     * @brief Batch request refresh for multiple forms.
     * @param refreshType The refresh type.
     * @param strategyType The stagger strategy type to use.
     * @param batch The batch of forms to refresh.
     * @return ERR_OK on success, error code on failure.
     */
    int32_t BatchRequestRefresh(const int32_t refreshType,
        const StaggerStrategyType strategyType, std::vector<RefreshData> &batch);

    /**
     * @brief Get stagger strategy for given strategy type.
     * @param strategyType The strategy type.
     * @return The stagger strategy instance as weak_ptr.
     */
    std::weak_ptr<IStaggerStrategy> GetStaggerStrategy(const StaggerStrategyType strategyType);

private:
    std::mutex strategyMutex_;
    std::shared_ptr<DefaultStaggerStrategy> defaultStrategy_;
    std::shared_ptr<DelayStaggerStrategy> delayStrategy_;
    std::shared_ptr<VisibleDelayStaggerStrategy> visibleDelayStrategy_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_BATCH_REFRESH_MGR_H
