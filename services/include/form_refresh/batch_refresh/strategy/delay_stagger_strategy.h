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

#ifndef OHOS_FORM_FWK_DELAY_STAGGER_STRATEGY_H
#define OHOS_FORM_FWK_DELAY_STAGGER_STRATEGY_H

#include <cstdint>
#include "common/util/form_task_common.h"
#include "form_constants.h"
#include "form_refresh/batch_refresh/strategy/stagger_strategy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class DelayStaggerStrategy
 * DelayStaggerStrategy is the base class for batch delay refresh strategies.
 * It returns all forms without filtering and refreshes them in batches with delay.
 */
class DelayStaggerStrategy : public IStaggerStrategy {
public:
    DelayStaggerStrategy() = default;
    ~DelayStaggerStrategy() override = default;

    void Filter(std::vector<RefreshData> &batch, int32_t refreshType) override {}
    int32_t ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType) override;

protected:
    int32_t batchSize_ = Constants::DELAY_REFRESH_PER_BATCH;
    int32_t delayMs_ = BATCH_DELAY_REFRESH_TIME;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_DELAY_STAGGER_STRATEGY_H
