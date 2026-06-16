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

#ifndef OHOS_FORM_FWK_DEFAULT_STAGGER_STRATEGY_H
#define OHOS_FORM_FWK_DEFAULT_STAGGER_STRATEGY_H

#include "form_refresh/batch_refresh/strategy/stagger_strategy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class DefaultStaggerStrategy
 * DefaultStaggerStrategy is the default stagger strategy.
 * It returns all forms without any filtering and refreshes them serially.
 */
class DefaultStaggerStrategy : public IStaggerStrategy {
public:
    DefaultStaggerStrategy() = default;
    ~DefaultStaggerStrategy() override = default;

    void Filter(std::vector<RefreshData> &batch, int32_t refreshType) override {}
    int32_t ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType) override;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_DEFAULT_STAGGER_STRATEGY_H
