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

#ifndef OHOS_FORM_FWK_STAGGER_STRATEGY_H
#define OHOS_FORM_FWK_STAGGER_STRATEGY_H

#include <vector>

#include "form_refresh/refresh_impl/form_refresh_interface.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class IStaggerStrategy
 * IStaggerStrategy is the interface for stagger refresh algorithm.
 * Different strategies can implement different filtering and refresh execution logic.
 */
class IStaggerStrategy {
public:
    virtual ~IStaggerStrategy() = default;

    /**
     * @brief Filter cards based on strategy, remove invisible cards from batch.
     * @param batch The batch of cards to filter (in-place modification).
     * @param refreshType The refresh type to use.
     */
    virtual void Filter(std::vector<RefreshData> &batch, int32_t refreshType) = 0;

    /**
     * @brief Execute refresh for the filtered cards.
     * Strategy decides how to execute (serial, batch delay, etc.).
     * @param batch The filtered batch of cards to refresh.
     * @param refreshType The refresh type to use.
     * @return ERR_OK on success, error code on failure.
     */
    virtual int32_t ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType) = 0;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_STAGGER_STRATEGY_H
