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

#include "form_refresh/batch_refresh/strategy/visible_delay_stagger_strategy.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const static std::unordered_map<int32_t, int32_t> CONDITION_TYPE_MAP = {
    { FormRefreshType::TYPE_NETWORK, Constants::REFRESHTYPE_NETWORKCHANGED },
};
}

void VisibleDelayStaggerStrategy::Filter(std::vector<RefreshData> &batch, int32_t refreshType)
{
    auto &refreshControlMgr = RefreshControlMgr::GetInstance();
    auto &refreshCacheMgr = RefreshCacheMgr::GetInstance();
    auto mapIt = CONDITION_TYPE_MAP.find(refreshType);
    int32_t conditionType = (mapIt != CONDITION_TYPE_MAP.end()) ? mapIt->second : Constants::REFRESHTYPE_DEFAULT;
    auto it = std::remove_if(batch.begin(), batch.end(),
        [&refreshControlMgr, &refreshCacheMgr, conditionType](const RefreshData &data) {
        if (refreshControlMgr.IsFormInvisible(data.record)) {
            refreshCacheMgr.AddFlagByInvisible(data.formId, conditionType);
            return true;
        }
        return false;
    });
    batch.erase(it, batch.end());
}
} // namespace AppExecFwk
} // namespace OHOS
