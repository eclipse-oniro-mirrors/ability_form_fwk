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

#include "fms_log_wrapper.h"
#include "form_refresh/batch_refresh/strategy/default_stagger_strategy.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {
int32_t DefaultStaggerStrategy::ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType)
{
    for (auto &data : batch) {
        int32_t ret = FormRefreshMgr::GetInstance().RequestRefresh(data, refreshType);
        if (ret != ERR_OK) {
            HILOG_WARN("DefaultStaggerStrategy::ExecuteRefresh: refresh failed for form %{public}" PRId64 ""
                ", err = %{public}d", data.formId, ret);
        }
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
