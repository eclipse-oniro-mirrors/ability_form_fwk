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

#include "form_host/form_mgr_host_adapter.h"

#include "data_center/database/form_db_cache.h"
#include "data_center/database/form_db_info.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormMgrHostAdapter::FormMgrHostAdapter()
{
    HILOG_DEBUG("call");
}

FormMgrHostAdapter::~FormMgrHostAdapter()
{
    HILOG_DEBUG("call");
}

void FormMgrHostAdapter::GetFormIdsByFormLocation(
    int32_t userId, Constants::FormLocation formLocation, std::vector<std::string> &formIds)
{
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    for (const auto &dbInfo : formDBInfos) {
        if (dbInfo.userId != userId) {
            continue;
        }
        if (dbInfo.formLocation == formLocation) {
            formIds.emplace_back(std::to_string(dbInfo.formId));
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS