/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "form_provider/form_provider_mgr.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockNotifyProviderFormsBatchDelete = false;
}

void MockNotifyProviderFormsBatchDelete(bool mockRet)
{
    g_mockNotifyProviderFormsBatchDelete = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
ErrCode FormProviderMgr::NotifyProviderFormsBatchDelete(const std::string &bundleName, const std::string &abilityName,
    const std::set<int64_t> &formIds, const int32_t userId)
{
    if (g_mockNotifyProviderFormsBatchDelete) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS