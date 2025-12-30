/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_APP_MGR_HELPER_H
#define OHOS_FORM_FWK_FORM_APP_MGR_HELPER_H

#include <singleton.h>

#include "app_mgr_interface.h"
#include "extension_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormAppMgrHelper
 * App mgr helper.
 */
class FormAppMgrHelper final : public DelayedRefSingleton<FormAppMgrHelper> {
    DECLARE_DELAYED_REF_SINGLETON(FormAppMgrHelper)
public:
    DISALLOW_COPY_AND_MOVE(FormAppMgrHelper);

    /**
     * @brief Check if ability is foreground
     * @param bundleName the bundle name
     * @param extensionAbilityType the extension ability type
     */
    bool IsAbilityForeground(const std::string &bundleName, ExtensionAbilityType extensionAbilityType);

    /**
     * @brief Check if ability is foreground
     * @param bundleName the bundle name
     * @param userId the user id that app belong to
     * @param info the running process info
     * @param processNameSuffix the suffix of process name
     */
    bool GetRunningProcessInfo(const std::string &bundleName, int32_t userId, RunningProcessInfo &info,
        const std::string &processNameSuffix = "");

private:
    /**
     * @brief acquire a form app manager if it not existed,
     * @return returns the app manager ipc object or nullptr for failed.
     */
    sptr<IAppMgr> GetAppMgr();
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_APP_MGR_HELPER_H
