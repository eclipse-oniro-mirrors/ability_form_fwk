/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_REPORTER_H
#define OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_REPORTER_H

#include <dlfcn.h>
#include <mutex>
#include <singleton.h>

#include "app_mgr_interface.h"
#include "form_ability_connection.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * Struct FormConnectionInfo
*/
struct FormConnectionInfo {
    int32_t pid_;
    int32_t connectCount_;
};

/**
 * @class FormAbilityConnectionReporter
 * Form Ability Connection Reporter.
 */
class FormAbilityConnectionReporter final : public DelayedRefSingleton<FormAbilityConnectionReporter> {
    DECLARE_DELAYED_REF_SINGLETON(FormAbilityConnectionReporter)
public:
    DISALLOW_COPY_AND_MOVE(FormAbilityConnectionReporter);

    /**
     * @brief Report form ability connection info to rss.
     * @param connection Form ability connection pointer.
     */
    void ReportFormAbilityConnection(const std::string &bundleName);

    /**
     * @brief Report form ability disconnection info to rss.
     * @param connection Form ability connection pointer.
     */
    void ReportFormAbilityDisconnection(const std::string &bundleName);

private:
    /**
     * @brief Get app manager proxy.
     * @return App manager proxy.
     */
    sptr<OHOS::AppExecFwk::IAppMgr> GetAppMgr();

    /**
     * @brief Add form ability connection info.
     * @param bundleName The bundle name of ability conncted with frs.
     * @param connectionProviderKey The connection's key of form ability connection.
     * @param infos The vector which contains running form ability process infos;
     */
    void AddFormAbilityConnectProcessInfo(const std::string &bundleName,
        std::vector<AppExecFwk::RunningProcessInfo> &infos);

    /**
     * @brief Reporter form ability connection infos to rss.
     * @param connectionProviderKey The connection's key of form ability connection.
     * @param isConnected True for form ability connected, false for form ability disconnected.
     */
    void ReportConnectionInfosToRss(const std::string &bundleName, bool isConnected);

private:
    std::mutex formConnectionInfoMapMutex_;
    std::map<std::string, FormConnectionInfo> formConnectionInfoMap_;
    sptr<OHOS::AppExecFwk::IAppMgr> appManager_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_REPORTER_H
