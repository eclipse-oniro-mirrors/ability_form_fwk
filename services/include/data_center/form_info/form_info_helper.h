/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_INFO_HELPER_H
#define OHOS_FORM_FWK_FORM_INFO_HELPER_H

#include <shared_mutex>
#include <singleton.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "form_constants.h"
#include "form_info.h"
#include "resource_manager.h"

namespace OHOS {
namespace AppExecFwk {
class FormInfoHelper {
public:
    static ErrCode LoadFormConfigInfoByBundleName(const std::string &bundleName, std::vector<FormInfo> &formInfos,
        int32_t userId);

private:
    static ErrCode LoadAbilityFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos);

    static ErrCode LoadStageFormConfigInfo(
        const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    static std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager(const BundleInfo &bundleInfo);

    static ErrCode GetFormInfoDescription(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
        FormInfo &formInfo);

    static ErrCode GetFormInfoDisplayName(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
        FormInfo &formInfo);

    static bool LoadSharedModuleInfo(const BundleInfo &bundleInfo, HapModuleInfo &shared);

    static void PrintLoadStageFormConfigInfo(const FormInfo &formInfo, bool hasDistributedForm);

    static void SetDistributedBundleStatus(int32_t userId, const std::string &entryModule, const std::string &uiModule,
        const std::string &bundleInfoName, bool hasDistributedForm);

    static void SendLoadStageFormConfigEvent(const FormInfo& formInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_INFO_HELPER_H
