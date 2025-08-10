/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_RECORD_H
#define OHOS_FORM_FWK_FORM_RECORD_H

#include <vector>
#include "form_constants.h"
#include "form_info_base.h"
#include "form_instance.h"
#include "form_provider_info.h"
#include "application_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
/**
 * @class FormRecord
 * Form data.
 */
class FormRecord {
public:
    int64_t formId = 0;
    bool isInited = false;
    bool needFreeInstall = false;
    bool versionUpgrade = false;
    bool needRefresh = false;
    int refreshType;
    bool needAddForm = false;
    bool isCountTimerRefresh = false;
    std::string packageName = "";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string abilityName = "";
    std::string formName = "";
    int32_t specification;
    bool isEnableUpdate = false;
    bool isVisible = false;
    int64_t updateDuration = 0;
    int updateAtHour = -1;
    int updateAtMin = -1;
    std::vector<std::vector<int>> updateAtTimes;
    FormProviderInfo formProviderInfo;
    std::vector<std::string> hapSourceDirs;
    std::map<std::string, std::string> modulePkgNameMap;
    std::string jsFormCodePath = "";
    bool formTempFlag = false;
    std::vector<int> formUserUids;
    bool formVisibleNotify = false;
    int formVisibleNotifyState = 0;
    int32_t userId = 0;
    int32_t providerUserId = Constants::DEFAULT_PROVIDER_USER_ID;
    std::string formSrc = "";
    FormWindow formWindow;
    uint32_t versionCode = 0;
    std::string versionName = "";
    uint32_t compatibleVersion = 0;
    FormType type = FormType::JS;
    FormType uiSyntax = FormType::JS;
    bool isDynamic = true;
    bool transparencyEnabled = false;
    bool isTimerRefresh = false;
    bool isHostRefresh = false;
    bool isDataProxy = false;
    bool isDataProxyIgnoreFormVisible = false;
    bool isSystemApp = false;
    int32_t uid = 0;
    std::string description = "";
    int32_t privacyLevel = 0;
    bool isNeedNotify = true;
    RecycleStatus recycleStatus = RecycleStatus::NON_RECYCLABLE;
    Constants::FormLocation formLocation;
    bool isThemeForm = false;
    BundleType formBundleType = BundleType::APP;
    bool enableForm = true;
    bool isRefreshDuringDisableForm = false;
    bool isUpdateDuringDisableForm = false;
    Constants::RenderingMode renderingMode = Constants::RenderingMode::FULL_COLOR;
    bool lockForm = false;
    bool protectForm = false;
    std::vector<int32_t> conditionUpdate;
    std::map<int64_t, Want> wantCacheMap;
    bool isLocationChange = false;
    bool isExistRecycleTask = false;
    bool isDataProxyUpdate = false;
    bool isDistributedForm = false;
    std::string uiModule = "";
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_RECORD_H
