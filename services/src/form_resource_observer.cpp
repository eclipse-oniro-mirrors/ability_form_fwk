/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_resource_observer.h"

#include <thread>

#include "fms_log_wrapper.h"
#include "form_resource_param.h"
#include "form_task_mgr.h"
#include "configuration.h"

namespace OHOS {
namespace AppExecFwk {
FormFwkResourceObserver::FormFwkResourceObserver()
{
    colorMode_ == FormResourceParam::GetSystemColorMode();
    language_ == FormResourceParam::GetSystemLanguage();
}

FormFwkResourceObserver::~FormFwkResourceObserver()
{}

void FormFwkResourceObserver::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    HILOG_INFO("call");
    bool needUpdateForms = false;
    std::string colorMode = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
    if (!colorMode.empty() && colorMode != colorMode_) {
        HILOG_INFO("colorMode:%{public}s", colorMode.c_str());
        needUpdateForms = true;
        colorMode_ = colorMode;
    }
    std::string language = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    if (!language.empty() && language != language_) {
        HILOG_INFO("language:%{public}s", language.c_str());
        needUpdateForms = true;
        language_ = language;
    }
    if (needUpdateForms) {
        FormTaskMgr::GetInstance().PostBatchRefreshForms(Constants::REFRESH_SYSTEMAPP_FORM);
    }
    HILOG_INFO("end");
}
} // AppExecFwk
} // OHOS
