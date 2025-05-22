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

#include "form_observer/form_resource_observer.h"

#include <thread>

#include "fms_log_wrapper.h"
#include "form_resource_param.h"
#include "form_observer/form_observer_task_mgr.h"
#include "configuration.h"

namespace OHOS {
namespace AppExecFwk {
FormFwkResourceObserver::FormFwkResourceObserver()
{
    language_ = FormResourceParam::GetSystemLanguage();
}

FormFwkResourceObserver::~FormFwkResourceObserver()
{}

void FormFwkResourceObserver::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    HILOG_INFO("language: %{public}s colorMode: %{public}s",
        configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE).c_str(),
        configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE).c_str());
    std::string language = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    if (!language.empty() && language != language_) {
        HILOG_INFO("language changed %{public}s to %{public}s", language_.c_str(), language.c_str());
        language_ = language;
        FormTaskMgr::GetInstance().PostBatchConfigurationUpdateForms(configuration);
    }
    HILOG_INFO("end");
}
} // AppExecFwk
} // OHOS
