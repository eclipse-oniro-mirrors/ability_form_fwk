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

#include "live_form_extension_module_loader.h"
#include "fms_log_wrapper.h"
#include "live_form_extension.h"

namespace OHOS {
namespace AbilityRuntime {
LiveFormExtensionModuleLoader::LiveFormExtensionModuleLoader() = default;
LiveFormExtensionModuleLoader::~LiveFormExtensionModuleLoader() = default;

Extension *LiveFormExtensionModuleLoader::Create(const std::unique_ptr<Runtime> &runtime) const
{
    HILOG_DEBUG("called");
    return LiveFormExtension::Create(runtime);
}

std::map<std::string, std::string> LiveFormExtensionModuleLoader::GetParams()
{
    HILOG_DEBUG("called");
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of
    // extension_ability_info.h, 30 means liveFormExtension.
    params.insert(std::pair<std::string, std::string>("type", "30"));
    params.insert(std::pair<std::string, std::string>("name", "LiveFormExtensionAbility"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void *OHOS_EXTENSION_GetExtensionModule()
{
    return &LiveFormExtensionModuleLoader::GetInstance();
}
} // namespace AbilityRuntime
} // namespace OHOS