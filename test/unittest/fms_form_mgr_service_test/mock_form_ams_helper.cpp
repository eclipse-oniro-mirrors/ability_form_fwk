/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_ams_helper.h"
#include "ability_connect_callback_interface.h"
#include "ability_manager_interface.h"
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace {
    OHOS::sptr<OHOS::AAFwk::IAbilityManager> g_mockAbilityManager_ = nullptr;
}

void MockGetAbilityManager(OHOS::sptr<OHOS::AAFwk::IAbilityManager> abilityManager)
{
    g_mockAbilityManager_ = abilityManager;
}

namespace OHOS {
namespace AppExecFwk {
FormAmsHelper::FormAmsHelper()
{}

FormAmsHelper::~FormAmsHelper()
{}

sptr<AAFwk::IAbilityManager> FormAmsHelper::GetAbilityManager()
{
    return g_mockAbilityManager_;
}

}  // namespace AppExecFwk
}  // namespace OHOS
