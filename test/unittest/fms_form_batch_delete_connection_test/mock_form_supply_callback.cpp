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

#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_provider/form_supply_callback.h"
#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {
void FormSupplyCallback::AddConnection(sptr<FormAbilityConnection> connection)
{
    HILOG_INFO("Mock FormSupplyCallback AddConnection");
    return;
}
} // namespace AppExecFwk
} // namespace OHOS
