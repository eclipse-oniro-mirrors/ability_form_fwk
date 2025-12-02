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

#include "mock_param_control.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/param_update/param_control.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockParamControl> MockParamControl::obj = nullptr;

ParamControl::ParamControl()
{}

ParamControl::~ParamControl()
{}

bool ParamControl::IsFormDisable(const FormRecord &formRecord)
{
    if (MockParamControl::obj) {
        return MockParamControl::obj->IsFormDisable(formRecord);
    }
    return false;
}

bool ParamControl::IsFormRemove(const FormRecord &formRecord)
{
    if (MockParamControl::obj) {
        return MockParamControl::obj->IsFormRemove(formRecord);
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS