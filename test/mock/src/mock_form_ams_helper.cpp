/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_form_ams_helper.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormAmsHelper> MockFormAmsHelper::obj = nullptr;

ErrCode FormAmsHelper::StartAbility(const Want &want, int32_t userId)
{
    GTEST_LOG_(INFO) << "StartAbility called";
    if (AppExecFwk::MockFormAmsHelper::obj) {
        return AppExecFwk::MockFormAmsHelper::obj->StartAbility(want, userId);
    }
    return ERR_OK;
}

ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    GTEST_LOG_(INFO) << "ConnectServiceAbility called";
    if (AppExecFwk::MockFormAmsHelper::obj) {
        return AppExecFwk::MockFormAmsHelper::obj->ConnectServiceAbility(want, connect);
    }
    return ERR_OK;
}

ErrCode FormAmsHelper::ConnectServiceAbilityWithUserId(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId)
{
    GTEST_LOG_(INFO) << "ConnectServiceAbilityWithUserId called";
    if (AppExecFwk::MockFormAmsHelper::obj) {
        return AppExecFwk::MockFormAmsHelper::obj->ConnectServiceAbilityWithUserId(want, connect, userId);
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
