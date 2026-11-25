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

#include "form_refresh/refresh_impl/form_reminder_agent_refresh_impl.h"

#include "data_center/form_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Configuration for reminder agent triggered refresh, check types and control checks
RefreshConfig CreateConfig()
{
    RefreshConfig config;
    // Check types configuration
    config.checkTypes = { TYPE_UNTRUST_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_ADD_FINISH };
    // Control checks configuration
    config.controlCheckFlags = CONTROL_CHECK_HEALTHY_CONTROL | CONTROL_CHECK_INVISIBLE |
        CONTROL_CHECK_SCREEN_OFF | CONTROL_CHECK_NEED_TO_FRESH;
    return config;
}
}

FormReminderAgentRefreshImpl::FormReminderAgentRefreshImpl() : BaseFormRefresh(CreateConfig()) {}
FormReminderAgentRefreshImpl::~FormReminderAgentRefreshImpl() {}

int FormReminderAgentRefreshImpl::DoControlCheck(RefreshData &data)
{
    data.want.SetParam(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY, true);
    FormDataMgr::GetInstance().SetReminderAgentRefresh(data.formId, true);
    // Execute base class control checks
    return BaseFormRefresh::DoControlCheck(data);
}
} // namespace AppExecFwk
} // namespace OHOS
