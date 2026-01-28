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

#include "form_refresh/refresh_impl/form_net_conn_refresh_impl.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Configuration for form network connection refresh, check types and control checks
static RefreshConfig CreateConfig()
{
    RefreshConfig config;
    // Check types configuration
    config.checkTypes = { TYPE_UNTRUST_APP, TYPE_SYSTEM_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_ADD_FINISH };
    // Control checks configuration
    config.controlCheckFlags = CONTROL_CHECK_HEALTHY_CONTROL | CONTROL_CHECK_INVISIBLE | CONTROL_CHECK_SCREEN_OFF |
        CONTROL_CHECK_NEED_TO_FRESH;
    config.refreshType = Constants::REFRESHTYPE_NETWORKCHANGED;
    return config;
}
}

FormNetConnRefreshImpl::FormNetConnRefreshImpl() : BaseFormRefresh(CreateConfig()) {}
FormNetConnRefreshImpl::~FormNetConnRefreshImpl() {}

int FormNetConnRefreshImpl::DoRefresh(RefreshData &data)
{
    // System app set refresh type
    if (data.record.isSystemApp) {
        data.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_NETWORKCHANGED);
    }
    return BaseFormRefresh::DoRefresh(data);
}
} // namespace AppExecFwk
} // namespace OHOS