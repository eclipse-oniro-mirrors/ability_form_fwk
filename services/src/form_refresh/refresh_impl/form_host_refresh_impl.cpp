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

#include "form_refresh/refresh_impl/form_host_refresh_impl.h"

#include "form_refresh/strategy/refresh_config.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// Configuration for TYPE_HOST - check types and control checks
static RefreshConfig CreateConfig()
{
    RefreshConfig config;
    // Check types configuration
    config.checkTypes = { TYPE_UNTRUST_APP, TYPE_SELF_FORM, TYPE_ACTIVE_USER };
    // Control checks configuration
    config.controlCheckFlags = CONTROL_CHECK_HEALTHY_CONTROL | CONTROL_CHECK_SCREEN_OFF | CONTROL_CHECK_NEED_TO_FRESH
    | CONTROL_CHECK_ADD_FINISH;
    config.isVisibleToFresh = true;
    return config;
}
}

FormHostRefreshImpl::FormHostRefreshImpl() : BaseFormRefresh(CreateConfig()) {}
FormHostRefreshImpl::~FormHostRefreshImpl() {}

CheckValidFactor FormHostRefreshImpl::BuildCheckFactor(RefreshData &data)
{
    CheckValidFactor factor = BaseFormRefresh::BuildCheckFactor(data);
    Want reqWant(data.want);
    reqWant.SetParam(Constants::PARAM_FORM_USER_ID, FormUtil::GetCurrentAccountId());
    factor.want = reqWant;
    data.want = reqWant;
    return factor;
}

int FormHostRefreshImpl::DoControlCheck(RefreshData &data)
{
    FormDataMgr::GetInstance().UpdateFormWant(data.formId, data.want, data.record);
    FormDataMgr::GetInstance().UpdateFormRecord(data.formId, data.record);
    FormDataMgr::GetInstance().SetHostRefresh(data.formId, true);
    // Execute base class control checks first
    int ret = BaseFormRefresh::DoControlCheck(data);
    if (ret != ERR_CONTINUE_REFRESH) {
        return ret;
    }

    // System app special handling
    if (data.record.isSystemApp) {
        data.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_HOST);
    }

    return ERR_CONTINUE_REFRESH;
}
} // namespace AppExecFwk
} // namespace OHOS