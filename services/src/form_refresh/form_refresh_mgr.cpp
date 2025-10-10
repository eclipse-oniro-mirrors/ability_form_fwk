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

#include "form_refresh/form_refresh_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_event_report.h"
#include "form_refresh/refresh_impl/form_host_refresh_impl.h"
#include "form_refresh/refresh_impl/form_net_conn_refresh_impl.h"
#include "form_refresh/refresh_impl/form_next_time_refresh_impl.h"
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#include "form_refresh/refresh_impl/form_data_refresh_impl.h"
#include "form_refresh/refresh_impl/form_force_refresh_impl.h"
#include "form_refresh/refresh_impl/form_refresh_after_uncontrol_impl.h"
#include "form_refresh/refresh_impl/form_app_upgrade_refresh_impl.h"
#include "form_refresh/refresh_impl/form_provider_refresh_impl.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const static std::set<int> ERROR_CODE_WHITE_LIST = {
    ERR_OK,
    ERR_APPEXECFWK_FORM_INVALID_PARAM,
    ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
    ERR_APPEXECFWK_FORM_DISABLE_REFRESH
};
}

FormRefreshMgr::FormRefreshMgr() {}
FormRefreshMgr::~FormRefreshMgr() {}

const static std::map<int32_t, IFormRefresh *> refreshMap = {
    { TYPE_HOST, &FormHostRefreshImpl::GetInstance() },
    { TYPE_NETWORK, &FormNetConnRefreshImpl::GetInstance() },
    { TYPE_NEXT_TIME, &FormNextTimeRefreshImpl::GetInstance() },
    { TYPE_TIMER, &FormTimerRefreshImpl::GetInstance() },
    { TYPE_DATA, &FormDataRefreshImpl::GetInstance() },
    { TYPE_FORCE, &FormForceRefreshImpl::GetInstance() },
    { TYPE_UNCONTROL, &FormRefreshAfterUncontrolImpl::GetInstance() },
    { TYPE_APP_UPGRADE, &FormAppUpgradeRefreshImpl::GetInstance() },
    { TYPE_PROVIDER, &FormProviderRefreshImpl::GetInstance() },
};

int FormRefreshMgr::RequestRefresh(RefreshData &data, const int32_t refreshType)
{
    HILOG_INFO("refreshInputType:%{public}d, formId:%{public}" PRId64, refreshType, data.formId);
    auto it = refreshMap.find(refreshType);
    if (it != refreshMap.end()) {
        int ret = it->second->RefreshFormRequest(data);
        if (ERROR_CODE_WHITE_LIST.find(ret) == ERROR_CODE_WHITE_LIST.end()) {
            FormEventReport::SendFormFailedEvent(FormEventName::UPDATE_FORM_FAILED,
                data.formId,
                data.record.bundleName,
                data.record.formName,
                refreshType,
                ret);
        }
        return ret;
    }

    HILOG_ERROR("invalid refreshType");
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

} // namespace AppExecFwk
} // namespace OHOS