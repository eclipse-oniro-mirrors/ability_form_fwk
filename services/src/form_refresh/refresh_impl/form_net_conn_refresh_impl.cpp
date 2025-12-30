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

#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {

FormNetConnRefreshImpl::FormNetConnRefreshImpl() {}
FormNetConnRefreshImpl::~FormNetConnRefreshImpl() {}

int FormNetConnRefreshImpl::RefreshFormRequest(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = { TYPE_UNTRUST_APP, TYPE_SYSTEM_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_ADD_FINISH };
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    Want reqWant;
    reqWant.SetParam(Constants::PARAM_FORM_USER_ID, FormUtil::GetCurrentAccountId());
    factor.want = reqWant;
    int ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor);
    if (ret != ERR_OK) {
        return ret;
    }

    if (RefreshControlMgr::GetInstance().IsHealthyControl(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(data.formId, true);
        return ERR_OK;
    }

    FormDataMgr::GetInstance().SetTimerRefresh(data.formId, true);
    if (RefreshControlMgr::GetInstance().IsFormInvisible(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByInvisible(data.formId, Constants::REFRESHTYPE_NETWORKCHANGED);
        return ERR_OK;
    }

    if (data.record.isSystemApp) {
        reqWant.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_NETWORKCHANGED);
    }

    if (RefreshControlMgr::GetInstance().IsScreenOff(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByScreenOff(data.formId, data.want, data.record);
        return ERR_OK;
    }

    if (!RefreshControlMgr::GetInstance().IsNeedToFresh(data.record, true)) {
        FormDataMgr::GetInstance().SetNeedRefresh(data.formId, true);
        return ERR_OK;
    }

    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(data.record);
    ret = RefreshExecMgr::AskForProviderData(data.formId, refreshRecord, reqWant);
    if (ret != ERR_OK) {
        HILOG_ERROR("ask for provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS