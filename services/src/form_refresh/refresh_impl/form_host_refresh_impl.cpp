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

#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {

FormHostRefreshImpl::FormHostRefreshImpl() {}
FormHostRefreshImpl::~FormHostRefreshImpl() {}

int FormHostRefreshImpl::RefreshFormInput(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = { TYPE_SELF_FORM, TYPE_ACTIVE_USER, TYPE_ADD_FINISH };
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    factor.callerToken = data.callerToken;
    Want reqWant(data.want);
    reqWant.SetParam(Constants::PARAM_FORM_USER_ID, FormUtil::GetCurrentAccountId());
    factor.want = reqWant;
    int ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor);
    if (ret != ERR_OK) {
        return ret;
    }

    FormDataMgr::GetInstance().UpdateFormWant(data.formId, data.want, data.record);
    FormDataMgr::GetInstance().UpdateFormRecord(data.formId, data.record);
    if (RefreshControlMgr::GetInstance().IsHealthyControl(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(data.formId, true);
        return ERR_OK;
    }

    if (data.record.isSystemApp) {
        reqWant.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_HOST);
    }

    if (RefreshControlMgr::GetInstance().IsScreenOff(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByScreenOff(data.formId, data.want, data.record);
        return ERR_OK;
    }

    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(data.record);
    ret = RefreshExecMgr::AskForProviderData(data.formId, data.record, reqWant);
    if (ret != ERR_OK) {
        HILOG_ERROR("ask for provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS