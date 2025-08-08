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

#include "form_refresh/refresh_impl/form_refresh_after_uncontrol_impl.h"

#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {

FormRefreshAfterUncontrolImpl::FormRefreshAfterUncontrolImpl() {}
FormRefreshAfterUncontrolImpl::~FormRefreshAfterUncontrolImpl() {}

int FormRefreshAfterUncontrolImpl::RefreshFormRequest(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = { TYPE_UNTRUST_APP, TYPE_ACTIVE_USER, TYPE_ADD_FINISH };
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    factor.want = data.want;
    int ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor);
    if (ret != ERR_OK) {
        return ret;
    }

    if (RefreshControlMgr::GetInstance().IsHealthyControl(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(data.formId, true);
        return ERR_OK;
    }

    bool isCountTimerRefresh = data.want.GetBoolParam(Constants::KEY_IS_TIMER, false);
    bool isTimerRefresh = data.want.GetBoolParam(Constants::KEY_TIMER_REFRESH, false);
    data.want.RemoveParam(Constants::KEY_IS_TIMER);
    data.want.RemoveParam(Constants::KEY_TIMER_REFRESH);

    if (!DetectControlPoint(data, isCountTimerRefresh, isTimerRefresh)) {
        return ERR_OK;
    }

    if (!RefreshControlMgr::GetInstance().IsNeedToFresh(data.record, true)) {
        return ERR_OK;
    }

    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(data.record);
    refreshRecord.isCountTimerRefresh = isCountTimerRefresh;
    refreshRecord.isTimerRefresh = isTimerRefresh;
    ret = RefreshExecMgr::AskForProviderData(data.formId, refreshRecord, data.want);
    if (ret != ERR_OK) {
        HILOG_ERROR("ask for provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }

    return ERR_OK;
}

bool FormRefreshAfterUncontrolImpl::DetectControlPoint(
    RefreshData &data, bool &isCountTimerRefresh, const bool isTimerRefresh)
{
    int refreshType = data.want.GetIntParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_DEFAULT);
    if (isTimerRefresh) {
        FormDataMgr::GetInstance().SetTimerRefresh(data.formId, true);
    }

    if (isTimerRefresh && RefreshControlMgr::GetInstance().IsFormInvisible(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByInvisible(data.formId, refreshType);
        return false;
    }

    if (refreshType == Constants::REFRESHTYPE_VISIABLE) {
        FormDataMgr::GetInstance().GetRefreshType(data.formId, refreshType);
        HILOG_INFO("refreshType:%{public}d, formId:%{public}" PRId64, refreshType, data.formId);
        if (refreshType == Constants::REFRESHTYPE_NETWORKCHANGED) {
            isCountTimerRefresh = false;
        }
    }

    if (data.record.isSystemApp &&
        refreshType != Constants::REFRESHTYPE_DEFAULT && refreshType != Constants::REFRESHTYPE_VISIABLE) {
        data.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, refreshType);
    } else {
        data.want.RemoveParam(Constants::PARAM_FORM_REFRESH_TYPE);
    }

    if (isCountTimerRefresh) {
        FormDataMgr::GetInstance().SetCountTimerRefresh(data.formId, true);
    }

    if (RefreshControlMgr::GetInstance().IsScreenOff(data.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByScreenOff(data.formId, data.want, data.record);
        return false;
    }

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS