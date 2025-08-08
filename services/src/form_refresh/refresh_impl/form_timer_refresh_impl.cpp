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

#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"

#include "ffrt.h"
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "data_center/form_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormTimerRefreshImpl::FormTimerRefreshImpl() {}
FormTimerRefreshImpl::~FormTimerRefreshImpl() {}

const static std::map<int32_t, int32_t> refreshTypeMap = {
    { RefreshType::TYPE_INTERVAL, Constants::REFRESHTYPE_INTERVAL },
    { RefreshType::TYPE_UPDATETIMES, Constants::REFRESHTYPE_UPDATETIMES },
    { RefreshType::TYPE_UPDATENEXTTIME, Constants::REFRESHTYPE_UPDATENEXTTIME },
};

int FormTimerRefreshImpl::RefreshFormRequest(RefreshData &data)
{
    FormRecord record;
    bool flag = FormDataMgr::GetInstance().GetFormRecord(data.formId, record);
    if (!flag) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", data.formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    Want reqWant;
    BuildTimerWant(data.formTimer, reqWant);
    auto task = [data, reqWant, record]() {
        RefreshData newData(data);
        newData.want = reqWant;
        newData.record = record;
        FormTimerRefreshImpl::GetInstance().DealRefresh(newData);
    };
    ffrt::submit(task);
    return ERR_OK;
}

int FormTimerRefreshImpl::DealRefresh(const RefreshData &data)
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

    if (RefreshControlMgr::GetInstance().IsSystemOverload()) {
        RefreshCacheMgr::GetInstance().AddToOverloadTaskQueue(data.formTimer);
        return ERR_OK;
    }

    RefreshData newData(data);
    if (RefreshControlMgr::GetInstance().IsHealthyControl(newData.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(newData.formId, true);
        return ERR_OK;
    }

    bool isCountTimerRefresh = newData.want.GetBoolParam(Constants::KEY_IS_TIMER, false);
    bool isTimerRefresh = newData.want.GetBoolParam(Constants::KEY_TIMER_REFRESH, false);
    newData.want.RemoveParam(Constants::KEY_IS_TIMER);
    newData.want.RemoveParam(Constants::KEY_TIMER_REFRESH);
    if (!DetectControlPoint(newData, isCountTimerRefresh, isTimerRefresh)) {
        return ERR_OK;
    }

    if (!RefreshControlMgr::GetInstance().IsNeedToFresh(newData.record, false)) {
        FormDataMgr::GetInstance().SetNeedRefresh(newData.formId, true);
        return ERR_OK;
    }

    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(newData.record);
    refreshRecord.isCountTimerRefresh = isCountTimerRefresh;
    refreshRecord.isTimerRefresh = isTimerRefresh;
    ret = RefreshExecMgr::AskForProviderData(newData.formId, refreshRecord, newData.want);
    if (ret != ERR_OK) {
        HILOG_ERROR("ask for provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, newData.formId);
        return ret;
    }

    return ERR_OK;
}

bool FormTimerRefreshImpl::DetectControlPoint(
    RefreshData &newData, const bool isCountTimerRefresh, const bool isTimerRefresh)
{
    int refreshType = newData.want.GetIntParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_DEFAULT);
    if (isTimerRefresh) {
        FormDataMgr::GetInstance().SetTimerRefresh(newData.formId, true);
    }

    if (RefreshControlMgr::GetInstance().IsFormInvisible(newData.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByInvisible(newData.formId, refreshType);
        return false;
    }

    if (!newData.record.isSystemApp) {
        newData.want.RemoveParam(Constants::PARAM_FORM_REFRESH_TYPE);
    }

    if (isCountTimerRefresh) {
        FormDataMgr::GetInstance().SetCountTimerRefresh(newData.formId, true);
    }

    if (RefreshControlMgr::GetInstance().IsScreenOff(newData.record)) {
        RefreshCacheMgr::GetInstance().AddFlagByScreenOff(newData.formId, newData.want, newData.record);
        return false;
    }

    return true;
}

void FormTimerRefreshImpl::BuildTimerWant(const FormTimer &timerTask, Want &want)
{
    if (timerTask.isCountTimer) {
        want.SetParam(Constants::KEY_IS_TIMER, true);
    }
    if (timerTask.isCountTimer || timerTask.isUpdateAt) {
        want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    }
    // multi user
    if (FormUtil::IsActiveUser(timerTask.userId)) {
        want.SetParam(Constants::PARAM_FORM_USER_ID, timerTask.userId);
    }
    auto it = refreshTypeMap.find(timerTask.refreshType);
    if (it != refreshTypeMap.end()) {
        want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, it->second);
    }
}

} // namespace AppExecFwk
} // namespace OHOS