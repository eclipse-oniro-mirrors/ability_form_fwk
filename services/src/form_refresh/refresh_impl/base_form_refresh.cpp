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

#include "form_refresh/refresh_impl/base_form_refresh.h"

#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "data_center/form_data_mgr.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

BaseFormRefresh::BaseFormRefresh(RefreshConfig config) 
    : config_(std::move(config))
{
}

int BaseFormRefresh::RefreshFormRequest(RefreshData &data)
{
    int ret = ERR_OK;
    // 1. Build check factor
    CheckValidFactor factor = BuildCheckFactor(data);

    // 2. Execute validation, check types are configured in each implementation class
    if (!config_.checkTypes.empty()) {
        ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(config_.checkTypes, factor);
        if (ret != ERR_OK) {
            return ret;
        }
    }

    // 3. Execute control checks, control checks are configured in each implementation class
    ret = DoControlCheck(data);
    if (ret != ERR_OK && ret != ERR_CONTINUE_REFRESH) {
        return ret;
    }

    // 4. Execute refresh if control checks pass
    if (ret == ERR_CONTINUE_REFRESH) {
        ret = DoRefresh(data);
        if (ret != ERR_OK) {
            HILOG_ERROR("do refresh failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
            return ret;
        }
    }

    return ret;
}

CheckValidFactor BaseFormRefresh::BuildCheckFactor(RefreshData &data)
{
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    factor.callerToken = data.callerToken;
    factor.want = data.want;
    factor.callingUid = data.callingUid;
    return factor;
}

int BaseFormRefresh::DoControlCheck(RefreshData &data)
{
    // Standard control check flow based on flags configured in each implementation class
    uint32_t flags = config_.controlCheckFlags;

    if (flags & CONTROL_CHECK_ADD_FINISH) {
        if (!RefreshControlMgr::GetInstance().IsAddFormFinish(data.formId)) {
            // Has set need update form on add form finish flag.
            return ERR_OK;
        }
    }

    // 1. System overload check for timer refresh
    if (flags & CONTROL_CHECK_SYSTEM_OVERLOAD) {
        if (RefreshControlMgr::GetInstance().IsSystemOverload()) {
            return ERR_OK;
        }
    }

    // 2. Healthy control check
    if (flags & CONTROL_CHECK_HEALTHY_CONTROL) {
        if (RefreshControlMgr::GetInstance().IsHealthyControl(data.record)) {
            RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(data.formId, true);
            return ERR_OK;
        }
    }

    // 3. Invisible check
    if (flags & CONTROL_CHECK_INVISIBLE) {
        if (RefreshControlMgr::GetInstance().IsFormInvisible(data.record)) {
            int32_t refreshType = data.want.GetIntParam(
                Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_DEFAULT);
            RefreshCacheMgr::GetInstance().AddFlagByInvisible(data.formId, refreshType);
            return ERR_OK;
        }
    }

    // 4. Screen off check
    if (flags & CONTROL_CHECK_SCREEN_OFF) {
        if (RefreshControlMgr::GetInstance().IsScreenOff(data.record)) {
            RefreshCacheMgr::GetInstance().AddFlagByScreenOff(data.formId, data.want, data.record);
            return ERR_OK;
        }
    }

    // 5. Need to fresh check
    if (flags & CONTROL_CHECK_NEED_TO_FRESH) {
        if (!RefreshControlMgr::GetInstance().IsNeedToFresh(data.record, config_.isVisibleToFresh)) {
            FormDataMgr::GetInstance().SetNeedRefresh(data.formId, true);
            return ERR_OK;
        }
    }

    return ERR_CONTINUE_REFRESH;
}

int BaseFormRefresh::DoRefresh(RefreshData &data)
{
    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(data.record);
    ErrCode ret = RefreshExecMgr::AskForProviderData(data.formId, refreshRecord, data.want);
    if (ret != ERR_OK) {
        HILOG_ERROR("ask for provider data failed, ret:%{public}d, formId:%{public}" PRId64, ret, data.formId);
        return ret;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS