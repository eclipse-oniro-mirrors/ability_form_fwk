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

#include "form_refresh/refresh_impl/form_next_time_refresh_impl.h"

#include "form_refresh/strategy/refresh_check_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "data_center/form_record/form_record_report.h"

namespace OHOS {
namespace AppExecFwk {

FormNextTimeRefreshImpl::FormNextTimeRefreshImpl() {}
FormNextTimeRefreshImpl::~FormNextTimeRefreshImpl() {}

int FormNextTimeRefreshImpl::RefreshFormRequest(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = {
        TYPE_UNTRUST_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_CALLING_BUNDLE, TYPE_ADD_FINISH
    };
    CheckValidFactor factor;
    factor.formId = data.formId;
    factor.record = data.record;
    int32_t userId = FormUtil::GetCurrentAccountId();
    Want reqWant;
    reqWant.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    factor.want = reqWant;
    int ret = RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor);
    if (ret != ERR_OK) {
        return ret;
    }

    if (data.nextTime < 0) {
        HILOG_ERROR("nextTime is negative, formId:%{public}" PRId64, data.formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
 
    const int32_t MAX_NEXT_TIME = INT32_MAX / Constants::SEC_PER_MIN;
    if (data.nextTime > MAX_NEXT_TIME) {
        HILOG_ERROR("nextTime exceeds safety range, formId:%{public}" PRId64, data.formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (data.record.isDataProxy) {
        HILOG_INFO("data proxy form set next refresh time formId:%{public}" PRId64, data.formId);
    }

    int32_t timerRefreshedCount = FormTimerMgr::GetInstance().GetRefreshCount(data.formId);
    if (timerRefreshedCount >= Constants::LIMIT_COUNT) {
        HILOG_WARN("already reach max times:%{public}d, formId:%{public}" PRId64, timerRefreshedCount, data.formId);
        FormRecordReport::GetInstance().IncreaseUpdateTimes(data.formId, HiSysEventPointType::TYPE_HIGH_FREQUENCY);
        FormTimerMgr::GetInstance().MarkRemind(data.formId);
        return ERR_APPEXECFWK_FORM_MAX_REFRESH;
    }

    int64_t safeNextTime = static_cast<int64_t>(data.nextTime) * Constants::SEC_PER_MIN;
    if (!FormTimerMgr::GetInstance().SetNextRefreshTime(data.formId, safeNextTime, userId)) {
        HILOG_ERROR("set next time refresh failed, formId:%{public}" PRId64, data.formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS