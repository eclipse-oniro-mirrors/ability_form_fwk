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

int FormNextTimeRefreshImpl::RefreshFormInput(RefreshData &data)
{
    const std::vector<int32_t> checkTypes = { TYPE_ACTIVE_USER, TYPE_CALLING_BUNDLE, TYPE_ADD_FINISH };
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

    if (!FormTimerMgr::GetInstance().SetNextRefreshTime(
        data.formId, data.nextTime * Constants::SEC_PER_MIN, userId)) {
        HILOG_ERROR("set next time refresh failed, formId:%{public}" PRId64, data.formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS