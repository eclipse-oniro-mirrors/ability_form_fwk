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

#include "mock_form_timer_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "common/timer_mgr/form_timer_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormTimerMgr> MockFormTimerMgr::obj = nullptr;

bool FormTimerMgr::AddFormTimer(int64_t formId, long updateDuration, int32_t userId)
{
    GTEST_LOG_(INFO) << "AddFormTimer(duration) called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->AddFormTimer(formId, updateDuration, userId);
    }
    return false;
}

bool FormTimerMgr::AddFormTimerForMultiUpdate(int64_t formId,
    std::vector<std::vector<int>> updateAtTimes, int32_t userId)
{
    GTEST_LOG_(INFO) << "AddFormTimerForMultiUpdate called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);
    }
    return false;
}

bool FormTimerMgr::AddFormTimer(int64_t formId, long updateAtHour, long updateAtMin, int32_t userId)
{
    GTEST_LOG_(INFO) << "AddFormTimer(hour,min) called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->AddFormTimerAtTime(formId, updateAtHour, updateAtMin, userId);
    }
    return false;
}

bool FormTimerMgr::GetIntervalTimer(int64_t formId, FormTimer &formTimer)
{
    GTEST_LOG_(INFO) << "GetIntervalTimer called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->GetIntervalTimer(formId, formTimer);
    }
    return false;
}

bool FormTimerMgr::GetUpdateAtTimer(int64_t formId, UpdateAtItem &updateAtItem)
{
    GTEST_LOG_(INFO) << "GetUpdateAtTimer called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->GetUpdateAtTimer(formId, updateAtItem);
    }
    return false;
}

bool FormTimerMgr::GetDynamicItem(int64_t formId, DynamicRefreshItem &dynamicItem)
{
    GTEST_LOG_(INFO) << "GetDynamicItem called";
    if (AppExecFwk::MockFormTimerMgr::obj) {
        return AppExecFwk::MockFormTimerMgr::obj->GetDynamicItem(formId, dynamicItem);
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
