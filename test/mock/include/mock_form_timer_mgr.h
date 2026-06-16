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

#ifndef OHOS_FORM_FWK_MOCK_FORM_TIMER_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_TIMER_MGR_H

#include <cstdint>
#include <memory>
#include <vector>
#include "common/timer_mgr/form_timer.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormTimerMgr {
public:
    virtual ~AbstractMockFormTimerMgr() = default;
    virtual bool AddFormTimer(int64_t formId, long updateDuration, int32_t userId) = 0;
    virtual bool AddFormTimerForMultiUpdate(int64_t formId,
        std::vector<std::vector<int>> updateAtTimes, int32_t userId) = 0;
    virtual bool AddFormTimerAtTime(int64_t formId, long updateAtHour, long updateAtMin, int32_t userId) = 0;
    virtual bool GetIntervalTimer(int64_t formId, FormTimer &formTimer) = 0;
    virtual bool GetUpdateAtTimer(int64_t formId, UpdateAtItem &updateAtItem) = 0;
    virtual bool GetDynamicItem(int64_t formId, DynamicRefreshItem &dynamicItem) = 0;
};

class MockFormTimerMgr : public AbstractMockFormTimerMgr {
public:
    static std::shared_ptr<MockFormTimerMgr> obj;
    MockFormTimerMgr() = default;
    ~MockFormTimerMgr() override = default;
    MOCK_METHOD3(AddFormTimer, bool(int64_t formId, long updateDuration, int32_t userId));
    MOCK_METHOD3(AddFormTimerForMultiUpdate, bool(int64_t formId,
        std::vector<std::vector<int>> updateAtTimes, int32_t userId));
    MOCK_METHOD4(AddFormTimerAtTime, bool(int64_t formId, long updateAtHour, long updateAtMin, int32_t userId));
    MOCK_METHOD2(GetIntervalTimer, bool(int64_t formId, FormTimer &formTimer));
    MOCK_METHOD2(GetUpdateAtTimer, bool(int64_t formId, UpdateAtItem &updateAtItem));
    MOCK_METHOD2(GetDynamicItem, bool(int64_t formId, DynamicRefreshItem &dynamicItem));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_TIMER_MGR_H
