/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <chrono>
#include <gtest/gtest.h>

#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "form_constants.h"
#define private public
#include "common/timer_mgr/form_refresh_limiter.h"
#include "common/timer_mgr/form_timer_mgr.h"
#undef private
#include "remote_native_token.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t PARAM_FORM_ID_VALUE_1 = 20210712;
const int64_t PARAM_FORM_ID_VALUE_2 = 20210713;
const int64_t PARAM_FORM_ID_VALUE_3 = 20210714;
const int64_t PARAM_FORM_ID_VALUE_4 = 20210715;
const int64_t PARAM_FORM_ID_VALUE_5 = 20210716;
const int64_t PARAM_FORM_ID_VALUE_6 = 20210717;

class FmsFormTimerMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormTimerMgrTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
}
void FmsFormTimerMgrTest::TearDownTestCase() {}
void FmsFormTimerMgrTest::SetUp() {}
void FmsFormTimerMgrTest::TearDown() {}

/**
 * @tc.number: Fms_FormTimerMgr_0001
 * @tc.name: AddFormTimer.
 * @tc.desc: Add duration form timer.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0001 start";
    bool isOk = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_1,  1 * Constants::MIN_PERIOD);
    EXPECT_EQ(isOk, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0001 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0002
 * @tc.name: AddFormTimer.
 * @tc.desc: Add scheduled form timer.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0002 start";
    bool isOk = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_2,  2, 50, 0);
    EXPECT_EQ(isOk, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0002 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0003
 * @tc.name: RemoveFormTimer.
 * @tc.desc: Delete form timer.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0003, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0003 start";
    bool isAddOk1 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_3,  336 * Constants::MIN_PERIOD);
    EXPECT_EQ(isAddOk1, true);
    bool isAddOk2 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_4,  3, 30, 0);
    EXPECT_EQ(isAddOk2, true);
    bool isDelOk1 = FormTimerMgr::GetInstance().RemoveFormTimer(PARAM_FORM_ID_VALUE_3);
    EXPECT_EQ(isDelOk1, true);
    bool isDelOk2 = FormTimerMgr::GetInstance().RemoveFormTimer(PARAM_FORM_ID_VALUE_4);
    EXPECT_EQ(isDelOk2, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0003 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0004
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_INTERVAL_CHANGE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0004, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0004 start";
    bool isAddOk1 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_1,  3 * Constants::MIN_PERIOD);
    EXPECT_EQ(isAddOk1, true);

    // TYPE_INTERVAL_CHANGE
    FormTimerCfg timerCfg1;
    timerCfg1.enableUpdate = true;
    timerCfg1.updateDuration = 2 * Constants::MIN_PERIOD;
    bool isUpdateOk1 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_1,
    UpdateType::TYPE_INTERVAL_CHANGE, timerCfg1);
    EXPECT_EQ(isUpdateOk1, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0004 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0005
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_ATTIME_CHANGE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0005, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0005 start";
    bool isAddOk2 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_2,  3, 30, 0);
    EXPECT_EQ(isAddOk2, true);

    // TYPE_ATTIME_CHANGE
    FormTimerCfg timerCfg2;
    timerCfg2.enableUpdate = true;
    timerCfg2.updateAtHour = 6;
    timerCfg2.updateAtMin = 55;
    bool isUpdateOk2 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_2,
    UpdateType::TYPE_ATTIME_CHANGE,  timerCfg2);
    EXPECT_EQ(isUpdateOk2, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0005 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0006
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_INTERVAL_TO_ATTIME).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0006, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0006 start";
    bool isAddOk3 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_3,  6 * Constants::MIN_PERIOD);
    EXPECT_EQ(isAddOk3, true);

    // TYPE_INTERVAL_TO_ATTIME
    FormTimerCfg timerCfg3;
    timerCfg3.enableUpdate = true;
    timerCfg3.updateAtHour = 8;
    timerCfg3.updateAtMin = 25;
    bool isUpdateOk3 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_3,
    UpdateType::TYPE_INTERVAL_TO_ATTIME,  timerCfg3);
    EXPECT_EQ(isUpdateOk3, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0006 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0007
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_ATTIME_TO_INTERVAL).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0007, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0007 start";
    bool isAddOk4 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_4,  10, 30, 0);
    EXPECT_EQ(isAddOk4, true);

    // TYPE_ATTIME_TO_INTERVAL
    FormTimerCfg timerCfg4;
    timerCfg4.enableUpdate = true;
    timerCfg4.updateDuration = 5 * Constants::MIN_PERIOD;
    bool isUpdateOk4 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_4,
    UpdateType::TYPE_ATTIME_TO_INTERVAL,  timerCfg4);
    EXPECT_EQ(isUpdateOk4, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0007 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0008
 * @tc.name: HandleSystemTimeChanged.
 * @tc.desc: Handle system time changed.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0008, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0008 start";
    bool isAddOk5 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_1,  11, 30, 0);
    EXPECT_EQ(isAddOk5, true);
    bool isAddOk6 = FormTimerMgr::GetInstance().HandleSystemTimeChanged();
    EXPECT_EQ(isAddOk6, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0008 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0009
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Receive common event(COMMON_EVENT_TIMEZONE_CHANGED).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0009, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0009 start";
    bool isAddOk5 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_2,  11, 30, 0);
    EXPECT_EQ(isAddOk5, true);
    bool isAddOk6 = FormTimerMgr::GetInstance().HandleSystemTimeChanged();
    EXPECT_EQ(isAddOk6, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0009 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0010
 * @tc.name: HandleResetLimiter.
 * @tc.desc: Handle reset limiter.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0010, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0010 start";
    bool isAddOk5 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_3,  16, 30, 0);
    EXPECT_EQ(isAddOk5, true);
    bool isAddOk6 = FormTimerMgr::GetInstance().HandleResetLimiter();
    EXPECT_EQ(isAddOk6, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0010 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0011
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc:handle attimer update.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0011, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0011 start";
    bool isAddOk5 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_4,  11, 30, 0);
    EXPECT_EQ(isAddOk5, true);

    bool isAddOk6 = FormTimerMgr::GetInstance().OnUpdateAtTrigger(90L);
    EXPECT_EQ(isAddOk6, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0011 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0012
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: handle dynamic update.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0012, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0012 start";
    bool isAddOk5 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_5,  11, 30, 0);
    EXPECT_EQ(isAddOk5, true);

    bool isAddOk6 = FormTimerMgr::GetInstance().OnDynamicTimeTrigger(90L);
    EXPECT_EQ(isAddOk6, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0012 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0013
 * @tc.name: AddFormTimer.
 * @tc.desc: Add duration form timer.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0013, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0013 start";
    bool isOk = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_1,  0);
    EXPECT_EQ(isOk, false);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0013 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0014
 * @tc.name: AddFormTimer.
 * @tc.desc: Add scheduled form timer.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0014, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0014 start";
    bool isOk = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_2,  0, 60, 0);
    EXPECT_EQ(isOk, false);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0014 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0015
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_INTERVAL_CHANGE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0015, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0015 start";
    bool isAddOk1 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_1,  3 * Constants::MIN_PERIOD);
    EXPECT_EQ(isAddOk1, true);

    // TYPE_INTERVAL_CHANGE
    FormTimerCfg timerCfg1;
    timerCfg1.enableUpdate = true;
    timerCfg1.updateDuration = 0;
    bool isUpdateOk1 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_1,
    UpdateType::TYPE_INTERVAL_CHANGE, timerCfg1);
    EXPECT_EQ(isUpdateOk1, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0015 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0016
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_ATTIME_CHANGE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0016, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0016 start";
    bool isAddOk2 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_2,  3, 30, 0);
    EXPECT_EQ(isAddOk2, true);

    // TYPE_ATTIME_CHANGE
    FormTimerCfg timerCfg2;
    timerCfg2.enableUpdate = true;
    timerCfg2.updateAtHour = 0;
    timerCfg2.updateAtMin = 60;
    bool isUpdateOk2 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_2,
    UpdateType::TYPE_ATTIME_CHANGE,  timerCfg2);
    EXPECT_EQ(isUpdateOk2, false);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0016 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0017
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_INTERVAL_TO_ATTIME).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0017, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0017 start";
    bool isAddOk3 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_3,  6 * Constants::MIN_PERIOD);
    EXPECT_EQ(isAddOk3, true);

    // TYPE_INTERVAL_TO_ATTIME
    FormTimerCfg timerCfg3;
    timerCfg3.enableUpdate = true;
    timerCfg3.updateAtHour = 0;
    timerCfg3.updateAtMin = 60;
    bool isUpdateOk3 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_3,
    UpdateType::TYPE_INTERVAL_TO_ATTIME,  timerCfg3);
    EXPECT_EQ(isUpdateOk3, false);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0017 end";
}
/**
 * @tc.number: Fms_FormTimerMgr_0018
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_ATTIME_TO_INTERVAL).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0018, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0018 start";
    bool isAddOk4 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_4,  10, 30, 0);
    EXPECT_EQ(isAddOk4, true);

    // TYPE_ATTIME_TO_INTERVAL
    FormTimerCfg timerCfg4;
    timerCfg4.enableUpdate = true;
    timerCfg4.updateDuration = 0;
    bool isUpdateOk4 = FormTimerMgr::GetInstance().UpdateFormTimer(PARAM_FORM_ID_VALUE_4,
    UpdateType::TYPE_ATTIME_TO_INTERVAL,  timerCfg4);
    EXPECT_EQ(isUpdateOk4, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0018 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0019
 * @tc.name: FormRefreshLimiter::AddItem.
 * @tc.desc: AddItem success.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0019, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0019 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_1);
    EXPECT_EQ(isAddOk, true);

    EXPECT_EQ(refreshLimiter.GetItemCount(), 1);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0019 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0020
 * @tc.name: FormRefreshLimiter::DeleteItem.
 * @tc.desc: DeleteItem success.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0020, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0020 start";

    FormRefreshLimiter refreshLimiter;
    refreshLimiter.DeleteItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(refreshLimiter.GetItemCount(), 0);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0020 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0021
 * @tc.name: FormRefreshLimiter::IsEnableRefresh.
 * @tc.desc: IsEnableRefresh.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0021, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0021 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);
    bool isEnableRefresh = refreshLimiter.IsEnableRefresh(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isEnableRefresh, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0021 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0022
 * @tc.name: FormRefreshLimiter::Increase.
 * @tc.desc: Increase refreshCount.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0022, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0022 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);

    refreshLimiter.Increase(PARAM_FORM_ID_VALUE_6);

    int count = refreshLimiter.GetRefreshCount(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(count, 1);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0022 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0023
 * @tc.name: FormRefreshLimiter::ResetLimit.
 * @tc.desc: ResetLimit.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0023, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0023 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);

    refreshLimiter.Increase(PARAM_FORM_ID_VALUE_6);

    refreshLimiter.ResetLimit();

    int count = refreshLimiter.GetRefreshCount(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(count, 0);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0023 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0024
 * @tc.name: FormRefreshLimiter::Increase.
 * @tc.desc: report refresh to 50 count.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0024, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0024 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);
    for (int iIndex = 0; iIndex < Constants::LIMIT_COUNT; iIndex++) {
        refreshLimiter.Increase(PARAM_FORM_ID_VALUE_6);
    }

    int count = refreshLimiter.GetRefreshCount(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(count, Constants::LIMIT_COUNT);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0024 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0025
 * @tc.name: FormRefreshLimiter::IsEnableRefresh.
 * @tc.desc: report refresh to 50 count.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0025, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0025 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);
    for (int iIndex = 0; iIndex < Constants::LIMIT_COUNT + 1; iIndex++) {
        refreshLimiter.Increase(PARAM_FORM_ID_VALUE_6);
    }

    bool isEnableRefresh = refreshLimiter.IsEnableRefresh(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isEnableRefresh, false);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0025 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0026
 * @tc.name: FormRefreshLimiter::MarkRemind.
 * @tc.desc: Mark remind when refresh count >= 50.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0026, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0026 start";

    FormRefreshLimiter refreshLimiter;
    bool isAddOk = refreshLimiter.AddItem(PARAM_FORM_ID_VALUE_6);
    EXPECT_EQ(isAddOk, true);
    for (int iIndex = 0; iIndex < Constants::LIMIT_COUNT + 1; iIndex++) {
        refreshLimiter.Increase(PARAM_FORM_ID_VALUE_6);
    }

    refreshLimiter.MarkRemind(PARAM_FORM_ID_VALUE_6);

    std::vector<int64_t> vIdlist = refreshLimiter.GetRemindList();
    EXPECT_EQ(vIdlist.size() > 0, true);

    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0026 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0027
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: Interval timer timeout.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0027, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0027 start";
    bool isAddOk4 = FormTimerMgr::GetInstance().AddFormTimer(PARAM_FORM_ID_VALUE_6,  10, 30, 0);
    EXPECT_EQ(isAddOk4, true);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0027 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0028
 * @tc.name: UpdateFormTimer.
 * @tc.desc: test UpdateFormTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0028, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0028 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateType type = UpdateType::TYPE_ATTIME_TO_INTERVAL;
    FormTimerCfg timerCfg;
    EXPECT_EQ(false, formTimerMgr.UpdateFormTimer(formId, type, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0028 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0029
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Update form timer(TYPE_INTERVAL_ONCE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0029, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0029 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateType type = UpdateType::TYPE_INTERVAL_ONCE;
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = true;
    EXPECT_EQ(false, formTimerMgr.UpdateFormTimer(formId, type, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0029 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0030
 * @tc.name: UpdateIntervalValue.
 * @tc.desc: test UpdateIntervalValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0030, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0030 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = 2 * Constants::MIN_PERIOD;
    EXPECT_EQ(false, formTimerMgr.UpdateIntervalValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0030 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0031
 * @tc.name: UpdateIntervalValue.
 * @tc.desc: test UpdateIntervalValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0031, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0031 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = Constants::MIN_PERIOD - 1;
    EXPECT_EQ(false, formTimerMgr.UpdateIntervalValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0031 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0032
 * @tc.name: UpdateIntervalValue.
 * @tc.desc: test UpdateIntervalValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0032, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0032 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = Constants::MAX_PERIOD + 1;
    EXPECT_EQ(false, formTimerMgr.UpdateIntervalValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0032 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0033
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0033, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0033 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME - 1;
    EXPECT_EQ(false, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0033 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0034
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0034, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0034 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MAX_HOUR + 1;
    EXPECT_EQ(false, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0034 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0035
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0035, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0035 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtMin = Constants::MAX_MINUTE + 1;
    EXPECT_EQ(false, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0035 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0036
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0036, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0036 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtMin = Constants::MIN_TIME - 1;
    EXPECT_EQ(false, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0036 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0037
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0037, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0037 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME + 1;
    timerCfg.updateAtMin = Constants::MIN_TIME + 1;
    EXPECT_EQ(true, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0037 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0038
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0038, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0038 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME + 1;
    timerCfg.updateAtMin = Constants::MIN_TIME + 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 0;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0038 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0039
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0039, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0039 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 0;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME + 1;
    timerCfg.updateAtMin = Constants::MIN_TIME + 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 0;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(false, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0039 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0040
 * @tc.name: IntervalToAtTimer.
 * @tc.desc: test IntervalToAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0040, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0040 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MAX_HOUR + 1;
    EXPECT_EQ(false, formTimerMgr.IntervalToAtTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0040 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0041
 * @tc.name: IntervalToAtTimer.
 * @tc.desc: test IntervalToAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0041, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0041 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtMin = Constants::MAX_MINUTE + 1;
    EXPECT_EQ(false, formTimerMgr.IntervalToAtTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0041 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0042
 * @tc.name: IntervalToAtTimer.
 * @tc.desc: test IntervalToAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0042, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0042 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtMin = Constants::MIN_TIME - 1;
    EXPECT_EQ(false, formTimerMgr.IntervalToAtTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0042 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0043
 * @tc.name: IntervalToAtTimer.
 * @tc.desc: test IntervalToAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0043, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0043 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME + 1;
    timerCfg.updateAtMin = Constants::MIN_TIME + 1;
    EXPECT_EQ(false, formTimerMgr.IntervalToAtTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0043 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0044
 * @tc.name: UpdateAtTimerValue.
 * @tc.desc: test UpdateAtTimerValue function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0044, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0044 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateAtHour = Constants::MIN_TIME + 1;
    timerCfg.updateAtMin = Constants::MIN_TIME + 1;
    EXPECT_EQ(true, formTimerMgr.UpdateAtTimerValue(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0044 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0045
 * @tc.name: AtTimerToIntervalTimer.
 * @tc.desc: test AtTimerToIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0045, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0045 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = Constants::MIN_PERIOD - 1;
    EXPECT_EQ(false, formTimerMgr.AtTimerToIntervalTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0045 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0046
 * @tc.name: AtTimerToIntervalTimer.
 * @tc.desc: test AtTimerToIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0046, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0046 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = Constants::MAX_PERIOD + 1;
    EXPECT_EQ(false, formTimerMgr.AtTimerToIntervalTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0046 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0047
 * @tc.name: AtTimerToIntervalTimer.
 * @tc.desc: test AtTimerToIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0047, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0047 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = 2 * Constants::MIN_PERIOD;
    EXPECT_EQ(true, formTimerMgr.AtTimerToIntervalTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0047 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0048
 * @tc.name: AtTimerToIntervalTimer.
 * @tc.desc: test AtTimerToIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0048, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0048 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 0;
    FormTimerCfg timerCfg;
    timerCfg.updateDuration = 2 * Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 0;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(false, formTimerMgr.AtTimerToIntervalTimer(formId, timerCfg));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0048 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0049
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0049, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0049 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME - 1;
    int32_t userId = 2;
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0049 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0050
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0050, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0050 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0050 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0051
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0051, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0051 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    dynamicRefreshItem.userId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0051 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0052
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0052, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0052 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    dynamicRefreshItem.userId = 3;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0052 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0053
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0053, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0053 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 2;
    dynamicRefreshItem.userId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0053 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0054
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0054, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0054 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 2;
    dynamicRefreshItem.userId = 3;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0054 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0055
 * @tc.name: SetEnableFlag.
 * @tc.desc: test SetEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0055, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0055 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    formTimerMgr->SetEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0055 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0056
 * @tc.name: SetEnableFlag.
 * @tc.desc: test SetEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0056, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0056 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    FormTimer formTimer;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->SetEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0056 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0057
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0057, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0057 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD;
    updateAtItem.refreshTask.isEnable = true;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0057 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0058
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0058, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0058 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD;
    updateAtItem.refreshTask.isEnable = false;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0058 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0059
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0059, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0059 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD + 1;
    updateAtItem.refreshTask.isEnable = false;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0059 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0060
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0060, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0060 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD + 1;
    updateAtItem.refreshTask.isEnable = true;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0060 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0061
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: test OnDynamicTimeTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0061, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0061 start";
    FormTimerMgr formTimerMgr;
    int64_t updateTime = 40;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.OnDynamicTimeTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0061 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0062
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: test OnDynamicTimeTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0062, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0062 start";
    FormTimerMgr formTimerMgr;
    int64_t updateTime = 40;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 41;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.OnDynamicTimeTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0062 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0063
 * @tc.name: SetIntervalEnableFlag.
 * @tc.desc: test SetIntervalEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0063, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0063 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    formTimerMgr->SetIntervalEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0063 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0064
 * @tc.name: SetIntervalEnableFlag.
 * @tc.desc: test SetIntervalEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0064, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0064 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    FormTimer formTimer;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->SetIntervalEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0064 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0065
 * @tc.name: GetIntervalTimer.
 * @tc.desc: test GetIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0065, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0065 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimer formTimer;
    EXPECT_EQ(false, formTimerMgr.GetIntervalTimer(formId, formTimer));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0065 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0066
 * @tc.name: GetIntervalTimer.
 * @tc.desc: test GetIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0066, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0066 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimer formTimer;
    formTimerMgr.intervalTimerTasks_.emplace(formId, formTimer);
    EXPECT_EQ(true, formTimerMgr.GetIntervalTimer(formId, formTimer));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0066 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0067
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0067, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0067 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    EXPECT_EQ(false, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0067 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0068
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0068, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0068 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 0;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(false, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0068 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0069
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0069, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0069 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 1;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0069 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0073
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0073, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0073 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0073 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0074
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0074, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0074 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0074 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0075
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0075, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0075 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    DynamicRefreshItem dynamicRefreshItems;
    dynamicRefreshItems.formId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItems);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0075 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0076
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0076, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0076 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0076 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0077
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0077, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0077 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    FormTimer formTimer;
    formTimer.refreshTime = INT64_MAX;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0077 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0078
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0078, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0078 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    FormTimer formTimer;
    formTimer.refreshTime = INT64_MAX - 1;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0078 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0079
 * @tc.name: ClearLimiterTimerResource.
 * @tc.desc: test ClearLimiterTimerResource function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0079, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->limiterTimerId_ = 1;
    formTimerMgr->ClearLimiterTimerResource();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0079_1
 * @tc.name: ClearLimiterTimerResource.
 * @tc.desc: test ClearLimiterTimerResource function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0079_1, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079_1 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->limiterTimerId_ = 0;
    formTimerMgr->CreateLimiterTimer();
    formTimerMgr->limiterTimerId_ = 1;
    formTimerMgr->ClearLimiterTimerResource();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079_1 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0080
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0080, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0080 start";
    FormTimerMgr formTimerMgr;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0080 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0081
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0081, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0081 start";
    FormTimerMgr formTimerMgr;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    formTimerMgr.dynamicWakeUpTime_ = 1;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0081 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0082
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0082, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0082 start";
    FormTimerMgr formTimerMgr;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    formTimerMgr.dynamicWakeUpTime_ = 2;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0082 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0083
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0083, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0083 start";
    FormTimerMgr formTimerMgr;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    formTimerMgr.dynamicWakeUpTime_ = 2;
    formTimerMgr.currentDynamicWantAgent_ = std::make_shared<WantAgent>();
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0083 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0084
 * @tc.name: ClearDynamicResource.
 * @tc.desc: test ClearDynamicResource function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0084, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0084 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->dynamicAlarmTimerId_ = 1;
    formTimerMgr->currentDynamicWantAgent_ = std::make_shared<WantAgent>();
    formTimerMgr->ClearDynamicResource();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0084 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0088
 * @tc.name: ExecTimerTask.
 * @tc.desc: test ExecTimerTask function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0088, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0088 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    FormTimer timerTask;
    formTimerMgr->ExecTimerTask(timerTask);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0088 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0089
 * @tc.name: IsDynamicTimerExpired.
 * @tc.desc: test IsDynamicTimerExpired function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0089, Function | MediumTest | Level0)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0089 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    EXPECT_TRUE(formTimerMgr->IsDynamicTimerExpired(PARAM_FORM_ID_VALUE_1));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0089 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0090
 * @tc.name: UpdateAtTimerAlarmDetail.
 * @tc.desc: test UpdateAtTimerAlarmDetail function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0090, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0090 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    FormTimer task;
    EXPECT_TRUE(formTimerMgr->UpdateAtTimerAlarmDetail(task));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0090 end";
}


/**
 * @tc.number: Fms_FormTimerMgr_0054
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: test SetNextRefreshTime function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10054, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0054 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    long nextGapTime = Constants::MIN_NEXT_TIME + 1;
    int32_t userId = 2;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 2;
    dynamicRefreshItem.userId = 3;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(false, formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0054 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0055
 * @tc.name: SetEnableFlag.
 * @tc.desc: test SetEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10055, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0055 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    formTimerMgr->SetEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0055 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0056
 * @tc.name: SetEnableFlag.
 * @tc.desc: test SetEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10056, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0056 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    FormTimer formTimer;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->SetEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0056 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0057
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10057, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0057 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD;
    updateAtItem.refreshTask.isEnable = true;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0057 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0058
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10058, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0058 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD;
    updateAtItem.refreshTask.isEnable = false;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0058 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0059
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10059, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0059 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD + 1;
    updateAtItem.refreshTask.isEnable = false;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0059 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0060
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: test OnUpdateAtTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10060, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0060 start";
    FormTimerMgr formTimerMgr;
    long updateTime = Constants::MIN_PERIOD;
    UpdateAtItem updateAtItem;
    updateAtItem.updateAtTime = Constants::MIN_PERIOD + 1;
    updateAtItem.refreshTask.isEnable = true;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.OnUpdateAtTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0060 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0061
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: test OnDynamicTimeTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10061, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0061 start";
    FormTimerMgr formTimerMgr;
    int64_t updateTime = 40;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.OnDynamicTimeTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0061 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0062
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: test OnDynamicTimeTrigger function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10062, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0062 start";
    FormTimerMgr formTimerMgr;
    int64_t updateTime = 40;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 41;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.OnDynamicTimeTrigger(updateTime));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0062 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0063
 * @tc.name: SetIntervalEnableFlag.
 * @tc.desc: test SetIntervalEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10063, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0063 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    formTimerMgr->SetIntervalEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0063 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0064
 * @tc.name: SetIntervalEnableFlag.
 * @tc.desc: test SetIntervalEnableFlag function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10064, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0064 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    bool flag = true;
    FormTimer formTimer;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->SetIntervalEnableFlag(formId, flag);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0064 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0065
 * @tc.name: GetIntervalTimer.
 * @tc.desc: test GetIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10065, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0065 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimer formTimer;
    EXPECT_EQ(false, formTimerMgr.GetIntervalTimer(formId, formTimer));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0065 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0066
 * @tc.name: GetIntervalTimer.
 * @tc.desc: test GetIntervalTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10066, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0066 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    FormTimer formTimer;
    formTimerMgr.intervalTimerTasks_.emplace(formId, formTimer);
    EXPECT_EQ(true, formTimerMgr.GetIntervalTimer(formId, formTimer));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0066 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0067
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10067, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0067 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    EXPECT_EQ(false, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0067 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0068
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10068, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0068 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 0;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(false, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0068 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0069
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: test GetUpdateAtTimer function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10069, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0069 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    UpdateAtItem updateAtItem;
    updateAtItem.refreshTask.formId = 1;
    formTimerMgr.updateAtTimerTasks_.emplace_back(updateAtItem);
    EXPECT_EQ(true, formTimerMgr.GetUpdateAtTimer(formId, updateAtItem));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0069 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0073
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10073, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0073 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0073 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0074
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10074, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0074 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0074 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0075
 * @tc.name: DeleteDynamicItem.
 * @tc.desc: test DeleteDynamicItem function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10075, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0075 start";
    FormTimerMgr formTimerMgr;
    int64_t formId = 1;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.formId = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    DynamicRefreshItem dynamicRefreshItems;
    dynamicRefreshItems.formId = 2;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItems);
    EXPECT_EQ(true, formTimerMgr.DeleteDynamicItem(formId));
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0075 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0076
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10076, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0076 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0076 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0077
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10077, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0077 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    FormTimer formTimer;
    formTimer.refreshTime = INT64_MAX;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0077 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0078
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: test OnIntervalTimeOut function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10078, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0078 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 1;
    FormTimer formTimer;
    formTimer.refreshTime = INT64_MAX - 1;
    formTimerMgr->intervalTimerTasks_.emplace(formId, formTimer);
    formTimerMgr->OnIntervalTimeOut();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0078 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0079
 * @tc.name: ClearLimiterTimerResource.
 * @tc.desc: test ClearLimiterTimerResource function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10079, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->limiterTimerId_ = 1;
    formTimerMgr->ClearLimiterTimerResource();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0079_1
 * @tc.name: ClearLimiterTimerResource.
 * @tc.desc: test ClearLimiterTimerResource function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10079_1, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079_1 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    formTimerMgr->limiterTimerId_ = 0;
    formTimerMgr->CreateLimiterTimer();
    formTimerMgr->limiterTimerId_ = 1;
    formTimerMgr->ClearLimiterTimerResource();
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0079_1 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0080
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10080, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0080 start";
    FormTimerMgr formTimerMgr;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0080 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0081
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10081, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0081 start";
    FormTimerMgr formTimerMgr;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    formTimerMgr.dynamicWakeUpTime_ = 1;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0081 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0082
 * @tc.name: UpdateDynamicAlarm.
 * @tc.desc: test UpdateDynamicAlarm function.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_10082, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0082 start";
    FormTimerMgr formTimerMgr;
    DynamicRefreshItem dynamicRefreshItem;
    dynamicRefreshItem.settedTime = 1;
    formTimerMgr.dynamicRefreshTasks_.emplace_back(dynamicRefreshItem);
    formTimerMgr.dynamicWakeUpTime_ = 2;
    EXPECT_EQ(true, formTimerMgr.UpdateDynamicAlarm());
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0082 end";
}
}
