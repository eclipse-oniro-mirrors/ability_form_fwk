/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @tc.number: Fms_FormTimerMgr_0091
 * @tc.name: IsLimiterEnableRefresh.
 * @tc.desc: Verify that the IsLimiterEnableRefresh interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0091, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0091 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    ASSERT_NE(nullptr, formTimerMgr);
    int64_t formId = 0;
    formTimerMgr->IsLimiterEnableRefresh(formId);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0091 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0092
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0092, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0092 start";
    EventFwk::CommonEventData eventData;
    std::string action = "fms.time_speed";
    AAFwk::Want want;
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0092 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0093
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0093, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0093 start";
    EventFwk::CommonEventData eventData;
    std::string action = "usual.event.TIME_CHANGED";
    AAFwk::Want want;
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0093 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0094
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0094, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0094 start";
    EventFwk::CommonEventData eventData;
    std::string action = "usual.event.TIMEZONE_CHANGED";
    AAFwk::Want want;
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0094 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0095
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0095, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0095 start";
    EventFwk::CommonEventData eventData;
    std::string action = "form_update_at_timer";
    AAFwk::Want want;
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0095 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0096
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0096, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0096 start";
    EventFwk::CommonEventData eventData;
    std::string action = "abc";
    AAFwk::Want want;
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0096 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0097
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0097, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0097 start";
    EventFwk::CommonEventData eventData;
    std::string action = "form_update_at_timer";
    AAFwk::Want want;
    want.SetParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_RESET_LIMIT);
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0097 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0098
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0098, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0098 start";
    EventFwk::CommonEventData eventData;
    std::string action = "form_update_at_timer";
    AAFwk::Want want;
    want.SetParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_DYNAMIC_UPDATE);
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0098 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0099
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0099, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0099 start";
    EventFwk::CommonEventData eventData;
    std::string action = "form_update_at_timer";
    AAFwk::Want want;
    constexpr int32_t typeStaticUpdate = Constants::TYPE_STATIC_UPDATE + 100;  // 100: static update
    want.SetParam(Constants::KEY_ACTION_TYPE, typeStaticUpdate);
    want.SetAction(action);
    eventData.SetWant(want);
    std::shared_ptr<FormTimerMgr::TimerReceiver> timeReceiver = std::make_shared<FormTimerMgr::TimerReceiver>();
    ASSERT_NE(nullptr, timeReceiver);
    timeReceiver->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0099 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0100
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with invalid updateAt parameters (hour out of range).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0100 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210718;
    timerTask.isUpdateAt = true;
    timerTask.hour = 25;  // Invalid hour (exceeds MAX_HOUR)
    timerTask.min = 30;
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.find(20210718), timerMgr.intervalTimerTasks_.end());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0100 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0101
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with invalid period parameters (period out of range).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0101, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0101 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210719;
    timerTask.isUpdateAt = false;
    timerTask.period = 1;  // Invalid period (less than MIN_PERIOD)
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.find(20210719), timerMgr.intervalTimerTasks_.end());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0101 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0102
 * @tc.name: AddFormTimerForMultiUpdate.
 * @tc.desc: Test AddFormTimerForMultiUpdate with empty updateAtTimes vector.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0102 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    int64_t formId = 20210720;
    std::vector<std::vector<int>> updateAtTimes;  // Empty vector
    int32_t userId = 0;
    bool result = timerMgr.AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    bool found = false;
    for (const auto& item : timerMgr.updateAtTimerTasks_) {
        if (item.refreshTask.formId == formId) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0102 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0103
 * @tc.name: AddFormTimerForMultiUpdate.
 * @tc.desc: Test AddFormTimerForMultiUpdate with invalid time size (less than TIME_MIN_SIZE).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0103 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    int64_t formId = 20210721;
    std::vector<std::vector<int>> updateAtTimes;
    std::vector<int> time = {10};  // Only one element (less than TIME_MIN_SIZE=2)
    updateAtTimes.push_back(time);
    int32_t userId = 0;
    bool result = timerMgr.AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    bool found = false;
    for (const auto& item : timerMgr.updateAtTimerTasks_) {
        if (item.refreshTask.formId == formId) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0103 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0104
 * @tc.name: RemoveFormTimer.
 * @tc.desc: Test RemoveFormTimer when form timer does not exist.
 * @tc.note: RemoveFormTimer returns true when DeleteUpdateAtTimer succeeds even if formId not found.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0104 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    size_t dynamicSizeBefore = timerMgr.dynamicRefreshTasks_.size();
    
    int64_t formId = 20210722;  // Non-existent formId
    bool result = timerMgr.RemoveFormTimer(formId);
    
    // RemoveFormTimer returns true because DeleteUpdateAtTimer returns true for non-existent formId
    EXPECT_EQ(result, true);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    EXPECT_EQ(timerMgr.dynamicRefreshTasks_.size(), dynamicSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0104 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0105
 * @tc.name: UpdateFormTimer.
 * @tc.desc: Test UpdateFormTimer with enableUpdate set to false.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0105, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0105 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    int64_t formId = 20210723;
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = false;  // enableUpdate is false
    UpdateType type = UpdateType::TYPE_INTERVAL_CHANGE;
    bool result = timerMgr.UpdateFormTimer(formId, type, timerCfg);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0105 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0106
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: Test SetNextRefreshTime when form record does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0106 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t dynamicSizeBefore = timerMgr.dynamicRefreshTasks_.size();
    
    int64_t formId = 20210724;  // Non-existent formId
    long nextGapTime = 60;
    int32_t userId = 0;
    bool result = timerMgr.SetNextRefreshTime(formId, nextGapTime, userId);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.dynamicRefreshTasks_.size(), dynamicSizeBefore);
    
    bool found = false;
    for (const auto& item : timerMgr.dynamicRefreshTasks_) {
        if (item.formId == formId) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0106 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0107
 * @tc.name: SetNextRefreshTime.
 * @tc.desc: Test SetNextRefreshTime with invalid nextGapTime for non-system app.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0107, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0107 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t dynamicSizeBefore = timerMgr.dynamicRefreshTasks_.size();
    
    int64_t formId = 20210725;
    long nextGapTime = 1;  // Less than MIN_NEXT_TIME for non-system app
    int32_t userId = 0;
    bool result = timerMgr.SetNextRefreshTime(formId, nextGapTime, userId);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.dynamicRefreshTasks_.size(), dynamicSizeBefore);
    
    bool found = false;
    for (const auto& item : timerMgr.dynamicRefreshTasks_) {
        if (item.formId == formId) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0107 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0108
 * @tc.name: OnDynamicTimeTrigger.
 * @tc.desc: Test OnDynamicTimeTrigger when dynamicRefreshTasks is empty.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0108, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0108 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    size_t dynamicSizeBefore = formTimerMgr->dynamicRefreshTasks_.size();
    int64_t updateTime = 1000000;  // Use a fixed time value instead of GetBootTimeMs()
    bool result = formTimerMgr->OnDynamicTimeTrigger(updateTime);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(formTimerMgr->dynamicRefreshTasks_.size(), dynamicSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0108 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0109
 * @tc.name: GetRemindTasks.
 * @tc.desc: Test GetRemindTasks when remindTasks is empty.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0109, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0109 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    std::vector<FormTimer> remindTasks;
    size_t remindSizeBefore = remindTasks.size();
    bool result = formTimerMgr->GetRemindTasks(remindTasks);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(remindTasks.size(), remindSizeBefore);
    EXPECT_TRUE(remindTasks.empty());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0109 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0110
 * @tc.name: GetIntervalTimer.
 * @tc.desc: Test GetIntervalTimer when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0110, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0110 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    int64_t formId = 20210726;  // Non-existent formId
    FormTimer formTimer;
    bool result = timerMgr.GetIntervalTimer(formId, formTimer);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0110 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0111
 * @tc.name: GetUpdateAtTimer.
 * @tc.desc: Test GetUpdateAtTimer when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0111, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0111 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    int64_t formId = 20210727;  // Non-existent formId
    UpdateAtItem updateAtItem;
    bool result = timerMgr.GetUpdateAtTimer(formId, updateAtItem);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0111 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0112
 * @tc.name: GetDynamicItem.
 * @tc.desc: Test GetDynamicItem when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0112, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0112 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t dynamicSizeBefore = timerMgr.dynamicRefreshTasks_.size();
    
    int64_t formId = 20210728;  // Non-existent formId
    DynamicRefreshItem dynamicItem;
    bool result = timerMgr.GetDynamicItem(formId, dynamicItem);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.dynamicRefreshTasks_.size(), dynamicSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0112 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0113
 * @tc.name: SetEnableFlag.
 * @tc.desc: Test SetEnableFlag when formId does not exist in intervalTimerTasks.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0113, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0113 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    int64_t formId = 20210729;  // Non-existent formId
    timerMgr.SetEnableFlag(formId, true);
    
    // SetEnableFlag does not return value, verify no task added
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.find(formId), timerMgr.intervalTimerTasks_.end());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0113 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0114
 * @tc.name: UpdateIntervalValue.
 * @tc.desc: Test UpdateIntervalValue with updateDuration > MAX_PERIOD.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0114, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0114 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    int64_t formId = 20210730;
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = true;
    timerCfg.updateDuration = Constants::MAX_PERIOD + Constants::MIN_PERIOD;  // Exceeds MAX_PERIOD
    bool result = timerMgr.UpdateFormTimer(formId, UpdateType::TYPE_INTERVAL_CHANGE, timerCfg);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0114 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0115
 * @tc.name: UpdateIntervalValue.
 * @tc.desc: Test UpdateIntervalValue with updateDuration not divisible by MIN_PERIOD.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0115, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0115 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    int64_t formId = 20210731;
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = true;
    timerCfg.updateDuration = 100;  // Not divisible by MIN_PERIOD (30 min)
    bool result = timerMgr.UpdateFormTimer(formId, UpdateType::TYPE_INTERVAL_CHANGE, timerCfg);
    
    EXPECT_EQ(result, false);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0115 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0116
 * @tc.name: SetIntervalEnableFlag.
 * @tc.desc: Test SetIntervalEnableFlag when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0116, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0116 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    int64_t formId = 20210732;  // Non-existent formId
    timerMgr.SetIntervalEnableFlag(formId, true);
    
    // SetIntervalEnableFlag does not return value, verify no task added
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.find(formId), timerMgr.intervalTimerTasks_.end());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0116 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0117
 * @tc.name: GetRefreshCount.
 * @tc.desc: Test GetRefreshCount when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0117, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0117 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    
    int64_t formId = 20210733;  // Non-existent formId
    int refreshCount = timerMgr.GetRefreshCount(formId);
    
    // GetRefreshCount returns -1 for non-existent formId (not added or already removed)
    EXPECT_EQ(refreshCount, -1);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0117 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0118
 * @tc.name: MarkRemind.
 * @tc.desc: Test MarkRemind when formId does not exist in limiter.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0118, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0118 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    
    int64_t formId = 20210734;  // Non-existent formId
    EXPECT_NO_FATAL_FAILURE(timerMgr.MarkRemind(formId));
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0118 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0119
 * @tc.name: IncreaseRefreshCount.
 * @tc.desc: Test IncreaseRefreshCount when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0119, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0119 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    
    int64_t formId = 20210735;  // Non-existent formId
    EXPECT_NO_FATAL_FAILURE(timerMgr.IncreaseRefreshCount(formId));
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0119 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0120
 * @tc.name: IsLimiterEnableRefresh.
 * @tc.desc: Test IsLimiterEnableRefresh when formId does not exist.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0120, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0120 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    
    int64_t formId = 20210736;  // Non-existent formId
    bool result = timerMgr.IsLimiterEnableRefresh(formId);
    
    // IsLimiterEnableRefresh returns false for non-existent formId
    EXPECT_EQ(result, false);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0120 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0121
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with period = MAX_PERIOD (boundary value).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0121, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0121 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210737;
    timerTask.isUpdateAt = false;
    timerTask.period = Constants::MAX_PERIOD;  // Boundary: MAX_PERIOD
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore + 1);
    
    // Cleanup
    timerMgr.RemoveFormTimer(20210737);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0121 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0122
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with hour = MAX_HOUR (boundary value).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0122, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0122 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210738;
    timerTask.isUpdateAt = true;
    timerTask.hour = Constants::MAX_HOUR;  // Boundary: MAX_HOUR (23)
    timerTask.min = Constants::MAX_MINUTE;  // Boundary: MAX_MINUTE (59)
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore + 1);
    
    // Cleanup
    timerMgr.RemoveFormTimer(20210738);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0122 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0123
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with period = MIN_PERIOD (boundary value).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0123, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0123 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t intervalSizeBefore = timerMgr.intervalTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210739;
    timerTask.isUpdateAt = false;
    timerTask.period = Constants::MIN_PERIOD;  // Boundary: MIN_PERIOD
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(timerMgr.intervalTimerTasks_.size(), intervalSizeBefore + 1);
    
    // Cleanup
    timerMgr.RemoveFormTimer(20210739);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0123 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0124
 * @tc.name: AddFormTimer.
 * @tc.desc: Test AddFormTimer with hour = MIN_TIME (boundary value 0).
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0124, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0124 start";
    auto& timerMgr = FormTimerMgr::GetInstance();
    size_t updateAtSizeBefore = timerMgr.updateAtTimerTasks_.size();
    
    FormTimer timerTask;
    timerTask.formId = 20210740;
    timerTask.isUpdateAt = true;
    timerTask.hour = Constants::MIN_TIME;  // Boundary: MIN_TIME (0)
    timerTask.min = Constants::MIN_TIME;  // Boundary: MIN_TIME (0)
    timerTask.userId = 0;
    bool result = timerMgr.AddFormTimer(timerTask);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(timerMgr.updateAtTimerTasks_.size(), updateAtSizeBefore + 1);
    
    timerMgr.RemoveFormTimer(20210740);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0124 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0125
 * @tc.name: OnUpdateAtTrigger.
 * @tc.desc: Test OnUpdateAtTrigger when updateTime does not match any task.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0125, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0125 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    size_t updateAtSizeBefore = formTimerMgr->updateAtTimerTasks_.size();
    long updateTime = 100;  // Non-matching updateTime
    bool result = formTimerMgr->OnUpdateAtTrigger(updateTime);
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(formTimerMgr->updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0125 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0126
 * @tc.name: OnIntervalTimeOut.
 * @tc.desc: Test OnIntervalTimeOut when intervalTimerTasks is empty.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0126, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0126 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    size_t intervalSizeBefore = formTimerMgr->intervalTimerTasks_.size();
    formTimerMgr->OnIntervalTimeOut();
    
    EXPECT_EQ(formTimerMgr->intervalTimerTasks_.size(), intervalSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0126 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0127
 * @tc.name: HandleSystemTimeChanged.
 * @tc.desc: Test HandleSystemTimeChanged with empty tasks.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0127, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0127 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    size_t updateAtSizeBefore = formTimerMgr->updateAtTimerTasks_.size();
    bool result = formTimerMgr->HandleSystemTimeChanged();
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(formTimerMgr->updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0127 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0128
 * @tc.name: UpdateAtTimerAlarm.
 * @tc.desc: Test UpdateAtTimerAlarm when updateAtTimerTasks is empty.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0128, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0128 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    size_t updateAtSizeBefore = formTimerMgr->updateAtTimerTasks_.size();
    bool result = formTimerMgr->UpdateAtTimerAlarm();
    
    EXPECT_EQ(result, true);
    EXPECT_EQ(formTimerMgr->updateAtTimerTasks_.size(), updateAtSizeBefore);
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0128 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0129
 * @tc.name: UpdateLimiterAlarm.
 * @tc.desc: Test UpdateLimiterAlarm when limiter has no items.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0129, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0129 start";
    std::shared_ptr<FormTimerMgr> formTimerMgr = std::make_shared<FormTimerMgr>();
    
    EXPECT_NO_FATAL_FAILURE(formTimerMgr->UpdateLimiterAlarm());
    
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0129 end";
}
}