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
#include "form_refresh_limiter.h"
#include "form_timer_mgr.h"
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0091, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0092, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0093, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0094, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0095, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0096, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0097, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0098, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0099, Function | MediumTest | Level1)
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
}
