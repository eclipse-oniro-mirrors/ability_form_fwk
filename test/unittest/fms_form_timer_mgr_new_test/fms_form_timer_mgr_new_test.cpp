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

/**
 * @tc.number: Fms_FormTimerMgr_0100
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0100 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0100 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0101
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0101, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0101 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0101 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0102
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0102, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0102 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0102 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0103
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0103, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0103 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0103 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0104
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0104, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0104 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0104 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0105
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0105, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0105 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0105 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0106
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0106, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0106 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0106 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0107
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0107, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0107 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0107 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0108
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0108, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0108 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0108 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0109
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0109, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0109 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0109 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0110
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0110, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0110 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0110 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0111
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0111, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0111 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0111 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0112
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0112, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0112 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0112 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0113
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0113, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0113 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0113 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0114
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0114, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0114 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0114 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0115
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0115, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0115 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0115 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0116
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0116, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0116 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0116 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0117
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0117, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0117 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0117 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0118
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0118, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0118 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0118 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0119
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0119, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0119 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0119 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0120
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0120, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0120 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0120 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0121
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0121, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0121 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0121 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0122
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0122, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0122 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0122 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0123
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0123, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0123 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0123 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0124
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0124, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0124 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0124 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0125
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0125, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0125 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0125 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0126
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0126, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0126 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0126 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0127
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0127, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0127 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0127 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0128
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0128, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0128 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0128 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0129
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0129, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0129 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0129 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0130
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0130, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0130 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0130 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0131
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0131, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0131 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0131 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0132
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0132, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0132 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0132 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0133
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0133, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0133 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0133 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0134
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0134, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0134 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0134 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0135
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0135, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0135 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0135 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0136
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0136, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0136 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0136 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0137
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0137, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0137 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0137 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0138
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0138, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0138 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0138 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0139
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0139, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0139 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0139 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0140
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0140, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0140 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0140 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0141
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0141, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0141 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0141 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0142
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0142, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0142 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0142 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0143
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0143, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0143 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0143 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0144
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0144, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0144 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0144 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0145
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0145, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0145 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0145 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0146
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0146, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0146 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0146 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0147
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0147, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0147 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0147 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0148
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0148, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0148 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0148 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0149
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0149, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0149 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0149 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0150
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0150, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0150 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0150 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0151
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0151, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0151 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0151 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0152
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0152, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0152 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0152 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0153
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0153, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0153 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0153 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0154
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0154, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0154 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0154 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0155
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0155, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0155 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0155 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0156
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0156, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0156 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0156 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0157
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0157, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0157 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0157 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0158
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0158, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0158 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0158 end";
}

/**
 * @tc.number: Fms_FormTimerMgr_0159
 * @tc.name: TimerReceiver::OnReceiveEvent.
 * @tc.desc: Verify that the OnReceiveEvent interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_0159, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0159 start";
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
    GTEST_LOG_(INFO) << "Fms_FormTimerMgr_0159 end";
}


/**
 * @tc.number: Fms_FormTimerMgr_0091
 * @tc.name: IsLimiterEnableRefresh.
 * @tc.desc: Verify that the IsLimiterEnableRefresh interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_91, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_92, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_93, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_94, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_95, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_96, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_97, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_98, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_99, Function | MediumTest | Level1)
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
 * @tc.number: Fms_FormTimerMgr_0091
 * @tc.name: IsLimiterEnableRefresh.
 * @tc.desc: Verify that the IsLimiterEnableRefresh interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_191, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_192, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_193, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_194, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_195, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_196, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_197, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_198, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_199, Function | MediumTest | Level1)
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
 * @tc.number: Fms_FormTimerMgr_0091
 * @tc.name: IsLimiterEnableRefresh.
 * @tc.desc: Verify that the IsLimiterEnableRefresh interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1091, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1092, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1093, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1094, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1095, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1096, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1097, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1098, Function | MediumTest | Level1)
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
HWTEST_F(FmsFormTimerMgrTest, Fms_FormTimerMgr_1099, Function | MediumTest | Level1)
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