/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <memory>

#include "appexecfwk_errors.h"
#include "gmock/gmock.h"
#include "form_mgr_errors.h"
#include "js_form_state_observer_proxy.h"
#include "mock_i_remote_object.h"

namespace {
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

class JsFormStateObserverProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockIRemoteObject_ = new MockIRemoteObject();
        jsFormStateObserverProxy = new JsFormStateObserverProxy(mockIRemoteObject_);
    }
    // TearDown() is unnecessary.
    sptr<MockIRemoteObject> mockIRemoteObject_;
    sptr<JsFormStateObserverProxy> jsFormStateObserverProxy;
};

/**
 * @tc.name: JsFormStateObserverProxyTest_0001
 * @tc.desc: test OnAddForm function.
 * @tc.type: FUNC
 */
HWTEST_F(JsFormStateObserverProxyTest, JsFormStateObserverProxyTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0001 starts";
    RunningFormInfo runningFormInfo = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = jsFormStateObserverProxy->OnAddForm("bundleName", runningFormInfo);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0001 test ends";
}

/**
 * @tc.name: JsFormStateObserverProxyTest_0002
 * @tc.desc: test OnRemoveForm function.
 * @tc.type: FUNC
 */
HWTEST_F(JsFormStateObserverProxyTest, JsFormStateObserverProxyTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0002 starts";
    RunningFormInfo runningFormInfo = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = jsFormStateObserverProxy->OnRemoveForm("bundleName", runningFormInfo);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0002 test ends";
}

/**
 * @tc.name: JsFormStateObserverProxyTest_0003
 * @tc.desc: test NotifyWhetherFormsVisible function.
 * @tc.type: FUNC
 */
HWTEST_F(JsFormStateObserverProxyTest, JsFormStateObserverProxyTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0003 starts";
    std::vector<FormInstance> formInstances;
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = jsFormStateObserverProxy->NotifyWhetherFormsVisible(FormVisibilityType::UNKNOWN,
        "bundleName", formInstances);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0003 test ends";
}

/**
 * @tc.name: JsFormStateObserverProxyTest_0004
 * @tc.desc: test NotifyWhetherFormsVisible function.
 * @tc.type: FUNC
 */
HWTEST_F(JsFormStateObserverProxyTest, JsFormStateObserverProxyTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0004 starts";
    RunningFormInfo runningFormInfo = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = jsFormStateObserverProxy->OnFormClickEvent("bundleName", "callType", runningFormInfo);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "JsFormStateObserverProxyTest_0004 test ends";
}
}