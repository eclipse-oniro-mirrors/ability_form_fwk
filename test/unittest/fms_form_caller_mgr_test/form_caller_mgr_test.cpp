/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#define private public
#include "form_caller_mgr.h"
#include "form_provider_caller.h"
#undef private
#include "form_host_caller.h"
#include "form_mgr.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_proxy.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormCallerMgrTest : public testing::Test {
public:
    // TestSuite setup has to be static
    static void SetUpTestCase()
    {
        if (mockProxy == nullptr) {
            GTEST_LOG_(INFO) << "SetUpTestCase";
            sptr<IRemoteObject> impl = nullptr;
            mockProxy = new (std::nothrow) MockFormMgrProxy(impl);
            FormMgr::GetInstance().SetFormMgrService(mockProxy);
        }
    }
    // TearDown is unnecessary.
    // TestSuite setup has to be static
    static sptr<MockFormMgrProxy> mockProxy;
};
// initialize static variable.
sptr<MockFormMgrProxy> FormCallerMgrTest::mockProxy = nullptr;

/**
 * @tc.name: FormCallerMgrTest_0015
 * @tc.desc: test GetEventHandler function eventHandler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0015 starts";
    // create eventHandler_
    FormCallerMgr::GetInstance().GetEventHandler();
    EXPECT_NE(FormCallerMgr::GetInstance().GetEventHandler(), nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0015 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0018
 * @tc.desc: test GetFormHostCaller function and formId is null
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0018 starts";
    std::shared_ptr<FormCallerMgr> formCallerMgr = std::make_shared<FormCallerMgr>();
    ASSERT_NE(nullptr, formCallerMgr);
    auto ret = formCallerMgr->GetFormHostCaller(-5);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0018 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0019
 * @tc.desc: test GetFormHostCaller function and formId is not null
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0019 starts";
    std::shared_ptr<FormCallerMgr> formCallerMgr = std::make_shared<FormCallerMgr>();
    ASSERT_NE(nullptr, formCallerMgr);
    FormJsInfo formJsInfo;
    formJsInfo.formId = 4;
    std::shared_ptr<FormHostCaller> caller = std::make_shared<FormHostCaller>(formJsInfo, nullptr);
    ASSERT_NE(nullptr, caller);
    formCallerMgr->formHostCallers_[formJsInfo.formId] = caller;
    std::shared_ptr<FormHostCaller> ret = formCallerMgr->GetFormHostCaller(formJsInfo.formId);
    ASSERT_EQ(ret, caller);
    formCallerMgr->RemoveFormHostCaller(formJsInfo.formId);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0019 test ends";
}
} // namespace