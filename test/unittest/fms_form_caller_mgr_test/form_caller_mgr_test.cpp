/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_proxy.h"
#include "mock_form_token.h"

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
 * @tc.name: FormCallerMgrTest_0001
 * @tc.desc: test RemoveFormHostCaller function forHostCallers is not empty and IsSameToken is true
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0001 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    FormCallerMgr::GetInstance().RemoveFormHostCaller(providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0001 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0002
 * @tc.desc: test OnHostCallBackDied function and remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0002 starts";
    FormCallerMgr::GetInstance().OnHostCallBackDied(nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0002 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0003
 * @tc.desc: test OnHostCallBackDied function and remote is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0003 starts";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().OnHostCallBackDied(providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0003 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0004
 * @tc.desc: test AddFormProviderCaller function
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0004 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test IsSameToken is true
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0004 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0005
 * @tc.desc: test RemoveFormHostCaller function forHostCallers is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0005 starts";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().RemoveFormHostCaller(providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0005 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0006
 * @tc.desc: test RemoveFormHostCaller function forHostCallers is nnot empty IsSameToken is false
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0006 starts";
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    FormCallerMgr::GetInstance().RemoveFormHostCaller(nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0006 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0007
 * @tc.desc: test GetFormProviderCaller function and HasForm is true
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0007 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    int64_t formId = 1;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test GetFormProviderCaller
    std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers;
    FormCallerMgr::GetInstance().GetFormProviderCaller(formId, formProviderCallers);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0007 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0008
 * @tc.desc: test GetFormProviderCaller function and HasForm is false
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0008 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    int64_t formId = 11;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test GetFormProviderCaller
    std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers;
    FormCallerMgr::GetInstance().GetFormProviderCaller(formId, formProviderCallers);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0008 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0009
 * @tc.desc: test RemoveFormProviderCaller function and IsSameToken is true IsFormEmpty is false
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0009 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    int64_t formId = 1;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test RemoveFormProviderCaller
    FormCallerMgr::GetInstance().RemoveFormProviderCaller(formId, providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0009 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0010
 * @tc.desc: test RemoveFormProviderCaller function and IsSameToken is false IsFormEmpty is true
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0010 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    int64_t formId = 1;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test RemoveFormProviderCaller
    FormCallerMgr::GetInstance().RemoveFormProviderCaller(formId, nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0010 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0011
 * @tc.desc: test RemoveFormProviderCaller function and IsSameToken is false
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0011 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test RemoveFormProviderCaller
    FormCallerMgr::GetInstance().RemoveFormProviderCaller(nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0011 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0012
 * @tc.desc: test RemoveFormProviderCaller function and IsSameToken is true
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0012 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // add formProviderCaller
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, providerToken);
    // test RemoveFormProviderCaller
    FormCallerMgr::GetInstance().RemoveFormProviderCaller(providerToken);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0012 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0013
 * @tc.desc: test OnProviderCallBackDied function and remote is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0013 starts";
    // test OnProviderCallBackDied
    FormCallerMgr::GetInstance().OnProviderCallBackDied(nullptr);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0013 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0014
 * @tc.desc: test GetEventHandler function eventHandler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0014 starts";
    bool result = true;
    // test GetEventHandler
    if (FormCallerMgr::GetInstance().GetEventHandler() != nullptr) {
        result = false;
    }
    EXPECT_EQ(false, result);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0014 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0015
 * @tc.desc: test GetEventHandler function eventHandler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0015 starts";
    // create eventHandler_
    FormCallerMgr::GetInstance().GetEventHandler();
    // test GetEventHandler
    bool result = true;
    if (FormCallerMgr::GetInstance().GetEventHandler() != nullptr) {
        result = false;
    }
    EXPECT_EQ(false, result);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0015 test ends";
}

/**
 * @tc.name: FormCallerMgrTest_0016
 * @tc.desc: test OnProviderCallBackDied function and remote is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormCallerMgrTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0016 starts";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    wptr<IRemoteObject> app = providerToken;
    // test OnProviderCallBackDied
    FormCallerMgr::GetInstance().OnProviderCallBackDied(app);
    GTEST_LOG_(INFO) << "FormCallerMgrTest_0016 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0001
 * @tc.desc: test UpdateForm function and callerToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormProviderCallerTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0001 starts";
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    // test UpdateForm
    FormProviderCaller formProviderCaller(providerToken);
    formProviderCaller.UpdateForm(formJsInfo);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0001 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0002
 * @tc.desc: test OnRemoteDied function and handler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormProviderCallerTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0002 starts";
    FormProviderCallerRecipient formProviderCallerRecipient(nullptr);
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    wptr<IRemoteObject> app = providerToken;
    // test OnRemoteDied
    formProviderCallerRecipient.OnRemoteDied(app);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0002 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0003
 * @tc.desc: test OnRemoteDied function and handler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormProviderCallerTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0003 starts";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    wptr<IRemoteObject> app = providerToken;
    auto func = [](const wptr<IRemoteObject> &remote) {
        FormCallerMgr::GetInstance().OnProviderCallBackDied(remote);
    };
    FormProviderCallerRecipient formProviderCallerRecipient(func);
    // test OnRemoteDied
    formProviderCallerRecipient.OnRemoteDied(app);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0003 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0001
 * @tc.desc: test OnRemoteDied function and handler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormHostCallerTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0001 starts";
    FormHostCallerRecipient formHostCallerRecipient(nullptr);
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    wptr<IRemoteObject> app = providerToken;
    // test OnRemoteDied
    formHostCallerRecipient.OnRemoteDied(app);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0001 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0002
 * @tc.desc: test OnRemoteDied function and handler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormCallerMgrTest, FormHostCallerTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0002 starts";
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    wptr<IRemoteObject> app = providerToken;
    auto func = [](const wptr<IRemoteObject> &remote) {
        FormCallerMgr::GetInstance().OnProviderCallBackDied(remote);
    };
    FormHostCallerRecipient formHostCallerRecipient(func);
    // test OnRemoteDied
    formHostCallerRecipient.OnRemoteDied(app);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0002 test ends";
}
} // namespace