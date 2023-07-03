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
#include <gtest/gtest.h>
#include <memory>

#include "appexecfwk_errors.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_service.h"
#include "mock_form_token.h"
#include "form_mgr_errors.h"
#include "form_render_proxy.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormRenderProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockFormMgrService = new MockFormMgrService();
        formRenderProxy = new FormRenderProxy(mockFormMgrService);
    }
    // TearDown() is unnecessary.
    sptr<MockFormMgrService> mockFormMgrService;
    sptr<FormRenderProxy> formRenderProxy;
};
/**
 * @tc.name: FormRenderProxyTest_0001
 * @tc.desc: test RenderForm function and callerToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0001 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1001L;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> callerToken = new (std::nothrow) MockFormToken();
    int result = formRenderProxy->RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0001 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0002
 * @tc.desc: test RenderForm function and callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0002 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1001L;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formRenderProxy->RenderForm(formJsInfo, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0002 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0003
 * @tc.desc: test StopRenderingForm function and callerToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0003 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1001L;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> callerToken = new (std::nothrow) MockFormToken();
    int result = formRenderProxy->StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0003 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0004
 * @tc.desc: test StopRenderingForm function and callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0004 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1001L;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formRenderProxy->StopRenderingForm(formJsInfo, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0004 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0005
 * @tc.desc: test CleanFormHost function and callerToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0005 starts";
    sptr<MockFormToken> callerToken = new (std::nothrow) MockFormToken();
    int result = formRenderProxy->CleanFormHost(callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0005 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0006
 * @tc.desc: test CleanFormHost function and callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0006 starts";
    int result = formRenderProxy->CleanFormHost(nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0006 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0007
 * @tc.desc: test ReloadForm function and formIds is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0007 starts";
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    int result = formRenderProxy->ReloadForm(std::move(formJsInfos), want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0007 test ends";
}
}