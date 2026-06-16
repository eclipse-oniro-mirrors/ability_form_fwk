/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "form_render_proxy.h"
#include "mock_form_token.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int64_t TEST_FORM_ID = 1001LL;
class FormRenderProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockIRemoteObject_ = new MockIRemoteObject();
        formRenderProxy_ = new FormRenderProxy(mockIRemoteObject_);
    }
    // TearDown() is unnecessary.
    sptr<MockIRemoteObject> mockIRemoteObject_;
    sptr<FormRenderProxy> formRenderProxy_;
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
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
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
    int result = formRenderProxy_->RenderForm(formJsInfo, want, nullptr);
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
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
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
    int result = formRenderProxy_->StopRenderingForm(formJsInfo, want, nullptr);
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
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->CleanFormHost(callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0005 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0006
 * @tc.desc: test CleanFormHost function and callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0006 starts";
    int result = formRenderProxy_->CleanFormHost(nullptr);
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
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->ReloadForm(std::move(formJsInfos), want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0007 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0008
 * @tc.desc: test ReleaseRenderer function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0008 starts";
    Want want;
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->ReleaseRenderer(TEST_FORM_ID, "compId", "uid", want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0008 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0009
 * @tc.desc: test OnUnlock function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0009 starts";
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->OnUnlock();
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0009 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0010
 * @tc.desc: test RecycleForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0010 starts";
    Want want = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->RecycleForm(TEST_FORM_ID, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0010 test ends";
}

/**
 * @tc.name: FormRenderProxyTest_0011
 * @tc.desc: test RecoverForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0011 starts";
    FormJsInfo formJsInfo = {};
    Want want = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->RecoverForm(formJsInfo, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0011 test ends";
}

/**
* @tc.name: FormRenderProxyTest_0012
* @tc.desc: test SetVisibleChange function.
* @tc.type: FUNC
*/
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0012 starts";
    Want want = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int result = formRenderProxy_->SetVisibleChange(TEST_FORM_ID, true, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0012 test ends";
}

/**
* @tc.name: FormRenderProxyTest_0013
* @tc.desc: test UpdateFormSize function.
* @tc.type: FUNC
*/
HWTEST_F(FormRenderProxyTest, FormRenderProxyTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0013 starts";
    Want want = {};
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    int64_t formId = 1;
    FormSurfaceInfo formSurfaceInfo;
    formSurfaceInfo.width = 1.1;
    formSurfaceInfo.height = 1.1;
    formSurfaceInfo.borderWidth = 1.1;
    formSurfaceInfo.formViewScale = 1.1;
    std::string uid = "uid";
    FormJsInfo formJsInfo;
    int result = formRenderProxy_->UpdateFormSize(formId, formSurfaceInfo, uid, formJsInfo);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderProxyTest_0013 test ends";
}

/**
 * @tc.name: RunCachedConfigurationUpdated_001
 * @tc.desc: test RunCachedConfigurationUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderProxyTest, RunCachedConfigurationUpdated_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdated_001 starts";
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    formRenderProxy_->RunCachedConfigurationUpdated();
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdated_001 test ends";
}
}