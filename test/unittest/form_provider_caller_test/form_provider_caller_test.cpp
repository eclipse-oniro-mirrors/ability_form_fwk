/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "form_provider_caller.h"
#undef private
#include "form_caller_mgr.h"
#include "form_host_caller.h"
#include "form_host_client.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "gmock/gmock.h"
#include "mock_form_token.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockConvertRawImageData(bool result);
const std::string FORM_MANAGER_SERVICE_BUNDLE_NAME = "com.form.fms.app";
const std::string FORM_SUPPLY_INFO = "com.form.supply.info.test";

namespace {
class FormProviderCallerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormProviderCallerTest::SetUpTestCase() {}
void FormProviderCallerTest::TearDownTestCase() {}
void FormProviderCallerTest::SetUp() {}
void FormProviderCallerTest::TearDown() {}


/**
 * @tc.name: FormProviderCallerTest_0001
 * @tc.desc: text OnRemoteDied function and handler_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0001 starts";
    FormProviderCallerRecipient formProviderCallerRecipient(nullptr);
    formProviderCallerRecipient.OnRemoteDied(nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0001 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0002
 * @tc.desc: text UpdateForm function and callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0002 starts";
    FormProviderCaller formProviderCaller(nullptr);
    FormJsInfo formJsInfo;
    formProviderCaller.UpdateForm(formJsInfo);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0002 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0003
 * @tc.desc: text UpdateForm function and GetFormJsInfo is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0003 starts";
    int64_t formId = 3;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.UpdateForm(formId, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0003 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0004
 * @tc.desc: text UpdateForm function and GetFormJsInfo is true ConvertRawImageData is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0004 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    FormJsInfo formJsInfo2;
    formJsInfo2.formId = 2;
    formJsInfo2.formName = "bb";
    int64_t formIder = 1;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    formProviderCaller.AddForm(formJsInfo2);
    MockConvertRawImageData(false);
    formProviderCaller.UpdateForm(formIder, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0004 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0005
 * @tc.desc: text UpdateForm function and GetFormJsInfo is true ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0004 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    FormJsInfo formJsInfo2;
    formJsInfo2.formId = 2;
    formJsInfo2.formName = "bb";
    int64_t formIder = 1;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    formProviderCaller.AddForm(formJsInfo2);
    MockConvertRawImageData(true);
    formProviderCaller.UpdateForm(formIder, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0005 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0006
 * @tc.desc: text OnAcquire function and ConvertRawImageData is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0006 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0006 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0007
 * @tc.desc: text OnAcquire function and ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0007 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0007 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0001
 * @tc.desc: text OnRemoteDied function and handler_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormHostCallerTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0001 starts";
    FormHostCallerRecipient formHostCallerRecipient(nullptr);
    formHostCallerRecipient.OnRemoteDied(nullptr);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0001 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0002
 * @tc.desc: text OnRemoteDied function and ConvertRawImageData is true .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormHostCallerTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0002 starts";
    FormJsInfo formJsInfo;
    int64_t formId = 1;
    FormProviderData formProviderData;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.UpdateForm(formId, formProviderData);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0002 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0003
 * @tc.desc: text RequestForm function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormHostCallerTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0002 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.RequestForm(formId, nullptr, want);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0003 test ends";
}

/**
 * @tc.name: FormHostCallerTest_0004
 * @tc.desc: text MessageEvent function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormHostCallerTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormHostCallerTest_0004 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.MessageEvent(formId, want, nullptr);
    GTEST_LOG_(INFO) << "FormHostCallerTest_0004 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0008
 * @tc.desc: text OnAcquire function.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0008 starts";
    Want want;
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0008 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0009
 * @tc.desc: text OnAcquire function token is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0009 starts";
    FormJsInfo formJsInfo;
    FormProviderCaller formProviderCaller(nullptr);
    EXPECT_EQ(formProviderCaller.OnAcquire(formJsInfo, nullptr), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0009 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0010
 * @tc.desc: text IsSameToken function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0010 starts";
    FormProviderCaller formProviderCaller(nullptr);
    auto result = formProviderCaller.IsSameToken(nullptr);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0010 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0011
 * @tc.desc: text DeleteForm function and callerToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0011 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 5;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    EXPECT_EQ(
        formProviderCaller.formJsInfoMap_.find(formJsInfo.formId) != formProviderCaller.formJsInfoMap_.end(), true);
    formProviderCaller.DeleteForm(formJsInfo.formId);
    EXPECT_EQ(
        formProviderCaller.formJsInfoMap_.find(formJsInfo.formId) == formProviderCaller.formJsInfoMap_.end(), true);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0011 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0012
 * @tc.desc: text OnRemoteDied function and ConvertRawImageData is true .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0012 starts";
    FormJsInfo formJsInfo;
    int64_t formId = 1;
    FormProviderData formProviderData;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.UpdateForm(formId, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0012 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0013
 * @tc.desc: text RequestForm function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0013 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.RequestForm(formId, nullptr, want);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0013 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0014
 * @tc.desc: text MessageEvent function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0014 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.MessageEvent(formId, want, nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0014 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0015
 * @tc.desc: text OnAcquire function.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0015 starts";
    Want want;
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0015 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0016
 * @tc.desc: text OnAcquire function token is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0016 starts";
    FormJsInfo formJsInfo;
    FormProviderCaller formProviderCaller(nullptr);
    EXPECT_EQ(formProviderCaller.OnAcquire(formJsInfo, nullptr), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0016 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0017
 * @tc.desc: text IsSameToken function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0017 starts";
    FormProviderCaller formProviderCaller(nullptr);
    auto result = formProviderCaller.IsSameToken(nullptr);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0017 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0018
 * @tc.desc: text DeleteForm function and callerToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0018 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 5;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    EXPECT_EQ(
        formProviderCaller.formJsInfoMap_.find(formJsInfo.formId) != formProviderCaller.formJsInfoMap_.end(), true);
    formProviderCaller.DeleteForm(formJsInfo.formId);
    EXPECT_EQ(
        formProviderCaller.formJsInfoMap_.find(formJsInfo.formId) == formProviderCaller.formJsInfoMap_.end(), true);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0018 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0019
 * @tc.desc: text UpdateForm function and GetFormJsInfo is true ConvertRawImageData is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0019 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    FormJsInfo formJsInfo2;
    formJsInfo2.formId = 2;
    formJsInfo2.formName = "bb";
    int64_t formIder = 1;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    formProviderCaller.AddForm(formJsInfo2);
    MockConvertRawImageData(false);
    formProviderCaller.UpdateForm(formIder, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0019 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0020
 * @tc.desc: text UpdateForm function and GetFormJsInfo is true ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0020 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    FormJsInfo formJsInfo2;
    formJsInfo2.formId = 2;
    formJsInfo2.formName = "bb";
    int64_t formIder = 1;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    formProviderCaller.AddForm(formJsInfo2);
    MockConvertRawImageData(true);
    formProviderCaller.UpdateForm(formIder, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0020 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0021
 * @tc.desc: text OnAcquire function and ConvertRawImageData is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0021 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0021 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0022
 * @tc.desc: text OnAcquire function and ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0022 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0022 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0023
 * @tc.desc: text OnRemoteDied function and handler_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0023 starts";
    FormHostCallerRecipient formHostCallerRecipient(nullptr);
    formHostCallerRecipient.OnRemoteDied(nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0023 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0024
 * @tc.desc: text OnRemoteDied function and ConvertRawImageData is true .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0024 starts";
    FormJsInfo formJsInfo;
    int64_t formId = 1;
    FormProviderData formProviderData;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.UpdateForm(formId, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0024 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0025
 * @tc.desc: text RequestForm function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0025 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.RequestForm(formId, nullptr, want);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0025 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0026
 * @tc.desc: text MessageEvent function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0026 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.MessageEvent(formId, want, nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0026 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0027
 * @tc.desc: text OnAcquire function.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0027 starts";
    Want want;
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0027 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0028
 * @tc.desc: text OnAcquire function token is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0028 starts";
    FormJsInfo formJsInfo;
    FormProviderCaller formProviderCaller(nullptr);
    EXPECT_EQ(formProviderCaller.OnAcquire(formJsInfo, nullptr), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0028 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0029
 * @tc.desc: text IsSameToken function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0029 starts";
    FormProviderCaller formProviderCaller(nullptr);
    auto result = formProviderCaller.IsSameToken(nullptr);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0029 test ends";
}
/**
 * @tc.name: FormProviderCallerTest_0030
 * @tc.desc: text UpdateForm function and GetFormJsInfo is true ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0030 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.formName = "aa";
    FormJsInfo formJsInfo2;
    formJsInfo2.formId = 2;
    formJsInfo2.formName = "bb";
    int64_t formIder = 1;
    FormProviderData formProviderData;
    FormProviderCaller formProviderCaller(nullptr);
    formProviderCaller.AddForm(formJsInfo);
    formProviderCaller.AddForm(formJsInfo2);
    MockConvertRawImageData(true);
    formProviderCaller.UpdateForm(formIder, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0030 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0031
 * @tc.desc: text OnAcquire function and ConvertRawImageData is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0031 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0031 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0032
 * @tc.desc: text OnAcquire function and ConvertRawImageData is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0032, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0032 starts";
    int64_t formId = -1;
    Want want;
    want.SetParam(Constants::PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY, FORM_MANAGER_SERVICE_BUNDLE_NAME)
        .SetParam(Constants::ACQUIRE_TYPE, 103)
        .SetParam(Constants::FORM_CONNECT_ID, 103L)
        .SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId))
        .SetParam(Constants::FORM_SUPPLY_INFO, FORM_SUPPLY_INFO);
    FormProviderInfo formProviderInfo;
    FormProviderCaller formProviderCaller(nullptr);
    FormProviderData formProviderData;
    formProviderInfo.SetFormData(formProviderData);
    MockConvertRawImageData(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formProviderCaller.OnAcquire(formProviderInfo, want, nullptr));
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0032 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0033
 * @tc.desc: text OnRemoteDied function and handler_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0033, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0033 starts";
    FormHostCallerRecipient formHostCallerRecipient(nullptr);
    formHostCallerRecipient.OnRemoteDied(nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0033 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0034
 * @tc.desc: text OnRemoteDied function and ConvertRawImageData is true .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0034, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0034 starts";
    FormJsInfo formJsInfo;
    int64_t formId = 1;
    FormProviderData formProviderData;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.UpdateForm(formId, formProviderData);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0034 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0035
 * @tc.desc: text RequestForm function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0035, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0035 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.RequestForm(formId, nullptr, want);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0035 test ends";
}

/**
 * @tc.name: FormProviderCallerTest_0036
 * @tc.desc: text MessageEvent function and callerToken_ is nullptr .
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderCallerTest, FormProviderCallerTest_0036, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0036 starts";
    Want want;
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    FormHostCaller formHostCaller(formJsInfo, nullptr);
    formHostCaller.MessageEvent(formId, want, nullptr);
    GTEST_LOG_(INFO) << "FormProviderCallerTest_0036 test ends";
}
} // namespace
