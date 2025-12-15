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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#define private public
#include "form_host_client.h"
#undef private
#include "mock_form_token.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using testing::_;

namespace {
const std::string FORM_PROVIDER_BUNDLE_NAME = "ohos.samples.ut.form";
const std::string FORM_PROVIDER_ABILITY_NAME = "FormAbility";

class MockFormDataCallback : public FormDataCallbackInterface {
public:
    MockFormDataCallback()
    {}
    virtual ~MockFormDataCallback() = default;
    void ProcessAcquireFormData(AAFwk::WantParams data) override
    {}
};

class FmsFormHostClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormHostClientTest::SetUpTestCase()
{}

void FmsFormHostClientTest::TearDownTestCase()
{}

void FmsFormHostClientTest::SetUp()
{}

void FmsFormHostClientTest::TearDown()
{}

class FormStateCallbackTest : public FormStateCallbackInterface {
public:
    FormStateCallbackTest() = default;

    virtual ~FormStateCallbackTest() = default;

    void ProcessAcquireState(FormState state) override
    {
        state_ = state;
    }

    FormState GetFormState()
    {
        return state_;
    }

    void SetFormState(FormState state)
    {
        state_ = state;
    }

private:
    FormState state_ = FormState::UNKNOWN;
};

class FormCallback : public FormCallbackInterface {
public:
    FormCallback() = default;
    virtual ~FormCallback() = default;

    MOCK_METHOD1(ProcessFormUpdate, void(const FormJsInfo &formJsInfo));
    MOCK_METHOD1(ProcessFormUninstall, void(const int64_t formId));
    MOCK_METHOD0(OnDeathReceived, void());
    MOCK_METHOD2(OnError, void(const int32_t errorCode, const std::string &errorMsg));
    MOCK_METHOD1(ProcessEnableForm, void(bool enable));
    MOCK_METHOD2(ProcessDueControlForm, void(bool isDisablePolicy, bool isControl));
    MOCK_METHOD0(ProcessCheckForm, void());
};

class ShareFormCallBackMock : public ShareFormCallBack {
public:
    ShareFormCallBackMock() = default;
    virtual ~ShareFormCallBackMock() = default;

    MOCK_METHOD1(ProcessShareFormResponse, void(int32_t result));
};

/**
 * @tc.name: AddFormState_0100
 * @tc.desc: add form state
 * @tc.type: AddFormState
 * @tc.require:
 */
HWTEST_F(FmsFormHostClientTest, AddFormState_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0100 start";

    std::shared_ptr<FormStateCallbackInterface> formStateCallback = std::make_shared<FormStateCallbackTest>();
    AAFwk::Want want;
    want.SetElementName(FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    bool result = formHostClient->AddFormState(formStateCallback, want);
    EXPECT_EQ(result, true);
    formHostClient->RemoveFormState(want);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0100 end";
}

/**
 * @tc.name: AddFormState_0200
 * @tc.desc: add form state
 * @tc.type: AddFormState
 * @tc.require:
 */
HWTEST_F(FmsFormHostClientTest, AddFormState_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0200 start";
    std::shared_ptr<FormStateCallbackTest> formStateCallback = std::make_shared<FormStateCallbackTest>();
    AAFwk::Want want;
    want.SetElementName(FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    bool result = formHostClient->AddFormState(formStateCallback, want);
    EXPECT_EQ(result, true);
    formHostClient->OnAcquireState(FormState::DEFAULT, want);
    FormState state = formStateCallback->GetFormState();
    EXPECT_EQ(state, FormState::DEFAULT);
    formHostClient->RemoveFormState(want);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0200 end";
}

/**
 * @tc.name: AddFormState_0300
 * @tc.desc: add form state
 * @tc.type: AddFormState
 * @tc.require:
 */
HWTEST_F(FmsFormHostClientTest, AddFormState_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0300 start";
    std::shared_ptr<FormStateCallbackTest> formStateCallback = std::make_shared<FormStateCallbackTest>();
    AAFwk::Want want;
    want.SetElementName(FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    bool result = formHostClient->AddFormState(formStateCallback, want);
    EXPECT_EQ(result, true);
    formHostClient->RemoveFormState(want);
    // FormStateCallbackTest will not be called while OnAcquireState, and state does not change.
    formHostClient->OnAcquireState(FormState::DEFAULT, want);
    FormState state = formStateCallback->GetFormState();
    EXPECT_EQ(state, FormState::UNKNOWN);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0300 end";
}

/**
 * @tc.name: RegisterUninstallCallback_0100
 * @tc.desc: test RegisterUninstallCallback function.
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FmsFormHostClientTest, RegisterUninstallCallback_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RegisterUninstallCallback_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    FormHostClient::UninstallCallback callback = nullptr;
    bool result = formHostClient->RegisterUninstallCallback(callback);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RegisterUninstallCallback_0100 end";
}

/**
 * @tc.name: OnAcquired_0100
 * @tc.desc: test OnAcquired function.
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FmsFormHostClientTest, OnAcquired_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquired_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    FormJsInfo formJsInfo;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    formHostClient->OnAcquired(formJsInfo, token);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquired_0100 end";
}

/**
 * @tc.name: OnUninstall_0100
 * @tc.desc: test OnUninstall function.
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FmsFormHostClientTest, OnUninstall_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUninstall_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    std::vector<int64_t> formIds;
    formHostClient->OnUninstall(formIds);
    int64_t formId = -1;
    formIds.emplace_back(formId);
    formHostClient->OnUninstall(formIds);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUninstall_0100 end";
}

/**
 * @tc.name: AddShareFormCallback_0100
 * @tc.desc: test AddShareFormCallback function.
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FmsFormHostClientTest, AddShareFormCallback_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddShareFormCallback_0100 start";
    std::shared_ptr<ShareFormCallBack> shareFormCallback = nullptr;
    int64_t requestCode = 1;
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    bool result = formHostClient->AddShareFormCallback(shareFormCallback, requestCode);
    EXPECT_EQ(result, true);
    int32_t result1 = 2;
    formHostClient->OnShareFormResponse(requestCode, result1);
    formHostClient->RemoveShareFormCallback(requestCode);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddShareFormCallback_0100 end";
}

/**
 * @tc.name: AddAcqiureFormDataCallback_0100
 * @tc.desc: test AddAcqiureFormDataCallback function.
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FmsFormHostClientTest, AddAcqiureFormDataCallback_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddAcqiureFormDataCallback_0100 start";
    std::shared_ptr<FormDataCallbackInterface> formDataCallbackInterface = nullptr;
    int64_t requestCode = 1;
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    bool result = formHostClient->AddAcqiureFormDataCallback(formDataCallbackInterface, requestCode);
    EXPECT_EQ(result, true);
    AAFwk::WantParams wantParams;
    formHostClient->OnAcquireDataResponse(wantParams, requestCode);
    formHostClient->RemoveAcquireDataCallback(requestCode);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddAcqiureFormDataCallback_0100 end";
}

/**
 * @tc.name: OnAcquireDataResponse_0100
 * @tc.desc: test OnAcquireDataResponse function.
 * @tc.type: FUNC
 * @tc.require: Cover OnAcquireDataResponse
 */
HWTEST_F(FmsFormHostClientTest, OnAcquireDataResponse_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquireDataResponse_0100 start";
    std::shared_ptr<FormDataCallbackInterface> formDataCallbackInterface = std::make_shared<MockFormDataCallback>();
    int64_t requestCode = 1;
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    AAFwk::WantParams wantParams;
    formHostClient->OnAcquireDataResponse(wantParams, requestCode);
    formHostClient->AddAcqiureFormDataCallback(formDataCallbackInterface, requestCode);
    formHostClient->OnAcquireDataResponse(wantParams, requestCode);
    formHostClient->RemoveAcquireDataCallback(requestCode);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquireDataResponse_0100 end";
}

/**
 * @tc.number: AddFormState_0400
 * @tc.name: AddFormState
 * @tc.desc: Verify AddFormState succeeded.
 */
HWTEST_F(FmsFormHostClientTest, AddFormState_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0400 start";
    auto formStateCallback = std::make_shared<FormStateCallbackTest>();
    AAFwk::Want want;
    want.SetElementName(FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    auto result = formHostClient->AddFormState(formStateCallback, want);
    EXPECT_TRUE(result);
    auto callback = std::make_shared<FormStateCallbackTest>();
    result = formHostClient->AddFormState(callback, want);
    EXPECT_TRUE(result);
    auto size = static_cast<int32_t>(formHostClient->formStateCallbackMap_.size());
    EXPECT_EQ(size, 1);
    formHostClient->formStateCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddFormState_0400 end";
}

/**
 * @tc.number: RemoveForm_0100
 * @tc.name: RemoveForm
 * @tc.desc: callback is nullptr, verify RemoveForm failed.
 */
HWTEST_F(FmsFormHostClientTest, RemoveForm_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    std::shared_ptr<FormCallbackInterface> formCallback = nullptr;
    formHostClient->RemoveForm(formCallback, formId);
    auto size = static_cast<int32_t>(formHostClient->formCallbackMap_.size());
    EXPECT_EQ(size, 1);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0100 end";
}

/**
 * @tc.number: RemoveForm_0200
 * @tc.name: RemoveForm
 * @tc.desc: Form id is less than 0, verify RemoveForm failed.
 */
HWTEST_F(FmsFormHostClientTest, RemoveForm_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    formId = -1;
    formHostClient->RemoveForm(callback, formId);
    auto size = static_cast<int32_t>(formHostClient->formCallbackMap_.size());
    EXPECT_EQ(size, 1);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0200 end";
}

/**
 * @tc.number: RemoveForm_0300
 * @tc.name: RemoveForm
 * @tc.desc: Form id is not exist, verify RemoveForm failed.
 */
HWTEST_F(FmsFormHostClientTest, RemoveForm_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0300 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    formId = 10;
    formHostClient->RemoveForm(callback, formId);
    auto size = static_cast<int32_t>(formHostClient->formCallbackMap_.size());
    EXPECT_EQ(size, 1);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0300 end";
}

/**
 * @tc.number: RemoveForm_0400
 * @tc.name: RemoveForm
 * @tc.desc: Verify RemoveForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, RemoveForm_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0400 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    formHostClient->RemoveForm(callback, formId);
    auto size = static_cast<int32_t>(formHostClient->formCallbackMap_.size());
    EXPECT_EQ(size, 0);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest RemoveForm_0400 end";
}

/**
 * @tc.number: ContainsForm_0100
 * @tc.name: ContainsForm
 * @tc.desc: Verify ContainsForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, ContainsForm_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest ContainsForm_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    auto result = formHostClient->ContainsForm(formId);
    EXPECT_TRUE(result);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest ContainsForm_0100 end";
}

/**
 * @tc.number: ContainsForm_0200
 * @tc.name: ContainsForm
 * @tc.desc: form id is not exist, verify ContainsForm failed.
 */
HWTEST_F(FmsFormHostClientTest, ContainsForm_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest ContainsForm_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto result = formHostClient->ContainsForm(formId);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest ContainsForm_0200 end";
}

/**
 * @tc.number: UpdateForm_0100
 * @tc.name: UpdateForm
 * @tc.desc: Verify UpdateForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, UpdateForm_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessFormUpdate(_)).Times(1);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    formHostClient->UpdateForm(formJsInfo);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0100 end";
}

/**
 * @tc.number: UpdateForm_0200
 * @tc.name: UpdateForm
 * @tc.desc: Form id is not exist, verify UpdateForm failed.
 */
HWTEST_F(FmsFormHostClientTest, UpdateForm_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    FormJsInfo formJsInfo;
    formJsInfo.formId = 2;
    formHostClient->UpdateForm(formJsInfo);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0200 end";
}

/**
 * @tc.number: UpdateForm_0300
 * @tc.name: UpdateForm
 * @tc.desc: Form id is less than 0, verify UpdateForm failed.
 */
HWTEST_F(FmsFormHostClientTest, UpdateForm_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0300 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    FormJsInfo formJsInfo;
    formJsInfo.formId = -1;
    formHostClient->UpdateForm(formJsInfo);
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest UpdateForm_0300 end";
}

/**
 * @tc.number: OnAcquired_0200
 * @tc.name: OnAcquired
 * @tc.desc: token is nullptr, Verify OnAcquired succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnAcquired_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquired_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessFormUpdate(_)).Times(1);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    sptr<MockFormToken> token = nullptr;
    formHostClient->OnAcquired(formJsInfo, token);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnAcquired_0200 end";
}

/**
 * @tc.number: OnUpdate_0100
 * @tc.name: OnUpdate
 * @tc.desc: token is nullptr, Verify OnUpdate succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnUpdate_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUpdate_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = 1;
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessFormUpdate(_)).Times(1);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    formHostClient->OnUpdate(formJsInfo);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUpdate_0100 end";
}

/**
 * @tc.number: OnUninstall_0200
 * @tc.name: OnUninstall
 * @tc.desc: Verify OnUninstall succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnUninstall_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUninstall_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    int64_t formId = 10;
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessFormUninstall(_)).Times(1);
    std::vector<int64_t> formIds;
    formIds.emplace_back(-1);
    formIds.emplace_back(100);
    formIds.emplace_back(formId);
    formHostClient->OnUninstall(formIds);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    formIds.clear();
    formIds.emplace_back(-1);
    formHostClient->OnUninstall(formIds);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnUninstall_0200 end";
}

/**
 * @tc.number: OnShareFormResponse_0100
 * @tc.name: OnShareFormResponse
 * @tc.desc: Verify OnShareFormResponse succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnShareFormResponse_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnShareFormResponse_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t requestCode = 1;
    auto callback = std::make_shared<ShareFormCallBackMock>();
    formHostClient->shareFormCallbackMap_.emplace(requestCode, callback);

    EXPECT_CALL(*callback, ProcessShareFormResponse(_)).Times(1);
    int32_t result = 0;
    formHostClient->OnShareFormResponse(2, result);
    formHostClient->OnShareFormResponse(requestCode, result);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->shareFormCallbackMap_.clear();
    int32_t errorCode = 1;
    std::string errorMsg = "this is errorMsg";
    formHostClient->OnError(errorCode, errorMsg);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnShareFormResponse_0100 end";
}
/**
 * @tc.number: OnRecycleForm_0100
 * @tc.name: OnRecycleForm
 * @tc.desc: Verify OnRecycleForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnRecycleForm_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnRecycleForm_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    int64_t formId = -1;
    formHostClient->OnRecycleForm(formId);

    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    formHostClient->formCallbackMap_.emplace(2, callbackSet);
    
    formId = 1;
    formHostClient->OnRecycleForm(formId);

    formId = 2;
    formHostClient->OnRecycleForm(formId);
    formHostClient->formCallbackMap_.clear();

    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnRecycleForm_0100 end";
}

/**
 * @tc.number: OnEnableForm_0300
 * @tc.name: OnEnableForm
 * @tc.desc: Verify OnEnableForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnEnableForm_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnEnableForm_0300 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    int64_t formId = 10;
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessEnableForm(_)).Times(1);
    std::vector<int64_t> formIds;
    formIds.emplace_back(-1);
    formIds.emplace_back(formId);
    formHostClient->OnEnableForm(formIds, true);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnEnableForm_0300 end";
}

/**
 * @tc.number: AddForm_0100
 * @tc.name: AddForm
 * @tc.desc: form callback is not nullptr.
 */
HWTEST_F(FmsFormHostClientTest, AddForm_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddForm_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.uiSyntax = FormType::ETS;
    std::shared_ptr<FormCallbackInterface> formCallback = std::make_shared<FormCallback>();
    ASSERT_NE(nullptr, formCallback);
    formHostClient->AddForm(formCallback, formJsInfo);
    EXPECT_EQ(
        formHostClient->formCallbackMap_.find(formJsInfo.formId) != formHostClient->formCallbackMap_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddForm_0100 end";
}

/**
 * @tc.number: AddForm_0200
 * @tc.name: AddForm
 * @tc.desc: form callback is nullptr, verify AddForm failed.
 */
HWTEST_F(FmsFormHostClientTest, AddForm_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddForm_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    std::shared_ptr<FormCallbackInterface> formCallback = nullptr;
    FormJsInfo formJsInfo;
    formJsInfo.formId = -1;
    formHostClient->AddForm(formCallback, formJsInfo);
    EXPECT_EQ(
        formHostClient->formCallbackMap_.find(formJsInfo.formId) == formHostClient->formCallbackMap_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest AddForm_0200 end";
}

/**
 * @tc.number: OnError_0100
 * @tc.name: OnError
 * @tc.desc: Cover OnError.
 */
HWTEST_F(FmsFormHostClientTest, OnError_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnError_0100 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.uiSyntax = FormType::ETS;
    formHostClient->AddForm(nullptr, formJsInfo);
    formJsInfo.formId = 2;
    std::shared_ptr<FormCallbackInterface> formCallback = std::make_shared<FormCallback>();
    formHostClient->AddForm(formCallback, formJsInfo);
    formHostClient->etsFormIds_.emplace(3);
    int32_t errorCode = 1;
    std::string errorMsg = "this is errorMsg";
    formHostClient->OnError(errorCode, errorMsg);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnError_0100 end";
}

/**
 * @tc.number: OnError_0200
 * @tc.name: OnError
 * @tc.desc: Cover OnError.
 */
HWTEST_F(FmsFormHostClientTest, OnError_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnError_0200 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    std::vector<int64_t> formIds = {1, 2, 3, 4};
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfo.uiSyntax = FormType::ETS;
    formHostClient->AddForm(nullptr, formJsInfo);
    formJsInfo.formId = 2;
    std::shared_ptr<FormCallbackInterface> formCallback = std::make_shared<FormCallback>();
    formHostClient->AddForm(nullptr, formJsInfo);
    formHostClient->etsFormIds_.emplace(3);
    int32_t errorCode = 1;
    std::string errorMsg = "this is errorMsg";
    formHostClient->OnError(errorCode, errorMsg, formIds);
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnError_0200 end";
}

/**
 * @tc.number: OnDueControlForm_001
 * @tc.name: OnDueControlForm
 * @tc.desc: Verify OnDueControlForm succeeded.
 */
HWTEST_F(FmsFormHostClientTest, OnDueControlForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnDueControlForm_001 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    int64_t formId = 10;
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessDueControlForm(_, _)).Times(1);
    std::vector<int64_t> formIds;
    formIds.emplace_back(-1);
    formIds.emplace_back(formId);
    formHostClient->OnDueControlForm(formIds, true, true);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnDueControlForm_001 end";
}

/**
 * @tc.number: OnCheckForm_001
 * @tc.name: OnCheckForm
 * @tc.desc: Verify OnCheckForm.
 */
HWTEST_F(FmsFormHostClientTest, OnCheckForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnCheckForm_001 start";
    sptr<FormHostClient> formHostClient = FormHostClient::GetInstance();
    auto callback = std::make_shared<FormCallback>();
    std::set<std::shared_ptr<FormCallbackInterface>> callbackSet;
    callbackSet.emplace(callback);
    int64_t formId = 10;
    formHostClient->formCallbackMap_.emplace(formId, callbackSet);

    EXPECT_CALL(*callback, ProcessCheckForm()).Times(1);
    std::vector<int64_t> formIds;
    formIds.emplace_back(-1);
    formIds.emplace_back(formId);
    formHostClient->OnCheckForm(formIds);
    testing::Mock::AllowLeak(callback.get());
    formHostClient->formCallbackMap_.clear();
    GTEST_LOG_(INFO) << "FmsFormHostClientTest OnCheckForm_001 end";
}
}