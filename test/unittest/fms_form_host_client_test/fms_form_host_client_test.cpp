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
#include "form_host_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string FORM_PROVIDER_BUNDLE_NAME = "ohos.samples.ut.form";
const std::string FORM_PROVIDER_ABILITY_NAME = "FormAbility";

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
}