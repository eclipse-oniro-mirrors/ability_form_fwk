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

#include <chrono>
#include <gtest/gtest.h>

#include "form_constants.h"
#include "form_js_info.h"
#include "form_mgr_errors.h"
#define private public
#include "form_render_impl.h"
#undef private
#include "form_supply_stub.h"
#include "gmock/gmock.h"
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr int32_t SET_VISIBLE_CHANGE_FAILED = -1;
} // namespace

class FormRenderImplTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRenderImplTest::SetUpTestCase()
{}

void FormRenderImplTest::TearDownTestCase()
{}

void FormRenderImplTest::SetUp()
{}

void FormRenderImplTest::TearDown()
{}

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub() {};
    virtual ~MockFormSupplyStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return number_;
    };
    int HandleOnAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnEventHandle(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnAcquireStateResult(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int32_t HandleOnShareAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return number_;
    };
    int OnEventHandle(const Want &want) override
    {
        return number_;
    };
    int OnAcquireStateResult(FormState state, const std::string &pro, const Want &wantArg,
        const Want &want) override
    {
        return number_;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
    {
        return ERR_OK;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    const int number_ = 1;
};

/**
 * @tc.name: FormRenderImplTest_001
 * @tc.desc: 1.Verify RenderForm interface executes as expected.
 *           2.callerToken is nullptr.
 *           3.formSupplyClient is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_001 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formSupplyClient = nullptr;
    auto ret = formRenderImpl.RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_001 end";
}

/**
 * @tc.name: FormRenderImplTest_002
 * @tc.desc: 1.Verify RenderForm interface executes as expected.
 *           2.callerToken is not nullptr.
 *           3.uid is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_002 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    auto ret = formRenderImpl.RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_002 end";
}

/**
 * @tc.name: FormRenderImplTest_003
 * @tc.desc: 1.Verify RenderForm interface executes as expected.
 *           2.callerToken is not nullptr.
 *           3.uid is not empty and hostToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_003 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    auto ret = formRenderImpl.RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_003 end";
}

/**
 * @tc.name: FormRenderImplTest_004
 * @tc.desc: 1.Verify StopRenderingForm interface executes as expected.
 *           2.callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_004 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formRenderImpl.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_004 end";
}

/**
 * @tc.name: FormRenderImplTest_005
 * @tc.desc: 1.Verify StopRenderingForm interface executes as expected.
 *           2.want is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_005 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    auto ret = formRenderImpl.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_005 end";
}

/**
 * @tc.name: FormRenderImplTest_006
 * @tc.desc: 1.Verify CleanFormHost interface executes as expected.
 *           2.renderRecord is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_006 start";
    FormRenderImpl formRenderImpl;
    sptr<IRemoteObject> hostToken = nullptr;
    std::string supplyUid = "UID";
    formRenderImpl.renderRecordMap_.emplace(supplyUid, nullptr);
    EXPECT_EQ(ERR_OK, formRenderImpl.CleanFormHost(hostToken));
    GTEST_LOG_(INFO) << "FormRenderImplTest_006 end";
}

/**
 * @tc.name: FormRenderImplTest_007
 * @tc.desc: 1.Verify CleanFormHost interface executes as expected.
 *           2.renderRecord is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_007 start";
    FormRenderImpl formRenderImpl;
    sptr<IRemoteObject> hostToken = nullptr;
    std::string supplyUid = "UID";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderImpl.renderRecordMap_.emplace(supplyUid, formRenderRecord);
    EXPECT_EQ(ERR_OK, formRenderImpl.CleanFormHost(hostToken));
    GTEST_LOG_(INFO) << "FormRenderImplTest_007 end";
}

/**
 * @tc.name: FormRenderImplTest_008
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_008 start";
    FormRenderImpl formRenderImpl;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderImpl.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderImplTest_008 end";
}

/**
 * @tc.name: FormRenderImplTest_009
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search == renderRecordMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_009 start";
    FormRenderImpl formRenderImpl;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    EXPECT_EQ(RELOAD_FORM_FAILED, formRenderImpl.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderImplTest_009 end";
}

/**
 * @tc.name: FormRenderImplTest_010
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search->second is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_010 start";
    FormRenderImpl formRenderImpl;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    formRenderImpl.renderRecordMap_.emplace(value, nullptr);
    EXPECT_EQ(ERR_OK, formRenderImpl.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderImplTest_010 end";
}

/**
 * @tc.name: FormRenderImplTest_011
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search->second is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_011 start";
    FormRenderImpl formRenderImpl;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderImpl.renderRecordMap_.emplace(value, formRenderRecord);
    EXPECT_EQ(ERR_OK, formRenderImpl.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderImplTest_011 end";
}

/**
 * @tc.name: FormRenderImplTest_012
 * @tc.desc: 1.Verify StopRenderingForm interface executes as expected.
 *           2.search != renderRecordMap_.end()
 *           3.search->second is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_012 start";
    FormRenderImpl formRenderImpl;
    FormJsInfo formJsInfo;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderImpl.renderRecordMap_.emplace(value, formRenderRecord);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    auto ret = formRenderImpl.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_012 end";
}

/**
 * @tc.name: FormRenderImplTest_013
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_013 start";
    FormRenderImpl formRenderImpl;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderImpl.renderRecordMap_.emplace(value, formRenderRecord);
    formRenderImpl.OnConfigurationUpdated(configuration);
    GTEST_LOG_(INFO) << "FormRenderImplTest_013 end";
}

/**
 * @tc.name: FormRenderImplTest_014
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_014 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    formRenderImpl.renderRecordMap_.emplace(value, formRenderRecord);
    formRenderImpl.SetConfiguration(configuration);
    GTEST_LOG_(INFO) << "FormRenderImplTest_014 end";
}

/**
 * @tc.name: FormRenderImplTest_015
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_015 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    formRenderImpl.renderRecordMap_.emplace(value, formRenderRecord);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formSupplyClient = nullptr;
    formRenderImpl.SetConfiguration(configuration);
    GTEST_LOG_(INFO) << "FormRenderImplTest_015 end";
}

/**
 * @tc.name: FormRenderImplTest_016
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_016 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    EXPECT_FALSE(formRenderImpl.configuration_);
    formRenderImpl.OnConfigurationUpdated(configuration);
    EXPECT_TRUE(formRenderImpl.configuration_);
    GTEST_LOG_(INFO) << "FormRenderImplTest_016 end";
}

/**
 * @tc.name: FormRenderImplTest_017
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_017 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderImpl.configUpdateTime_ = std::chrono::steady_clock::now();
    formRenderImpl.OnConfigurationUpdated(configuration);
#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    if (!screenOnFlag) {
        EXPECT_EQ(0, formRenderImpl.serialQueue_->taskMap_.size());
        EXPECT_TRUE(formRenderImpl.hasCachedConfig_);
    } else {
        EXPECT_EQ(1, formRenderImpl.serialQueue_->taskMap_.size());
    }
#endif
    GTEST_LOG_(INFO) << "FormRenderImplTest_017 end";
}

/**
 * @tc.name: FormRenderImplTest_018
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_018 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderImpl.configUpdateTime_ =
        std::chrono::steady_clock::now() - std::chrono::milliseconds(3000);
    formRenderImpl.OnConfigurationUpdated(configuration);
    EXPECT_EQ(0, formRenderImpl.serialQueue_->taskMap_.size());
    GTEST_LOG_(INFO) << "FormRenderImplTest_018 end";
}

/**
 * @tc.name: FormRenderImplTest_019
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_019 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;

    EXPECT_FALSE(formRenderImpl.configuration_);
    formRenderImpl.SetConfiguration(configuration);
    EXPECT_FALSE(formRenderImpl.configuration_);
    configuration = std::make_shared<Configuration>();
    formRenderImpl.OnConfigurationUpdated(configuration);
    EXPECT_TRUE(formRenderImpl.configuration_);
    GTEST_LOG_(INFO) << "FormRenderImplTest_019 end";
}

/**
 * @tc.name: FormRenderImplTest_020
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_020 start";
    FormRenderImpl formRenderImpl;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    EXPECT_FALSE(formRenderImpl.configuration_);
    formRenderImpl.SetConfiguration(configuration);
    EXPECT_TRUE(formRenderImpl.configuration_);
    GTEST_LOG_(INFO) << "FormRenderImplTest_020 end";
}

/**
 * @tc.name: FormRenderImplTest_021
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_021 start";
    FormRenderImpl formRenderImpl;
    formRenderImpl.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderImpl.configuration_->AddItem("ohos.system.colorMode", "rgb");

    formRenderImpl.SetConfiguration(configuration);
    EXPECT_TRUE(formRenderImpl.configuration_);
    EXPECT_EQ(formRenderImpl.configuration_->GetItem("ohos.system.colorMode"), "rgb");
    GTEST_LOG_(INFO) << "FormRenderImplTest_021 end";
}

/**
 * @tc.name: FormRenderImplTest_022
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_022 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ -1 };
    std::string compId{ "1" };
    std::string uid{ "202410101010" };
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_022 end";
}

/**
 * @tc.name: FormRenderImplTest_023
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_023 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 15 };
    std::string compId{ "" };
    std::string uid{ "202410101010" };
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_023 end";
}

/**
 * @tc.name: FormRenderImplTest_024
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_024 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 15 };
    std::string compId{ "15" };
    std::string uid{ "" };
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_024 end";
}

/**
 * @tc.name: FormRenderImplTest_025
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_025 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 15 };
    std::string compId{ "15" };
    std::string uid{ "202410101010" };
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_025 end";
}

/**
 * @tc.name: FormRenderImplTest_026
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_026 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 15 };
    std::string compId{ "15" };
    std::string uid{ "202410101010" };
    formRenderImpl.renderRecordMap_.emplace(uid, nullptr);
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_026 end";
}

/**
 * @tc.name: FormRenderImplTest_027
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_027 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 15 };
    std::string compId{ "15" };
    std::string uid{ "202410101010" };

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    EXPECT_TRUE(formSupplyClient);
    formRenderImpl.formSupplyClient_ = formSupplyClient;

    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    formRenderImpl.renderRecordMap_.emplace(uid, formRenderRecord);
    EXPECT_EQ(formRenderImpl.ReleaseRenderer(formId, compId, uid), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_027 end";
}

/**
 * @tc.name: FormRenderImplTest_028
 * @tc.desc: 1.Verify OnUnlock interface executes as expected.
 *           2.call OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_028 start";
    FormRenderImpl formRenderImpl;
    EXPECT_EQ(formRenderImpl.OnUnlock(), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_028 end";
}

/**
 * @tc.name: FormRenderImplTest_029
 * @tc.desc: 1.Verify OnUnlock interface executes as expected.
 *           2.call OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_029 start";
    FormRenderImpl formRenderImpl;
    formRenderImpl.isVerified_ = true;
    EXPECT_EQ(formRenderImpl.OnUnlock(), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_029 end";
}

/**
 * @tc.name: FormRenderImplTest_030
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_030 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 0 };
    Want want;

    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderImplTest_030 end";
}

/**
 * @tc.name: FormRenderImplTest_031
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_031 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;

    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_031 end";
}

/**
 * @tc.name: FormRenderImplTest_032
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_032 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    std::string uid{ "202410101010" };
    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_032 end";
}

/**
 * @tc.name: FormRenderImplTest_033
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_033 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    formRenderImpl.renderRecordMap_.emplace("2024101010", nullptr);
    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_033 end";
}

/**
 * @tc.name: FormRenderImplTest_034
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_034 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "2024101010");
    formRenderImpl.renderRecordMap_.emplace("2024101010", formRenderRecord);
    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_034 end";
}

/**
 * @tc.name: FormRenderImplTest_035
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_035 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    EXPECT_TRUE(formRenderRecord);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderImpl.renderRecordMap_.emplace(uid, formRenderRecord);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    EXPECT_TRUE(formSupplyClient);
    formRenderImpl.formSupplyClient_ = formSupplyClient;
    EXPECT_EQ(formRenderImpl.RecycleForm(formId, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_035 end";
}

/**
 * @tc.name: FormRenderImplTest_036
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_036 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 0 };
    Want want;
    FormJsInfo info;
    info.formId = formId;
    EXPECT_EQ(formRenderImpl.RecoverForm(info, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderImplTest_036 end";
}

/**
 * @tc.name: FormRenderImplTest_037
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_037 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    FormJsInfo info;
    info.formId = formId;
    EXPECT_EQ(formRenderImpl.RecoverForm(info, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_037 end";
}

/**
 * @tc.name: FormRenderImplTest_038
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_038 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    FormJsInfo info;
    info.formId = formId;
    EXPECT_EQ(formRenderImpl.RecoverForm(info, want), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_038 end";
}

/**
 * @tc.name: FormRenderImplTest_039
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_039 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    FormJsInfo info;
    info.formId = formId;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    std::string val{ "non" };
    want.SetParam(Constants::FORM_STATUS_DATA, val);
    formRenderImpl.renderRecordMap_.emplace("2024101010", nullptr);
    EXPECT_EQ(formRenderImpl.RecoverForm(info, want), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_039 end";
}

/**
 * @tc.name: FormRenderImplTest_040
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_040 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    FormJsInfo info;
    info.formId = formId;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    std::string val{ "non" };
    want.SetParam(Constants::FORM_STATUS_DATA, val);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    EXPECT_TRUE(formSupplyClient);
    formRenderRecord->formSupplyClient_ = formSupplyClient;

    formRenderImpl.renderRecordMap_.emplace(uid, formRenderRecord);
    EXPECT_EQ(formRenderImpl.RecoverForm(info, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_040 end";
}

/**
 * @tc.name: FormRenderImplTest_041
 * @tc.desc: 1.Verify ConfirmUnlockState interface executes as expected.
 *           2.call ConfirmUnlockState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_041 start";
    FormRenderImpl formRenderImpl;
    formRenderImpl.isVerified_ = true;
    Want want;
    formRenderImpl.ConfirmUnlockState(want);

    auto param = want.GetBoolParam(Constants::FORM_RENDER_STATE, false);
    EXPECT_TRUE(param);
    GTEST_LOG_(INFO) << "FormRenderImplTest_041 end";
}

/**
 * @tc.name: FormRenderImplTest_042
 * @tc.desc: 1.Verify ConfirmUnlockState interface executes as expected.
 *           2.call ConfirmUnlockState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, FormRenderImplTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_042 start";
    FormRenderImpl formRenderImpl;
    EXPECT_FALSE(formRenderImpl.isVerified_);
    Want want;
    want.SetParam(Constants::FORM_RENDER_STATE, true);
    formRenderImpl.ConfirmUnlockState(want);

    EXPECT_TRUE(formRenderImpl.isVerified_);
    GTEST_LOG_(INFO) << "FormRenderImplTest_042 end";
}

/**
* @tc.name: FormRenderImplTest_043
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_043 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 0 };
    Want want;

    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderImplTest_043 end";
}

/**
* @tc.name: FormRenderImplTest_044
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_044 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_044 end";
}

/**
* @tc.name: FormRenderImplTest_045
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_045 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    std::string uid{ "202410101010" };
    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_045 end";
}

/**
* @tc.name: FormRenderImplTest_046
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_046 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    formRenderImpl.renderRecordMap_.emplace("2024101010", nullptr);
    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_046 end";
}

/**
* @tc.name: FormRenderImplTest_047
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_047 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "2024101010");
    formRenderImpl.renderRecordMap_.emplace("2024101010", formRenderRecord);
    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderImplTest_047 end";
}

/**
* @tc.name: FormRenderImplTest_048
* @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
* 2.call SetVisibleChange
* @tc.type: FUNC
*/
HWTEST_F(FormRenderImplTest, FormRenderImplTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderImplTest_048 start";
    FormRenderImpl formRenderImpl;
    int64_t formId{ 3 };
    Want want;
    std::string uid{ "202410101010" };
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    EXPECT_TRUE(formRenderRecord);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderImpl.renderRecordMap_.emplace(uid, formRenderRecord);
    EXPECT_EQ(formRenderImpl.SetVisibleChange(formId, true, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderImplTest_048 end";
}

/**
 * @tc.name: RunCachedConfigurationUpdatedTest_001
 * @tc.desc: Verify RunCachedConfigurationUpdated interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderImplTest, RunCachedConfigurationUpdatedTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdatedTest_001 start";
    FormRenderImpl formRenderImpl;
    formRenderImpl.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    formRenderImpl.configuration_->AddItem("ohos.system.colorMode", "dark");
    formRenderImpl.hasCachedConfig_ = true;

    formRenderImpl.RunCachedConfigurationUpdated();
    EXPECT_FALSE(formRenderImpl.hasCachedConfig_);
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdatedTest_001 end";
}
