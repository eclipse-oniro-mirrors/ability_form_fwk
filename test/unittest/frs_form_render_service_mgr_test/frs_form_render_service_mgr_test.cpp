/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "form_memmgr_client.h"
#include "form_render_service_mgr.h"
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
constexpr int32_t ERR_FAILED = -1;
constexpr int32_t UPDATE_FORM_SIZE_FAILED = -1;
}  // namespace

class FormRenderServiceMgrTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRenderServiceMgrTest::SetUpTestCase()
{}

void FormRenderServiceMgrTest::TearDownTestCase()
{}

void FormRenderServiceMgrTest::SetUp()
{}

void FormRenderServiceMgrTest::TearDown()
{}

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub(){};
    virtual ~MockFormSupplyStub(){};
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
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
    int OnAcquireStateResult(FormState state, const std::string &pro, const Want &wantArg, const Want &want) override
    {
        return number_;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
    {
        return ERR_OK;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId, const AAFwk::WantParams &wantParams,
        int64_t requestCode, const bool &result) override{};
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

static void SetFormSupplyClient(FormRenderServiceMgr &formRenderServiceMgr)
{
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formRenderServiceMgr.SetFormSupplyClient(formSupplyClient);
}

/**
 * @tc.name: FormRenderServiceMgrTest_001
 * @tc.desc: 1.Verify RenderForm interface executes as expected.
 *           2.callerToken is nullptr.
 *           3.formSupplyClient is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_001 start";
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_001 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_002
 * @tc.desc: Verify RenderForm.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_002 start";

    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    auto ret = FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    const std::string value = "UID";
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, value);
    ret = FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    ret = FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_002 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_003
 * @tc.desc: Verify ProcessRenderForm.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_003 start";

    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = FormRenderServiceMgr::GetInstance().ProcessRenderForm(formJsInfo, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    FormRenderServiceMgr::GetInstance().SetFormSupplyClient(nullptr);
    ret = FormRenderServiceMgr::GetInstance().ProcessRenderForm(formJsInfo, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);

    callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderServiceMgr::GetInstance().SetFormSupplyClient(formSupplyClient);
    ret = FormRenderServiceMgr::GetInstance().ProcessRenderForm(formJsInfo, want);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_003 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_004
 * @tc.desc: 1.Verify StopRenderingForm interface executes as expected.
 *           2.callerToken is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_004 start";
    FormRenderServiceMgr formRenderServiceMgr;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_004 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_005
 * @tc.desc: 1.Verify StopRenderingForm interface executes as expected.
 *           2.want is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_005 start";
    FormRenderServiceMgr formRenderServiceMgr;
    FormJsInfo formJsInfo;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    auto ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_005 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_006
 * @tc.desc: 1.Verify CleanFormHost interface executes as expected.
 *           2.renderRecord is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_006 start";
    FormRenderServiceMgr formRenderServiceMgr;
    sptr<IRemoteObject> hostToken = nullptr;
    std::string supplyUid = "UID";
    formRenderServiceMgr.renderRecordMap_.emplace(supplyUid, nullptr);
    EXPECT_EQ(ERR_OK, formRenderServiceMgr.CleanFormHost(hostToken));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_006 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_007
 * @tc.desc: 1.Verify CleanFormHost interface executes as expected.
 *           2.renderRecord is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_007 start";
    FormRenderServiceMgr formRenderServiceMgr;
    sptr<IRemoteObject> hostToken = nullptr;
    std::string supplyUid = "UID";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderServiceMgr.renderRecordMap_.emplace(supplyUid, formRenderRecord);
    EXPECT_EQ(ERR_OK, formRenderServiceMgr.CleanFormHost(hostToken));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_007 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_008
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_008 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderServiceMgr.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_008 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_009
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search == renderRecordMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_009 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string bundleName = "bundleName";
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, bundleName);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderServiceMgr.ReloadForm(std::move(formJsInfos), want));
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD, formRenderServiceMgr.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_009 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_010
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search->second is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_010 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    std::string bundleName = "bundleName";
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, bundleName);
    formRenderServiceMgr.renderRecordMap_.emplace(value, nullptr);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD, formRenderServiceMgr.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_010 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_011
 * @tc.desc: 1.Verify ReloadForm interface executes as expected.
 *           2.uid is not empty.
 *           3.search->second is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_011 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    std::string bundleName = "bundleName";
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, bundleName);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderServiceMgr.renderRecordMap_.emplace(value, formRenderRecord);
    EXPECT_EQ(ERR_OK, formRenderServiceMgr.ReloadForm(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_011 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_012
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_012 start";
    FormRenderServiceMgr formRenderServiceMgr;
    FormJsInfo formJsInfo;
    Want want;
    std::string value = "UID";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    auto ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    want.SetParam(Constants::FORM_STATUS_EVENT_ID, value);
    ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD);

    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderServiceMgr.renderRecordMap_.emplace(value, formRenderRecord);
    ret = formRenderServiceMgr.StopRenderingForm(formJsInfo, want, callerToken);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_012 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_013
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_013 start";
    FormRenderServiceMgr formRenderServiceMgr;
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderServiceMgr.renderRecordMap_.emplace(value, formRenderRecord);
    formRenderServiceMgr.OnConfigurationUpdated(configuration);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_013 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_014
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_014 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    formRenderServiceMgr.renderRecordMap_.emplace(value, formRenderRecord);
    formRenderServiceMgr.SetConfiguration(configuration);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_014 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_015
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_015 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    Want want;
    std::string value = "UID";
    want.SetParam(Constants::FORM_SUPPLY_UID, value);
    formRenderServiceMgr.renderRecordMap_.emplace(value, formRenderRecord);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formSupplyClient = nullptr;
    formRenderServiceMgr.SetConfiguration(configuration);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_015 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_016
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_016 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    EXPECT_FALSE(formRenderServiceMgr.configuration_);
    formRenderServiceMgr.OnConfigurationUpdated(configuration);
    EXPECT_TRUE(formRenderServiceMgr.configuration_);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_016 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_017
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_017 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderServiceMgr.configUpdateTime_ = std::chrono::steady_clock::now();
    formRenderServiceMgr.OnConfigurationUpdated(configuration);
#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    EXPECT_EQ(1, formRenderServiceMgr.serialQueue_->taskMap_.size());
#endif
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_017 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_018
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_018 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderServiceMgr.configUpdateTime_ = std::chrono::steady_clock::now() - std::chrono::milliseconds(3000);
    formRenderServiceMgr.OnConfigurationUpdated(configuration);
    EXPECT_EQ(0, formRenderServiceMgr.serialQueue_->taskMap_.size());
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_018 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_019
 * @tc.desc: 1.Verify OnConfigurationUpdated interface executes as expected.
 *           2.call OnConfigurationUpdated
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_019 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration;

    EXPECT_FALSE(formRenderServiceMgr.configuration_);
    formRenderServiceMgr.SetConfiguration(configuration);
    EXPECT_FALSE(formRenderServiceMgr.configuration_);
    configuration = std::make_shared<Configuration>();
    formRenderServiceMgr.OnConfigurationUpdated(configuration);
    EXPECT_TRUE(formRenderServiceMgr.configuration_);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_019 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_020
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_020 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    EXPECT_FALSE(formRenderServiceMgr.configuration_);
    formRenderServiceMgr.SetConfiguration(configuration);
    EXPECT_TRUE(formRenderServiceMgr.configuration_);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_020 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_021
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_021 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();

    formRenderServiceMgr.configuration_->AddItem("ohos.system.colorMode", "rgb");

    formRenderServiceMgr.SetConfiguration(configuration);
    EXPECT_TRUE(formRenderServiceMgr.configuration_);
    EXPECT_EQ(formRenderServiceMgr.configuration_->GetItem("ohos.system.colorMode"), "rgb");
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_021 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_022
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_022 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{-1};
    std::string compId{"1"};
    std::string uid{"202410101010"};
    Want want;
    EXPECT_EQ(
        formRenderServiceMgr.ReleaseRenderer(formId, compId, uid, want), ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_022 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_023
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_023 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{15};
    std::string compId{""};
    std::string uid{"202410101010"};
    std::string eventId = "123";
    Want want;
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(
        formRenderServiceMgr.ReleaseRenderer(formId, compId, uid, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_023 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_024
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_024 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{15};
    std::string compId{"15"};
    std::string uid{""};
    std::string eventId = "123";
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(
        formRenderServiceMgr.ReleaseRenderer(formId, compId, uid, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_024 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_025
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_025 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{15};
    std::string compId{"15"};
    std::string uid{"202410101010"};
    std::string eventId = "123";
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(
        formRenderServiceMgr.ReleaseRenderer(formId, compId, uid, want), ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_025 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_027
 * @tc.desc: 1.Verify SetConfiguration interface executes as expected.
 *           2.call SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_027 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{15};
    std::string compId{"15"};
    std::string uid{"202410101010"};

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    EXPECT_TRUE(formSupplyClient);
    formRenderServiceMgr.formSupplyClient_ = formSupplyClient;

    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    formRenderServiceMgr.renderRecordMap_.emplace(uid, formRenderRecord);
    std::string eventId = "123";
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    EXPECT_EQ(formRenderServiceMgr.ReleaseRenderer(formId, compId, uid, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_027 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_028
 * @tc.desc: 1.Verify OnUnlock interface executes as expected.
 *           2.call OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_028 start";
    FormRenderServiceMgr formRenderServiceMgr;
    EXPECT_EQ(formRenderServiceMgr.OnUnlock(), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_028 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_029
 * @tc.desc: 1.Verify OnUnlock interface executes as expected.
 *           2.call OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_029 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.isVerified_ = true;
    EXPECT_EQ(formRenderServiceMgr.OnUnlock(), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_029 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_030
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_030 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{0};
    Want want;

    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_030 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_031
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_031 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{0};
    Want want;
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_031 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_032
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_032 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_032 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_033
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_033 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    SetFormSupplyClient(formRenderServiceMgr);
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_033 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_034
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_034 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    SetFormSupplyClient(formRenderServiceMgr);
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "2024101010");
    formRenderServiceMgr.renderRecordMap_.emplace("2024101010", formRenderRecord);
    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_034 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_035
 * @tc.desc: 1.Verify RecycleForm interface executes as expected.
 *           2.call RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_035 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    EXPECT_TRUE(formRenderRecord);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderServiceMgr.renderRecordMap_.emplace(uid, formRenderRecord);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    EXPECT_TRUE(formSupplyClient);
    formRenderServiceMgr.formSupplyClient_ = formSupplyClient;
    EXPECT_EQ(formRenderServiceMgr.RecycleForm(formId, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_035 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_036
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_036 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{0};
    Want want;
    FormJsInfo info;
    info.formId = formId;
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_APPEXECFWK_FORM_SUPPLY_CLIENT_NULL);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_036 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_037
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_037 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    FormJsInfo info;
    info.formId = formId;
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_037 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_038
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_038 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{0};
    Want want;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, uid);
    FormJsInfo info;
    info.formId = formId;
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_038 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_039
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_039 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    FormJsInfo info;
    info.formId = formId;
    std::string uid{"202410101010"};
    std::string val{"non"};
    want.SetParam(Constants::FORM_STATUS_DATA, val);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, uid);
    SetFormSupplyClient(formRenderServiceMgr);
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_APPEXECFWK_FORM_NOT_EXIST_RENDER_RECORD);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_039 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_040
 * @tc.desc: 1.Verify RecoverForm interface executes as expected.
 *           2.call RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_040 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    FormJsInfo info;
    info.formId = formId;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    std::string val{"non"};
    want.SetParam(Constants::FORM_STATUS_DATA, val);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formRenderServiceMgr.SetFormSupplyClient(formSupplyClient);
    formRenderRecord->formSupplyClient_ = formSupplyClient;

    formRenderServiceMgr.renderRecordMap_.emplace(uid, formRenderRecord);
    EXPECT_EQ(formRenderServiceMgr.RecoverForm(info, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_040 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_041
 * @tc.desc: 1.Verify ConfirmUnlockState interface executes as expected.
 *           2.call ConfirmUnlockState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_041 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.isVerified_ = true;
    Want want;
    formRenderServiceMgr.ConfirmUnlockState(want);

    auto param = want.GetBoolParam(Constants::FORM_RENDER_STATE, false);
    EXPECT_TRUE(param);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_041 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_042
 * @tc.desc: 1.Verify ConfirmUnlockState interface executes as expected.
 *           2.call ConfirmUnlockState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_042 start";
    FormRenderServiceMgr formRenderServiceMgr;
    EXPECT_FALSE(formRenderServiceMgr.isVerified_);
    Want want;
    want.SetParam(Constants::FORM_RENDER_STATE, true);
    formRenderServiceMgr.ConfirmUnlockState(want);

    EXPECT_TRUE(formRenderServiceMgr.isVerified_);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_042 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_043
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_043 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{0};
    Want want;

    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_043 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_044
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_044 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_044 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_045
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_045 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    std::string uid{"202410101010"};
    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_045 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_046
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_046 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    formRenderServiceMgr.renderRecordMap_.emplace("2024101010", nullptr);
    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_046 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_047
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_047 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "2024101010");
    formRenderServiceMgr.renderRecordMap_.emplace("2024101010", formRenderRecord);
    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_047 end";
}

/**
 * @tc.name: FormRenderServiceMgrTest_048
 * @tc.desc: 1.Verify SetVisibleChange interface executes as expected.
 * 2.call SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, FormRenderServiceMgrTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_048 start";
    FormRenderServiceMgr formRenderServiceMgr;
    int64_t formId{3};
    Want want;
    std::string uid{"202410101010"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    EXPECT_TRUE(formRenderRecord);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderServiceMgr.renderRecordMap_.emplace(uid, formRenderRecord);
    EXPECT_EQ(formRenderServiceMgr.SetVisibleChange(formId, true, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderServiceMgrTest_048 end";
}

/**
 * @tc.name: RunCachedConfigurationUpdatedTest_001
 * @tc.desc: Verify RunCachedConfigurationUpdated interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, RunCachedConfigurationUpdatedTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdatedTest_001 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    formRenderServiceMgr.configuration_->AddItem("ohos.system.colorMode", "dark");
    formRenderServiceMgr.hasCachedConfig_ = true;
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formRenderServiceMgr.SetFormSupplyClient(formSupplyClient);
    formRenderServiceMgr.RunCachedConfigurationUpdated();
    EXPECT_TRUE(formRenderServiceMgr.hasCachedConfig_);

    callerToken = new (std::nothrow) MockFormSupplyStub();
    formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formRenderServiceMgr.SetFormSupplyClient(formSupplyClient);
    formRenderServiceMgr.RunCachedConfigurationUpdated();
    EXPECT_FALSE(formRenderServiceMgr.hasCachedConfig_);
    GTEST_LOG_(INFO) << "RunCachedConfigurationUpdatedTest_001 end";
}

/**
 * @tc.name: RunCachedConfigurationUpdatedTest_001
 * @tc.desc: Verify RunCachedConfigurationUpdated interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, SetCriticalFalseOnAllFormInvisible_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetCriticalFalseOnAllFormInvisible_001 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.renderRecordMap_.clear();
    formRenderServiceMgr.SetCriticalFalseOnAllFormInvisible();
    EXPECT_FALSE(FormMemmgrClient::GetInstance().IsCritical());
    GTEST_LOG_(INFO) << "SetCriticalFalseOnAllFormInvisible_001 end";
}

/**
 * @tc.name: GetNeedApplyConfigTest_001
 * @tc.desc: Verify GetNeedApplyConfigTest interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, GetNeedApplyConfigTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetNeedApplyConfigTest_001 start";
    FormRenderServiceMgr formRenderServiceMgr;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> applyConfig = formRenderServiceMgr.GetNeedApplyConfig();
    EXPECT_FALSE(applyConfig);

    formRenderServiceMgr.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    formRenderServiceMgr.configuration_->AddItem("ohos.system.colorMode", "dark");
    formRenderServiceMgr.SetConfiguration(configuration);
    applyConfig = formRenderServiceMgr.GetNeedApplyConfig();
    EXPECT_TRUE(applyConfig);
    EXPECT_EQ(applyConfig->GetItem("ohos.system.colorMode"), "dark");
    GTEST_LOG_(INFO) << "GetNeedApplyConfigTest_001 end";
}

/**
 * @tc.name: cacheAppliedConfig_001
 * @tc.desc: Verify CacheAppliedConfig interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, cacheAppliedConfig_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "cacheAppliedConfig_001 start";
    FormRenderServiceMgr formRenderServiceMgr;
    formRenderServiceMgr.CacheAppliedConfig();
    EXPECT_EQ(formRenderServiceMgr.appliedConfig_->GetItem("ohos.system.colorMode"), "");

    formRenderServiceMgr.configuration_ = std::make_shared<Configuration>();
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    formRenderServiceMgr.configuration_->AddItem("ohos.system.colorMode", "dark");
    formRenderServiceMgr.CacheAppliedConfig();
    EXPECT_EQ(formRenderServiceMgr.appliedConfig_->GetItem("ohos.system.colorMode"), "dark");
    GTEST_LOG_(INFO) << "cacheAppliedConfig_001 end";
}

/**
 * @tc.name: UpdateFormSize_001
 * @tc.desc: Verify UpdateFormSize.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, UpdateFormSize_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_001 start";
    int64_t formId{1};
    FormSurfaceInfo formSurfaceInfo;
    formSurfaceInfo.width = 100.0;
    formSurfaceInfo.height = 100.0;
    formSurfaceInfo.borderWidth = 100.0;
    formSurfaceInfo.formViewScale = 1.0;
    std::string uid{"uid"};
    FormRenderServiceMgr formRenderServiceMgr;
    FormJsInfo formJsInfo;
    int32_t ret = formRenderServiceMgr.UpdateFormSize(formId, formSurfaceInfo, uid, formJsInfo);
    EXPECT_EQ(ret, UPDATE_FORM_SIZE_FAILED);

    formRenderServiceMgr.renderRecordMap_.emplace(uid, nullptr);
    ret = formRenderServiceMgr.UpdateFormSize(formId, formSurfaceInfo, uid, formJsInfo);
    EXPECT_EQ(ret, UPDATE_FORM_SIZE_FAILED);

    std::string uidNew{"uidNew"};
    auto formRenderRecord = FormRenderRecord::Create("bundleName", uidNew);
    formRenderServiceMgr.renderRecordMap_.emplace(uidNew, formRenderRecord);
    ret = formRenderServiceMgr.UpdateFormSize(formId, formSurfaceInfo, uidNew, formJsInfo);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "UpdateFormSize_001 end";
}

/**
 * @tc.name: SetMainRuntimeCb_001
 * @tc.desc: Verify SetMainRuntimeCb.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, SetMainRuntimeCb_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetMainRuntimeCb_001 start";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto cb = [&runtime]() -> const std::unique_ptr<Runtime> & {
        return runtime;
    };
    FormRenderServiceMgr::GetInstance().SetMainRuntimeCb(cb);
    EXPECT_EQ(FormRenderServiceMgr::GetInstance().mainRuntimeCb_(), nullptr);

    GTEST_LOG_(INFO) << "SetMainRuntimeCb_001 end";
}

/**
 * @tc.name: SetRenderGroupParams_001
 * @tc.desc: Verify SetRenderGroupParams.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceMgrTest, SetRenderGroupParams_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetRenderGroupParams_001 start";
    int64_t formId = 0;
    Want want;
    FormRenderServiceMgr formRenderServiceMgr;
    int32_t ret = formRenderServiceMgr.SetRenderGroupParams(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);

    formId = 1;
    ret = formRenderServiceMgr.SetRenderGroupParams(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    std::string uid{"20251209"};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    ret = formRenderServiceMgr.SetRenderGroupParams(formId, want);
    EXPECT_EQ(ret, RENDER_FORM_FAILED);

    formRenderServiceMgr.renderRecordMap_.emplace(uid, nullptr);
    ret = formRenderServiceMgr.SetRenderGroupParams(formId, want);
    EXPECT_EQ(ret, RENDER_FORM_FAILED);

    auto formRenderRecord = FormRenderRecord::Create("bundleName", uid);
    formRenderServiceMgr.renderRecordMap_[uid] = formRenderRecord;
    ret = formRenderServiceMgr.SetRenderGroupParams(formId, want);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "SetRenderGroupParams_001 end";
}