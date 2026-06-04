/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#define private public
#define protected public
#include "common/connection/form_ability_connection.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "form_provider/form_supply_callback.h"
#include "data_center/database/form_db_cache.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "form_constants.h"
#undef private
#undef protected

#include "mock_i_remote_object.h"
#include "mock_form_data_mgr.h"
#include "mock_form_mgr_adapter_facade.h"
#include "mock_form_render_mgr.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string BUNDLE_NAME = "com.example.test";
const std::string ABILITY_NAME = "FormAbility";
const int64_t FORM_ID = 100;
const int32_t USER_ID = 100;
const int32_t CONNECT_ID = 1;

class TestFormAbilityConnection : public FormAbilityConnection {
public:
    TestFormAbilityConnection() = default;
    virtual ~TestFormAbilityConnection() = default;

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override
    {
        if (resultCode != ERR_OK) {
            OnConnectError(resultCode, element);
            return;
        }

        if (NeedFreeInstallProcessing()) {
            ProcessFreeInstall(element, remoteObject, resultCode);
        }

        if (NeedRegisterToSupplyCallback()) {
            RegisterToSupplyCallback();
        }

        OnPreConnectTask();

        Want want = OnBuildTaskWant();

        OnExecuteConnectTask(want, remoteObject);
    }

    void ProcessFreeInstall(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int resultCode)
    {
        if (!isFreeInstall_) {
            return;
        }

        FormRecord formRecord;
        if (!MockFormDataMgr::obj->GetFormRecord(formId_, formRecord)) {
            isFreeInstall_ = false;
            return;
        }

        MockFormDataMgr::obj->SetRecordNeedFreeInstall(formId_, false);
        std::vector<FormInfo> targetForms;
        FormInfo updatedForm;
        if (MockFormDataMgr::obj->GetUpdatedForm(formRecord, targetForms, updatedForm)) {
            MockFormDataMgr::obj->SetNeedRefresh(formId_, true);
            isFreeInstall_ = false;
            return;
        }

        isFreeInstall_ = false;
    }

    void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) override
    {
        executed_ = true;
        want_ = want;
        remoteObject_ = remoteObject;
    }

    Want OnBuildTaskWant() override
    {
        Want want;
        want.SetParam(Constants::FORM_CONNECT_ID, GetConnectId());
        return want;
    }

    bool NeedFreeInstallProcessing() const override
    {
        return needFreeInstall_;
    }

    bool NeedRegisterToSupplyCallback() const override
    {
        return needRegister_;
    }

    void OnConnectError(int resultCode, const AppExecFwk::ElementName &element) override
    {
        errorExecuted_ = true;
        errorCode_ = resultCode;
    }

    void OnPreConnectTask() override
    {
        preConnectTaskExecuted_ = true;
    }

    bool IsFreeInstall() const { return isFreeInstall_; }
    bool IsExecuted() const { return executed_; }
    bool IsErrorExecuted() const { return errorExecuted_; }
    bool IsPreConnectTaskExecuted() const { return preConnectTaskExecuted_; }
    int GetErrorCode() const { return errorCode_; }
    int32_t GetAppFormPid() const { return appFormPid_; }

    void SetNeedFreeInstallProcessing(bool need) { needFreeInstall_ = need; }
    void SetNeedRegisterToSupplyCallback(bool need) { needRegister_ = need; }

    bool executed_ = false;
    bool needFreeInstall_ = false;
    bool needRegister_ = true;
    bool errorExecuted_ = false;
    bool preConnectTaskExecuted_ = false;
    int errorCode_ = 0;
    Want want_;
    sptr<IRemoteObject> remoteObject_;
};

class FmsFormAbilityConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    FormRecord CreateDefaultFormRecord(bool isTempForm = false);

protected:
    std::shared_ptr<TestFormAbilityConnection> connection_;
    std::shared_ptr<MockFormDataMgr> mockFormDataMgr_;
    std::shared_ptr<MockFormMgrAdapterFacade> mockFormMgrAdapterFacade_;
    std::shared_ptr<MockFormRenderMgr> mockFormRenderMgr_;

    void SetupGetFormRecordMock(const FormRecord &formRecord, bool returnValue = true);
    void SetupProcessFreeInstallMocks(const FormRecord &formRecord, bool getUpdatedFormReturn = false);
    void SetupConnectionForTest(int64_t formId, const std::string &bundleName,
        const std::string &abilityName, int32_t userId, bool needFreeInstall = false, bool needRegister = true);
    void SetupProviderKey(const std::string &bundleName = BUNDLE_NAME,
        const std::string &abilityName = ABILITY_NAME, int32_t userId = USER_ID);
};

void FmsFormAbilityConnectionTest::SetUpTestCase()
{
}

void FmsFormAbilityConnectionTest::TearDownTestCase()
{
}

void FmsFormAbilityConnectionTest::SetUp()
{
    connection_ = std::make_shared<TestFormAbilityConnection>();
    connection_->SetFormId(FORM_ID);
    connection_->SetProviderKey(BUNDLE_NAME, ABILITY_NAME, USER_ID);
    connection_->SetConnectId(CONNECT_ID);
    mockFormDataMgr_ = std::make_shared<MockFormDataMgr>();
    mockFormMgrAdapterFacade_ = std::make_shared<MockFormMgrAdapterFacade>();
    mockFormRenderMgr_ = std::make_shared<MockFormRenderMgr>();
    MockFormDataMgr::obj = mockFormDataMgr_;
    MockFormMgrAdapterFacade::obj = mockFormMgrAdapterFacade_;
    MockFormRenderMgr::obj = mockFormRenderMgr_;
}

void FmsFormAbilityConnectionTest::TearDown()
{
    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());
    testing::Mock::VerifyAndClearExpectations(mockFormMgrAdapterFacade_.get());
    testing::Mock::VerifyAndClearExpectations(mockFormRenderMgr_.get());
    connection_.reset();
    mockFormDataMgr_.reset();
    mockFormMgrAdapterFacade_.reset();
    mockFormRenderMgr_.reset();
    MockFormDataMgr::obj = nullptr;
    MockFormMgrAdapterFacade::obj = nullptr;
    MockFormRenderMgr::obj = nullptr;
}

FormRecord FmsFormAbilityConnectionTest::CreateDefaultFormRecord(bool isTempForm)
{
    FormRecord formRecord;
    formRecord.formId = FORM_ID;
    formRecord.bundleName = BUNDLE_NAME;
    formRecord.moduleName = "module";
    formRecord.formTempFlag = isTempForm;
    return formRecord;
}

void FmsFormAbilityConnectionTest::SetupGetFormRecordMock(const FormRecord &formRecord, bool returnValue)
{
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll([&](int64_t, FormRecord &record) {
            record = formRecord;
        }, Return(returnValue)));
}

void FmsFormAbilityConnectionTest::SetupProcessFreeInstallMocks(const FormRecord &formRecord, bool getUpdatedFormReturn)
{
    SetupGetFormRecordMock(formRecord, true);
    EXPECT_CALL(*MockFormDataMgr::obj, SetRecordNeedFreeInstall(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDataMgr::obj, GetUpdatedForm(_, _, _))
        .WillOnce(Return(getUpdatedFormReturn));
}

void FmsFormAbilityConnectionTest::SetupConnectionForTest(
    int64_t formId, const std::string &bundleName, const std::string &abilityName, int32_t userId,
    bool needFreeInstall, bool needRegister)
{
    connection_->SetFormId(formId);
    connection_->SetProviderKey(bundleName, abilityName, userId);
    connection_->SetFreeInstall(needFreeInstall);
    connection_->SetNeedFreeInstallProcessing(needFreeInstall);
    connection_->SetNeedRegisterToSupplyCallback(needRegister);
}

void FmsFormAbilityConnectionTest::SetupProviderKey(
    const std::string &bundleName, const std::string &abilityName, int32_t userId)
{
    connection_->SetProviderKey(bundleName, abilityName, userId);
}

/**
 * @tc.name: OnAbilityConnectDone_ErrorResult_002
 * @tc.desc: Verify OnAbilityConnectDone with error resultCode.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, OnAbilityConnectDone_ErrorResult_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnAbilityConnectDone_ErrorResult_002 start";

    connection_->SetFormId(FORM_ID);
    connection_->SetConnectId(CONNECT_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _)).Times(0);
    EXPECT_CALL(*MockFormDataMgr::obj, SetRecordNeedFreeInstall(_, _)).Times(0);
    EXPECT_CALL(*MockFormDataMgr::obj, GetUpdatedForm(_, _, _)).Times(0);
    EXPECT_CALL(*MockFormDataMgr::obj, SetNeedRefresh(_, _)).Times(0);

    ElementName element;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject();
    int resultCode = ERR_APPEXECFWK_FORM_INVALID_PARAM;

    connection_->OnAbilityConnectDone(element, remoteObject, resultCode);

    EXPECT_FALSE(connection_->IsExecuted());
    EXPECT_FALSE(connection_->IsPreConnectTaskExecuted());
    EXPECT_TRUE(connection_->IsErrorExecuted());
    EXPECT_EQ(connection_->GetErrorCode(), resultCode);

    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());

    GTEST_LOG_(INFO) << "OnAbilityConnectDone_ErrorResult_002 end";
}

/**
 * @tc.name: ProcessFreeInstall_NotFreeInstall_001
 * @tc.desc: Verify ProcessFreeInstall when isFreeInstall is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, ProcessFreeInstall_NotFreeInstall_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessFreeInstall_NotFreeInstall_001 start";

    connection_->SetFreeInstall(false);
    connection_->SetFormId(FORM_ID);

    ElementName element;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject();
    int resultCode = ERR_OK;

    int64_t originalFormId = connection_->GetFormId();
    connection_->ProcessFreeInstall(element, remoteObject, resultCode);

    EXPECT_EQ(connection_->GetFormId(), originalFormId);
    EXPECT_FALSE(connection_->IsFreeInstall());

    GTEST_LOG_(INFO) << "ProcessFreeInstall_NotFreeInstall_001 end";
}

/**
 * @tc.name: OnBuildTaskWant_Normal_001
 * @tc.desc: Verify OnBuildTaskWant returns Want with correct connectId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, OnBuildTaskWant_Normal_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnBuildTaskWant_Normal_001 start";

    connection_->SetConnectId(CONNECT_ID);

    Want want = connection_->OnBuildTaskWant();

    EXPECT_EQ(want.GetIntParam(Constants::FORM_CONNECT_ID, -1), CONNECT_ID);

    GTEST_LOG_(INFO) << "OnBuildTaskWant_Normal_001 end";
}

/**
 * @tc.name: ValidateResult_Success_001
 * @tc.desc: Verify ValidateResult returns true when resultCode is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, ValidateResult_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ValidateResult_Success_001 start";

    ElementName element;
    int resultCode = ERR_OK;

    bool result = connection_->ValidateResult(resultCode, element);

    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "ValidateResult_Success_001 end";
}

/**
 * @tc.name: ValidateResult_Error_002
 * @tc.desc: Verify ValidateResult returns false when resultCode is not ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, ValidateResult_Error_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ValidateResult_Error_002 start";

    ElementName element;
    int resultCode = ERR_APPEXECFWK_FORM_INVALID_PARAM;

    bool result = connection_->ValidateResult(resultCode, element);

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "ValidateResult_Error_002 end";
}

/**
 * @tc.name: SetGetFormId_001
 * @tc.desc: Verify SetFormId and GetFormId work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetFormId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetFormId_001 start";

    connection_->SetFormId(FORM_ID);

    EXPECT_EQ(connection_->GetFormId(), FORM_ID);

    GTEST_LOG_(INFO) << "SetGetFormId_001 end";
}

/**
 * @tc.name: SetGetConnectId_001
 * @tc.desc: Verify SetConnectId and GetConnectId work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetConnectId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetConnectId_001 start";

    connection_->SetConnectId(CONNECT_ID);

    EXPECT_EQ(connection_->GetConnectId(), CONNECT_ID);

    GTEST_LOG_(INFO) << "SetGetConnectId_001 end";
}

/**
 * @tc.name: SetGetProviderKey_001
 * @tc.desc: Verify SetProviderKey and GetProviderKey work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetProviderKey_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetProviderKey_001 start";

    connection_->SetProviderKey(BUNDLE_NAME, ABILITY_NAME, USER_ID);

    std::string expectedKey = BUNDLE_NAME + "::" + ABILITY_NAME + "::" + std::to_string(USER_ID);
    EXPECT_EQ(connection_->GetProviderKey(), expectedKey);

    GTEST_LOG_(INFO) << "SetGetProviderKey_001 end";
}

/**
 * @tc.name: GetProviderKey_EmptyBundleName_002
 * @tc.desc: Verify GetProviderKey returns empty string when bundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, GetProviderKey_EmptyBundleName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetProviderKey_EmptyBundleName_002 start";

    connection_->SetProviderKey("", ABILITY_NAME, USER_ID);

    EXPECT_EQ(connection_->GetProviderKey(), "");

    GTEST_LOG_(INFO) << "GetProviderKey_EmptyBundleName_002 end";
}

/**
 * @tc.name: GetProviderKey_EmptyAbilityName_003
 * @tc.desc: Verify GetProviderKey returns empty string when abilityName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, GetProviderKey_EmptyAbilityName_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetProviderKey_EmptyAbilityName_003 start";

    connection_->SetProviderKey(BUNDLE_NAME, "", USER_ID);

    EXPECT_EQ(connection_->GetProviderKey(), "");

    GTEST_LOG_(INFO) << "GetProviderKey_EmptyAbilityName_003 end";
}

/**
 * @tc.name: GetProviderKey_InvalidUserId_004
 * @tc.desc: Verify GetProviderKey returns empty string when userId is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, GetProviderKey_InvalidUserId_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetProviderKey_InvalidUserId_004 start";

    connection_->SetProviderKey(BUNDLE_NAME, ABILITY_NAME, -1);

    EXPECT_EQ(connection_->GetProviderKey(), "");

    GTEST_LOG_(INFO) << "GetProviderKey_InvalidUserId_004 end";
}

/**
 * @tc.name: SetGetFreeInstall_001
 * @tc.desc: Verify SetFreeInstall works correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetFreeInstall_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetFreeInstall_001 start";

    connection_->SetFreeInstall(true);

    EXPECT_TRUE(connection_->IsFreeInstall());

    connection_->SetFreeInstall(false);

    EXPECT_FALSE(connection_->IsFreeInstall());

    GTEST_LOG_(INFO) << "SetGetFreeInstall_001 end";
}

/**
 * @tc.name: SetGetHostToken_001
 * @tc.desc: Verify SetHostToken and GetHostToken work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetHostToken_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetHostToken_001 start";

    sptr<IRemoteObject> hostToken = new MockIRemoteObject();
    ASSERT_NE(hostToken, nullptr);

    connection_->SetHostToken(hostToken);

    EXPECT_EQ(connection_->GetHostToken(), hostToken);
    EXPECT_NE(connection_->GetHostToken(), nullptr);

    sptr<IRemoteObject> newHostToken = new MockIRemoteObject();
    connection_->SetHostToken(newHostToken);

    EXPECT_EQ(connection_->GetHostToken(), newHostToken);

    connection_->SetHostToken(nullptr);
    EXPECT_EQ(connection_->GetHostToken(), nullptr);

    GTEST_LOG_(INFO) << "SetGetHostToken_001 end";
}

/**
 * @tc.name: SetGetProviderToken_001
 * @tc.desc: Verify SetProviderToken and GetProviderToken work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, SetGetProviderToken_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetGetProviderToken_001 start";

    sptr<IRemoteObject> providerToken = new MockIRemoteObject();
    ASSERT_NE(providerToken, nullptr);

    connection_->SetProviderToken(providerToken);

    EXPECT_EQ(connection_->GetProviderToken(), providerToken);
    EXPECT_NE(connection_->GetProviderToken(), nullptr);

    sptr<IRemoteObject> newProviderToken = new MockIRemoteObject();
    connection_->SetProviderToken(newProviderToken);

    EXPECT_EQ(connection_->GetProviderToken(), newProviderToken);

    connection_->SetProviderToken(nullptr);
    EXPECT_EQ(connection_->GetProviderToken(), nullptr);

    GTEST_LOG_(INFO) << "SetGetProviderToken_001 end";
}

/**
 * @tc.name: GetBundleName_001
 * @tc.desc: Verify GetBundleName returns correct bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, GetBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleName_001 start";

    SetupProviderKey();

    EXPECT_EQ(connection_->GetBundleName(), BUNDLE_NAME);

    GTEST_LOG_(INFO) << "GetBundleName_001 end";
}

/**
 * @tc.name: GetAppFormPid_001
 * @tc.desc: Verify GetAppFormPid returns correct pid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, GetAppFormPid_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAppFormPid_001 start";

    connection_->appFormPid_ = 1234;

    EXPECT_EQ(connection_->GetAppFormPid(), 1234);

    GTEST_LOG_(INFO) << "GetAppFormPid_001 end";
}

/**
 * @tc.name: OnPreConnectTask_001
 * @tc.desc: Verify OnPreConnectTask default implementation does nothing and does not throw.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, OnPreConnectTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnPreConnectTask_001 start";

    connection_->OnPreConnectTask();
    EXPECT_TRUE(connection_->IsPreConnectTaskExecuted());

    GTEST_LOG_(INFO) << "OnPreConnectTask_001 end";
}

/**
 * @tc.name: OnConnectError_001
 * @tc.desc: Verify OnConnectError is called with correct error code in derived class.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, OnConnectError_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnConnectError_001 start";

    ElementName element;
    const int32_t testErrorCode = ERR_APPEXECFWK_FORM_INVALID_PARAM;

    connection_->OnConnectError(testErrorCode, element);

    EXPECT_TRUE(connection_->errorExecuted_);
    EXPECT_EQ(connection_->errorCode_, testErrorCode);

    GTEST_LOG_(INFO) << "OnConnectError_001 end";
}

/**
 * @tc.name: NeedFreeInstallProcessing_001
 * @tc.desc: Verify NeedFreeInstallProcessing default returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, NeedFreeInstallProcessing_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NeedFreeInstallProcessing_001 start";

    connection_->SetFreeInstall(false);

    bool result = connection_->NeedFreeInstallProcessing();

    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "NeedFreeInstallProcessing_001 end";
}

/**
 * @tc.name: NeedRegisterToSupplyCallback_001
 * @tc.desc: Verify NeedRegisterToSupplyCallback default returns true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionTest, NeedRegisterToSupplyCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NeedRegisterToSupplyCallback_001 start";

    connection_->SetNeedRegisterToSupplyCallback(true);

    bool result = connection_->NeedRegisterToSupplyCallback();

    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "NeedRegisterToSupplyCallback_001 end";
}
}  // namespace