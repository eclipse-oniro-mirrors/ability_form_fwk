/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#define protected public
#include "form_provider/connection/form_acquire_connection.h"
#include "form_provider/connection/form_acquire_state_connection.h"
#include "bms_mgr/form_bundle_event_callback.h"
#include "data_center/form_cache_mgr.h"
#include "form_provider/connection/form_cast_temp_connection.h"
#include "form_provider/connection/form_delete_connection.h"
#include "common/event/form_event_handler.h"
#include "form_host/form_host_record.h"
#include "data_center/form_info/form_item_info.h"
#include "form_provider/connection/form_msg_event_connection.h"
#include "form_provider/connection/form_refresh_connection.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#include "feature/form_share/form_share_connection.h"
#include "form_provider/form_supply_callback.h"
#include "common/util/form_util.h"
#include "feature/free_install/free_install_status_callback_stub.h"
#include "mock_form_provider_task_mgr.h"
#include "mock_form_provider_refresh_error_handler.h"
#include "mock_form_supply_callback.h"
#include "mock_form_data_mgr.h"
#undef private
#undef protected
#include "ipc_types.h"
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using ::testing::_;

namespace {

const std::string FORM_MESSAGE_EVENT_VALUE_1 = "event message1";
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
constexpr int32_t DISCONNECT_ERROR = -1;
constexpr int32_t TEST_CONNECT_ID = 100;

class FmsFormRefreshConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    sptr<FormRefreshConnection> CreateRefreshConnection(int64_t formId, Want &want);
};

class MockFreeInstallStatusCallBackStub : public FreeInstallStatusCallBackStub {
public:
    MockFreeInstallStatusCallBackStub() = default;
    virtual ~MockFreeInstallStatusCallBackStub() = default;

    virtual void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId) {}
};

void FmsFormRefreshConnectionTest::SetUp()
{
    MockFormProviderTaskMgr::obj = std::make_shared<MockFormProviderTaskMgr>();
    MockFormProviderRefreshErrorHandler::obj = std::make_shared<MockFormProviderRefreshErrorHandler>();
}

void FmsFormRefreshConnectionTest::TearDown()
{
    MockFormProviderTaskMgr::obj = nullptr;
    MockFormProviderRefreshErrorHandler::obj = nullptr;
}

sptr<FormRefreshConnection> FmsFormRefreshConnectionTest::CreateRefreshConnection(int64_t formId, Want &want)
{
    return new (std::nothrow) FormRefreshConnection(formId, want, "aa", "bb", false, 100);
}

/**
 * @tc.name: FormRefreshConnection_001
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    int32_t userId = 100;
    sptr<FormRefreshConnection> formRefreshConnection =
        new (std::nothrow) FormRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall, userId);
    ASSERT_NE(nullptr, formRefreshConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formRefreshConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 end";
}

/**
 * @tc.name: FormRefreshConnection_002
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_002 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    int32_t userId = 100;
    sptr<FormRefreshConnection> formRefreshConnection =
        new (std::nothrow) FormRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall, userId);
    ASSERT_NE(nullptr, formRefreshConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    const std::string message = "";
    want.SetParam(Constants::PARAM_MESSAGE_KEY, message);
    formRefreshConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_002 end";
}

/**
 * @tc.name: FormRefreshConnection_003
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_003 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    int32_t userId = 100;
    sptr<FormRefreshConnection> formRefreshConnection =
        new (std::nothrow) FormRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall, userId);
    ASSERT_NE(nullptr, formRefreshConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    const std::string message = "";
    want.SetParam(Constants::RECREATE_FORM_KEY, message);
    formRefreshConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_003 end";
}

/**
 * @tc.name: FormRefreshConnection_004
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_004 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    int32_t userId = 100;
    sptr<FormRefreshConnection> formRefreshConnection =
        new (std::nothrow) FormRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall, userId);
    ASSERT_NE(nullptr, formRefreshConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formRefreshConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_004 end";
}

/**
 * @tc.name: OnAbilityDisconnectDone_DisconnectError_001
 * @tc.desc: test OnAbilityDisconnectDone when DISCONNECT_ERROR and CONNECTED state
 *           HandleDisconnectError should be called
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnAbilityDisconnectDone_DisconnectError_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_DisconnectError_001 start";
    AppExecFwk::ElementName element;
    Want want;

    sptr<FormRefreshConnection> conn = CreateRefreshConnection(1, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    conn->OnPreConnectTask();
    EXPECT_CALL(*MockFormProviderRefreshErrorHandler::obj, HandleDisconnectError(1, _, _, _)).Times(1);
    conn->OnAbilityDisconnectDone(element, DISCONNECT_ERROR);
    EXPECT_EQ(0, conn->GetConnectId());

    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_DisconnectError_001 end";
}

/**
 * @tc.name: OnAbilityDisconnectDone_ErrOk_001
 * @tc.desc: test OnAbilityDisconnectDone when ERR_OK and CONNECTED state
 *           HandleDisconnectError should NOT be called
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnAbilityDisconnectDone_ErrOk_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_ErrOk_001 start";
    AppExecFwk::ElementName element;
    Want want;

    sptr<FormRefreshConnection> conn = CreateRefreshConnection(2, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    conn->OnPreConnectTask();
    EXPECT_CALL(*MockFormProviderRefreshErrorHandler::obj, HandleDisconnectError(_, _, _, _)).Times(0);
    conn->OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_EQ(0, conn->GetConnectId());

    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_ErrOk_001 end";
}

/**
 * @tc.name: OnAbilityDisconnectDone_NotConnected_001
 * @tc.desc: test OnAbilityDisconnectDone when DISCONNECT_ERROR and NOT CONNECTED state
 *           HandleDisconnectError should NOT be called
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnAbilityDisconnectDone_NotConnected_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_NotConnected_001 start";
    AppExecFwk::ElementName element;
    Want want;

    sptr<FormRefreshConnection> conn = CreateRefreshConnection(3, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    EXPECT_CALL(*MockFormProviderRefreshErrorHandler::obj, HandleDisconnectError(_, _, _, _)).Times(0);
    conn->OnAbilityDisconnectDone(element, DISCONNECT_ERROR);
    EXPECT_EQ(0, conn->GetConnectId());

    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_NotConnected_001 end";
}

/**
 * @tc.name: OnAbilityDisconnectDone_OtherResultCode_001
 * @tc.desc: test OnAbilityDisconnectDone when other resultCode and CONNECTED state
 *           HandleDisconnectError should NOT be called
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnAbilityDisconnectDone_OtherResultCode_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_OtherResultCode_001 start";
    AppExecFwk::ElementName element;
    Want want;

    sptr<FormRefreshConnection> conn = CreateRefreshConnection(4, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    conn->OnPreConnectTask();
    EXPECT_CALL(*MockFormProviderRefreshErrorHandler::obj, HandleDisconnectError(_, _, _, _)).Times(0);
    conn->OnAbilityDisconnectDone(element, -2);
    EXPECT_EQ(0, conn->GetConnectId());

    GTEST_LOG_(INFO) << "OnAbilityDisconnectDone_OtherResultCode_001 end";
}

/**
 * @tc.name: OnBuildTaskWant_ParamMessageKey_001
 * @tc.desc: test OnBuildTaskWant when PARAM_MESSAGE_KEY is set
 *           result should have FORM_CONNECT_ID and PARAM_MESSAGE_KEY
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnBuildTaskWant_ParamMessageKey_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnBuildTaskWant_ParamMessageKey_001 start";

    Want want;
    const std::string message = "test_message";
    want.SetParam(Constants::PARAM_MESSAGE_KEY, message);
    sptr<FormRefreshConnection> conn = CreateRefreshConnection(1, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    Want result = conn->OnBuildTaskWant();
    EXPECT_TRUE(result.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_EQ(TEST_CONNECT_ID, result.GetIntParam(Constants::FORM_CONNECT_ID, 0));
    EXPECT_TRUE(result.HasParameter(Constants::PARAM_MESSAGE_KEY));

    GTEST_LOG_(INFO) << "OnBuildTaskWant_ParamMessageKey_001 end";
}

/**
 * @tc.name: OnBuildTaskWant_RecreateFormKey_001
 * @tc.desc: test OnBuildTaskWant when RECREATE_FORM_KEY is set
 *           result should have ACQUIRE_TYPE and FORM_CONNECT_ID
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnBuildTaskWant_RecreateFormKey_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnBuildTaskWant_RecreateFormKey_001 start";

    Want want;
    const std::string recreateFlag = "true";
    want.SetParam(Constants::RECREATE_FORM_KEY, recreateFlag);
    sptr<FormRefreshConnection> conn = CreateRefreshConnection(2, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    Want result = conn->OnBuildTaskWant();
    EXPECT_TRUE(result.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_EQ(TEST_CONNECT_ID, result.GetIntParam(Constants::FORM_CONNECT_ID, 0));
    EXPECT_TRUE(result.HasParameter(Constants::ACQUIRE_TYPE));
    EXPECT_EQ(Constants::ACQUIRE_TYPE_RECREATE_FORM, result.GetIntParam(Constants::ACQUIRE_TYPE, 0));
    EXPECT_TRUE(result.HasParameter(Constants::RECREATE_FORM_KEY));

    GTEST_LOG_(INFO) << "OnBuildTaskWant_RecreateFormKey_001 end";
}

/**
 * @tc.name: OnBuildTaskWant_NoSpecialKeys_001
 * @tc.desc: test OnBuildTaskWant when no special keys are set
 *           result should only have FORM_CONNECT_ID
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnBuildTaskWant_NoSpecialKeys_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnBuildTaskWant_NoSpecialKeys_001 start";

    Want want;
    sptr<FormRefreshConnection> conn = CreateRefreshConnection(3, want);
    ASSERT_NE(nullptr, conn);
    conn->SetConnectId(TEST_CONNECT_ID);
    Want result = conn->OnBuildTaskWant();
    EXPECT_TRUE(result.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_EQ(TEST_CONNECT_ID, result.GetIntParam(Constants::FORM_CONNECT_ID, 0));
    EXPECT_FALSE(result.HasParameter(Constants::PARAM_MESSAGE_KEY));
    EXPECT_FALSE(result.HasParameter(Constants::RECREATE_FORM_KEY));
    EXPECT_FALSE(result.HasParameter(Constants::ACQUIRE_TYPE));

    GTEST_LOG_(INFO) << "OnBuildTaskWant_NoSpecialKeys_001 end";
}

/**
 * @tc.name: OnExecuteConnectTask_MultiBranch_001
 * @tc.desc: test OnExecuteConnectTask with multiple scenarios:
 *           (1) PARAM_MESSAGE_KEY → PostFormEventTask called
 *           (2) RECREATE_FORM_KEY → PostAcquireTask called
 *           (3) No special keys → PostRefreshTask called
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnExecuteConnectTask_MultiBranch_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnExecuteConnectTask_MultiBranch_001 start";
    sptr<IRemoteObject> remoteObject = nullptr;

    // Segment 1: PARAM_MESSAGE_KEY → PostFormEventTask called
    Want want1;
    const std::string message2 = "test_message";
    want1.SetParam(Constants::PARAM_MESSAGE_KEY, message2);
    sptr<FormRefreshConnection> conn1 = CreateRefreshConnection(1, want1);
    ASSERT_NE(nullptr, conn1);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostFormEventTask(1, "test_message", _, remoteObject)).Times(1);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostRefreshTask(_, _, _)).Times(0);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostAcquireTask(_, _, _)).Times(0);
    conn1->OnExecuteConnectTask(want1, remoteObject);

    // Segment 2: RECREATE_FORM_KEY → PostAcquireTask called
    Want want2;
    const std::string recreateFlag2 = "true";
    want2.SetParam(Constants::RECREATE_FORM_KEY, recreateFlag2);
    sptr<FormRefreshConnection> conn2 = CreateRefreshConnection(2, want2);
    ASSERT_NE(nullptr, conn2);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostAcquireTask(2, _, remoteObject)).Times(1);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostRefreshTask(_, _, _)).Times(0);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostFormEventTask(_, _, _, _)).Times(0);
    conn2->OnExecuteConnectTask(want2, remoteObject);

    // Segment 3: No special keys → PostRefreshTask called
    Want want3;
    sptr<FormRefreshConnection> conn3 = CreateRefreshConnection(3, want3);
    ASSERT_NE(nullptr, conn3);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostRefreshTask(3, _, remoteObject)).Times(1);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostAcquireTask(_, _, _)).Times(0);
    EXPECT_CALL(*MockFormProviderTaskMgr::obj, PostFormEventTask(_, _, _, _)).Times(0);
    conn3->OnExecuteConnectTask(want3, remoteObject);

    GTEST_LOG_(INFO) << "OnExecuteConnectTask_MultiBranch_001 end";
}

/**
 * @tc.name: OnPreConnectTask_001
 * @tc.desc: test OnPreConnectTask.
 *           Verify connectState_ is set to CONNECTED.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsFormRefreshConnectionTest, OnPreConnectTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnPreConnectTask_001 start";
    Want want;
    sptr<FormRefreshConnection> connection = CreateRefreshConnection(1, want);
    ASSERT_NE(nullptr, connection);
    EXPECT_EQ(ConnectState::DISCONNECTED, connection->connectState_);
    connection->OnPreConnectTask();
    EXPECT_EQ(ConnectState::CONNECTED, connection->connectState_);
    GTEST_LOG_(INFO) << "OnPreConnectTask_001 end";
}

/**
 * @tc.name: FormUtil_001
 * @tc.desc: test PaddingUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_001 start";
    std::shared_ptr<FormUtil> formUtil = std::make_shared<FormUtil>();
    ASSERT_NE(nullptr, formUtil);
    uint64_t formId = 0;
    uint64_t udidHash = 3;
    EXPECT_EQ(3, formUtil->PaddingUdidHash(formId, udidHash));
    GTEST_LOG_(INFO) << "FormUtil_001 end";
}

/**
 * @tc.name: FormUtil_002
 * @tc.desc: test GenerateUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_002 start";
    std::shared_ptr<FormUtil> formUtil = std::make_shared<FormUtil>();
    ASSERT_NE(nullptr, formUtil);
    int64_t udidHash = 100;
    EXPECT_EQ(true, formUtil->GenerateUdidHash(udidHash));
    GTEST_LOG_(INFO) << "FormUtil_002 end";
}

/**
 * @tc.name: FormSupplyCallback_001
 * @tc.desc: test AddConnection function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 start";
    std::shared_ptr<FormSupplyCallback> formSupplyCallback = std::make_shared<FormSupplyCallback>();
    ASSERT_NE(nullptr, formSupplyCallback);
    sptr<FormAbilityConnection> connection = nullptr;
    formSupplyCallback->AddConnection(connection);
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 end";
}

/**
 * @tc.name: FormSupplyCallback_002
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = nullptr;
    EXPECT_EQ(false, formSupplyCallback.CanDisconnect(connection));
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 end";
}

/**
 * @tc.name: FormShareConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormShareConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    std::string deviceId = "cc";
    int64_t formShareRequestCode = 2;
    int32_t userId = 100;
    sptr<FormShareConnection> formShareConnection =
        new (std::nothrow) FormShareConnection(formId, bundleName, abilityName, deviceId, formShareRequestCode, userId);
    ASSERT_NE(nullptr, formShareConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t resultCode = 3;
    formShareConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormShareConnection_001 end";
}

/**
 * @tc.name: FormHostRecord_001
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_001 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    bool flag = true;
    formHostRecord->SetEnableRefresh(formId, flag);
    GTEST_LOG_(INFO) << "FormHostRecord_001 end";
}

/**
 * @tc.name: FormHostRecord_002
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_002 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    EXPECT_EQ(false, formHostRecord->IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_002 end";
}

/**
 * @tc.name: FormHostRecord_003
 * @tc.desc: test SetEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_003 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    bool enable = true;
    formHostRecord->SetEnableUpdate(formId, enable);
    GTEST_LOG_(INFO) << "FormHostRecord_003 end";
}

/**
 * @tc.name: FormHostRecord_004
 * @tc.desc: test SetEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_004 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    bool enable = true;
    formHostRecord->forms_.emplace(formId, enable);
    formHostRecord->SetEnableUpdate(formId, enable);
    GTEST_LOG_(INFO) << "FormHostRecord_004 end";
}

/**
 * @tc.name: FormHostRecord_005
 * @tc.desc: test IsEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_005 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    bool enable = true;
    formHostRecord.enableUpdateMap_.emplace(formId, enable);
    EXPECT_EQ(true, formHostRecord.IsEnableUpdate(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_005 end";
}

/**
 * @tc.name: FormHostRecord_006
 * @tc.desc: test IsNeedRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_006 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    EXPECT_EQ(false, formHostRecord.IsNeedRefresh(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_006 end";
}

/**
 * @tc.name: FormHostRecord_007
 * @tc.desc: test OnAcquire function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_007 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    FormRecord record;
    formHostRecord->OnAcquire(formId, record);
    GTEST_LOG_(INFO) << "FormHostRecord_007 end";
}

/**
 * @tc.name: FormHostRecord_008
 * @tc.desc: test OnUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_008 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    int64_t formId = 1;
    FormRecord record;
    formHostRecord->formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord->OnUpdate(formId, record);
    GTEST_LOG_(INFO) << "FormHostRecord_008 end";
}

/**
 * @tc.name: FormHostRecord_009
 * @tc.desc: test OnFormUninstalled function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_009 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    std::vector<int64_t> formIds;
    formHostRecord->formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord->OnFormUninstalled(formIds);
    GTEST_LOG_(INFO) << "FormHostRecord_009 end";
}

/**
 * @tc.name: FormHostRecord_010
 * @tc.desc: test OnAcquireState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_010 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    formHostRecord->formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord->OnAcquireState(state, want);
    GTEST_LOG_(INFO) << "FormHostRecord_010 end";
}

/**
 * @tc.name: FormHostRecord_011
 * @tc.desc: test AddDeathRecipient function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_011 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formHostRecord->AddDeathRecipient(deathRecipient);
    GTEST_LOG_(INFO) << "FormHostRecord_011 end";
}

/**
 * @tc.name: FormHostRecord_012
 * @tc.desc: test OnAcquireFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_012 start";
    std::shared_ptr<FormHostRecord> formHostRecord = std::make_shared<FormHostRecord>();
    ASSERT_NE(nullptr, formHostRecord);
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    formHostRecord->formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord->OnAcquireFormData(wantParams, requestCode);
    GTEST_LOG_(INFO) << "FormHostRecord_012 end";
}

/**
 * @tc.name: FormAcquireConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_001 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    sptr<FormAcquireConnection> formAcquireConnection =
        new (std::nothrow) FormAcquireConnection(formId, info, wantParams, hostToken);
    ASSERT_NE(nullptr, formAcquireConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formAcquireConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnection_001 end";
}

/**
 * @tc.name: FormCastTempConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCastTempConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCastTempConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    int32_t userId = 100;
    sptr<FormCastTempConnection> formCastTempConnection =
        new (std::nothrow) FormCastTempConnection(formId, bundleName, abilityName, userId);
    ASSERT_NE(nullptr, formCastTempConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formCastTempConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormCastTempConnection_001 end";
}

/**
 * @tc.name: FormDeleteConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormDeleteConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormDeleteConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    int32_t userId = 100;
    sptr<FormDeleteConnection> formDeleteConnection =
        new (std::nothrow) FormDeleteConnection(formId, bundleName, abilityName, userId);
    ASSERT_NE(nullptr, formDeleteConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormDeleteConnection_001 end";
}

/**
 * @tc.name: FormEventHandler_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormEventHandler_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventHandler_001 start";
    std::shared_ptr<FormEventHandler> formEventHandler = std::make_shared<FormEventHandler>(nullptr);
    ASSERT_NE(nullptr, formEventHandler);
    constexpr int64_t eventMsg = 1;
    constexpr int64_t eventId = 2;
    // text ProcessEvent
    formEventHandler->ProcessEvent(eventMsg, eventId);
    GTEST_LOG_(INFO) << "FormEventHandler_001 end";
}

/**
 * @tc.name: FormEventHandler_002
 * @tc.desc: test UnregisterEventTimeoutObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormEventHandler_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventHandler_002 start";
    std::shared_ptr<FormEventHandler> formEventHandler = std::make_shared<FormEventHandler>(nullptr);
    ASSERT_NE(nullptr, formEventHandler);
    std::shared_ptr<FormEventTimeoutObserver> observer = nullptr;
    formEventHandler->observers_.insert(observer);
    formEventHandler->UnregisterEventTimeoutObserver(observer);
    GTEST_LOG_(INFO) << "FormEventHandler_002 end";
}

/**
 * @tc.name: FormItemInfo_001
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_001 start";
    FormItemInfo formItemInfo;
    formItemInfo.providerBundleName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_001 end";
}

/**
 * @tc.name: FormItemInfo_002
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_002 start";
    FormItemInfo formItemInfo;
    formItemInfo.moduleName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_002 end";
}

/**
 * @tc.name: FormItemInfo_003
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_003 start";
    FormItemInfo formItemInfo;
    formItemInfo.abilityName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_003 end";
}

/**
 * @tc.name: FormItemInfo_004
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_004 start";
    FormItemInfo formItemInfo;
    formItemInfo.formName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_004 end";
}

/**
 * @tc.name: FormRefreshLimiter_001
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_001 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT;
    limitInfo.isReported = true;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(false, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_001 end";
}

/**
 * @tc.name: FormRefreshLimiter_002
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_002 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT;
    limitInfo.isReported = false;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(false, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_002 end";
}

/**
 * @tc.name: FormRefreshLimiter_003
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_003 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    limitInfo.isReported = false;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(true, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_003 end";
}

/**
 * @tc.name: FormRefreshLimiter_004
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_004 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    limitInfo.isReported = true;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(true, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_004 end";
}

/**
 * @tc.name: FormRefreshLimiter_005
 * @tc.desc: test GetRefreshCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_005 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    EXPECT_EQ(-1, formRefreshLimiter.GetRefreshCount(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_005 end";
}

/**
 * @tc.name: FormRefreshLimiter_006
 * @tc.desc: test Increase function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_006 start";
    std::shared_ptr<FormRefreshLimiter> formRefreshLimiter = std::make_shared<FormRefreshLimiter>();
    ASSERT_NE(nullptr, formRefreshLimiter);
    int64_t formId = 1;
    formRefreshLimiter->Increase(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_006 end";
}

/**
 * @tc.name: FormRefreshLimiter_007
 * @tc.desc: test MarkRemind function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_007 start";
    std::shared_ptr<FormRefreshLimiter> formRefreshLimiter = std::make_shared<FormRefreshLimiter>();
    ASSERT_NE(nullptr, formRefreshLimiter);
    int64_t formId = 1;
    formRefreshLimiter->MarkRemind(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_007 end";
}

/**
 * @tc.name: FormRefreshLimiter_008
 * @tc.desc: test MarkRemind function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_008 start";
    std::shared_ptr<FormRefreshLimiter> formRefreshLimiter = std::make_shared<FormRefreshLimiter>();
    ASSERT_NE(nullptr, formRefreshLimiter);
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    formRefreshLimiter->limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter->MarkRemind(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_008 end";
}

/**
 * @tc.name: FormRefreshLimiter_009
 * @tc.desc: test GetRemindList function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_009 start";
    std::shared_ptr<FormRefreshLimiter> formRefreshLimiter = std::make_shared<FormRefreshLimiter>();
    ASSERT_NE(nullptr, formRefreshLimiter);
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.remindFlag = false;
    formRefreshLimiter->limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter->GetRemindList();
    GTEST_LOG_(INFO) << "FormRefreshLimiter_009 end";
}

/**
 * @tc.name: FormRefreshLimiter_010
 * @tc.desc: test GetRemindListAndResetLimit function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_010 start";
    std::shared_ptr<FormRefreshLimiter> formRefreshLimiter = std::make_shared<FormRefreshLimiter>();
    ASSERT_NE(nullptr, formRefreshLimiter);
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.remindFlag = true;
    formRefreshLimiter->limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter->GetRemindListAndResetLimit();
    GTEST_LOG_(INFO) << "FormRefreshLimiter_010 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_001
 * @tc.desc: test GetRemindListAndResetLimit function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_001 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ERR_INVALID_VALUE, mockFreeInstallStatusCallBackStub.OnInstallFinishedInner(data, reply));
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_001 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_002
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_002 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_INVALID_STATE, mockFreeInstallStatusCallBackStub.OnRemoteRequest(code, data, reply, option));
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_002 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_003
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_003 start";
    std::shared_ptr<MockFreeInstallStatusCallBackStub> mockFreeInstallStatusCallBackStub =
        std::make_shared<MockFreeInstallStatusCallBackStub>();
    ASSERT_NE(nullptr, mockFreeInstallStatusCallBackStub);
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string remoteDescriptor = u"ohos.IAtomicServiceStatusCallback";
    data.WriteInterfaceToken(remoteDescriptor);
    mockFreeInstallStatusCallBackStub->OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_003 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_004
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_004 start";
    std::shared_ptr<MockFreeInstallStatusCallBackStub> mockFreeInstallStatusCallBackStub =
        std::make_shared<MockFreeInstallStatusCallBackStub>();
    ASSERT_NE(nullptr, mockFreeInstallStatusCallBackStub);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string remoteDescriptor = u"ohos.IAtomicServiceStatusCallback";
    data.WriteInterfaceToken(remoteDescriptor);
    mockFreeInstallStatusCallBackStub->OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_004 end";
}

/**
 * @tc.name: FormBundleEventCallback_001
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_001 start";
    std::shared_ptr<FormBundleEventCallback> formBundleEventCallback = std::make_shared<FormBundleEventCallback>();
    ASSERT_NE(nullptr, formBundleEventCallback);
    EventFwk::CommonEventData eventData;
    formBundleEventCallback->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_001 end";
}

/**
 * @tc.name: FormBundleEventCallback_002
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_002 start";
    FormBundleEventCallback formBundleEventCallback;
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "";
    want.SetAction(action);
    std::string bundleName = "";
    want.SetBundle(bundleName);
    formBundleEventCallback.OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_002 end";
}

/**
 * @tc.name: FormBundleEventCallback_003
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_003 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED;
    want.SetAction(action);
    std::string bundleName = "com.example.abc";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_003 end";
}

/**
 * @tc.name: FormBundleEventCallback_004
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_004 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    want.SetAction(action);
    OHOS::AppExecFwk::ElementName element;
    std::string bundleName = "com.example.abc";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_004 end";
}

/**
 * @tc.name: FormBundleEventCallback_005
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_005 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED;
    want.SetAction(action);
    std::string bundleName = "com.example.abc";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_005 end";
}

/**
 * @tc.name: FormBundleEventCallback_006
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_006 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED;
    want.SetAction(action);
    std::string bundleName = "com.example.abc";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_006 end";
}

/**
 * @tc.name: FormBundleEventCallback_007
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_007 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "abcd";
    want.SetAction(action);
    std::string bundleName = "com.example.abc";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == "abcd");
    GTEST_LOG_(INFO) << "FormBundleEventCallback_007 end";
}

/**
 * @tc.name: FormBundleEventCallback_008
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_008 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "abc";
    want.SetAction(action);
    std::string bundleName = "";
    std::string abilityName = "abc";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_FALSE(want.GetAction().empty());
    EXPECT_TRUE(want.GetElement().GetBundleName().empty());
    GTEST_LOG_(INFO) << "FormBundleEventCallback_008 end";
}

/**
 * @tc.name: FormBundleEventCallback_009
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_009 start";
    sptr<FormBundleEventCallback> formBundleEventCallback = new (std::nothrow) FormBundleEventCallback();
    EXPECT_TRUE(formBundleEventCallback != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = BMS_EVENT_ADDITIONAL_INFO_CHANGED;
    want.SetAction(action);
    std::string bundleName = "com.example.form";
    std::string abilityName = "entry";
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    formBundleEventCallback->OnReceiveEvent(eventData);
    EXPECT_TRUE(want.GetAction() == BMS_EVENT_ADDITIONAL_INFO_CHANGED);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_009 end";
}

/**
 * @tc.name: FormMsgEventConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormMsgEventConnection_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0001 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    int32_t userId = 100;
    std::shared_ptr<FormMsgEventConnection> formMsgEventConnection =
        std::make_shared<FormMsgEventConnection>(formId, want, bundleName, abilityName, userId);
    ASSERT_NE(nullptr, formMsgEventConnection);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 22;
    formMsgEventConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0001 end";
}

/**
 * @tc.name: FormAcquireStateConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireStateConnection_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0001 start";
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    Want want;
    std::string state = "cc";
    int32_t userId = 100;
    std::shared_ptr<FormAcquireStateConnection> formAcquireStateConnection =
        std::make_shared<FormAcquireStateConnection>(bundleName, abilityName, want, state, userId);
    ASSERT_NE(nullptr, formAcquireStateConnection);
    // test OnAbilityConnectDone function
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 55;
    formAcquireStateConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0001 end";
}

/**
 * @tc.name: FormAcquireConnection_002
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_002 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    sptr<FormAcquireConnection> formAcquireConnection =
        new (std::nothrow) FormAcquireConnection(formId, info, wantParams, hostToken);
    ASSERT_NE(nullptr, formAcquireConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAcquireConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnection_002 end";
}

/**
 * @tc.name: FormAcquireConnection_003
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_003 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;

    sptr<IRemoteObject> hostToken = nullptr;
    sptr<FormAcquireConnection> formAcquireConnection =
        new (std::nothrow) FormAcquireConnection(formId, info, wantParams, hostToken);
    ASSERT_NE(nullptr, formAcquireConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAcquireConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnection_003 end";
}

/**
 * @tc.name: FormAcquireConnection_004
 * @tc.desc: test OnAbilityDisconnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_004 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    sptr<FormAcquireConnection> formAcquireConnection =
        new (std::nothrow) FormAcquireConnection(formId, info, wantParams, hostToken);
    ASSERT_NE(nullptr, formAcquireConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAcquireConnection->OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnection_004 end";
}

/**
 * @tc.name: FormAcquireConnection_005
 * @tc.desc: test OnFormAbilityConnectDoneCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_005 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    sptr<FormAcquireConnection> formAcquireConnection =
        new (std::nothrow) FormAcquireConnection(formId, info, wantParams, hostToken);
    ASSERT_NE(nullptr, formAcquireConnection);
    auto &&connectCallback = [](const std::string &bundleName) {};
    formAcquireConnection->SetFormAbilityConnectCb(connectCallback);
    formAcquireConnection->OnFormAbilityConnectDoneCallback();
    formAcquireConnection->SetFormAbilityConnectCb(nullptr);
    formAcquireConnection->OnFormAbilityConnectDoneCallback();
    formAcquireConnection->SetFormAbilityDisconnectCb(connectCallback);
    formAcquireConnection->OnFormAbilityDisconnectDoneCallback();
    formAcquireConnection->SetFormAbilityDisconnectCb(nullptr);
    formAcquireConnection->OnFormAbilityDisconnectDoneCallback();
    GTEST_LOG_(INFO) << "FormAcquireConnection_005 end";
}

/**
 * @tc.name: FormDeleteConnection_002
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormDeleteConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormDeleteConnection_002 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    int32_t userId = 100;
    sptr<FormDeleteConnection> formDeleteConnection =
        new (std::nothrow) FormDeleteConnection(formId, bundleName, abilityName, userId);
    ASSERT_NE(nullptr, formDeleteConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormDeleteConnection_002 end";
}

/**
 * @tc.name: FormCastTempConnection
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCastTempConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCastTempConnection_002 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    int32_t userId = 100;
    sptr<FormCastTempConnection> formCastTempConnection =
        new (std::nothrow) FormCastTempConnection(formId, bundleName, abilityName, userId);
    ASSERT_NE(nullptr, formCastTempConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formCastTempConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormCastTempConnection_002 end";
}
}