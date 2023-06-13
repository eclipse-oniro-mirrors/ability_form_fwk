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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "form_render_connection.h"
#undef private
#include "ipc_types.h"
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetCompileMode(bool mockRet);

namespace {
class FmsFormRenderConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FmsFormRenderConnectionTest::SetUp()
{}

void FmsFormRenderConnectionTest::TearDown()
{}

/**
 * @tc.name: FormRenderConnection_001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_001 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formRenderConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_001 end";
}

/**
 * @tc.name: FormRenderConnection_002
 * @tc.desc: test OnAbilityConnectDone function and GetCompileMode is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_002 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    MockGetCompileMode(false);
    formRenderConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_002 end";
}

/**
 * @tc.name: FormRenderConnection_003
 * @tc.desc: test OnAbilityConnectDone function and GetCompileMode is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_003 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    MockGetCompileMode(true);
    formRenderConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_003 end";
}

/**
 * @tc.name: FormRenderConnection_004
 * @tc.desc: test OnAbilityDisconnectDone function and resultCode is 0 connectState_ is ConnectState::CONNECTING.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_004 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    // set connectState_ is ConnectState::CONNECTING
    formRenderConnection->SetStateConnecting();
    AppExecFwk::ElementName element;
    int resultCode = 0;
    formRenderConnection->OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_004 end";
}

/**
 * @tc.name: FormRenderConnection_005
 * @tc.desc: test OnAbilityDisconnectDone function and resultCode is 0 connectState_ is ConnectState::DISCONNECTED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_005 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    // set connectState_ is ConnectState::DISCONNECTED
    formRenderConnection->SetStateDisconnected();
    AppExecFwk::ElementName element;
    int resultCode = 0;
    formRenderConnection->OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_005 end";
}

/**
 * @tc.name: FormRenderConnection_006
 * @tc.desc: test OnAbilityDisconnectDone function and resultCode is 100 connectState_ is ConnectState::DISCONNECTED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_006 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    // set connectState_ is ConnectState::DISCONNECTED
    formRenderConnection->SetStateDisconnected();
    AppExecFwk::ElementName element;
    int resultCode = 100;
    formRenderConnection->OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_006 end";
}

/**
 * @tc.name: FormRenderConnection_007
 * @tc.desc: test OnAbilityDisconnectDone function and resultCode is 100 connectState_ is ConnectState::CONNECTING.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_007 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    // set connectState_ is ConnectState::CONNECTING
    formRenderConnection->SetStateConnecting();
    AppExecFwk::ElementName element;
    int resultCode = 100;
    formRenderConnection->OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FormRenderConnection_007 end";
}

/**
 * @tc.name: FormRenderConnection_008
 * @tc.desc: test UpdateWantParams function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRenderConnectionTest, FormRenderConnection_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderConnection_008 start";
    FormRecord formRecord;
    WantParams wantParams;
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    ASSERT_NE(nullptr, formRenderConnection);
    formRenderConnection->UpdateWantParams(wantParams);
    GTEST_LOG_(INFO) << "FormRenderConnection_008 end";
}
}