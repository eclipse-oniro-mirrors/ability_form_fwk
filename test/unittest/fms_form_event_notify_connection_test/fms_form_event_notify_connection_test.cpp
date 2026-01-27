/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "common/event/form_event_notify_connection.h"
#undef private
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormEventNotifyConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<FormEventNotifyConnection> formEventNotifyConnection_ = nullptr;
};


void FormEventNotifyConnectionTest::SetUpTestCase()
{}

void FormEventNotifyConnectionTest::TearDownTestCase()
{}

void FormEventNotifyConnectionTest::SetUp()
{}

void FormEventNotifyConnectionTest::TearDown()
{
    formEventNotifyConnection_ = nullptr;
}

/**
 * @tc.name: FormEventNotifyConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0001, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0001 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 21;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0001 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0002, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0003
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0003, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0003 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0003 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0004
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0004, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0004 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0004 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0005, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0006, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0007, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0008, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0009, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0010, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0011, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0012, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0013, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0014, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0015, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0016, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0017, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0018, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0019, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0020, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0021, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0022, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0023, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0024, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0025, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0026, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0027, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0028, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0029, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0030, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0031, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0032, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0033, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0034, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}


/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0035, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormEventNotifyConnectionTest, FormEventNotifyConnection_0036, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}
}