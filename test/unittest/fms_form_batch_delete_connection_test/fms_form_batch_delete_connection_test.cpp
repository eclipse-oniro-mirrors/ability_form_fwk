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
#include "form_batch_delete_connection.h"
#include "form_event_notify_connection.h"
#undef private
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormBatchDeleteConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void FormBatchDeleteConnectionTest::SetUpTestCase()
{}

void FormBatchDeleteConnectionTest::TearDownTestCase()
{}

void FormBatchDeleteConnectionTest::SetUp()
{}

void FormBatchDeleteConnectionTest::TearDown()
{}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0001, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0001 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormBatchDeleteConnection formBatchDeleteConnection(formIds, bundleName, abilityName);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection.onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0001 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0002, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0002 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormBatchDeleteConnection formBatchDeleteConnection(formIds, bundleName, abilityName);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0002 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormEventNotifyConnection_0001, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0001 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    FormEventNotifyConnection formEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 21;
    formEventNotifyConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0001 end";
}

/**
 * @tc.name: FormEventNotifyConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormEventNotifyConnection_0002, TestSize.Level0)
{
    HILOG_INFO("FormEventNotifyConnection_0002 start");
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    std::string bundleName = "aaa";
    std::string abilityName = "bbb";
    FormEventNotifyConnection formEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}
}