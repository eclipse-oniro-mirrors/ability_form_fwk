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
    int32_t userId = 100;
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName, userId);
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
    int32_t userId = 100;
    sptr<FormEventNotifyConnection> formEventNotifyConnection =
        new FormEventNotifyConnection(formEvents, formVisibleType, bundleName, abilityName, userId);
    formEventNotifyConnection_ = formEventNotifyConnection;

    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formEventNotifyConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormEventNotifyConnection_0002 end";
}
}