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
#include "form_provider/connection/form_batch_delete_connection.h"
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

    sptr<FormBatchDeleteConnection> formBatchDeleteConnection_ = nullptr;
};


void FormBatchDeleteConnectionTest::SetUpTestCase()
{}

void FormBatchDeleteConnectionTest::TearDownTestCase()
{}

void FormBatchDeleteConnectionTest::SetUp()
{}

void FormBatchDeleteConnectionTest::TearDown()
{
    formBatchDeleteConnection_ = nullptr;
}

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
    int32_t userId = 100;
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName, userId);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
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
    int32_t userId = 100;
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName, userId);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0002 end";
}
}