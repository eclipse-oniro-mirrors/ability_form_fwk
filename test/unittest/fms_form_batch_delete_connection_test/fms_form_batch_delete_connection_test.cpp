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

/**
 * @tc.name: FormBatchDeleteConnectionTest_0003
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0003, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0003 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0003 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0004
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0004, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0004 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0004 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0005
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0005, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0005 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0005 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0006
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0006, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0006 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0006 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0007
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0007, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0007 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0007 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0008
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0008, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0008 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0008 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0009
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0009, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0009 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0009 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0010
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0010, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0010 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0010 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0011
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0011, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0011 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0011 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0012
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0012, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0012 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0012 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0013
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0013, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0013 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0013 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0014
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0014, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0014 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0014 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0015
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0015, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0015 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 11;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    ASSERT_FALSE(formBatchDeleteConnection->onFormAppConnect());
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0015 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0016
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0016, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0016 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0016 end";
}

/**
 * @tc.name: FormBatchDeleteConnectionTest_0017
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormBatchDeleteConnectionTest, FormBatchDeleteConnectionTest_0017, TestSize.Level0)
{
    HILOG_INFO("FormBatchDeleteConnectionTest_0017 start");
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    sptr<FormBatchDeleteConnection> formBatchDeleteConnection =
        new FormBatchDeleteConnection(formIds, bundleName, abilityName);
    formBatchDeleteConnection_ = formBatchDeleteConnection;

    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formBatchDeleteConnection->OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormBatchDeleteConnectionTest_0017 end";
}
}