/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "form_ams_helper.h"
#define private public
#include "form_bms_helper.h"
#undef private
#include "form_data_mgr.h"
#include "form_db_cache.h"
#include "form_host_interface.h"
#define private public
#include "form_mgr.h"
#undef private
#include "form_mgr_service.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#include "running_process_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace {
const std::string PERMISSION_NAME_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
const std::string PARAM_PROVIDER_PACKAGE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_BUNDLE_NAME = "com.form.provider.service";
const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";

const std::string FORM_JS_COMPONENT_NAME = "jsComponentName";
const std::string FORM_PROVIDER_MODULE_SOURCE_DIR = "";

const std::string FORM_HOST_BUNDLE_NAME = "com.form.host.app";

const std::string DEVICE_ID = "ohos-phone1";
const std::string DEF_LABEL1 = "PermissionFormRequireGrant";

class FmsFormHostRecordTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
};

void FmsFormHostRecordTest::SetUpTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormHostRecordTest::TearDownTestCase()
{}

void FmsFormHostRecordTest::SetUp()
{
    formyMgrServ_->OnStart();
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormHostRecordTest::TearDown()
{}

/*
 * Feature: FormMgrService
 * Function: FormHostRecord
 * SubFunction: OnRemoteDied Function
 * FunctionPoints: FormMgr OnRemoteDied interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Quote of form is not 0 after remote died.
 */
HWTEST_F(FmsFormHostRecordTest, OnRemoteDied_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_host_record_test_001 start";

    int64_t formId1 {12001};
    int callingUid {0};
    // Create cache
    FormItemInfo record1;
    record1.SetFormId(formId1);
    record1.SetProviderBundleName(FORM_HOST_BUNDLE_NAME);
    record1.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record1.SetTemporaryFlag(true);
    FormDataMgr::GetInstance().AllotFormRecord(record1, callingUid);
    int64_t formId2 {12002};
    FormItemInfo record2;
    record2.SetFormId(formId2);
    record2.SetProviderBundleName(FORM_HOST_BUNDLE_NAME);
    record2.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record2.SetTemporaryFlag(true);
    FormDataMgr::GetInstance().AllotFormRecord(record2, callingUid);
    // Set host record
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId1, callingUid);

    std::vector<FormHostRecord> hostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId1, hostRecords);
    hostRecords[0].GetDeathRecipient()->OnRemoteDied(token_);

    FormDataMgr::GetInstance().DeleteFormRecord(formId1);
    FormDataMgr::GetInstance().DeleteFormRecord(formId2);
    FormDataMgr::GetInstance().ClearHostDataByUId(callingUid);

    GTEST_LOG_(INFO) << "fms_form_host_record_test_001 end";
}

/**
 * @tc.name: FormDbCache_001
 * @tc.desc: test GetBundleMgr function.
 * @tc.type: GetBundleMgr
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_001 start";
    FormBmsHelper formBmsHelper;
    bool formBms = true;
    if (nullptr != formBmsHelper.GetBundleMgr()) {
        formBms = false;
    }
    EXPECT_EQ(false, formBms);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_001 end";
}

/**
 * @tc.name: FormDbCache_002
 * @tc.desc: test NotifyModuleRemovable function.
 * @tc.type: NotifyModuleRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_002 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "";
    std::string moduleName = "";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_002 end";
}

/**
 * @tc.name: FormDbCache_003
 * @tc.desc: test NotifyModuleRemovable function.
 * @tc.type: NotifyModuleRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_003 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "";
    std::string moduleName = "aa";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_003 end";
}

/**
 * @tc.name: FormDbCache_004
 * @tc.desc: test NotifyModuleRemovable function.
 * @tc.type: NotifyModuleRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_004 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "bb";
    std::string moduleName = "";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_004 end";
}

/**
 * @tc.name: FormDbCache_005
 * @tc.desc: test NotifyModuleRemovable function.
 * @tc.type: NotifyModuleRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_005 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "bb";
    std::string moduleName = "aa";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_005 end";
}

/**
 * @tc.name: FormDbCache_006
 * @tc.desc: test NotifyModuleNotRemovable function.
 * @tc.type: NotifyModuleNotRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_006 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "";
    std::string moduleName = "";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_006 end";
}

/**
 * @tc.name: FormDbCache_007
 * @tc.desc: test NotifyModuleNotRemovable function.
 * @tc.type: NotifyModuleNotRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_007 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "";
    std::string moduleName = "aa";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_007 end";
}

/**
 * @tc.name: FormDbCache_008
 * @tc.desc: test NotifyModuleNotRemovable function.
 * @tc.type: NotifyModuleNotRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_008 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "bb";
    std::string moduleName = "";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_008 end";
}

/**
 * @tc.name: FormDbCache_009
 * @tc.desc: test NotifyModuleNotRemovable function.
 * @tc.type: NotifyModuleNotRemovable
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_009 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "bb";
    std::string moduleName = "aa";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_009 end";
}

/**
 * @tc.name: FormDbCache_010
 * @tc.desc: test GetBundlePackInfo function.
 * @tc.type: GetBundlePackInfo
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_010 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "aa";
    int32_t userId = 1;
    BundlePackInfo bundlePackInfo;
    EXPECT_EQ(false, formBmsHelper.GetBundlePackInfo(bundleName, userId, bundlePackInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_010 end";
}

/**
 * @tc.name: FormDbCache_011
 * @tc.desc: test GetAbilityInfoByAction function.
 * @tc.type: GetAbilityInfoByAction
 */
HWTEST_F(FmsFormHostRecordTest, FormDbCache_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_011 start";
    FormBmsHelper formBmsHelper;
    std::string action = "";
    int32_t userId = 1;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    EXPECT_EQ(false, formBmsHelper.GetAbilityInfoByAction(action, userId, abilityInfo, extensionAbilityInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FormDbCache_011 end";
}
}
