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
#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "ams_mgr/form_ams_helper.h"
#define private public
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "data_center/form_data_mgr.h"
#include "data_center/database/form_db_cache.h"
#define private public
#include "data_center/database/form_db_info.h"
#include "feature/form_share/form_free_install_operator.h"
#undef private
#include "form_host_interface.h"
#define private public
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_service.h"
#include "feature/form_share/form_share_mgr.h"
#undef private
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#include "mock_form_provider_client.h"
#include "running_process_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using ::testing::Invoke;
using ::testing::_;

namespace {
const std::string PERMISSION_NAME_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
const std::string PARAM_PROVIDER_PACKAGE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_BUNDLE_NAME = "com.form.provider.service";
const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";

const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

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
    static sptr<BundleMgrService> mockBundleMgrService;
};

void FmsFormHostRecordTest::SetUpTestCase()
{
    mockBundleMgrService = new BundleMgrService();
    FormBmsHelper::GetInstance().SetBundleManager(mockBundleMgrService);
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

sptr<BundleMgrService> FmsFormHostRecordTest::mockBundleMgrService = nullptr;

void FmsFormHostRecordTest::TearDownTestCase()
{}

void FmsFormHostRecordTest::SetUp()
{
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
    EXPECT_NE(formBmsHelper.GetBundleMgr(), nullptr);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "";
    std::string moduleName = "";
    formBmsHelper->NotifyModuleRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "";
    std::string moduleName = "aa";
    formBmsHelper->NotifyModuleRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "bb";
    std::string moduleName = "";
    formBmsHelper->NotifyModuleRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "bb";
    std::string moduleName = "aa";
    formBmsHelper->NotifyModuleRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "";
    std::string moduleName = "";
    formBmsHelper->NotifyModuleNotRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "";
    std::string moduleName = "aa";
    formBmsHelper->NotifyModuleNotRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "bb";
    std::string moduleName = "";
    formBmsHelper->NotifyModuleNotRemovable(bundleName, moduleName);
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
    std::shared_ptr<FormBmsHelper> formBmsHelper = std::make_shared<FormBmsHelper>();
    ASSERT_NE(nullptr, formBmsHelper);
    std::string bundleName = "bb";
    std::string moduleName = "aa";
    formBmsHelper->NotifyModuleNotRemovable(bundleName, moduleName);
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

/**
 * @tc.name: FormMgrService_0004
 * @tc.desc: test LifecycleUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0004 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    bool updateType = false;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.LifecycleUpdate(formIds, callerToken, updateType));
    GTEST_LOG_(INFO) << "FormMgrService_0004 end";
}

/**
 * @tc.name: FormMgrService_0005
 * @tc.desc: test AddForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0005 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrService_0005 end";
}

/**
 * @tc.name: FormMgrService_0006
 * @tc.desc: test DeleteForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0006 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0006 end";
}

/**
 * @tc.name: FormMgrService_0007
 * @tc.desc: test ReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0007 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    bool delCache = false;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrService_0007 end";
}

/**
 * @tc.name: FormMgrService_0009
 * @tc.desc: test RequestForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0009 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    Want want;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrService_0009 end";
}

/**
 * @tc.name: FormMgrService_0010
 * @tc.desc: test NotifyWhetherVisibleForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0010 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t formVisibleType = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrService_0010 end";
}

/**
 * @tc.name: FormMgrService_0011
 * @tc.desc: test CastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0011 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0011 end";
}

/**
 * @tc.name: FormMgrService_0012
 * @tc.desc: test MessageEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0012 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0012 end";
}

/**
 * @tc.name: FormMgrService_0013
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0013 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.RouterEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0013 end";
}

/**
 * @tc.name: FormMgrService_0014
 * @tc.desc: test OnStart function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0014 start";
    FormMgrService formMgrService;
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    formMgrService.OnStart();
    GTEST_LOG_(INFO) << "FormMgrService_0014 end";
}

/**
 * @tc.name: FormMgrService_0015
 * @tc.desc: test OnStop function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0015 start";
    FormMgrService formMgrService;
    formMgrService.handler_ = nullptr;
    formMgrService.serialQueue_ = nullptr;
    formMgrService.OnStop();
    GTEST_LOG_(INFO) << "FormMgrService_0015 end";
}

/**
 * @tc.name: FormMgrService_0017
 * @tc.desc: test DeleteInvalidForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0017 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrService_0017 end";
}

/**
 * @tc.name: FormMgrService_0018
 * @tc.desc: test AcquireFormState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0018 start";
    FormMgrService formMgrService;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.AcquireFormState(want, callerToken, stateInfo));
    GTEST_LOG_(INFO) << "FormMgrService_0018 end";
}

/**
 * @tc.name: FormMgrService_0019
 * @tc.desc: test NotifyFormsVisible function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0019 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    bool isVisible = false;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0019 end";
}

/**
 * @tc.name: FormMgrService_0020
 * @tc.desc: test NotifyFormsPrivacyProtected function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0020 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    bool isProtected = false;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0020 end";
}

/**
 * @tc.name: FormMgrService_0021
 * @tc.desc: test NotifyFormsEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0021 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    bool isEnableUpdate = false;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0021 end";
}

/**
 * @tc.name: FormMgrService_0022
 * @tc.desc: test GetFormsInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0022 start";
    FormMgrService formMgrService;
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = FORM_PROVIDER_BUNDLE_NAME;
        GTEST_LOG_(INFO) << "AddForm_002 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrService.GetFormsInfo(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0022 end";
}

/**
 * @tc.name: FormMgrService_0023
 * @tc.desc: test GetFormsInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0023 start";
    FormMgrService formMgrService;
    FormInfoFilter filter;
    filter.moduleName = "aa";
    std::vector<FormInfo> formInfos;
    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = FORM_PROVIDER_BUNDLE_NAME;
        GTEST_LOG_(INFO) << "AddForm_002 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrService.GetFormsInfo(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0023 end";
}

/**
 * @tc.name: FormMgrService_0024
 * @tc.desc: test IsRequestPublishFormSupported function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0024 start";
    FormMgrService formMgrService;
    EXPECT_EQ(false, formMgrService.IsRequestPublishFormSupported());
    GTEST_LOG_(INFO) << "FormMgrService_0024 end";
}

/**
 * @tc.name: FormMgrService_0025
 * @tc.desc: test StartAbility function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0025 start";
    FormMgrService formMgrService;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.StartAbility(want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0025 end";
}

/**
 * @tc.name: FormMgrService_0026
 * @tc.desc: test ShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0026 start";
    FormMgrService formMgrService;
    int64_t formId = 0;
    std::string deviceId = "aa";
    sptr<IRemoteObject> callerToken = nullptr;
    int64_t requestCode = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
    GTEST_LOG_(INFO) << "FormMgrService_0026 end";
}

/**
 * @tc.name: FormMgrService_0027
 * @tc.desc: test ShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0027 start";
    FormMgrService formMgrService;
    int64_t formId = 2;
    std::string deviceId = "";
    sptr<IRemoteObject> callerToken = nullptr;
    int64_t requestCode = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
    GTEST_LOG_(INFO) << "FormMgrService_0027 end";
}

/**
 * @tc.name: FormMgrService_0028
 * @tc.desc: test ShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0028 start";
    FormMgrService formMgrService;
    int64_t formId = 2;
    std::string deviceId = "aa";
    sptr<IRemoteObject> callerToken = nullptr;
    int64_t requestCode = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
    GTEST_LOG_(INFO) << "FormMgrService_0028 end";
}

/**
 * @tc.name: FormMgrService_0029
 * @tc.desc: test ShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0029 start";
    FormMgrService formMgrService;
    int64_t formId = 2;
    std::string deviceId = "aa";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int64_t requestCode = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
    GTEST_LOG_(INFO) << "FormMgrService_0029 end";
}

/**
 * @tc.name: FormMgrService_0030
 * @tc.desc: test ShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0030 start";
    FormMgrService formMgrService;
    int64_t formId = 2;
    std::string deviceId = "aa";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int64_t requestCode = 2;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
    GTEST_LOG_(INFO) << "FormMgrService_0030 end";
}

/**
 * @tc.name: FormMgrService_0031
 * @tc.desc: test Dump function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0031 start";
    FormMgrService formMgrService;
    int fd = 1;
    std::vector<std::u16string> args;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.Dump(fd, args));
    GTEST_LOG_(INFO) << "FormMgrService_0031 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump with no args works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_001 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);
    GTEST_LOG_(INFO) << "FormMgrService_dump_001 end";
}


/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump help works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_002 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-h"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_NE(result.find("options list:"), string::npos);

    args[0] = u"--help";
    formMgrService.Dump(args, result);
    EXPECT_NE(result.find("options list:"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_002 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump storage works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_003 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-s"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    args[0] = u"--storage";
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_003 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump by bundle name works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_004 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-n"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_004 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump by form id works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_005 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-i"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_005 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump temp-form works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_005 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-t"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    args[0] = u"--temp";
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_005 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump static-form-info works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_007 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-b"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    args[0] = u"--bundle-form-info";
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_007 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump form works.
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_dump_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_dump_008 start";
    FormMgrService formMgrService;
    std::vector<std::u16string> args = {u"-r"};
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    args[0] = u"--running";
    formMgrService.Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "FormMgrService_dump_008 end";
}

/**
 * @tc.name: FormMgrService_0032
 * @tc.desc: test HiDumpFormInfoByBundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0032 start";
    std::shared_ptr<FormMgrService> formMgrService = std::make_shared<FormMgrService>();
    ASSERT_NE(nullptr, formMgrService);
    std::string args = "aa";
    std::string result = "bb";
    formMgrService->HiDumpFormInfoByBundleName(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0032 end";
}

/**
 * @tc.name: FormMgrService_0033
 * @tc.desc: test HiDumpFormInfoByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0033 start";
    std::shared_ptr<FormMgrService> formMgrService = std::make_shared<FormMgrService>();
    ASSERT_NE(nullptr, formMgrService);
    std::string args = "aa";
    std::string result = "bb";
    formMgrService->HiDumpFormInfoByFormId(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0033 end";
}

/**
 * @tc.name: FormMgrService_0034
 * @tc.desc: test OnAddSystemAbility function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormMgrService_0034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrService_0034 start";
    std::shared_ptr<FormMgrService> formMgrService = std::make_shared<FormMgrService>();
    ASSERT_NE(nullptr, formMgrService);
    int32_t systemAbilityId = RES_SCHED_SYS_ABILITY_ID;
    std::string deviceId;
    formMgrService->OnAddSystemAbility(systemAbilityId, deviceId);
    GTEST_LOG_(INFO) << "FormMgrService_0034 end";
}

/**
 * @tc.name: InnerFormInfo_0001
 * @tc.desc: test AddUserUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, InnerFormInfo_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InnerFormInfo_0001 start";
    std::shared_ptr<InnerFormInfo> innerFormInfo = std::make_shared<InnerFormInfo>();
    ASSERT_NE(nullptr, innerFormInfo);
    int callingUid = 1;
    innerFormInfo->AddUserUid(callingUid);
    GTEST_LOG_(INFO) << "InnerFormInfo_0001 end";
}

/**
 * @tc.name: InnerFormInfo_0002
 * @tc.desc: test AddUserUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, InnerFormInfo_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InnerFormInfo_0002 start";
    std::shared_ptr<InnerFormInfo> innerFormInfo = std::make_shared<InnerFormInfo>();
    ASSERT_NE(nullptr, innerFormInfo);
    int callingUid = 1;
    std::vector<int> formUserUids;
    formUserUids.emplace_back(callingUid);
    innerFormInfo->SetUserUids(formUserUids);
    innerFormInfo->AddUserUid(callingUid);
    GTEST_LOG_(INFO) << "InnerFormInfo_0002 end";
}

/**
 * @tc.name: InnerFormInfo_0003
 * @tc.desc: test DeleteUserUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, InnerFormInfo_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InnerFormInfo_0003 start";
    InnerFormInfo innerFormInfo;
    int callingUid = 1;
    EXPECT_EQ(false, innerFormInfo.DeleteUserUid(callingUid));
    GTEST_LOG_(INFO) << "InnerFormInfo_0003 end";
}

/**
 * @tc.name: InnerFormInfo_0004
 * @tc.desc: test DeleteUserUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, InnerFormInfo_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InnerFormInfo_0004 start";
    InnerFormInfo innerFormInfo;
    int callingUid = 1;
    std::vector<int> formUserUids;
    formUserUids.emplace_back(callingUid);
    innerFormInfo.SetUserUids(formUserUids);
    EXPECT_EQ(true, innerFormInfo.DeleteUserUid(callingUid));
    GTEST_LOG_(INFO) << "InnerFormInfo_0004 end";
}

/**
 * @tc.name: FormFreeInstallOperator_0001
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormFreeInstallOperator_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormFreeInstallOperator_0001 start";
    std::string formShareInfoKey = "aa";
    FormFreeInstallOperator formFreeInstallOperator(formShareInfoKey, nullptr);
    int32_t resultCode = 1;
    formFreeInstallOperator.OnInstallFinished(resultCode);
    GTEST_LOG_(INFO) << "FormFreeInstallOperator_0001 end";
}

/**
 * @tc.name: FreeInstallStatusCallBack_0001
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FreeInstallStatusCallBack_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBack_0001 start";
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperators = nullptr;
    std::weak_ptr<FormFreeInstallOperator> freeInstallOperator = freeInstallOperators;
    FreeInstallStatusCallBack freeInstallStatusCallBack(freeInstallOperator);
    int32_t resultCode = 1;
    Want want;
    int32_t userId = 1;
    freeInstallStatusCallBack.OnInstallFinished(resultCode, want, userId);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBack_0001 end";
}

/**
 * @tc.name: FreeInstallStatusCallBack_0002
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FreeInstallStatusCallBack_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBack_0002 start";
    std::string formShareInfoKey = "aa";
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperators =
        std::make_shared<FormFreeInstallOperator>(formShareInfoKey, nullptr);
    std::weak_ptr<FormFreeInstallOperator> freeInstallOperator = freeInstallOperators;
    FreeInstallStatusCallBack freeInstallStatusCallBack(freeInstallOperator);
    int32_t resultCode = 1;
    Want want;
    int32_t userId = 1;
    freeInstallStatusCallBack.OnInstallFinished(resultCode, want, userId);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBack_0002 end";
}

/**
 * @tc.name: FormShareMgr_0001
 * @tc.desc: test RecvFormShareInfoFromRemote function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostRecordTest, FormShareMgr_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_0001 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formShareMgr.RecvFormShareInfoFromRemote(info));
    GTEST_LOG_(INFO) << "FormShareMgr_0001 end";
}
}
