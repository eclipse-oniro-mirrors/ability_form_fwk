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
#define private public
#undef private
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#define private public
#include "data_center/form_data_mgr.h"
#undef private
#include "data_center/database/form_db_cache.h"
#include "form_host_interface.h"
#define private public
#include "form_mgr.h"
#include "form_info.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_service.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#include "remote_native_token.h"
#include "running_process_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgReferee;

extern void MockGetAbilityInfo(bool mockRet);
extern void MockGetAbilityInfoByAction(bool mockRet);
extern void MockCheckAcrossLocalAccountsPermission(bool mockRet);

namespace {
const std::string PERMISSION_NAME_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
const std::string PARAM_PROVIDER_PACKAGE_NAME = "com.form.provider.app.test.ability";
const std::string LAUNCHER_BUNDLE_NAME = "com.ohos.launcher";
const std::string FORM_PROVIDER_BUNDLE_NAME = "com.form.provider.service";
const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";

const std::string FORM_JS_COMPONENT_NAME = "jsComponentName";
const std::string FORM_PROVIDER_MODULE_SOURCE_DIR = "";

const std::string FORM_HOST_BUNDLE_NAME = "com.form.host.app";

const int32_t PARAM_FORM_DIMENSION_VALUE = 1;

const std::string DEVICE_ID = "ohos-phone1";
const std::string DEF_LABEL1 = "PermissionFormRequireGrant";
const std::string FORM_MESSAGE_EVENT_VALUE_1 = "event message1";
const int32_t USER_ID = 100;

class FmsFormMgrPublishFormTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateProviderData();
protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
};

void FmsFormMgrPublishFormTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormMgrPublishFormTest::TearDownTestCase()
{}

void FmsFormMgrPublishFormTest::SetUp()
{
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormMgrPublishFormTest::TearDown()
{}
void FmsFormMgrPublishFormTest::CreateProviderData()
{
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_PROVIDER_BUNDLE_NAME);
    std::vector<FormInfoStorage> formInfoStorages;
    FormInfo formInfo;
    formInfo.bundleName = FORM_PROVIDER_BUNDLE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.name = PARAM_FORM_NAME;
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 1;
    formInfo.scheduledUpdateTime = "06:06";
    formInfo.jsComponentName = FORM_JS_COMPONENT_NAME;
    formInfo.formVisibleNotify = true;
    formInfo.supportDimensions = {1, 2};
    formInfo.defaultDimension = 1;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);

    FormInfoMgr::GetInstance().bundleFormInfoMap_ = bundleFormInfoMap;
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: PublishForm Function
 * FunctionPoints: FormMgr PublishForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke PublishForm works.
 */

HWTEST_F(FmsFormMgrPublishFormTest, publishForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_Publish_form_test_001 start";
    CreateProviderData();
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    // clear old data
    FormDataMgr::GetInstance().ClearFormRecords();
    std::vector<FormDBInfo> oldFormDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(oldFormDBInfos);
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(FORM_PROVIDER_BUNDLE_NAME, USER_ID, oldFormDBInfos);

    // publish form
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    // not system app GetBundleName failed
    BundleMgrService::IsSystemApp = false;
    EXPECT_NE(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,
        FormMgr::GetInstance().RequestPublishForm(want, false, formBindingData, formId));
    GTEST_LOG_(INFO) << "fms_form_mgr_publish_form_test_001 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: PublishForm Function
 * FunctionPoints: FormMgr PublishForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke PublishForm works.
 */
HWTEST_F(FmsFormMgrPublishFormTest, publishForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_Publish_form_test_002 start";
    CreateProviderData();
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    // clear old data
    FormDataMgr::GetInstance().ClearFormRecords();
    std::vector<FormDBInfo> oldFormDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(oldFormDBInfos);
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(FORM_PROVIDER_BUNDLE_NAME, USER_ID, oldFormDBInfos);

    // publish form
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    // not system app GetBundleName failed
    BundleMgrService::IsSystemApp = false;
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_NE(ERR_APPEXECFWK_FORM_PERMISSION_DENY,
        FormMgr::GetInstance().RequestPublishForm(want, false, formBindingData, formId));
    MockCheckAcrossLocalAccountsPermission(true);
    GTEST_LOG_(INFO) << "fms_form_mgr_publish_form_test_002 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: PublishForm Function
 * FunctionPoints: FormMgr PublishForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke PublishForm works.
 */
HWTEST_F(FmsFormMgrPublishFormTest, publishForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_Publish_form_test_003 start";
    CreateProviderData();
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    // clear old data
    FormDataMgr::GetInstance().ClearFormRecords();
    std::vector<FormDBInfo> oldFormDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(oldFormDBInfos);
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(FORM_PROVIDER_BUNDLE_NAME, USER_ID, oldFormDBInfos);

    // publish form
    sptr<MockBundleMgrService> mockBms_ = new MockBundleMgrService();
    FormBmsHelper::GetInstance().SetBundleManager(mockBms_);
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 2;
    MockGetAbilityInfo(true);
    MockGetAbilityInfoByAction(true);
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*mockBms_, GetApplicationInfoV9(_, _, _, _)).Times(testing::AnyNumber())
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));
    EXPECT_CALL(*mockBms_, CheckIsSystemAppByUid(_)).Times(testing::AnyNumber()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockBms_, GetNameForUid(_, _)).Times(testing::AnyNumber())
        .WillRepeatedly(DoAll(SetArgReferee<1>(LAUNCHER_BUNDLE_NAME), Return(ERR_OK)));
    EXPECT_EQ(ERR_OK,
        formyMgrServ_->RequestPublishForm(want, false, formBindingData, formId));
    mockBms_.clear();
    FormBmsHelper::GetInstance().SetBundleManager(nullptr);
    GTEST_LOG_(INFO) << "fms_form_mgr_publish_form_test_003 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: PublishForm Function
 * FunctionPoints: FormMgr PublishForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke PublishForm works without permission.
 */
HWTEST_F(FmsFormMgrPublishFormTest, publishForm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_Publish_form_test_004 start";
    CreateProviderData();
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    // clear old data
    FormDataMgr::GetInstance().ClearFormRecords();
    std::vector<FormDBInfo> oldFormDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(oldFormDBInfos);
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(FORM_PROVIDER_BUNDLE_NAME, USER_ID, oldFormDBInfos);

    // publish form
    sptr<MockBundleMgrService> mockBms_ = new MockBundleMgrService();
    FormBmsHelper::GetInstance().SetBundleManager(mockBms_);
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 3;
    std::string bundleName = "com.ohos.test";
    MockGetAbilityInfo(true);
    MockGetAbilityInfoByAction(true);
    EXPECT_CALL(*mockBms_, GetApplicationInfoV9(_, _, _, _)).Times(testing::AnyNumber()).WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mockBms_, CheckIsSystemAppByUid(_)).Times(testing::AnyNumber()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockBms_, GetNameForUid(_, _)).Times(testing::AnyNumber())
    .WillRepeatedly(DoAll(SetArgReferee<1>(bundleName), Return(ERR_OK)));
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formyMgrServ_->RequestPublishForm(want, false, formBindingData, formId));
    mockBms_.clear();
    FormBmsHelper::GetInstance().SetBundleManager(nullptr);
    GTEST_LOG_(INFO) << "fms_form_mgr_publish_form_test_004 end";
}
}
