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
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#define private public
#include "data_center/form_data_mgr.h"
#undef private
#include "data_center/database/form_db_cache.h"
#include "form_host_interface.h"
#define private public
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/bundle_form_info.h"
#include "form_mgr.h"
#undef private
#include "form_mgr/form_mgr_service.h"
#include "common/util/form_util.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_death_callback.h"
#include "mock_form_host_client.h"
#include "remote_native_token.h"
#include "running_process_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using ::testing::Invoke;
using ::testing::_;

void MockGetCallingUid(int32_t mockRet);

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

const int32_t PARAM_FORM_DIMENSION_VALUE = 1;

const std::string DEVICE_ID = "ohos-phone1";
const std::string DEF_LABEL1 = "PermissionFormRequireGrant";

class FmsFormMgrDeathCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateProviderData();
protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
    int32_t userId_ = FormUtil::GetCurrentAccountId();
    static sptr<BundleMgrService> mockBundleMgrService;
};

void FmsFormMgrDeathCallbackTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
    mockBundleMgrService = new BundleMgrService();
    FormBmsHelper::GetInstance().SetBundleManager(mockBundleMgrService);
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

sptr<BundleMgrService> FmsFormMgrDeathCallbackTest::mockBundleMgrService = nullptr;

void FmsFormMgrDeathCallbackTest::TearDownTestCase()
{
    mockBundleMgrService = nullptr;
}

void FmsFormMgrDeathCallbackTest::SetUp()
{
    formyMgrServ_->OnStart();
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormMgrDeathCallbackTest::TearDown()
{}

void FmsFormMgrDeathCallbackTest::CreateProviderData()
{
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_PROVIDER_BUNDLE_NAME);
    std::vector<FormInfo> formInfos;
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
    formInfo.supportShapes = {1};
    formInfo.defaultDimension = 1;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = userId_;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);

    FormInfoMgr::GetInstance().bundleFormInfoMap_ = bundleFormInfoMap;
}
/*
 * Feature: FormMgrService
 * Function: FormMgr::FormMgrDeathRecipient
 * SubFunction: OnRemoteDied Function
 * FunctionPoints: FormMgr::FormMgrDeathRecipient OnRemoteDied interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr::FormMgrDeathRecipient invoke OnRemoteDied works.
 */
HWTEST_F(FmsFormMgrDeathCallbackTest, OnRemoteDied_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_death_callback_test_001 start";
    CreateProviderData();
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME)
        .SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME)
        .SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME)
        .SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE)
        .SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME)
        .SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false)
        .SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);

    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = FORM_PROVIDER_BUNDLE_NAME;
        GTEST_LOG_(INFO) << "AddForm_002 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    int32_t callingUid {20000001};
    MockGetCallingUid(callingUid);
    EXPECT_EQ(ERR_OK, FormMgr::GetInstance().AddForm(0L, want, token_, formJsInfo));
    token_->Wait();

    std::shared_ptr<FormCallbackInterface> deathCallback = std::make_shared<MockFormDeathCallback>();
    FormMgr::GetInstance().RegisterDeathCallback(deathCallback);
    EXPECT_EQ(true, FormMgr::GetInstance().CheckIsDeathCallbackRegistered(deathCallback));
    FormMgr::GetInstance().GetDeathRecipient()->OnRemoteDied(formyMgrServ_->AsObject());

    int64_t formId = formJsInfo.formId;

    std::vector<FormHostRecord> hostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, hostRecords);
    if (hostRecords.size() > 0) {
        EXPECT_EQ(true, token_->AsObject() == hostRecords[0].formHostClient_);
    }

    EXPECT_EQ(true, FormMgr::GetRecoverStatus() == Constants::NOT_IN_RECOVERY);

    FormMgr::GetInstance().UnRegisterDeathCallback(deathCallback);
    EXPECT_EQ(false, FormMgr::GetInstance().CheckIsDeathCallbackRegistered(deathCallback));

    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    FormDbCache::GetInstance().DeleteFormInfo(formId);
    FormDataMgr::GetInstance().DeleteHostRecord(token_, formId);

    GTEST_LOG_(INFO) << "fms_form_mgr_death_callback_test_001 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr::FormMgrDeathRecipient
 * SubFunction: OnRemoteDied Function
 * FunctionPoints: FormMgr::FormMgrDeathRecipient OnRemoteDied interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr::FormMgrDeathRecipient invoke OnRemoteDied works when remote is nullptr.
 */
HWTEST_F(FmsFormMgrDeathCallbackTest, OnRemoteDied_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_death_callback_test_002 start";
    // No cache
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME)
        .SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME)
        .SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME)
        .SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE)
        .SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME)
        .SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false)
        .SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);

    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = FORM_PROVIDER_BUNDLE_NAME;
        GTEST_LOG_(INFO) << "AddForm_002 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    int32_t callingUid {20000001};
    MockGetCallingUid(callingUid);
    EXPECT_EQ(ERR_OK, FormMgr::GetInstance().AddForm(0L, want, token_, formJsInfo));
    token_->Wait();

    std::shared_ptr<FormCallbackInterface> deathCallback = std::make_shared<MockFormDeathCallback>();
    FormMgr::GetInstance().RegisterDeathCallback(deathCallback);
    EXPECT_EQ(true, FormMgr::GetInstance().CheckIsDeathCallbackRegistered(deathCallback));

    int beforeRecoverStatus = FormMgr::GetRecoverStatus();
    FormMgr::GetInstance().GetDeathRecipient()->OnRemoteDied(nullptr);
    EXPECT_EQ(true, FormMgr::GetRecoverStatus() == beforeRecoverStatus);

    int64_t formId = formJsInfo.formId;
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    FormDbCache::GetInstance().DeleteFormInfo(formId);
    FormDataMgr::GetInstance().DeleteHostRecord(token_, formId);

    GTEST_LOG_(INFO) << "fms_form_mgr_death_callback_test_002 end";
}

/**
 * @tc.name: OnRemoteDied_003
 * @tc.desc: Verify ProcessRecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDeathCallbackTest, OnRemoteDied_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRemoteDied_003 begin";
    std::shared_ptr<FormCallbackInterface> deathCallback = std::make_shared<MockFormDeathCallback>();
    EXPECT_NE(deathCallback, nullptr);
    deathCallback->ProcessRecycleForm();
    GTEST_LOG_(INFO) << "OnRemoteDied_003 end";
}
}