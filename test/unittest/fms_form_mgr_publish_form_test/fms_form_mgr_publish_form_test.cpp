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
#define private public
#include "form_acquire_state_connection.h"
#undef private
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#define private public
#include "form_data_mgr.h"
#undef private
#include "form_db_cache.h"
#include "form_host_interface.h"
#define private public
#include "form_mgr.h"
#include "form_info.h"
#include "form_info_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#define private public
#include "form_msg_event_connection.h"
#include "form_task_mgr.h"
#undef private
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
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormMgrPublishFormTest::TearDownTestCase()
{}

void FmsFormMgrPublishFormTest::SetUp()
{
    formyMgrServ_->OnStart();
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormMgrPublishFormTest::TearDown()
{
    formyMgrServ_->OnStop();
}
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
    int64_t formId;
    // not system app GetBundleName failed
    BundleMgrService::IsSystemApp = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,
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
    BundleMgrService::IsSystemApp = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId;
    EXPECT_EQ(ERR_OK,
        formyMgrServ_->RequestPublishForm(want, false, formBindingData, formId));
    GTEST_LOG_(INFO) << "fms_form_mgr_publish_form_test_002 end";
}

/**
 * @tc.name: FormMsgEventConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrPublishFormTest, FormMsgEventConnection_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0001 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormMsgEventConnection formMsgEventConnection(formId, want, bundleName, abilityName);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 22;
    formMsgEventConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0001 end";
}

/**
 * @tc.name: FormMsgEventConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * HasParameter is not Constants::PARAM_MESSAGE_KEY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrPublishFormTest, FormMsgEventConnection_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0002 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormMsgEventConnection formMsgEventConnection(formId, want, bundleName, abilityName);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formMsgEventConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0002 end";
}

/**
 * @tc.name: FormMsgEventConnection_0003
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * HasParameter is Constants::PARAM_MESSAGE_KEY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrPublishFormTest, FormMsgEventConnection_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0003 start";
    int64_t formId = 1;
    Want want;
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormMsgEventConnection formMsgEventConnection(formId, want, bundleName, abilityName);
    // test OnAbilityConnectDone
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formMsgEventConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormMsgEventConnection_0003 end";
}

/**
 * @tc.name: FormAcquireStateConnection_0001
 * @tc.desc: test OnAbilityConnectDone function and resultCode != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrPublishFormTest, FormAcquireStateConnection_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0001 start";
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    Want want;
    std::string provider = "cc";
    FormAcquireStateConnection formAcquireStateConnection(bundleName, abilityName, want, provider);
    // test OnAbilityConnectDone function
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 55;
    formAcquireStateConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0001 end";
}

/**
 * @tc.name: FormAcquireStateConnection_0002
 * @tc.desc: test OnAbilityConnectDone function and resultCode == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrPublishFormTest, FormAcquireStateConnection_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0002 start";
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    Want want;
    std::string provider = "cc";
    FormAcquireStateConnection formAcquireStateConnection(bundleName, abilityName, want, provider);
    // test OnAbilityConnectDone function
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAcquireStateConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireStateConnection_0002 end";
}
}