/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <thread>
#include <chrono>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "accesstoken_kit.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_db_cache.h"
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#define private public
#include "form_data_mgr.h"
#include "form_distributed_client.h"
#include "form_mgr.h"
#include "form_info.h"
#include "form_info_mgr.h"
#include "form_share_mgr.h"
#include "form_event_handler.h"
#include "want.h"
#undef private
#include "dm_constants.h"
#include "dm_device_info.h"
#include "iremote_proxy.h"
#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_distributed_sched.h"
#include "mock_form_host_client.h"
#include "mock_form_provider_client.h"
#include "string_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using namespace OHOS::DistributedSchedule;
using testing::_;

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

const std::string LOCAL_DEVICE_ID = "ohos-phone1";
const std::string REMOTE_DEVICE_ID = "ohos-phone2";

const std::string WANT_PARAM_KEY = "key";
const std::string WANT_PARAM_VALUE = "value";
const int64_t UNKNOWN_FORM_ID = 111;
const int64_t DIFF_FORM_ID = 222;
const std::string DEF_LABEL1 = "PermissionFormRequireGrant";
const int32_t USER_ID = 100;
const std::string FORM_SHARE_NULL = "";
const std::string FORM_NULL_BUNDLE_NAME = "";
}  // namespace

class FmsFormShareMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateProviderData();
    void CreateForm(FormJsInfo &formInfo);
    void ClearFormShareMgrMapData();

protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
    sptr<DistributedSchedService> dmsSerice = new DistributedSchedService();
};

class MockFormHostCallback : public FormHostStub {
public:
    MockFormHostCallback() = default;
    virtual ~MockFormHostCallback() = default;

    MOCK_METHOD1(OnAcquired, void(const FormJsInfo &formInfo));
    MOCK_METHOD1(OnUpdate, void(const FormJsInfo &formInfo));
    MOCK_METHOD1(OnUninstall, void(const std::vector<int64_t> &formIds));
    MOCK_METHOD2(OnAcquireState, void(AppExecFwk::FormState state, const AAFwk::Want &want));
    MOCK_METHOD2(OnShareFormResponse, void(const int64_t requestCode, const int32_t result));
};

static sptr<BundleMgrService> bundleMgr_ = nullptr;

void FmsFormShareMgrTest::SetUpTestCase()
{
    bundleMgr_ = new BundleMgrService();
    FormBmsHelper::GetInstance().SetBundleManager(bundleMgr_);
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormShareMgrTest::TearDownTestCase()
{
    bundleMgr_.clear();
}

void FmsFormShareMgrTest::SetUp()
{
    formyMgrServ_->OnStart();
    FormShareMgr::GetInstance().formDmsClient_ = std::make_shared<FormDistributedClient>();
    FormShareMgr::GetInstance().formDmsClient_->SetDmsProxy(dmsSerice->AsObject());
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int32_t userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormShareMgrTest::TearDown()
{
    formyMgrServ_->OnStop();
}

void FmsFormShareMgrTest::CreateProviderData()
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

void FmsFormShareMgrTest::CreateForm(FormJsInfo &formJsInfo)
{
    // No cache
    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(LOCAL_DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    want.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);
    // clear old data
    FormDataMgr::GetInstance().ClearFormRecords();
    std::vector<FormDBInfo> oldFormDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(oldFormDBInfos);
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(FORM_PROVIDER_BUNDLE_NAME, USER_ID, oldFormDBInfos);

    // add form
    FormMgr::GetInstance().AddForm(0, want, token_, formJsInfo);
    token_->Wait();
}

void FmsFormShareMgrTest::ClearFormShareMgrMapData()
{
    FormShareMgr::GetInstance().shareInfo_.clear();
    FormShareMgr::GetInstance().eventMap_.clear();
    FormShareMgr::GetInstance().freeInstallOperatorMap_.clear();
}

/**
 * @tc.name: RecvFormShareInfoFromRemote_001
 * @tc.desc: check form share info case.
 * @tc.type: RecvFormShareInfoFromRemote
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, RecvFormShareInfoFromRemote_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest RecvFormShareInfoFromRemote_001 start";
    auto runner = EventRunner::Create("FormMgrService");
    auto handler = std::make_shared<FormEventHandler>(runner);
    FormShareMgr::GetInstance().SetEventHandler(handler);
    FormShareInfo info;
    auto result = FormShareMgr::GetInstance().RecvFormShareInfoFromRemote(info);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest RecvFormShareInfoFromRemote_001 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_001
 * @tc.desc: check form share info case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleRecvFormShareInfoFromRemoteTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_001 start";

    WantParams wantParams;
    wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box("device"));
    FormShareInfo info;
    info.formId = 1;
    info.formName = "";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;
    auto result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.formName = "form";
    info.bundleName = "";
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.bundleName = "form_bundle";
    info.moduleName = "";
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.moduleName = "form_module";
    info.abilityName = "";
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.abilityName = "form_ability";
    info.dimensionId = -1;
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_EQ(result, ERR_OK);

    info.dimensionId = 1;
    info.deviceId = "";
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.deviceId = "device";
    result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_001 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_002
 * @tc.desc: Failed to Recv Form Share info.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleRecvFormShareInfoFromRemoteTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_002 start";

    WantParams wantParams;
    wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box("device"));

    FormShareInfo info;
    info.formId = 1;
    info.formName = "form";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;
    auto key = FormShareMgr::GetInstance().MakeFormShareInfoKey(info);
    FormShareMgr::GetInstance().shareInfo_.emplace(key, info);

    auto result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    FormShareMgr::GetInstance().shareInfo_.erase(key);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_002 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_003
 * @tc.desc: free install success case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleRecvFormShareInfoFromRemoteTask_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_003 start";

    WantParams wantParams;
    wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box("device"));

    FormShareInfo info;
    info.formId = 1;
    info.formName = "form";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;

    auto func = [](const Want &want,
                    int32_t flags,
                    int32_t userId,
                    AbilityInfo &abilityInfo,
                    const sptr<IRemoteObject> &callBack) -> bool { return true; };

    EXPECT_CALL(*bundleMgr_, QueryAbilityInfo(_, _, _, _, _)).Times(1).WillOnce(testing::Invoke(func));

    Want want;
    int32_t flags = 0;
    int32_t userId = 0;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bundleMgr_->ImplicitQueryInfoByPriority(want, flags, userId, abilityInfo, extensionInfo);

    auto result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_EQ(result, ERR_OK);

    ClearFormShareMgrMapData();

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_003 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_004
 * @tc.desc: free install success case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleRecvFormShareInfoFromRemoteTask_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_004 start";

    WantParams wantParams;
    wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box("device"));

    FormShareInfo info;
    info.formId = 1;
    info.formName = "form";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;

    auto func = [](const Want &want,
                    int32_t flags,
                    int32_t userId,
                    AbilityInfo &abilityInfo,
                    const sptr<IRemoteObject> &callBack) -> bool { return false; };

    EXPECT_CALL(*bundleMgr_, QueryAbilityInfo(_, _, _, _, _)).Times(1).WillOnce(testing::Invoke(func));

    auto key = FormShareMgr::GetInstance().MakeFormShareInfoKey(info);
    FormShareMgr::GetInstance().shareInfo_.emplace(key, info);

    auto result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    ClearFormShareMgrMapData();

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_004 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_005
 * @tc.desc: free install failed case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleRecvFormShareInfoFromRemoteTask_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_005 start";

    WantParams wantParams;
    wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box("device"));

    FormShareInfo info;
    info.formId = 1;
    info.formName = "form";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;

    auto func = [](const Want &want,
                    int32_t flags,
                    int32_t userId,
                    AbilityInfo &abilityInfo,
                    const sptr<IRemoteObject> &callBack) -> bool { return true; };

    EXPECT_CALL(*bundleMgr_, QueryAbilityInfo(_, _, _, _, _)).Times(1).WillOnce(testing::Invoke(func));

    auto key = FormShareMgr::GetInstance().MakeFormShareInfoKey(info);
    FormShareMgr::GetInstance().shareInfo_.emplace(key, info);

    auto result = FormShareMgr::GetInstance().HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_005 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_001
 * @tc.desc: shareForm function success
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, FmsFormShareMgrTest_ShareForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_001 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 1;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int32_t result = FormShareMgr::GetInstance().ShareForm(formInfo1.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_001  end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_002
 * @tc.desc: shareForm function fail
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, FmsFormShareMgrTest_ShareForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_002 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 2;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int32_t result = FormShareMgr::GetInstance().ShareForm(formJsInfo.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    int64_t inValidFormId = -1;
    result = FormShareMgr::GetInstance().ShareForm(inValidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_002 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_003
 * @tc.desc: shareForm function fail
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, FmsFormShareMgrTest_ShareForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_003 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 3;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int64_t inValidFormId = 123456789;
    int32_t result = FormShareMgr::GetInstance().ShareForm(inValidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_003 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_004
 * @tc.desc: shareForm function fail
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, FmsFormShareMgrTest_ShareForm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_004 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);
    const int64_t requestCode = 4;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    formInfo.bundleName = FORM_NULL_BUNDLE_NAME;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);

    formInfo1.bundleName = FORM_NULL_BUNDLE_NAME;
    FormDataMgr::GetInstance().UpdateFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int32_t result = FormShareMgr::GetInstance().ShareForm(formJsInfo.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_004 end";
}

/**
 * @tc.name: AcquireShareFormData_001
 * @tc.desc: AcquireShareFormData function success
 * @tc.type: AcquireShareFormData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, AcquireShareFormData_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_001 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(LOCAL_DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    want.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);

    sptr<MockFormProviderClient> mockClient = new (std::nothrow) MockFormProviderClient();
    EXPECT_FALSE(mockClient->state_AcquireShareFormData_);
    FormShareMgr::GetInstance().AcquireShareFormData(UNKNOWN_FORM_ID, REMOTE_DEVICE_ID, want, mockClient);

    EXPECT_TRUE(mockClient->state_AcquireShareFormData_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_001 end";
}

/**
 * @tc.name: AcquireShareFormData_002
 * @tc.desc: AcquireShareFormData function success
 * @tc.type: AcquireShareFormData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, AcquireShareFormData_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_002 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, PARAM_FORM_DIMENSION_VALUE);
    want.SetElementName(LOCAL_DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    want.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);

    sptr<MockFormProviderClient> mockClient = new (std::nothrow) MockFormProviderClient();
    EXPECT_FALSE(mockClient->state_AcquireShareFormData_);
    FormShareMgr::GetInstance().AcquireShareFormData(0, REMOTE_DEVICE_ID, want, mockClient);

    EXPECT_TRUE(mockClient->state_AcquireShareFormData_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_001 end";
}

/**
 * @tc.name: HandleProviderShareData_001
 * @tc.desc: HandleProviderShareData function success
 * @tc.type: HandleProviderShareData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleProviderShareData_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_001 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    auto func = [](const Want &want,
                    int32_t flags,
                    int32_t userId,
                    AbilityInfo &abilityInfo,
                    const sptr<IRemoteObject> &callBack) -> bool { return true; };

    EXPECT_CALL(*bundleMgr_, QueryAbilityInfo(_, _, _, _, _)).Times(1).WillOnce(testing::Invoke(func));

    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);
    const int64_t requestCode = 5;
    AAFwk::WantParams wantParams;
    std::string keyStr = WANT_PARAM_KEY;
    std::string valueString = WANT_PARAM_VALUE;
    wantParams.SetParam(keyStr, AAFwk::String::Box(valueString));
    bool testFlag = false;
    auto hostCallback = [&](const int64_t requestCode, const int32_t result) { testFlag = true; };
    bool results = true;
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    FormShareMgr::GetInstance().requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    FormShareMgr::GetInstance().HandleProviderShareData(
        UNKNOWN_FORM_ID, REMOTE_DEVICE_ID, wantParams, requestCode, results);
    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_001 end";
}

/**
 * @tc.name: HandleProviderShareData_002
 * @tc.desc: HandleProviderShareData function success
 * @tc.type: HandleProviderShareData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleProviderShareData_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_002 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);
    const int64_t requestCode = 6;
    AAFwk::WantParams wantParams;
    std::string keyStr = WANT_PARAM_KEY;
    std::string valueString = WANT_PARAM_VALUE;
    wantParams.SetParam(keyStr, AAFwk::String::Box(valueString));
    bool testFlag = false;
    auto hostCallback = [&](const int64_t requestCode, const int32_t result) { testFlag = true; };
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    FormShareMgr::GetInstance().requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    bool results = true;
    FormShareMgr::GetInstance().HandleProviderShareData(
        DIFF_FORM_ID, REMOTE_DEVICE_ID, wantParams, requestCode, results);

    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_002 end";
}

/**
 * @tc.name: HandleProviderShareData_003
 * @tc.desc: HandleProviderShareData function success
 * @tc.type: HandleProviderShareData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, HandleProviderShareData_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_003 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);
    const int64_t requestCode = 7;
    AAFwk::WantParams wantParams;
    std::string keyStr = WANT_PARAM_KEY;
    std::string valueString = WANT_PARAM_VALUE;
    wantParams.SetParam(keyStr, AAFwk::String::Box(valueString));

    bool testFlag = false;
    auto hostCallback = [&](const int64_t requestCode, const int32_t result) { testFlag = true; };
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    FormShareMgr::GetInstance().requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    bool results = true;
    FormShareMgr::GetInstance().HandleProviderShareData(
        formJsInfo.formId, REMOTE_DEVICE_ID, wantParams, requestCode, results);

    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_003 end";
}

/**
 * @tc.name: ShareForm_001
 * @tc.desc: .
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, ShareForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_001 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 8;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int64_t inValidFormId = 0;
    int32_t result = FormMgr::GetInstance().ShareForm(inValidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    inValidFormId = -1;
    result = FormMgr::GetInstance().ShareForm(inValidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_001  end";
}

/**
 * @tc.name: ShareForm_002
 * @tc.desc: .
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, ShareForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_002 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 9;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int32_t result = FormMgr::GetInstance().ShareForm(formJsInfo.formId, "", nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_002 end";
}

/**
 * @tc.name: ShareForm_003
 * @tc.desc: .
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, ShareForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_003 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 10;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    int64_t unExistFormId = 12345678;
    int32_t result = FormMgr::GetInstance().ShareForm(unExistFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_003  end";
}

/**
 * @tc.name: ShareForm_004
 * @tc.desc: .
 * @tc.type: ShareForm
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, ShareForm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_004 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    const int64_t requestCode = 11;
    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    EXPECT_EQ(PARAM_FORM_NAME, formInfo1.formName);

    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    int32_t result = FormMgr::GetInstance().ShareForm(formJsInfo.formId, REMOTE_DEVICE_ID, mockHost, requestCode);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_004  end";
}

/**
 * @tc.name: GetLocalDeviceInfo_001
 * @tc.desc: GetLocalDeviceInfo function success
 * @tc.type: GetLocalDeviceInfo
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, GetLocalDeviceInfo_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_001 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo = {{0}, {0}, 0, {0}};
    auto result = FormShareMgr::GetInstance().GetLocalDeviceInfo(FORM_PROVIDER_BUNDLE_NAME, deviceInfo);
    EXPECT_EQ(result, ERR_OK);
    std::string deviceId(deviceInfo.deviceId);
    EXPECT_FALSE(deviceId.empty());

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_001 end";
}

/**
 * @tc.name: GetLocalDeviceInfo_002
 * @tc.desc: GetLocalDeviceInfo function success
 * @tc.type: GetLocalDeviceInfo
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, GetLocalDeviceInfo_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_002 start";
    FormJsInfo formJsInfo;
    CreateProviderData();
    CreateForm(formJsInfo);

    FormRecord formInfo;
    formInfo.formName = PARAM_FORM_NAME;
    formInfo.formId = formJsInfo.formId;
    FormRecord formInfo1;
    FormDataMgr::GetInstance().formRecords_.emplace(formJsInfo.formId, formInfo);
    bool ret = FormDataMgr::GetInstance().GetFormRecord(formJsInfo.formId, formInfo1);
    EXPECT_TRUE(ret);
    OHOS::DistributedHardware::DmDeviceInfo deviceInfo;
    auto result = FormShareMgr::GetInstance().GetLocalDeviceInfo(FORM_NULL_BUNDLE_NAME, deviceInfo);
    EXPECT_EQ(result, DistributedHardware::ERR_DM_IPC_SEND_REQUEST_FAILED);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_002 end";
}

/**
 * @tc.name: AddProviderData_001
 * @tc.desc: AddProviderData function success
 * @tc.type: AddProviderData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, AddProviderData_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_001 start";

    FormShareMgr::GetInstance().shareInfo_.clear();

    std::string formName = "Form0200";
    std::string moduleName = "ModuleName0200";
    std::string bundleName = "Bundle0200";
    std::string abilityName = "Ability0200";
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName)
        .SetParam(Constants::PARAM_MODULE_NAME_KEY, moduleName)
        .SetElementName(bundleName, abilityName);

    WantParams wantParams;
    FormShareInfo info;
    info.formId = 1;
    info.formName = "form";
    info.bundleName = "form_bundle";
    info.moduleName = "form_module";
    info.abilityName = "form_ability";
    info.dimensionId = 1;
    info.formTempFlag = false;
    info.deviceId = "device";
    info.providerShareData = wantParams;
    auto key = FormShareMgr::GetInstance().MakeFormShareInfoKey(want);
    FormShareMgr::GetInstance().shareInfo_.emplace(key, info);

    FormShareMgr::GetInstance().AddProviderData(want, wantParams);
    auto result = wantParams.GetParam(Constants::PARAM_DEVICE_ID_KEY);
    IString *ao = IString::Query(result);
    if (ao != nullptr) {
        EXPECT_EQ(String::Unbox(ao), "device");
    }

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_001 end";
}

/**
 * @tc.name: AddProviderData_002
 * @tc.desc: AddProviderData function success
 * @tc.type: AddProviderData
 * @tc.require: Issue I5MDLJ
 */
HWTEST_F(FmsFormShareMgrTest, AddProviderData_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_002 start";

    FormShareMgr::GetInstance().shareInfo_.clear();

    std::string formName = "Form0200";
    std::string moduleName = "ModuleName0200";
    std::string bundleName = "Bundle0200";
    std::string abilityName = "Ability0200";
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName)
        .SetParam(Constants::PARAM_MODULE_NAME_KEY, moduleName)
        .SetElementName(bundleName, abilityName);

    WantParams wantParams;
    FormShareMgr::GetInstance().AddProviderData(want, wantParams);
    auto result = wantParams.GetParam(Constants::PARAM_DEVICE_ID_KEY);
    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_002 end";
}