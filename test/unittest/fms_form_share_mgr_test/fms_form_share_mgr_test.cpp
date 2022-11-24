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
#include "dm_constants.h"
#include "dm_device_info.h"
#define private public
#include "form_ams_helper.h"
#undef private
#include "form_bms_helper.h"
#include "form_db_cache.h"
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#define private public
#include "form_data_mgr.h"
#include "form_distributed_client.h"
#include "form_event_handler.h"
#include "form_info.h"
#include "form_info_mgr.h"
#include "form_mgr.h"
#include "form_share_mgr.h"
#undef private
#include "iremote_proxy.h"
#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_distributed_sched.h"
#include "mock_form_host_client.h"
#include "mock_form_provider_client.h"
#include "string_wrapper.h"
#include "want.h"

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

    MOCK_METHOD2(OnAcquired, void(const FormJsInfo &formInfo, const sptr<IRemoteObject> &token));
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
    DelayedSingleton<FormShareMgr>::GetInstance()->formDmsClient_ = std::make_shared<FormDistributedClient>();
    DelayedSingleton<FormShareMgr>::GetInstance()->formDmsClient_->SetDmsProxy(dmsSerice->AsObject());
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int32_t userId = 100;
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
    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.clear();
    DelayedSingleton<FormShareMgr>::GetInstance()->eventMap_.clear();
    DelayedSingleton<FormShareMgr>::GetInstance()->freeInstallOperatorMap_.clear();
}

/**
 * @tc.name: RecvFormShareInfoFromRemote_001
 * @tc.desc: Check form share info case.
 * @tc.type: RecvFormShareInfoFromRemote
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormShareMgrTest, RecvFormShareInfoFromRemote_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest RecvFormShareInfoFromRemote_001 start";
    auto runner = EventRunner::Create("FormMgrService");
    auto handler = std::make_shared<FormEventHandler>(runner);
    DelayedSingleton<FormShareMgr>::GetInstance()->SetEventHandler(handler);
    FormShareInfo info;
    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->RecvFormShareInfoFromRemote(info);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest RecvFormShareInfoFromRemote_001 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_001
 * @tc.desc: Check form share info case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: issueI581YL
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
    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.formName = "form";
    info.bundleName = "";
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.bundleName = "form_bundle";
    info.moduleName = "";
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.moduleName = "form_module";
    info.abilityName = "";
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.abilityName = "form_ability";
    info.dimensionId = -1;
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_EQ(result, ERR_OK);

    info.dimensionId = 1;
    info.deviceId = "";
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    info.deviceId = "device";
    result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_001 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_002
 * @tc.desc: Failed to Recv Form Share info.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: issueI581YL
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
    auto key = DelayedSingleton<FormShareMgr>::GetInstance()->MakeFormShareInfoKey(info);
    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.emplace(key, info);

    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.erase(key);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_002 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_003
 * @tc.desc: Free install success case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: issueI581YL
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

    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_EQ(result, ERR_OK);

    ClearFormShareMgrMapData();

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_003 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_004
 * @tc.desc: Free install success case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: issueI581YL
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

    auto key = DelayedSingleton<FormShareMgr>::GetInstance()->MakeFormShareInfoKey(info);
    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.emplace(key, info);

    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    ClearFormShareMgrMapData();

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_004 end";
}

/**
 * @tc.name: HandleRecvFormShareInfoFromRemoteTask_005
 * @tc.desc: Free install failed case.
 * @tc.type: HandleRecvFormShareInfoFromRemoteTask
 * @tc.require: issueI581YL
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

    auto key = DelayedSingleton<FormShareMgr>::GetInstance()->MakeFormShareInfoKey(info);
    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.emplace(key, info);

    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    EXPECT_NE(result, ERR_OK);

    testing::Mock::AllowLeak(bundleMgr_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleRecvFormShareInfoFromRemoteTask_005 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_001
 * @tc.desc: Share form success.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    int32_t result = DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(
        formInfo1.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_001  end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_002
 * @tc.desc: FormId invalid, share form failed.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    int32_t result = DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(
        formJsInfo.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    int64_t invalidFormId = -1;
    result = DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(
        invalidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_002 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_003
 * @tc.desc: FormId invalid, share form failed.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    int64_t invalidFormId = 123456789;
    int32_t result = DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(
        invalidFormId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_003 end";
}

/**
 * @tc.name: FmsFormShareMgrTest_ShareForm_004
 * @tc.desc: Share form success.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    int32_t result = DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(
        formJsInfo.formId, REMOTE_DEVICE_ID, nullptr, requestCode);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FmsFormShareMgrTest_ShareForm_004 end";
}

/**
 * @tc.name: AcquireShareFormData_001
 * @tc.desc: Acquire share form data success.
 * @tc.type: AcquireShareFormData
 * @tc.require: issueI581YL
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
    EXPECT_FALSE(mockClient->acquireShareFormState_);
    DelayedSingleton<FormShareMgr>::GetInstance()->AcquireShareFormData(
        UNKNOWN_FORM_ID, REMOTE_DEVICE_ID, want, mockClient);

    EXPECT_TRUE(mockClient->acquireShareFormState_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_001 end";
}

/**
 * @tc.name: AcquireShareFormData_002
 * @tc.desc: Acquire share form data success.
 * @tc.type: AcquireShareFormData
 * @tc.require: issueI581YL
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
    EXPECT_FALSE(mockClient->acquireShareFormState_);
    DelayedSingleton<FormShareMgr>::GetInstance()->AcquireShareFormData(0, REMOTE_DEVICE_ID, want, mockClient);

    EXPECT_TRUE(mockClient->acquireShareFormState_);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AcquireShareFormData_001 end";
}

/**
 * @tc.name: HandleProviderShareData_001
 * @tc.desc: Handle provider share data success.
 * @tc.type: HandleProviderShareData
 * @tc.require: issueI581YL
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
    auto hostCallback = [&testFlag](const int64_t requestCode, const int32_t result) { testFlag = true; };
    bool results = true;
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    DelayedSingleton<FormShareMgr>::GetInstance()->requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    DelayedSingleton<FormShareMgr>::GetInstance()->HandleProviderShareData(
        UNKNOWN_FORM_ID, REMOTE_DEVICE_ID, wantParams, requestCode, results);
    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_001 end";
}

/**
 * @tc.name: HandleProviderShareData_002
 * @tc.desc: Handle provider share data success.
 * @tc.type: HandleProviderShareData
 * @tc.require: issueI581YL
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
    auto hostCallback = [&testFlag](const int64_t requestCode, const int32_t result) { testFlag = true; };
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    DelayedSingleton<FormShareMgr>::GetInstance()->requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    bool results = true;
    DelayedSingleton<FormShareMgr>::GetInstance()->HandleProviderShareData(
        DIFF_FORM_ID, REMOTE_DEVICE_ID, wantParams, requestCode, results);

    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_002 end";
}

/**
 * @tc.name: HandleProviderShareData_003
 * @tc.desc: Handle provider share data success.
 * @tc.type: HandleProviderShareData
 * @tc.require: issueI581YL
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
    auto hostCallback = [&testFlag](const int64_t requestCode, const int32_t result) { testFlag = true; };
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    DelayedSingleton<FormShareMgr>::GetInstance()->requestMap_.emplace(requestCode, mockHost);
    EXPECT_CALL(*mockHost, OnShareFormResponse(_, _)).Times(1).WillOnce(Invoke(hostCallback));
    bool results = true;
    DelayedSingleton<FormShareMgr>::GetInstance()->HandleProviderShareData(
        formJsInfo.formId, REMOTE_DEVICE_ID, wantParams, requestCode, results);

    EXPECT_TRUE(testFlag);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest HandleProviderShareData_003 end";
}

/**
 * @tc.name: ShareForm_001
 * @tc.desc: FormId invalid, share form failed.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    int64_t invalidFormId = 0;
    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    int32_t result = FormMgr::GetInstance().ShareForm(invalidFormId, REMOTE_DEVICE_ID, mockHost, requestCode);
    EXPECT_NE(result, ERR_OK);

    invalidFormId = -1;
    result = FormMgr::GetInstance().ShareForm(invalidFormId, REMOTE_DEVICE_ID, mockHost, requestCode);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_001  end";
}

/**
 * @tc.name: ShareForm_002
 * @tc.desc: DeviceId is empty, share form failed.
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
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

    sptr<MockFormHostCallback> mockHost = new (std::nothrow) MockFormHostCallback();
    int32_t result = FormMgr::GetInstance().ShareForm(formJsInfo.formId, "", mockHost, requestCode);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrAddFormTest ShareForm_002 end";
}

/**
 * @tc.name: GetLocalDeviceInfo_001
 * @tc.desc: Verify that the local device is successfully obtained.
 * @tc.type: GetLocalDeviceInfo
 * @tc.require: issueI581YL
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
    auto result =
        DelayedSingleton<FormShareMgr>::GetInstance()->GetLocalDeviceInfo(FORM_PROVIDER_BUNDLE_NAME, deviceInfo);
    EXPECT_EQ(result, ERR_OK);
    std::string deviceId(deviceInfo.deviceId);
    EXPECT_FALSE(deviceId.empty());

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_001 end";
}

/**
 * @tc.name: GetLocalDeviceInfo_002
 * @tc.desc: BundleName is empty, get local device info failed.
 * @tc.type: GetLocalDeviceInfo
 * @tc.require: issueI581YL
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
    auto result = DelayedSingleton<FormShareMgr>::GetInstance()->GetLocalDeviceInfo(FORM_NULL_BUNDLE_NAME, deviceInfo);
    EXPECT_EQ(result, DistributedHardware::ERR_DM_IPC_SEND_REQUEST_FAILED);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest GetLocalDeviceInfo_002 end";
}

/**
 * @tc.name: AddProviderData_001
 * @tc.desc: Add provider data success.
 * @tc.type: AddProviderData
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormShareMgrTest, AddProviderData_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_001 start";

    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.clear();

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
    auto key = DelayedSingleton<FormShareMgr>::GetInstance()->MakeFormShareInfoKey(want);
    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.emplace(key, info);

    DelayedSingleton<FormShareMgr>::GetInstance()->AddProviderData(want, wantParams);
    auto result = wantParams.GetParam(Constants::PARAM_DEVICE_ID_KEY);
    IString *ao = IString::Query(result);
    if (ao != nullptr) {
        EXPECT_EQ(String::Unbox(ao), "device");
    }

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_001 end";
}

/**
 * @tc.name: AddProviderData_002
 * @tc.desc: Verify that deviceId does not exist.
 * @tc.type: AddProviderData
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormShareMgrTest, AddProviderData_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_002 start";

    DelayedSingleton<FormShareMgr>::GetInstance()->shareInfo_.clear();

    std::string formName = "Form0200";
    std::string moduleName = "ModuleName0200";
    std::string bundleName = "Bundle0200";
    std::string abilityName = "Ability0200";
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName)
        .SetParam(Constants::PARAM_MODULE_NAME_KEY, moduleName)
        .SetElementName(bundleName, abilityName);

    WantParams wantParams;
    DelayedSingleton<FormShareMgr>::GetInstance()->AddProviderData(want, wantParams);
    auto result = wantParams.GetParam(Constants::PARAM_DEVICE_ID_KEY);
    EXPECT_EQ(result, nullptr);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest AddProviderData_002 end";
}

/**
 * @tc.name: FormInfoHelper_001
 * @tc.desc: test LoadFormConfigInfoByBundleName function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_001 start";

    FormInfoHelper formInfoHelper;
    std::string bundleName = "";
    std::vector<FormInfo> formInfos;
    int32_t userId = 2;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formInfoHelper.LoadFormConfigInfoByBundleName(bundleName, formInfos, userId));

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_001 end";
}

/**
 * @tc.name: FormInfoHelper_002
 * @tc.desc: test UpdateStaticFormInfos function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_002 start";

    std::string bundleName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.UpdateStaticFormInfos(userId));

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_002 end";
}

/**
 * @tc.name: FormInfoHelper_003
 * @tc.desc: test UpdateStaticFormInfos function and item->userId != userId.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_003 start";

    std::string bundleName = "aaa";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    std::vector<AAFwk::FormInfoStorage> formInfoStorages_;
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);

    bundleFormInfo.UpdateStaticFormInfos(userId);

    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_003 end";
}

/**
 * @tc.name: FormInfoHelper_004
 * @tc.desc: test Remove function formInfoStorages_ is nullptr.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_004 start";
    std::string bundleName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.Remove(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_004 end";
}

/**
 * @tc.name: FormInfoHelper_005
 * @tc.desc: test Remove function formInfoStorages_ is not nullptr.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_005 start";
    std::string bundleName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    std::vector<AAFwk::FormInfoStorage> formInfoStorages_;
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.Remove(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_005 end";
}

/**
 * @tc.name: FormInfoHelper_006
 * @tc.desc: test Remove function and userId is 100.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_006 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
    std::vector<AAFwk::FormInfoStorage> formInfoStorages_;
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.Remove(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_006 end";
}

/**
 * @tc.name: FormInfoHelper_007
 * @tc.desc: test AddDynamicFormInfo function formInfoStorages_ is nullptr.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_007 start";
    std::string bundleName = "";
    int32_t userId = 2;
    FormInfo formInfo;
    BundleFormInfo bundleFormInfo(bundleName);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfo, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_007 end";
}

/**
 * @tc.name: FormInfoHelper_008
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_008 start";
    std::string bundleName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfo, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_008 end";
}

/**
 * @tc.name: FormInfoHelper_009
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_009 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfo, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_009 end";
}

/**
 * @tc.name: FormInfoHelper_010
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_010 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
    FormInfo formInfo;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfo, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_010 end";
}

/**
 * @tc.name: FormInfoHelper_011
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_011 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfo formInfoll;
    formInfoll.name = "aaaa";
    formInfoll.moduleName = "bbbbb";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfoll, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_011 end";
}

/**
 * @tc.name: FormInfoHelper_012
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_012 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfo formInfoll;
    formInfoll.name = PARAM_FORM_NAME;
    formInfoll.moduleName = "bbbbb";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfoll, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_012 end";
}

/**
 * @tc.name: FormInfoHelper_013
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_013 start";
    std::string bundleName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoStorage formInfoStorageOne;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorageOne);
    FormInfoStorage formInfoStorageTwo;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorageTwo);
    FormInfo formInfoll;
    formInfoll.name = "aaaa";
    formInfoll.moduleName = PARAM_PROVIDER_MODULE_NAME;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.AddDynamicFormInfo(formInfoll, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_013 end";
}

/**
 * @tc.name: FormInfoHelper_014
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_014 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_014 end";
}

/**
 * @tc.name: FormInfoHelper_015
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_015 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = "";
    int32_t userId = 2;
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
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_015 end";
}

/**
 * @tc.name: FormInfoHelper_016
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_016 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_016 end";
}

/**
 * @tc.name: FormInfoHelper_017
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_017 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
    FormInfo formInfo;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_017 end";
}

/**
 * @tc.name: FormInfoHelper_018
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_018 start";
    std::string bundleName = "";
    std::string moduleName = PARAM_PROVIDER_MODULE_NAME;
    std::string formName = PARAM_FORM_NAME;
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_018 end";
}

/**
 * @tc.name: FormInfoHelper_019
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_019 start";
    std::string bundleName = "";
    std::string moduleName = PARAM_PROVIDER_MODULE_NAME;
    std::string formName = "";
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_019 end";
}

/**
 * @tc.name: FormInfoHelper_020
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_020 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = PARAM_FORM_NAME;
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_020 end";
}

/**
 * @tc.name: FormInfoHelper_021
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_021 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = PARAM_FORM_NAME;
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoStorage formInfoStorageOne;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorageOne);
    FormInfoStorage formInfoStorageTwo;
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorageTwo);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_021 end";
}

/**
 * @tc.name: FormInfoHelper_022
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_022 start";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = PARAM_FORM_NAME;
    int32_t userId = 100;
    BundleFormInfo bundleFormInfo(bundleName);
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
    FormInfo formInfoOne;
    formInfoStorage.formInfos.push_back(formInfoOne);
    FormInfo formInfoTwo;
    formInfoStorage.formInfos.push_back(formInfoTwo);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_022 end";
}

/**
 * @tc.name: FormInfoHelper_023
 * @tc.desc: test RemoveAllDynamicFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_023 start";
    std::string bundleName = "";
    int32_t userId = 2;
    BundleFormInfo bundleFormInfo(bundleName);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveAllDynamicFormsInfo(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_023 end";
}

/**
 * @tc.name: FormInfoHelper_024
 * @tc.desc: test RemoveAllDynamicFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_024 start";
    std::string bundleName = "";
    int32_t userId = 2;
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
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveAllDynamicFormsInfo(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_024 end";
}

/**
 * @tc.name: FormInfoHelper_025
 * @tc.desc: test RemoveAllDynamicFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_025 start";
    std::string bundleName = "";
    int32_t userId = 100;
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
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveAllDynamicFormsInfo(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_025 end";
}

/**
 * @tc.name: FormInfoHelper_026
 * @tc.desc: test RemoveAllDynamicFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_026 start";
    std::string bundleName = "";
    int32_t userId = 100;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfo.RemoveAllDynamicFormsInfo(userId);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_026 end";
}

/**
 * @tc.name: FormInfoHelper_027
 * @tc.desc: test RemoveAllDynamicFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_027 start";
    std::string bundleName = "";
    int32_t userId = 100;
    FormInfoStorage formInfoStorage;
    FormInfo formInfo;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(formInfo);
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveAllDynamicFormsInfo(userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_027 end";
}

/**
 * @tc.name: FormInfoHelper_028
 * @tc.desc: test UpdateFormInfoStorageLocked function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_028 start";
    std::string bundleName = "";
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
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfo.UpdateFormInfoStorageLocked();
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_028 end";
}

/**
 * @tc.name: FormInfoHelper_029
 * @tc.desc: test UpdateStaticFormInfos function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_029 start";
    std::string bundleName = "";
    int32_t userId = 1;
    BundleFormInfo bundleFormInfo(bundleName);
    FormInfoMgr formInfoMgr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formInfoMgr.UpdateStaticFormInfos(bundleName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_029 end";
}

/**
 * @tc.name: FormInfoHelper_030
 * @tc.desc: test UpdateStaticFormInfos function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_030 start";
    std::string bundleName = "";
    std::string bundleNames = "aa";
    int32_t userId = 1;
    BundleFormInfo bundleFormInfo(bundleName);
    FormInfoMgr formInfoMgr;
    EXPECT_EQ(ERR_OK, formInfoMgr.UpdateStaticFormInfos(bundleNames, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_030 end";
}

/**
 * @tc.name: FormInfoHelper_031
 * @tc.desc: test Remove function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_031 start";
    std::string bundleName = "";
    int32_t userId = 1;
    FormInfoMgr formInfoMgr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formInfoMgr.Remove(bundleName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_031 end";
}

/**
 * @tc.name: FormInfoHelper_032
 * @tc.desc: test Remove function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_032 start";
    std::string bundleName = FORM_PROVIDER_BUNDLE_NAME;
    int32_t userId = 1;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = std::make_shared<BundleFormInfo>("");
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
    bundleFormInfoMap.emplace("aa", bundleFormInfo);
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formInfoMgr.Remove(bundleName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_032 end";
}

/**
 * @tc.name: FormInfoHelper_033
 * @tc.desc: test Remove function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_033 start";
    std::string bundleName = FORM_PROVIDER_BUNDLE_NAME;
    int32_t userId = 1;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = nullptr;
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);
    bundleFormInfoMap.emplace("aa", bundleFormInfo);
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    EXPECT_EQ(ERR_OK, formInfoMgr.Remove(bundleName, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_033 end";
}

/**
 * @tc.name: FormInfoHelper_034
 * @tc.desc: test GetAllFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_034 start";
    std::vector<FormInfo> formInfos;
    FormInfoMgr formInfoMgr;
    EXPECT_EQ(ERR_OK, formInfoMgr.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_034 end";
}

/**
 * @tc.name: FormInfoHelper_035
 * @tc.desc: test GetAllFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_035 start";
    std::vector<FormInfo> formInfos;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = std::make_shared<BundleFormInfo>("");
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
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    EXPECT_EQ(ERR_OK, formInfoMgr.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_035 end";
}

/**
 * @tc.name: FormInfoHelper_036
 * @tc.desc: test GetAllFormsInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_036 start";
    std::vector<FormInfo> formInfos;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = nullptr;
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    EXPECT_EQ(ERR_OK, formInfoMgr.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_036 end";
}

/**
 * @tc.name: FormInfoHelper_037
 * @tc.desc: test GetFormsInfoByBundle function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_037 start";
    FormInfoMgr formInfoMgr;
    std::string bundleName = "";
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_037 end";
}

/**
 * @tc.name: FormInfoHelper_038
 * @tc.desc: test GetFormsInfoByBundle function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_038 start";
    FormInfoMgr formInfoMgr;
    std::string bundleName = "aaa";
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_038 end";
}

/**
 * @tc.name: FormInfoHelper_039
 * @tc.desc: test GetFormsInfoByModule function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_039 start";
    FormInfoMgr formInfoMgr;
    std::string bundleName = "";
    std::string moduleName = "";
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_039 end";
}

/**
 * @tc.name: FormInfoHelper_040
 * @tc.desc: test GetFormsInfoByModule function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_040 start";
    FormInfoMgr formInfoMgr;
    std::string bundleName = "aaa";
    std::string moduleName = "";
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_040 end";
}

/**
 * @tc.name: FormInfoHelper_041
 * @tc.desc: test GetFormsInfoByModule function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_041 start";
    std::string bundleName = FORM_PROVIDER_BUNDLE_NAME;
    std::string moduleName = "";
    std::vector<FormInfo> formInfos;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = nullptr;
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    EXPECT_EQ(ERR_OK, formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_041 end";
}

/**
 * @tc.name: FormInfoHelper_042
 * @tc.desc: test CheckDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_042 start";
    FormInfoMgr formInfoMgr;
    FormInfo formInfo;
    BundleInfo bundleInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NO_SUCH_MODULE, formInfoMgr.CheckDynamicFormInfo(formInfo, bundleInfo));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_042 end";
}

/**
 * @tc.name: FormInfoHelper_043
 * @tc.desc: test CheckDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_043 start";
    FormInfoMgr formInfoMgr;
    FormInfo formInfo;
    formInfo.moduleName = "entry";
    HapModuleInfo info;
    info.name = "com.ohos.contactsdataability";
    info.moduleName = "entry";
    info.description = "dataability_description";
    info.iconPath = "$media:icon";
    info.deviceTypes = {"smartVision"};
    info.bundleName = "com.ohos.contactsdataability";
    BundleInfo bundleInfo;
    bundleInfo.hapModuleInfos.push_back(info);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY, formInfoMgr.CheckDynamicFormInfo(formInfo, bundleInfo));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_043 end";
}

/**
 * @tc.name: FormInfoHelper_044
 * @tc.desc: test CheckDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_044 start";
    FormInfoMgr formInfoMgr;
    FormInfo formInfo;
    formInfo.moduleName = "";
    HapModuleInfo info;
    info.name = "com.ohos.contactsdataability";
    info.moduleName = "entry";
    info.description = "dataability_description";
    info.iconPath = "$media:icon";
    info.deviceTypes = {"smartVision"};
    info.bundleName = "com.ohos.contactsdataability";
    BundleInfo bundleInfo;
    bundleInfo.hapModuleInfos.push_back(info);
    HapModuleInfo infos;
    bundleInfo.hapModuleInfos.push_back(infos);
    HapModuleInfo infoed;
    bundleInfo.hapModuleInfos.push_back(infoed);
    formInfoMgr.CheckDynamicFormInfo(formInfo, bundleInfo);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_044 end";
}

/**
 * @tc.name: FormInfoHelper_045
 * @tc.desc: test AddDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_045 start";
    FormInfoMgr formInfoMgr;
    FormInfo formInfo;
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_INFO_FAILED, formInfoMgr.AddDynamicFormInfo(formInfo, userId));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_045 end";
}

/**
 * @tc.name: FormInfoHelper_046
 * @tc.desc: test RemoveDynamicFormInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_046 start";
    FormInfoMgr formInfoMgr;
    std::string bundleName = "";
    std::string moduleName = "";
    std::string formName = "";
    int32_t userId = 1;
    formInfoMgr.RemoveDynamicFormInfo(bundleName, moduleName, formName, userId);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_046 end";
}

/**
 * @tc.name: FormInfoHelper_047
 * @tc.desc: test GetOrCreateBundleFromInfo function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_047 start";
    std::string bundleName = FORM_PROVIDER_BUNDLE_NAME;
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = nullptr;
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);
    FormInfoMgr formInfoMgr;
    formInfoMgr.bundleFormInfoMap_ = bundleFormInfoMap;
    formInfoMgr.GetOrCreateBundleFromInfo(bundleName);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_047 end";
}

/**
 * @tc.name: FormInfoHelper_048
 * @tc.desc: test IsCaller function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_048 start";
    std::string bundleName = FORM_PROVIDER_BUNDLE_NAME;
    FormInfoMgr formInfoMgr;
    EXPECT_EQ(false, formInfoMgr.IsCaller(bundleName));
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_048 end";
}

/**
 * @tc.name: FormInfoHelper_049
 * @tc.desc: test ReloadFormInfos function.
 * @tc.type: FormInfoHelper
 */
HWTEST_F(FmsFormShareMgrTest, FormInfoHelper_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_049 start";
    int32_t userId = 1;
    FormInfoMgr formInfoMgr;
    formInfoMgr.ReloadFormInfos(userId);
    GTEST_LOG_(INFO) << "FmsFormShareMgrTest FormInfoHelper_049 end";
}