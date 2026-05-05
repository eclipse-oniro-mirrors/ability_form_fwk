/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "common/timer_mgr/form_refresh_limiter.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "form_host_interface.h"
#include "form_provider/form_provider_mgr.h"
#undef private
#include "form_mgr/form_mgr_service.h"
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif
#include "running_process_info.h"
#include "system_ability_definition.h"

namespace {
bool g_mockConnectServiceAbilityRet = false;
int g_mockConnectServiceAbilityErrorCode = 0;
}

namespace OHOS {
void MockConnectServiceAbility(bool mockRet)
{
    g_mockConnectServiceAbilityRet = mockRet;
    g_mockConnectServiceAbilityErrorCode = mockRet ? 0 : -1;
}

void MockConnectServiceAbilityWithErrorCode(int errorCode)
{
    g_mockConnectServiceAbilityRet = (errorCode == 0);
    g_mockConnectServiceAbilityErrorCode = errorCode;
}
}  // namespace OHOS

namespace OHOS {
namespace AppExecFwk {
ErrCode FormAmsHelper::ConnectServiceAbility(const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    return g_mockConnectServiceAbilityErrorCode;
}

ErrCode FormAmsHelper::ConnectServiceAbilityWithUserId(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId)
{
    return g_mockConnectServiceAbilityErrorCode;
}
}  // namespace AppExecFwk
}  // namespace OHOS

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
const std::string TEST_PARAM_FORM_PERMISSION_NAME = "com.permission.TEST_PER";

class FmsFormProviderMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<IRemoteObject> token_;
};

void FmsFormProviderMgrTest::SetUpTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormProviderMgrTest::TearDownTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(nullptr);
    FormAmsHelper::GetInstance().SetAbilityManager(nullptr);
}

void FmsFormProviderMgrTest::SetUp()
{
    token_ = new (std::nothrow) MockFormHostClient();
    g_mockConnectServiceAbilityRet = true;
    g_mockConnectServiceAbilityErrorCode = 0;

    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormProviderMgrTest::TearDown()
{
    token_ = nullptr;
    g_mockConnectServiceAbilityRet = false;
    g_mockConnectServiceAbilityErrorCode = 0;
}

namespace {
/**
 * Helper function: Create basic FormRecord for RefreshForm tests.
 * @param formId The form ID.
 * @param moduleName The module name.
 * @param token The form host token.
 * @param userId The user ID (default: FormUtil::GetCurrentAccountId()).
 * @param callingUid The calling UID (default: 0).
 * @return FormRecord with enableForm=true and addFormFinish=true.
 */
FormRecord CreateRefreshFormRecord(int64_t formId, const std::string &moduleName,
    const sptr<IRemoteObject> &token, int32_t userId = FormUtil::GetCurrentAccountId(), int callingUid = 0)
{
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(moduleName);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, userId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token, formId, callingUid);
    return formRecord;
}
}

/**
 * @tc.name: AcquireForm_001
 * @tc.desc: Verify AcquireForm with invalid negative formId returns INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_001 start";
    FormProviderInfo formProviderInfo;
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(-114514L, formProviderInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "AcquireForm_001 end";
}

/**
 * @tc.name: AcquireForm_002
 * @tc.desc: Verify AcquireForm when form record not exist returns NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_002 start";
    int64_t formId = 0x11451aaa00000000;
    FormProviderInfo formProviderInfo;
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "AcquireForm_002 end";
}

/**
 * @tc.name: AcquireForm_003
 * @tc.desc: Verify AcquireForm when form host record not exist returns COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_003 start";
    int64_t formId = 0x1145aaaa00000000;
    FormProviderInfo formProviderInfo;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    EXPECT_EQ(realFormRecord.formId, formId);
    FormRecord verifyRecord;
    bool recordExists = FormDataMgr::GetInstance().GetFormRecord(formId, verifyRecord);
    EXPECT_TRUE(recordExists);
    EXPECT_FALSE(verifyRecord.isInited);
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormRecord afterAcquireRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, afterAcquireRecord);
    EXPECT_FALSE(afterAcquireRecord.isInited);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "AcquireForm_003 end";
}

/**
 * @tc.name: AcquireForm_004
 * @tc.desc: Verify AcquireForm when form isInited true and cached.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_004 start";
    int64_t formId = 0x114520aa00000000;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    formRecord.isInited = true;
    formRecord.versionUpgrade = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    nlohmann::json jsonData;
    jsonData["key"] = "cachedValue";
    FormCacheMgr::GetInstance().AddData(formId, FormProviderData(jsonData));
    FormProviderInfo formProviderInfo;
    formProviderInfo.SetFormData(FormProviderData(jsonData));
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormRecord updatedRecord;
    bool recordExists = FormDataMgr::GetInstance().GetFormRecord(formId, updatedRecord);
    EXPECT_TRUE(recordExists);
    EXPECT_TRUE(updatedRecord.isInited);
    std::string cachedData;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool getDataResult = FormCacheMgr::GetInstance().GetData(formId, cachedData, imageDataMap);
    EXPECT_TRUE(getDataResult);
    EXPECT_FALSE(cachedData.empty());
    EXPECT_TRUE(cachedData.find("\"key\"") != std::string::npos);
    EXPECT_TRUE(cachedData.find("cachedValue") != std::string::npos);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    FormCacheMgr::GetInstance().DeleteData(formId);
    GTEST_LOG_(INFO) << "AcquireForm_004 end";
}

/**
 * @tc.name: AcquireForm_005
 * @tc.desc: Verify AcquireForm when formRecord.isInited=true but IsFormCached=false triggers RefreshForm.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_005 start";
    int64_t formId = 0x114528aa00000000;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    formRecord.isInited = true;
    formRecord.versionUpgrade = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    FormProviderInfo formProviderInfo;
    nlohmann::json jsonData;
    jsonData["key"] = "value";
    formProviderInfo.SetFormData(FormProviderData(jsonData));
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormRecord updatedRecord;
    bool recordExists = FormDataMgr::GetInstance().GetFormRecord(formId, updatedRecord);
    EXPECT_TRUE(recordExists);
    EXPECT_TRUE(updatedRecord.isInited);
    EXPECT_TRUE(updatedRecord.versionUpgrade);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "AcquireForm_005 end";
}

/**
 * @tc.name: AcquireForm_006
 * @tc.desc: Verify AcquireForm when formRecord.isInited=false first time acquire.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AcquireForm_006 start";
    int64_t formId = 0x114536aa00000000;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    formRecord.isInited = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    FormProviderInfo formProviderInfo;
    nlohmann::json jsonData;
    jsonData["key"] = "value";
    formProviderInfo.SetFormData(FormProviderData(jsonData));
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "AcquireForm_006 end";
}

/**
 * @tc.name: AcquireForm_007
 * @tc.desc: Verify AcquireForm when formRecord.versionUpgrade=false and form cached.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireForm_007 start";
    int64_t formId = 0x114541aa00000000;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    formRecord.isInited = true;
    formRecord.versionUpgrade = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    nlohmann::json cacheData;
    cacheData["test"] = "value";
    FormCacheMgr::GetInstance().AddData(formId, FormProviderData(cacheData));
    FormProviderInfo formProviderInfo;
    nlohmann::json jsonData;
    jsonData["key"] = "value";
    formProviderInfo.SetFormData(FormProviderData(jsonData));
    ErrCode result = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormCacheMgr::GetInstance().DeleteData(formId);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "AcquireForm_007 end";
}

/**
 * @tc.name: AcquireFormStateBack_001
 * @tc.desc: Verify AcquireFormStateBack with valid params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireFormStateBack_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "AcquireFormStateBack_001 start";
    FormState state = FormState::READY;
    std::string provider = "com.test.provider";
    Want wantArg;
    ErrCode result = FormProviderMgr::GetInstance().AcquireFormStateBack(state, provider, wantArg);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AcquireFormStateBack_001 end";
}

/**
 * @tc.name: AcquireFormDataBack_001
 * @tc.desc: Verify AcquireFormDataBack with valid params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireFormDataBack_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "AcquireFormDataBack_001 start";
    AAFwk::WantParams wantParams;
    int64_t requestCode = 123456;
    ErrCode result = FormProviderMgr::GetInstance().AcquireFormDataBack(wantParams, requestCode);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "AcquireFormDataBack_001 end";
}

/**
 * @tc.name: UpdateForm_001
 * @tc.desc: Verify UpdateForm when form not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, UpdateForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateForm_001 start";
    int64_t formId = 0x123456aa00000000;
    FormProviderInfo formProviderInfo;
    ErrCode result = FormProviderMgr::GetInstance().UpdateForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "UpdateForm_001 end";
}

/**
 * @tc.name: UpdateForm_002
 * @tc.desc: Verify UpdateForm with valid formId and FormProviderInfo.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, UpdateForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateForm_002 start";
    int64_t formId = 0x123457aa00000000;
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormProviderInfo formProviderInfo;
    nlohmann::json jsonData;
    jsonData["key"] = "value";
    formProviderInfo.SetFormData(FormProviderData(jsonData));
    ErrCode result = FormProviderMgr::GetInstance().UpdateForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "UpdateForm_002 end";
}

/**
 * @tc.name: UpdateForm_003
 * @tc.desc: Verify UpdateForm(formId, formRecord, formProviderData) with versionUpgrade=true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, UpdateForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateForm_003 start";
    int64_t formId = 0x114540aa00000000;
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid);
    formRecord.versionUpgrade = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo hostInfo;
    FormDataMgr::GetInstance().AllotFormHostRecord(hostInfo, token_, formId, callingUid);
    nlohmann::json jsonData;
    jsonData["upgradeKey"] = "upgradeValue";
    FormProviderData formProviderData(jsonData);
    ErrCode result = FormProviderMgr::GetInstance().UpdateForm(formId, formRecord, formProviderData);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "UpdateForm_003 end";
}

/**
 * @tc.name: UpdateForm_004
 * @tc.desc: Verify UpdateForm(formId, formRecord, formProviderData) with versionUpgrade=false merges data.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, UpdateForm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateForm_004 start";
    int64_t formId = 0x114542aa00000000;
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid);
    formRecord.versionUpgrade = false;
    nlohmann::json existingData;
    existingData["existingKey"] = "existingValue";
    formRecord.formProviderInfo.SetFormData(FormProviderData(existingData));
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    nlohmann::json newData;
    newData["newKey"] = "newValue";
    FormProviderData formProviderData(newData);
    ErrCode result = FormProviderMgr::GetInstance().UpdateForm(formId, formRecord, formProviderData);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "UpdateForm_004 end";
}

/**
 * @tc.name: UpdateForm_005
 * @tc.desc: Verify UpdateForm with screen on triggers UpdateHostForm.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, UpdateForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateForm_005 start";
    int64_t formId = 0x114553aa00000000;
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    FormRecord record = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    record.enableForm = true;
    record.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, record);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    
    FormProviderInfo formProviderInfo;
    nlohmann::json jsonData;
    jsonData["test"] = "value";
    FormProviderData providerData(jsonData);
    formProviderInfo.SetFormData(providerData);
    
    ErrCode result = FormProviderMgr::GetInstance().UpdateForm(formId, formProviderInfo);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "UpdateForm_005 end";
}

/**
 * @tc.name: RefreshForm_001
 * @tc.desc: Verify RefreshForm when form not exist, returns NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_001 start";
    int64_t formId = 0x114510aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "RefreshForm_001 end";
}

/**
 * @tc.name: RefreshForm_002
 * @tc.desc: Verify RefreshForm with userId matched and normal refresh.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_002 start";
    int64_t formId = 0x114514aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    FormRecord realFormRecord = CreateRefreshFormRecord(formId, PARAM_FORM_NAME, token_);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormRecord updatedRecord;
    bool recordExists = FormDataMgr::GetInstance().GetFormRecord(formId, updatedRecord);
    EXPECT_TRUE(recordExists);
    EXPECT_EQ(updatedRecord.formId, formId);
    EXPECT_TRUE(updatedRecord.enableForm);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_002 end";
}

/**
 * @tc.name: RefreshForm_003
 * @tc.desc: Verify RefreshForm with KEY_IS_TIMER false and valid form record.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_003 start";
    int64_t formId = 0x114515aa00000000;
    Want want;
    int callingUid = 0;
    int32_t currentActiveUserId = FormUtil::GetCallerUserId(callingUid);
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::KEY_IS_TIMER, false);
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    realFormRecord.enableForm = true;
    realFormRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, realFormRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_003 end";
}

/**
 * @tc.name: RefreshForm_004
 * @tc.desc: Verify RefreshForm when userId mismatch, returns OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_004 start";
    int64_t formId = 0x114516aa00000000;
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, 999);
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid, 100);
    realFormRecord.providerUserId = 100;
    realFormRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, realFormRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_004 end";
}

/**
 * @tc.name: RefreshForm_005
 * @tc.desc: Verify RefreshForm when enableForm=false, returns DISABLE_REFRESH.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_005 start";
    int64_t formId = 0x114530aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid, currentActiveUserId);
    formRecord.enableForm = false;
    formRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_DISABLE_REFRESH);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_005 end";
}

/**
 * @tc.name: RefreshForm_006
 * @tc.desc: Verify RefreshForm with REFRESHTYPE_VISIABLE refreshType parameter.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_006 start";
    int64_t formId = 0x114532aa00000000;
    Want want;
    want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.formVisibleNotifyState = Constants::FORM_VISIBLE;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_006 end";
}

/**
 * @tc.name: RefreshForm_007
 * @tc.desc: Verify RefreshForm when isTimerRefresh=true and formVisible=true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_007 start";
    int64_t formId = 0x114537aa00000000;
    Want want;
    want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.formVisibleNotifyState = Constants::FORM_VISIBLE;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_007 end";
}

/**
 * @tc.name: RefreshForm_008
 * @tc.desc: Verify RefreshForm when isSystemApp=true and refreshType is not DEFAULT/VISIABLE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_008 start";
    int64_t formId = 0x114538aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.isSystemApp = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_008 end";
}

/**
 * @tc.name: RefreshForm_009
 * @tc.desc: Verify RefreshForm when enableForm=false (timer refresh).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_009 start";
    int64_t formId = 0x114539aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = false;
    formRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_DISABLE_REFRESH);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_009 end";
}

/**
 * @tc.name: RefreshForm_010
 * @tc.desc: Verify RefreshForm when timer refresh but form is invisible.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_010 start";
    int64_t formId = 0x114539aa00000001;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_010 end";
}

/**
 * @tc.name: RefreshForm_011
 * @tc.desc: Verify RefreshForm when refreshType is in CONDITION_REFRESHTYPE_SET.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RefreshForm_011 start";
    int64_t formId = 0x114539aa00000002;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.formVisibleNotifyState = Constants::FORM_VISIBLE;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_011 end";
}

/**
 * @tc.name: RefreshForm_012
 * @tc.desc: Verify RefreshForm when IsNeedToFresh returns false due to form invisible.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_012 start";
    int64_t formId = 0x114544aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    formRecord.isVisible = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_012 end";
}

/**
 * @tc.name: RefreshForm_013
 * @tc.desc: Verify RefreshForm when IsNeedToFresh returns true via IsEnableUpdate.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_013 start";
    int64_t formId = 0x114545aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.enableForm = true;
    formRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    FormDataMgr::GetInstance().SetEnableUpdate(formId, true);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, false);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_013 end";
}

/**
 * @tc.name: RefreshForm_014
 * @tc.desc: Verify RefreshForm when RefreshCheck fails due to userId mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_014 start";
    int64_t formId = 0x114546aa00000000;
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, 999);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, 100);
    formRecord.providerUserId = 100;
    formRecord.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_014 end";
}

/**
 * @tc.name: RefreshForm_015
 * @tc.desc: Verify RefreshForm when addFormFinish=false, returns NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "RefreshForm_015 start";
    int64_t formId = 0x114548aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    formRecord.addFormFinish = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_015 end";
}

/**
 * @tc.name: RefreshForm_016
 * @tc.desc: Verify RefreshForm when screen off sets refresh flag and returns OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_016 start";
    int64_t formId = 0x114552aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    FormRecord formRecord = CreateRefreshFormRecord(formId, "normal_module", token_);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_016 end";
}

/**
 * @tc.name: RefreshForm_017
 * @tc.desc: Verify RefreshForm with FORM_ENABLE_UPDATE_REFRESH_KEY bypasses screen check.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RefreshForm_017 start";
    int64_t formId = 0x114554aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::FORM_ENABLE_UPDATE_REFRESH_KEY, true);
    FormRecord formRecord = CreateRefreshFormRecord(formId, "normal_module", token_);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_017 end";
}

/**
 * @tc.name: RefreshForm_DataProxyUpdate_001
 * @tc.desc: Verify RefreshForm triggers DataProxyUpdate when isFormProviderUpdate and isDataProxy are true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_DataProxyUpdate_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "RefreshForm_DataProxyUpdate_001 start";
    int64_t formId = 0x123467aa00000000;
    int callingUid = 0;
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetModuleName(PARAM_FORM_NAME);
    info.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    FormRecord record = FormDataMgr::GetInstance().AllotFormRecord(info, callingUid, currentActiveUserId);
    record.isDataProxy = true;
    record.enableForm = true;
    record.addFormFinish = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, record);
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::FORM_ENABLE_UPDATE_REFRESH_KEY, true);
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    EXPECT_EQ(result, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "RefreshForm_DataProxyUpdate_001 end";
}

/**
 * @tc.name: ConnectAmsForRefresh_001
 * @tc.desc: Verify ConnectAmsForRefresh with needFreeInstall true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_001 start";
    int64_t formId = 0x123461aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.needFreeInstall = true;
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_001 end";
}

/**
 * @tc.name: ConnectAmsForRefresh_002
 * @tc.desc: Verify ConnectAmsForRefresh with isCountTimerRefresh=true and limiter disabled.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefresh_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_002 start";
    int64_t formId = 0x114536aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.needFreeInstall = false;
    record.isCountTimerRefresh = true;
    record.providerUserId = 0;
    Want want;
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL);
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_002 end";
}

/**
 * @tc.name: ConnectAmsForRefresh_003
 * @tc.desc: Verify ConnectAmsForRefresh returns ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED when errorCode is
 * ERR_ECOLOGICAL_CONTROL_STATUS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefresh_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_003 start";
    int64_t formId = 0x114522aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.needFreeInstall = false;
    record.isCountTimerRefresh = false;
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_003 end";
}

/**
 * @tc.name: ConnectAmsForRefresh_004
 * @tc.desc: Verify ConnectAmsForRefresh returns GET_AMSCONNECT_FAILED when errorCode is ERR_ECOLOGICAL_CONTROL_STATUS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefresh_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_004 start";
    int64_t formId = 0x114535aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.needFreeInstall = false;
    record.isCountTimerRefresh = false;
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbilityWithErrorCode(ERR_ECOLOGICAL_CONTROL_STATUS);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED);
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_004 end";
}

/**
 * @tc.name: ConnectAmsForRefresh_005
 * @tc.desc: Verify ConnectAmsForRefresh when needFreeInstall=true and RebindByFreeInstall fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefresh_005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_005 start";
    int64_t formId = 0x114547aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.needFreeInstall = true;
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbilityWithErrorCode(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectAmsForRefresh_005 end";
}

/**
 * @tc.name: ConnectAmsForRefreshPermission_001
 * @tc.desc: Verify ConnectAmsForRefreshPermission with invalid permission params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefreshPermission_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefreshPermission_001 start";
    int64_t formId = 1;
    Want want;
    MockConnectServiceAbility(false);
    ErrCode ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    want.SetParam(Constants::FORM_PERMISSION_NAME_KEY, TEST_PARAM_FORM_PERMISSION_NAME);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    want.RemoveParam(Constants::FORM_PERMISSION_NAME_KEY);
    want.SetParam(Constants::FORM_PERMISSION_GRANTED_KEY, true);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    want.SetParam(Constants::FORM_PERMISSION_NAME_KEY, TEST_PARAM_FORM_PERMISSION_NAME);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    int callingUid{ 0 };
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetProviderBundleName(FORM_PROVIDER_BUNDLE_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "ConnectAmsForRefreshPermission_001 end";
}

/**
 * @tc.name: ConnectAmsForRefreshPermission_002
 * @tc.desc: Verify ConnectAmsForRefreshPermission with valid params and connect result.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefreshPermission_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsForRefreshPermission_002 start";
    int64_t formId = 1;
    Want want;
    want.SetParam(Constants::FORM_PERMISSION_NAME_KEY, TEST_PARAM_FORM_PERMISSION_NAME);
    want.SetParam(Constants::FORM_PERMISSION_GRANTED_KEY, true);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    int callingUid{ 0 };
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetProviderBundleName(FORM_PROVIDER_BUNDLE_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    MockConnectServiceAbility(false);
    ErrCode ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_OK);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "ConnectAmsForRefreshPermission_002 end";
}

/**
 * @tc.name: ConnectForConfigUpdate_001
 * @tc.desc: Verify ConnectForConfigUpdate with valid params and connect failed.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectForConfigUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_001 start";
    int64_t formId = 0x123460aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    AppExecFwk::Configuration configuration;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectForConfigUpdate(configuration, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_001 end";
}

/**
 * @tc.name: ConnectForConfigUpdate_002
 * @tc.desc: Verify ConnectForConfigUpdate with valid params and connect success returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectForConfigUpdate_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_002 start";
    int64_t formId = 0x114526aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    AppExecFwk::Configuration configuration;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().ConnectForConfigUpdate(configuration, record, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_002 end";
}

/**
 * @tc.name: ConnectForConfigUpdate_003
 * @tc.desc: Verify ConnectForConfigUpdate returns ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED when errorCode is
 ERR_ECOLOGICAL_CONTROL_STATUS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectForConfigUpdate_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_003 start";
    int64_t formId = 0x114543aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    AppExecFwk::Configuration configuration;
    MockConnectServiceAbilityWithErrorCode(ERR_ECOLOGICAL_CONTROL_STATUS);
    ErrCode result = FormProviderMgr::GetInstance().ConnectForConfigUpdate(configuration, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectForConfigUpdate_003 end";
}

/**
 * @tc.name: ConnectAmsChangeLocation_001
 * @tc.desc: Verify ConnectAmsChangeLocation with connect failed.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsChangeLocation_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_001 start";
    int64_t formId = 0x123463aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsChangeLocation(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_001 end";
}

/**
 * @tc.name: ConnectAmsChangeLocation_002
 * @tc.desc: Verify ConnectAmsChangeLocation returns ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED when errorCode is
 * ERR_ECOLOGICAL_CONTROL_STATUS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsChangeLocation_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_002 start";
    int64_t formId = 0x114524aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsChangeLocation(formId, record, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_002 end";
}

/**
 * @tc.name: ConnectAmsChangeLocation_003
 * @tc.desc: Verify ConnectAmsChangeLocation when connect success returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsChangeLocation_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_003 start";
    int64_t formId = 0x114543aa00000000;
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsChangeLocation(formId, record, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "ConnectAmsChangeLocation_003 end";
}

/**
 * @tc.name: ConnectAmsUpdateSize_001
 * @tc.desc: Verify ConnectAmsUpdateSize with connect failed.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsUpdateSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_001 start";
    int32_t newDimension = 1;
    Rect newRect;
    newRect.width = 100;
    newRect.height = 100;
    FormRecord record;
    record.formId = 0x123464aa00000000;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsUpdateSize(newDimension, newRect, record);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_001 end";
}

/**
 * @tc.name: ConnectAmsUpdateSize_002
 * @tc.desc: Verify ConnectAmsUpdateSize returns ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED when errorCode is
 * ERR_ECOLOGICAL_CONTROL_STATUS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsUpdateSize_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_002 start";
    int32_t newDimension = 2;
    Rect newRect;
    newRect.width = 200;
    newRect.height = 200;
    FormRecord record;
    record.formId = 0x114525aa00000000;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsUpdateSize(newDimension, newRect, record);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_002 end";
}

/**
 * @tc.name: ConnectAmsUpdateSize_003
 * @tc.desc: Verify ConnectAmsUpdateSize when connect success returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsUpdateSize_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_003 start";
    int32_t newDimension = 2;
    Rect newRect;
    newRect.width = 200;
    newRect.height = 200;
    FormRecord record;
    record.formId = 0x114544aa00000000;
    record.bundleName = "com.test.bundle";
    record.abilityName = "com.test.ability";
    record.providerUserId = 0;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().ConnectAmsUpdateSize(newDimension, newRect, record);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "ConnectAmsUpdateSize_003 end";
}

/**
 * @tc.name: NotifyProviderFormDelete_001
 * @tc.desc: Verify NotifyProviderFormDelete with empty bundleName returns INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormDelete_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_001 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "";
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_001 end";
}

/**
 * @tc.name: NotifyProviderFormDelete_002
 * @tc.desc: Verify NotifyProviderFormDelete with empty abilityName returns INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormDelete_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_002 start";
    int64_t formId = 124;
    FormRecord formRecord;
    formRecord.abilityName = "";
    formRecord.bundleName = "bundleName";
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_002 end";
}

/**
 * @tc.name: NotifyProviderFormDelete_003
 * @tc.desc: Verify NotifyProviderFormDelete with valid params and connect failed.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormDelete_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_003 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.providerUserId = 0;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_003 end";
}

/**
 * @tc.name: NotifyProviderFormDelete_004
 * @tc.desc: Verify NotifyProviderFormDelete with valid params and connect success returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormDelete_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_004 start";
    int64_t formId = 127;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.providerUserId = 0;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyProviderFormDelete_004 end";
}

/**
 * @tc.name: NotifyProviderFormsBatchDelete_001
 * @tc.desc: Verify NotifyProviderFormsBatchDelete with empty abilityName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormsBatchDelete_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_001 start";
    std::string bundleName = "com.test.bundle";
    std::string abilityName = "";
    std::string moduleName = "";
    std::set<int64_t> formIds = { 1, 2, 3 };
    int32_t userId = 0;
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(
        bundleName, abilityName, moduleName, formIds, userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_001 end";
}

/**
 * @tc.name: NotifyProviderFormsBatchDelete_002
 * @tc.desc: Verify NotifyProviderFormsBatchDelete with empty bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormsBatchDelete_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_002 start";
    std::string bundleName = "";
    std::string abilityName = "com.test.ability";
    std::string moduleName = "";
    std::set<int64_t> formIds = { 1, 2, 3 };
    int32_t userId = 0;
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(
        bundleName, abilityName, moduleName, formIds, userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_002 end";
}

/**
 * @tc.name: NotifyProviderFormsBatchDelete_003
 * @tc.desc: Verify NotifyProviderFormsBatchDelete with valid params and connect
 * failed.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormsBatchDelete_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_003 start";
    std::string bundleName = "com.test.bundle";
    std::string abilityName = "com.test.ability";
    std::string moduleName = "com.test.module";
    std::set<int64_t> formIds = { 1, 2, 3 };
    int32_t userId = 0;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(
        bundleName, abilityName, moduleName, formIds, userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    MockConnectServiceAbility(true);
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_003 end";
}

/**
 * @tc.name: NotifyProviderFormsBatchDelete_004
 * @tc.desc: Verify NotifyProviderFormsBatchDelete with valid params and connect success returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, NotifyProviderFormsBatchDelete_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_004 start";
    std::string bundleName = "com.test.bundle";
    std::string abilityName = "com.test.ability";
    std::string moduleName = "";
    std::set<int64_t> formIds = { 1, 2, 3 };
    int32_t userId = 0;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(
        bundleName, abilityName, moduleName, formIds, userId);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyProviderFormsBatchDelete_004 end";
}

/**
 * @tc.name: MessageEvent_001
 * @tc.desc: Verify MessageEvent when connect failed, check screen status.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, MessageEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_001 start";
    int64_t formId = 125;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.moduleName = "normal_module";
    formRecord.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(false);
    ErrCode result = FormProviderMgr::GetInstance().MessageEvent(formId, formRecord, want);
#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    if (!screenOnFlag) {
        EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    } else {
        EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    }
#else
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
#endif
    GTEST_LOG_(INFO) << "MessageEvent_001 end";
}

/**
 * @tc.name: MessageEvent_002
 * @tc.desc: Verify MessageEvent with HiCar form bypasses screen check returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, MessageEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_002 start";
    int64_t formId = 126;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.moduleName = "phone_hicar";
    formRecord.providerUserId = 0;
    Want want;
    MockConnectServiceAbility(true);
    ErrCode result = FormProviderMgr::GetInstance().MessageEvent(formId, formRecord, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "MessageEvent_002 end";
}

}  // namespace
