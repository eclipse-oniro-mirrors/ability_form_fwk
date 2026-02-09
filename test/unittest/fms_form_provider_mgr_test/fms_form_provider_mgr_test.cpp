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
#include "data_center/database/form_db_cache.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#include "common/util/form_util.h"
#include "form_host_interface.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_service.h"
#include "form_provider/form_provider_mgr.h"
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
#include "form_provider/mock_form_provider_mgr.h"

namespace {
    bool g_mockConnectServiceAbilityRet = false;
}

namespace OHOS {
void MockConnectServiceAbility(bool mockRet)
{
    g_mockConnectServiceAbilityRet = mockRet;
}
} // namespace OHOS

namespace OHOS {
namespace AppExecFwk {
ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    if (!g_mockConnectServiceAbilityRet) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS

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
{}

void FmsFormProviderMgrTest::SetUp()
{
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormProviderMgrTest::TearDown()
{}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: AcquireForm Function
 * FunctionPoints: FormMgr AcquireForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  AcquireForm works with invalid formid.
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_001 start";
    int64_t formId = 0x114514aa00000000;
    FormProviderInfo formProviderInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        FormProviderMgr::GetInstance().AcquireForm(-114514L, formProviderInfo));
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_001 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: AcquireForm Function
 * FunctionPoints: FormMgr AcquireForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  AcquireForm works without formrecord.
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_002 start";
    int64_t formId = 0x11451aaa00000000;
    FormProviderInfo formProviderInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo));
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_002 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: AcquireForm Function
 * FunctionPoints: FormMgr AcquireForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  AcquireForm works without form host record.
 */
HWTEST_F(FmsFormProviderMgrTest, AcquireForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_003 start";
    int64_t formId = 0x1145aaaa00000000;
    FormProviderInfo formProviderInfo;
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
    FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo));
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_003 end";
}


/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: RefreshForm Function
 * FunctionPoints: FormMgr RefreshForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  RefreshForm works without form host record.
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_004 start";
    int64_t formId = 0x1145aaaa00001200;
    Want want;
    MockRefreshCheck(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormProviderMgr::GetInstance().RefreshForm(formId, want, true));
    MockRefreshCheck(true);
    FormRecord record;
    record.enableForm = true;
    FormProviderMgr::GetInstance().RefreshForm(formId, want, true);

    record.enableForm = false;
    want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    want.SetParam(Constants::KEY_CONNECT_REFRESH, true);
    record.formVisibleNotifyState = Constants::FORM_DEFAULT;
    EXPECT_EQ(ERR_OK, FormProviderMgr::GetInstance().RefreshForm(formId, want, true));

    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    record.isSystemApp = true;
    FormProviderMgr::GetInstance().RefreshForm(formId, want, true);

    record.isSystemApp = false;
    FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_004 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: RefreshForm Function
 * FunctionPoints: FormMgr RefreshForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  RefreshForm works without form host record.
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_005 start";
    int64_t formId = 0x114514aa00000000;
    Want want;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::KEY_IS_TIMER, true);
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);

    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_005 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: RefreshForm Function
 * FunctionPoints: FormMgr RefreshForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  RefreshForm works without form host record.
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_006 start";
    int64_t formId = 0x114514aa00000000;
    Want want;
    int callingUid {0};
    int32_t currentActiveUserId = FormUtil::GetCallerUserId(callingUid);
    want.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    want.SetParam(Constants::KEY_IS_TIMER, false);
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
#ifdef SUPPORT_POWER
    MockConnectServiceAbility(true);
    FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
#endif

    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_006 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: RefreshForm Function
 * FunctionPoints: FormMgr RefreshForm interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Check that the caller of RefreshForm is the currently inactive user.
 */
HWTEST_F(FmsFormProviderMgrTest, RefreshForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_007 start";
    int64_t formId = 0x114514aa00000000;
    Want want;
    want.SetParam(Constants::KEY_IS_TIMER, false);
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
#ifdef SUPPORT_POWER
    FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
#endif
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_007 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: ConnectAmsForRefreshPermission Function
 * FunctionPoints: FormMgr ConnectAmsForRefreshPermission interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if ConnectAmsForRefreshPermission works without permission parameters or form record.
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefreshPermission_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_008 start";
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
    int callingUid {0};
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetProviderBundleName(FORM_PROVIDER_BUNDLE_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    ret = FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_008 end";
}

/*
 * Feature: FmsFormProviderMgr
 * Function: FormMgr
 * SubFunction: ConnectAmsForRefreshPermission Function
 * FunctionPoints: FormMgr ConnectAmsForRefreshPermission interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if ConnectAmsForRefreshPermission works without application service.
 */
HWTEST_F(FmsFormProviderMgrTest, ConnectAmsForRefreshPermission_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_009 start";
    int64_t formId = 1;
    Want want;
    want.SetParam(Constants::FORM_PERMISSION_NAME_KEY, TEST_PARAM_FORM_PERMISSION_NAME);
    want.SetParam(Constants::FORM_PERMISSION_GRANTED_KEY, true);
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    int callingUid {0};
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
    GTEST_LOG_(INFO) << "fms_form_mgr_provider_test_009 end";
}


/**
 * @tc.name: FormProviderMgrTest_001
 * @tc.desc: Verify NotifyProviderFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_001 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_001 end";
}

/**
 * @tc.name: FormProviderMgrTest_002
 * @tc.desc: Verify NotifyProviderFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_002 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_002 end";
}

/**
 * @tc.name: FormProviderMgrTest_003
 * @tc.desc: Verify MessageEvent
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_003 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    Want want;
    FormProviderMgr::GetInstance().MessageEvent(formId, formRecord, want);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_003 end";
}

/**
 * @tc.name: FormProviderMgrTest_004
 * @tc.desc: Verify NotifyProviderFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_004 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_004 end";
}

/**
 * @tc.name: FormProviderMgrTest_005
 * @tc.desc: Verify NotifyProviderFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_005 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_005 end";
}

/**
 * @tc.name: FormProviderMgrTest_006
 * @tc.desc: Verify MessageEvent
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderMgrTest, FormProviderMgrTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgrTest_006 start";
    int64_t formId = 123;
    FormRecord formRecord;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    Want want;
    FormProviderMgr::GetInstance().MessageEvent(formId, formRecord, want);
    GTEST_LOG_(INFO) << "FormProviderMgrTest_006 end";
}
}
