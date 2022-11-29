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
#include "form_ability_connection.h"
#undef private
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#define private public
#include "form_db_cache.h"
#undef private
#include "form_host_interface.h"
#define private public
#include "form_info_mgr.h"
#include "form_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif
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

const std::string DEVICE_ID = "ohos-phone1";

const std::string FORM_MESSAGE_EVENT_VALUE_1 = "event message1";

class FmsFormMgrMessageEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
};

void FmsFormMgrMessageEventTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormMgrMessageEventTest::TearDownTestCase()
{}

void FmsFormMgrMessageEventTest::SetUp()
{
    formyMgrServ_->OnStart();
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormMgrMessageEventTest::TearDown()
{}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke MessageEvent works.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_001 start";

    int64_t formId {10000001};
    int callingUid {20000007};
    // Create cache
    FormItemInfo record1;
    record1.SetFormId(formId);
    record1.SetProviderBundleName(FORM_PROVIDER_BUNDLE_NAME);
    record1.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record1.SetTemporaryFlag(false);
    FormRecord retFormRec = FormDataMgr::GetInstance().AllotFormRecord(record1, callingUid);
    // User Uid Add some Useruids into a form in cache
    int formUserUid {1};
    FormDataMgr::GetInstance().AddFormUserUid(formId, formUserUid);
    // Set form host record
    retFormRec.formUserUids.emplace_back(formUserUid);
    FormDBInfo formDBInfo(formId, retFormRec);
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
    // Set host record
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);

#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    if (!screenOnFlag) {
        EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormMgr::GetInstance().MessageEvent(formId, want, token_));
    } else {
        EXPECT_EQ(ERR_OK, FormMgr::GetInstance().MessageEvent(formId, want, token_));
    }
#endif
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_001 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if formId == 0.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_003 start";
    int64_t formId = 0;

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, FormMgr::GetInstance().MessageEvent(formId, want, token_));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_003 end";
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if callerToken == nullptr.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_004 start";
    int64_t formId {10000001};

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, FormMgr::GetInstance().MessageEvent(formId, want, nullptr));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_004 end";
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if message info is not exist.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_005 start";
    int64_t formId {10000001};

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);

    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, FormMgr::GetInstance().MessageEvent(formId, want, token_));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_005 end";
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if not exist such form.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_006 start";
    int64_t formId {11100002};

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormMgr::GetInstance().MessageEvent(formId, want, token_));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_006 end";
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if cannot find target client.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_007 start";
    int64_t formId {10000001};

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormMgr::GetInstance().MessageEvent(formId, want,
    new (std::nothrow) MockFormHostClient()));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_007 end";
}
/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: MessageEvent Function
 * FunctionPoints: FormMgr MessageEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: An exception tests if form is not self-owned.
 */
HWTEST_F(FmsFormMgrMessageEventTest, MessageEvent_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_008 start";
    int64_t formId2 {10000001};
    int64_t formId {10000002};
    int callingUid {0};
    // Create cache
    FormItemInfo record1;
    record1.SetFormId(formId);
    record1.SetProviderBundleName(FORM_HOST_BUNDLE_NAME);
    record1.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record1.SetTemporaryFlag(false);
    FormRecord retFormRec = FormDataMgr::GetInstance().AllotFormRecord(record1, callingUid);
    // User Uid Add some Useruids into a form in cache
    int formUserUid {1};
    FormDataMgr::GetInstance().AddFormUserUid(formId, formUserUid);
    // Set form host record
    retFormRec.formUserUids.emplace_back(formUserUid);
    FormDBInfo formDBInfo(formId, retFormRec);
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
    // Set host record
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);

    FormDataMgr::GetInstance().DeleteHostRecord(token_, formId2);

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, FORM_HOST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, PARAM_PROVIDER_MODULE_NAME);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, PARAM_FORM_NAME);
    want.SetElementName(DEVICE_ID, FORM_PROVIDER_BUNDLE_NAME, FORM_PROVIDER_ABILITY_NAME);
    want.SetParam(Constants::PARAM_MESSAGE_KEY, FORM_MESSAGE_EVENT_VALUE_1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormMgr::GetInstance().MessageEvent(formId2, want, token_));
    GTEST_LOG_(INFO) << "fms_form_mgr_message_event_test_008 end";
}

/**
 * @tc.name: FormDbCache_001
 * @tc.desc: test SaveFormInfoNolock function.
 * @tc.type: SaveFormInfoNolock
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_001 start";
    FormDbCache formDbCache;
    FormDBInfo formDBInfo;
    formDbCache.SaveFormInfoNolock(formDBInfo);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_001 end";
}

/**
 * @tc.name: FormDbCache_002
 * @tc.desc: test SaveFormInfoNolock function.
 * @tc.type: SaveFormInfoNolock
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_002 start";
    FormDbCache formDbCache;
    FormDBInfo formDBInfo;
    formDBInfo.formName = "aa";
    FormDBInfo formDBInfos;
    formDBInfos.formName = "aa";
    formDbCache.formDBInfos_.emplace_back(formDBInfos);
    formDbCache.SaveFormInfoNolock(formDBInfo);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_002 end";
}

/**
 * @tc.name: FormDbCache_003
 * @tc.desc: test SaveFormInfoNolock function.
 * @tc.type: SaveFormInfoNolock
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_003 start";
    FormDbCache formDbCache;
    FormDBInfo formDBInfo;
    formDBInfo.formName = "aa";
    FormDBInfo formDBInfos;
    formDBInfos.formName = "bb";
    formDbCache.formDBInfos_.emplace_back(formDBInfos);
    formDbCache.SaveFormInfoNolock(formDBInfo);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_003 end";
}

/**
 * @tc.name: FormDbCache_004
 * @tc.desc: test GetDBRecord function.
 * @tc.type: GetDBRecord
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_004 start";
    FormDbCache formDbCache;
    FormDBInfo formDBInfos;
    formDBInfos.formId = 1;
    formDbCache.formDBInfos_.emplace_back(formDBInfos);
    int64_t formIds = 1;
    FormDBInfo record;
    EXPECT_EQ(ERR_OK, formDbCache.GetDBRecord(formIds, record));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_004 end";
}

/**
 * @tc.name: FormDbCache_005
 * @tc.desc: test GetDBRecord function.
 * @tc.type: GetDBRecord
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_005 start";
    FormDbCache formDbCache;
    FormDBInfo formDBInfos;
    formDBInfos.formId = 1;
    formDbCache.formDBInfos_.emplace_back(formDBInfos);
    int64_t formIds = 2;
    FormDBInfo record;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formDbCache.GetDBRecord(formIds, record));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_005 end";
}

/**
 * @tc.name: FormDbCache_006
 * @tc.desc: test GetNoHostDBForms function.
 * @tc.type: GetNoHostDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_006 start";
    FormDbCache formDbCache;
    int uid = 1;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDBList;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 1;
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    EXPECT_EQ(ERR_OK, formDbCache.GetNoHostDBForms(uid, noHostFormDBList, foundFormsMap));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_006 end";
}

/**
 * @tc.name: FormDbCache_007
 * @tc.desc: test GetNoHostDBForms function.
 * @tc.type: GetNoHostDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_007 start";
    FormDbCache formDbCache;
    int uid = 1;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDBList;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 2;
    formDBInfo.formUserUids.emplace_back(uid);
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    FormDBInfo formDBInfos;
    formDBInfos.userId = 1;
    formDBInfos.formUserUids.emplace_back(uid);
    formDbCache.formDBInfos_.emplace_back(formDBInfos);
    EXPECT_EQ(ERR_OK, formDbCache.GetNoHostDBForms(uid, noHostFormDBList, foundFormsMap));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_007 end";
}

/**
 * @tc.name: FormDbCache_008
 * @tc.desc: test GetMatchCount function.
 * @tc.type: GetMatchCount
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_008 start";
    FormDbCache formDbCache;
    std::string bundleName = "aa";
    std::string moduleName = "bb";
    FormDBInfo formDBInfo;
    formDBInfo.bundleName = "aa";
    formDBInfo.moduleName = "bb";
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    EXPECT_EQ(1, formDbCache.GetMatchCount(bundleName, moduleName));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_008 end";
}

/**
 * @tc.name: FormDbCache_009
 * @tc.desc: test DeleteDBFormsByUserId function.
 * @tc.type: DeleteDBFormsByUserId
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_009 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 1;
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.DeleteDBFormsByUserId(userId);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_009 end";
}

/**
 * @tc.name: FormDbCache_010
 * @tc.desc: test DeleteDBFormsByUserId function.
 * @tc.type: DeleteDBFormsByUserId
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_010 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 2;
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.DeleteDBFormsByUserId(userId);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_010 end";
}

/**
 * @tc.name: FormDbCache_011
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_011 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 2;
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_011 end";
}

/**
 * @tc.name: FormDbCache_012
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_012 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 1;
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_012 end";
}

/**
 * @tc.name: FormDbCache_013
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_013 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.userId = 1;
    formDBInfo.formUserUids.emplace_back(2);
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_013 end";
}

/**
 * @tc.name: FormDbCache_014
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_014 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    int64_t formIds = 3;
    matchedFormIds.insert(formIds);
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.formId = 3;
    formDBInfo.userId = 1;
    formDBInfo.formUserUids.emplace_back(2);
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_014 end";
}

/**
 * @tc.name: FormDbCache_015
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_015 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    int64_t formIds = 4;
    matchedFormIds.insert(formIds);
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    std::map<int64_t, bool> foundFormsMap;
    FormDBInfo formDBInfo;
    formDBInfo.formId = 3;
    formDBInfo.userId = 1;
    formDBInfo.formUserUids.emplace_back(2);
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_015 end";
}

/**
 * @tc.name: FormDbCache_016
 * @tc.desc: test GetNoHostInvalidDBForms function.
 * @tc.type: GetNoHostInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_016 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    int64_t formIds = 4;
    matchedFormIds.insert(formIds);
    std::map<int64_t, bool> foundFormsMap;
    // set formDBInfos_
    FormDBInfo formDBInfo;
    formDBInfo.formId = 3;
    formDBInfo.userId = 1;
    formDBInfo.bundleName = "com.form.start";
    formDBInfo.abilityName = "bbbbbb";
    formDBInfo.formUserUids.emplace_back(2);
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    // set noHostDBFormsMap
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    FormIdKey formIdKey(formDBInfo.bundleName, formDBInfo.abilityName);
    std::set<int64_t> host;
    host.insert(formIds);
    noHostDBFormsMap.emplace(formIdKey, host);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_016 end";
}

/**
 * @tc.name: FormDbCache_017
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: BatchDeleteNoHostDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_017 start";
    FormDbCache formDbCache;
    int32_t callingUid = 1;
    // set noHostDBFormsMap
    FormDBInfo formDBInfo;
    formDBInfo.formId = 2;
    formDBInfo.bundleName = "com.form.start";
    formDBInfo.abilityName = "bbbbbb";
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    FormIdKey formIdKey(formDBInfo.bundleName, formDBInfo.abilityName);
    std::set<int64_t> host;
    int64_t formId = 2;
    host.insert(formId);
    noHostDBFormsMap.emplace(formIdKey, host);
    // set formDBInfos_
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    std::map<int64_t, bool> foundFormsMap;
    formDbCache.BatchDeleteNoHostDBForms(callingUid, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_017 end";
}

/**
 * @tc.name: FormDbCache_018
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: BatchDeleteNoHostDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_018 start";
    FormDbCache formDbCache;
    int32_t callingUid = 1;
    // set noHostDBFormsMap
    FormDBInfo formDBInfo;
    formDBInfo.formId = 2;
    formDBInfo.bundleName = "com.form.start";
    formDBInfo.abilityName = "bbbbbb";
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    FormIdKey formIdKey(formDBInfo.bundleName, formDBInfo.abilityName);
    std::set<int64_t> host;
    int64_t formId = 3;
    host.insert(formId);
    noHostDBFormsMap.emplace(formIdKey, host);
    // set formDBInfos_
    formDbCache.formDBInfos_.emplace_back(formDBInfo);
    std::map<int64_t, bool> foundFormsMap;
    formDbCache.BatchDeleteNoHostDBForms(callingUid, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_018 end";
}

/**
 * @tc.name: FormDbCache_019
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: BatchDeleteNoHostDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_019 start";
    FormDbCache formDbCache;
    int32_t callingUid = 1;
    // set noHostDBFormsMap
    FormDBInfo formDBInfo;
    formDBInfo.formId = 2;
    formDBInfo.bundleName = "com.form.start";
    formDBInfo.abilityName = "bbbbbb";
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap;
    FormIdKey formIdKey(formDBInfo.bundleName, formDBInfo.abilityName);
    std::set<int64_t> host;
    int64_t formId = 2;
    host.insert(formId);
    noHostDBFormsMap.emplace(formIdKey, host);
    // set formDBInfos_
    FormDBInfo formDBInfoes;
    formDBInfoes.formId = 2;
    formDBInfoes.bundleName = "aaaaaaaa";
    formDBInfoes.abilityName = "sssssss";
    formDbCache.formDBInfos_.emplace_back(formDBInfoes);
    std::map<int64_t, bool> foundFormsMap;
    formDbCache.BatchDeleteNoHostDBForms(callingUid, noHostDBFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_019 end";
}

/**
 * @tc.name: FormDbCache_020
 * @tc.desc: test DeleteInvalidDBForms function.
 * @tc.type: DeleteInvalidDBForms
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormDbCache_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_020 start";
    FormDbCache formDbCache;
    int32_t userId = 1;
    int32_t callingUid = 2;
    std::set<int64_t> matchedFormIds;
    std::map<int64_t, bool> removedFormsMap;
    EXPECT_EQ(ERR_OK, formDbCache.DeleteInvalidDBForms(userId, callingUid, matchedFormIds, removedFormsMap));
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormDbCache_020 end";
}

/**
 * @tc.name: FormAbilityConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: OnAbilityConnectDone
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_001 start";
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 2;
    formAbilityConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_001 end";
}

/**
 * @tc.name: FormAbilityConnection_002
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: OnAbilityConnectDone
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_002 start";
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAbilityConnection.isFreeInstall_ = false;
    formAbilityConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_002 end";
}

/**
 * @tc.name: FormAbilityConnection_003
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: OnAbilityConnectDone
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_003 start";
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = ERR_OK;
    formAbilityConnection.isFreeInstall_ = true;
    formAbilityConnection.bundleName_ = "";
    formAbilityConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_003 end";
}

/**
 * @tc.name: FormAbilityConnection_004
 * @tc.desc: test OnAbilityDisconnectDone function.
 * @tc.type: OnAbilityDisconnectDone
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_004 start";
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    int resultCode = 1;
    formAbilityConnection.connectId_ = 0;
    formAbilityConnection.OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_004 end";
}

/**
 * @tc.name: FormAbilityConnection_005
 * @tc.desc: test OnAbilityDisconnectDone function.
 * @tc.type: OnAbilityDisconnectDone
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_005 start";
    FormAbilityConnection formAbilityConnection;
    AppExecFwk::ElementName element;
    int resultCode = 1;
    formAbilityConnection.connectId_ = 1;
    formAbilityConnection.OnAbilityDisconnectDone(element, resultCode);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_005 end";
}

/**
 * @tc.name: FormAbilityConnection_006
 * @tc.desc: test OnConnectDied function.
 * @tc.type: OnConnectDied
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_006 start";
    FormAbilityConnection formAbilityConnection;
    wptr<IRemoteObject> remoteObject = nullptr;
    formAbilityConnection.connectId_ = 0;
    formAbilityConnection.OnConnectDied(remoteObject);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_006 end";
}

/**
 * @tc.name: FormAbilityConnection_007
 * @tc.desc: test OnConnectDied function.
 * @tc.type: OnConnectDied
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_007 start";
    FormAbilityConnection formAbilityConnection;
    wptr<IRemoteObject> remoteObject = nullptr;
    formAbilityConnection.connectId_ = 1;
    formAbilityConnection.OnConnectDied(remoteObject);
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_007 end";
}

/**
 * @tc.name: FormAbilityConnection_008
 * @tc.desc: test GetProviderKey function.
 * @tc.type: GetProviderKey
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_008 start";
    FormAbilityConnection formAbilityConnection;
    formAbilityConnection.bundleName_ = "";
    formAbilityConnection.abilityName_ = "";
    EXPECT_EQ("", formAbilityConnection.GetProviderKey());
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_008 end";
}

/**
 * @tc.name: FormAbilityConnection_009
 * @tc.desc: test GetProviderKey function.
 * @tc.type: GetProviderKey
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_009 start";
    FormAbilityConnection formAbilityConnection;
    formAbilityConnection.bundleName_ = "";
    formAbilityConnection.abilityName_ = "aa";
    EXPECT_EQ("", formAbilityConnection.GetProviderKey());
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_009 end";
}

/**
 * @tc.name: FormAbilityConnection_010
 * @tc.desc: test GetProviderKey function.
 * @tc.type: GetProviderKey
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_010 start";
    FormAbilityConnection formAbilityConnection;
    formAbilityConnection.bundleName_ = "bb";
    formAbilityConnection.abilityName_ = "";
    EXPECT_EQ("", formAbilityConnection.GetProviderKey());
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_010 end";
}

/**
 * @tc.name: FormAbilityConnection_011
 * @tc.desc: test GetProviderKey function.
 * @tc.type: GetProviderKey
 */
HWTEST_F(FmsFormMgrMessageEventTest, FormAbilityConnection_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_011 start";
    FormAbilityConnection formAbilityConnection;
    formAbilityConnection.bundleName_ = "bb";
    formAbilityConnection.abilityName_ = "aa";
    EXPECT_EQ("bb::aa", formAbilityConnection.GetProviderKey());
    GTEST_LOG_(INFO) << "FmsFormMgrMessageEventTest FormAbilityConnection_011 end";
}
}