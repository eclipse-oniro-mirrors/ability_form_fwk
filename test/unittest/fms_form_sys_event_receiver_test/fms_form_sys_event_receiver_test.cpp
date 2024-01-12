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
#include "common_event_manager.h"
#include "common_event_data.h"
#include "common_event_support.h"
#include "form_ams_helper.h"
#include "form_constants.h"
#define private public
#include "form_data_mgr.h"
#include "form_db_cache.h"
#include "form_host_interface.h"
#include "form_info_mgr.h"
#include "form_info_storage.h"
#include "form_mgr.h"
#include "form_sys_event_receiver.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#include "form_refresh_limiter.h"
#include "form_sys_event_receiver.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "form_bms_helper.h"
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
const std::string FORM_PROVIDER_BUNDLE_NAME_1 = "com.form.provider.service1";
const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";

const std::string FORM_JS_COMPONENT_NAME = "jsComponentName";
const std::string FORM_PROVIDER_MODULE_SOURCE_DIR = "";

const std::string FORM_HOST_BUNDLE_NAME = "com.form.host.app";

const int32_t PARAM_FORM_DIMENSION_VALUE = 1;

const std::string KEY_UID = "uid";
const std::string KEY_USER_ID = "userId";
const std::string KEY_BUNDLE_NAME = "bundleName";
const std::string DEVICE_ID = "ohos-phone1";
const std::string DEF_LABEL1 = "PermissionFormRequireGrant";

class FmsFormSysEventReceiverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void CreateEventData(std::string bundle, int64_t formId,
        int callingUid, std::string actionType, EventFwk::CommonEventData &eventData);
    void CreateEventData(std::string bundle, int64_t formId,
        int callingUid, int32_t userId, std::string actionType, EventFwk::CommonEventData &eventData);
    void CreateFormRecordAndFormInfo(std::string bundle, int64_t formId, int callingUid);
    void ClearFormRecord(int64_t formId);
    void CreateProviderData() const;
protected:
    sptr<MockFormHostClient> token_;
};

void FmsFormSysEventReceiverTest::SetUpTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormSysEventReceiverTest::TearDownTestCase()
{
}

void FmsFormSysEventReceiverTest::SetUp()
{
    token_ = new (std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormSysEventReceiverTest::TearDown()
{}

void FmsFormSysEventReceiverTest::CreateProviderData() const
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
    formInfoStorage.userId = 0;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfoMap.emplace(FORM_PROVIDER_BUNDLE_NAME, bundleFormInfo);

    FormInfoMgr::GetInstance().bundleFormInfoMap_ = bundleFormInfoMap;
}

void FmsFormSysEventReceiverTest::CreateEventData(std::string bundle, int64_t formId,
    int callingUid, std::string actionType, EventFwk::CommonEventData &eventData)
{
    Want want;
    want.SetAction(actionType);
    want.SetBundle(bundle);
    want.SetParam(KEY_UID, callingUid);
    eventData.SetWant(want);
}
void FmsFormSysEventReceiverTest::CreateEventData(std::string bundle, int64_t formId,
    int callingUid, int32_t userId, std::string actionType, EventFwk::CommonEventData &eventData)
{
    Want want;
    want.SetAction(actionType);
    want.SetBundle(bundle);
    want.SetParam(KEY_UID, callingUid);
    want.SetParam(KEY_USER_ID, userId);
    eventData.SetWant(want);
}
void FmsFormSysEventReceiverTest::CreateFormRecordAndFormInfo(std::string bundle, int64_t formId, int callingUid)
{
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(bundle);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(true);

    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);

    FormRecord realFormRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, realFormRecord);

    FormDBInfo formDBInfo(formId, realFormRecord);
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);

    FormDataMgr::GetInstance().AllotFormHostRecord(record, token_, formId, callingUid);
}

void FmsFormSysEventReceiverTest::ClearFormRecord(int64_t formId)
{
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    FormDbCache::GetInstance().DeleteFormInfo(formId);
    FormDataMgr::GetInstance().DeleteHostRecord(token_, formId);
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleProviderRemoved works.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_001 start";
    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcff00000000;
    int callingUid {0};

    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(bundle);
    record.SetModuleName(PARAM_PROVIDER_MODULE_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    want.SetBundle(bundle);
    FormRecord realFormRecord = FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    // Set database info
    FormDBInfo formDBInfo(formId, realFormRecord);
    std::vector<FormDBInfo> allFormInfo;
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
    // Set form host record
    FormItemInfo info;
    FormDataMgr::GetInstance().AllotFormHostRecord(info, token_, formId, callingUid);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);
    FormDbCache::GetInstance().GetAllFormInfo(allFormInfo);
    FormDBInfo tempFormDBInfo;
    EXPECT_NE(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormDbCache::GetInstance().GetDBRecord(formId, tempFormDBInfo));
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    FormDbCache::GetInstance().DeleteFormInfo(formId);
    FormDataMgr::GetInstance().DeleteHostRecord(token_, formId);
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_001 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleBundleDataCleared works.
 * [COMMON_EVENT_PACKAGE_DATA_CLEARED] want's uid is 0.  formrecord's uid is 15.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_002 start";
    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcff00000000;
    int callingUid {15};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED;
    EventFwk::CommonEventData eventData;
    int callingUidForWant = 0;
    CreateEventData(bundle, formId, callingUidForWant, actionType, eventData);
    CreateFormRecordAndFormInfo(bundle, formId, callingUid);

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_002 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleBundleDataCleared works.
 * [COMMON_EVENT_PACKAGE_DATA_CLEARED] want's uid and formrecord's and hostrecord's uid is 15.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_003 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    std::string bundle1 = FORM_PROVIDER_BUNDLE_NAME_1;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {15};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle1, formId, callingUid, actionType, eventData);
    CreateFormRecordAndFormInfo(bundle, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_003 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleBundleDataCleared works.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_004 start";
    EventFwk::CommonEventData eventData;
    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int callingUid {15};
    Want want;
    FormRecord tempFormRecord;
    eventData.SetWant(want);
    want.SetBundle(bundle);
    want.SetParam(KEY_UID, callingUid);
    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_004 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleBundleDataCleared works.
 * invalid action.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_005 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {15};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED + "ERROR";
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_005 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if  HandleBundleDataCleared works.
 * [COMMON_EVENT_PACKAGE_DATA_CLEARED] There is 2 callingUids.
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_006 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {15};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);

    // CreateFormRecordAndFormInfo
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(bundle);
    record.SetModuleName(PARAM_FORM_NAME);
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(true);
    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    // AddFormUserUid
    int new_callingUid = 150;
    FormDataMgr::GetInstance().AddFormUserUid(formId, new_callingUid);
    FormRecord realFormRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, realFormRecord);
    FormDBInfo formDBInfo(formId, realFormRecord);
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
    FormDataMgr::GetInstance().AllotFormHostRecord(record, token_, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_006 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if HandleProviderUpdated works.
 * [COMMON_EVENT_ABILITY_UPDATED] ProviderFormUpdated return false. delete formrecord.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_007 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {0};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);
    CreateFormRecordAndFormInfo(bundle, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_007 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if HandleProviderUpdated works.
 * [COMMON_EVENT_ABILITY_UPDATED] ProviderFormUpdated return true. refresh form.
 */

HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_008 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {15};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);

    // CreateFormRecordAndFormInfo
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(bundle);
    record.SetModuleName(PARAM_PROVIDER_MODULE_NAME); // model name
    record.SetAbilityName(FORM_PROVIDER_ABILITY_NAME); // ability name
    record.SetFormName(PARAM_FORM_NAME); // form name
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(true);

    FormDataMgr::GetInstance().AllotFormRecord(record, callingUid);
    FormRecord realFormRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, realFormRecord);
    FormDBInfo formDBInfo(formId, realFormRecord);
    FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
    FormDataMgr::GetInstance().AllotFormHostRecord(record, token_, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_008 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if HandleProviderUpdated works.
 * [COMMON_EVENT_PACKAGE_CHANGED] ProviderFormUpdated return false. delete formRecord.
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_009 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {0};
    CreateProviderData();
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);
    CreateFormRecordAndFormInfo(bundle, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    // clear provider data
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_009 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: OnReceiveEvent Functions
 * FunctionPoints: FormMgr OnReceiveEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if HandleProviderUpdated works.
 * [COMMON_EVENT_PACKAGE_CHANGED] ProviderFormUpdated return true. refresh form.
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_0010 start";

    std::string bundle = FORM_PROVIDER_BUNDLE_NAME;
    int64_t formId = 0x0ffabcdf00000000;
    int callingUid {0};
    std::string actionType = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED;
    EventFwk::CommonEventData eventData;
    CreateEventData(bundle, formId, callingUid, actionType, eventData);
    CreateFormRecordAndFormInfo(bundle, formId, callingUid);

    FormRecord tempFormRecord;
    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    auto testCase = std::make_shared<FormSysEventReceiver>();
    testCase->SetSerialQueue(nullptr);
    testCase->OnReceiveEvent(eventData);

    ASSERT_TRUE(FormDataMgr::GetInstance().GetFormRecord(formId, tempFormRecord));

    ClearFormRecord(formId);

    GTEST_LOG_(INFO) << "fms_form_sys_event_receiver_test_0010 end";
}

/**
 * @tc.number: OnReceiveEvent_0011
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the bundleName is null, and the action is neither COMMON_EVENT_USER_REMOVED nor
 *           COMMON_EVENT_BUNDLE_SCAN_FINISHED, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0011 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "abc";
    std::string bundleName = "";
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    testCase->OnReceiveEvent(eventData);
    EXPECT_FALSE(want.GetAction().empty());
    EXPECT_TRUE(want.GetElement().GetBundleName().empty() &&
    action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED &&
    action != EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0011 end";
}

/**
 * @tc.number: OnReceiveEvent_0012
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the eventHandler_ is nullptr, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0012 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "abc";
    std::string bundleName = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    testCase->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0012 end";
}

/**
 * @tc.number: OnReceiveEvent_0013
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the action is COMMON_EVENT_USER_REMOVED and userId is -1, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0013 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    const int32_t code = -1;
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string bundleName = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    eventData.SetCode(code);
    testCase->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0013 end";
}

/**
 * @tc.number: OnReceiveEvent_0014
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the action is COMMON_EVENT_USER_REMOVED and userId is 1, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0014 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    const int32_t code = 1;
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string bundleName = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    eventData.SetCode(code);
    testCase->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0014 end";
}

/**
 * @tc.number: OnReceiveEvent_0015
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the action is COMMON_EVENT_BUNDLE_SCAN_FINISHED, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0015 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED;
    std::string bundleName = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    testCase->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0015 end";
}

/**
 * @tc.number: OnReceiveEvent_0016
 * @tc.name: OnReceiveEvent
 * @tc.desc: When the action is COMMON_EVENT_PACKAGE_REPLACED, the program executes normally as expected
 */
HWTEST_F(FmsFormSysEventReceiverTest, OnReceiveEvent_0016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnReceiveEvent_0016 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    EXPECT_TRUE(testCase != nullptr);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REPLACED;
    std::string bundleName = EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED;
    std::string abilityName = "abc";
    want.SetAction(action);
    want.SetElementName(bundleName, abilityName);
    eventData.SetWant(want);
    testCase->OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "OnReceiveEvent_0016 end";
}

/**
 * @tc.number: HandleUserIdRemoved_0001
 * @tc.name: HandleUserIdRemoved
 * @tc.desc: Verify whether the HandleUserIdRemoved interface is called normally
 */
HWTEST_F(FmsFormSysEventReceiverTest, HandleUserIdRemoved_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandleUserIdRemoved_0001 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    ASSERT_NE(nullptr, testCase);
    const int32_t userId = 0;
    testCase->HandleUserIdRemoved(userId);
    GTEST_LOG_(INFO) << "HandleUserIdRemoved_0001 end";
}

/**
 * @tc.number: HandleBundleScanFinished_0001
 * @tc.name: HandleBundleScanFinished
 * @tc.desc: Verify whether the HandleBundleScanFinished interface is called normally
 */
HWTEST_F(FmsFormSysEventReceiverTest, HandleBundleScanFinished_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandleBundleScanFinished_0001 start";
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>();
    ASSERT_NE(nullptr, testCase);
    testCase->HandleBundleScanFinished();
    GTEST_LOG_(INFO) << "HandleBundleScanFinished_0001 end";
}

/**
 * @tc.number: HandleUserSwitched_0001
 * @tc.name: HandleUserSwitched
 * @tc.desc: Verify whether the HandleUserSwitched interface is called normally
 */
HWTEST_F(FmsFormSysEventReceiverTest, HandleUserSwitched_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandleUserSwitched_0001 start";
    std::shared_ptr<FormSysEventReceiver> receiver = std::make_shared<FormSysEventReceiver>();
    ASSERT_NE(nullptr, receiver);
    OHOS::EventFwk::CommonEventData eventData;
    eventData.SetCode(Constants::ANY_USERID);
    receiver->HandleUserSwitched(eventData);
    GTEST_LOG_(INFO) << "HandleUserSwitched_0001 end";
}

/**
 * @tc.number: HandleUserSwitched_0002
 * @tc.name: HandleUserSwitched
 * @tc.desc: Verify whether the HandleUserSwitched interface is called normally
 */
HWTEST_F(FmsFormSysEventReceiverTest, HandleUserSwitched_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "HandleUserSwitched_0002 start";
    std::shared_ptr<FormSysEventReceiver> receiver = std::make_shared<FormSysEventReceiver>();
    ASSERT_NE(nullptr, receiver);
    OHOS::EventFwk::CommonEventData eventData;
    const int32_t MAIN_USER_ID = 100;
    eventData.SetCode(MAIN_USER_ID);
    receiver->HandleUserSwitched(eventData);
    GTEST_LOG_(INFO) << "HandleUserSwitched_0002 end";
}

/**
 * @tc.number: FormSysEventReceiver_0001
 * @tc.name: FormSysEventReceiver
 * @tc.desc: Verify whether the FormSysEventReceiver interface is called normally
 */
HWTEST_F(FmsFormSysEventReceiverTest, FormSysEventReceiver_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSysEventReceiver_0001 start";
    EventFwk::CommonEventSubscribeInfo subscriberInfo;
    std::shared_ptr<FormSysEventReceiver> testCase = std::make_shared<FormSysEventReceiver>(subscriberInfo);
    ASSERT_NE(nullptr, testCase);
    GTEST_LOG_(INFO) << "FormSysEventReceiver_0001 end";
}
}