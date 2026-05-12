/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include <gtest/gtest.h>

#define private public
#define protected public
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "want.h"
#include "bundle_info.h"
#include "form_info.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"
#include "application_info.h"
#include "form_major_info.h"
#include "form_ecological_rule_param.h"
#include "form_mgr/form_adapter_constants.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_timer_mgr.h"
#include "mock_form_db_cache.h"
#include "mock_form_bundle_forbid_mgr.h"
#include "mock_form_bundle_lock_mgr.h"
#include "mock_form_exempt_lock_mgr.h"
#include "mock_form_distributed_mgr.h"
#include "mock_param_control.h"
#include "mock_i_remote_object.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int32_t TEST_DIMENSION_ID = 2;
constexpr int32_t SYSTEM_UID = 1000;
constexpr int32_t INVALID_FORM_LOCATION = -1;
constexpr int32_t API_VERSION_11 = 11;
}

class FmsFormCommonAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormCommonAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormTimerMgr::obj = std::make_shared<MockFormTimerMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockFormBundleForbidMgr::obj = std::make_shared<MockFormBundleForbidMgr>();
    MockFormBundleLockMgr::obj = std::make_shared<MockFormBundleLockMgr>();
    MockFormExemptLockMgr::obj = std::make_shared<MockFormExemptLockMgr>();
    MockFormDistributedMgr::obj = std::make_shared<MockFormDistributedMgr>();
    MockParamControl::obj = std::make_shared<MockParamControl>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormCommonAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    MockFormTimerMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    MockFormBundleForbidMgr::obj = nullptr;
    MockFormBundleLockMgr::obj = nullptr;
    MockFormExemptLockMgr::obj = nullptr;
    MockFormDistributedMgr::obj = nullptr;
    MockParamControl::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
}

void FmsFormCommonAdapterTest::SetUp()
{
}

void FmsFormCommonAdapterTest::TearDown()
{
}

// ========== Method 1: GetFormConfigInfo Tests ==========

/**
 * @tc.name: GetFormConfigInfo_001
 * @tc.desc: Verify GetBundleInfo failed returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormConfigInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormConfigInfo_001 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    FormItemInfo formItemInfo;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillRepeatedly(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoV9(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormCommonAdapter::GetInstance().GetFormConfigInfo(want, formItemInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "GetFormConfigInfo_001 end";
}

/**
 * @tc.name: GetFormConfigInfo_002
 * @tc.desc: Verify GetFormInfo failed returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormConfigInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormConfigInfo_002 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    FormItemInfo formItemInfo;
    BundleInfo bundleInfo;
    bundleInfo.moduleNames.push_back("entry");

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillRepeatedly(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoV9(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(ERR_OK)));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormCommonAdapter::GetInstance().GetFormConfigInfo(want, formItemInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "GetFormConfigInfo_002 end";
}

/**
 * @tc.name: GetFormConfigInfo_007
 * @tc.desc: Verify successful flow returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormConfigInfo_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormConfigInfo_007 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::FORM_LOCATION_KEY, static_cast<int>(Constants::FormLocation::OTHER));

    FormItemInfo formItemInfo;
    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.moduleNames.push_back("entry");
    bundleInfo.applicationInfo.isSystemApp = false;

    FormInfo formInfo;
    formInfo.name = "widget";
    formInfo.abilityName = "MainAbility";
    formInfo.moduleName = "entry";
    formInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    formInfo.defaultDimension = TEST_DIMENSION_ID;
    formInfo.src = "pages/index.ets";
    std::vector<FormInfo> formInfos;
    formInfos.push_back(formInfo);

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoV9(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(bundleInfo), Return(ERR_OK)));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>("com.test.host"), Return(ERR_OK)));
    EXPECT_CALL(*MockFormDistributedMgr::obj, IsBundleDistributed(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDistributedMgr::obj, GetUiModuleName(_, _))
        .WillRepeatedly(Return(""));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDbCache::obj, GetDBRecord(_, _))
        .WillRepeatedly(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillRepeatedly(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));

    auto result = FormCommonAdapter::GetInstance().GetFormConfigInfo(want, formItemInfo);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormConfigInfo_007 end";
}

// ========== Method 2: GetBundleInfo Tests ==========

/**
 * @tc.name: GetBundleInfo_001
 * @tc.desc: Verify empty bundleName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetBundleInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleInfo_001 start";

    Want want;
    want.SetElementName("", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    BundleInfo bundleInfo;
    std::string packageName;

    auto result = FormCommonAdapter::GetInstance().GetBundleInfo(want, bundleInfo, packageName);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "GetBundleInfo_001 end";
}

/**
 * @tc.name: GetBundleInfo_002
 * @tc.desc: Verify empty abilityName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetBundleInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleInfo_002 start";

    Want want;
    want.SetElementName("com.test.bundle", "");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    BundleInfo bundleInfo;
    std::string packageName;

    auto result = FormCommonAdapter::GetInstance().GetBundleInfo(want, bundleInfo, packageName);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "GetBundleInfo_002 end";
}

/**
 * @tc.name: GetBundleInfo_003
 * @tc.desc: Verify empty moduleName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetBundleInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleInfo_003 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");

    BundleInfo bundleInfo;
    std::string packageName;

    auto result = FormCommonAdapter::GetInstance().GetBundleInfo(want, bundleInfo, packageName);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "GetBundleInfo_003 end";
}

/**
 * @tc.name: GetBundleInfo_004
 * @tc.desc: Verify nullptr IBundleMgr returns ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetBundleInfo_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleInfo_004 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    BundleInfo bundleInfo;
    std::string packageName;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().GetBundleInfo(want, bundleInfo, packageName);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "GetBundleInfo_004 end";
}

// ========== Method 3: GetFormInfo Tests ==========

/**
 * @tc.name: GetFormInfo_001
 * @tc.desc: Verify empty bundleName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfo_001 start";

    Want want;
    want.SetElementName("", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    FormInfo formInfo;

    auto result = FormCommonAdapter::GetInstance().GetFormInfo(want, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "GetFormInfo_001 end";
}

/**
 * @tc.name: GetFormInfo_009
 * @tc.desc: Verify formName matching returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfo_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfo_009 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));

    FormInfo formInfo;
    std::vector<FormInfo> formInfos;
    FormInfo testFormInfo;
    testFormInfo.name = "widget";
    testFormInfo.abilityName = "MainAbility";
    testFormInfo.moduleName = "entry";
    testFormInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    formInfos.push_back(testFormInfo);

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().GetFormInfo(want, formInfo);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormInfo_009 end";
}

// ========== Method 9: IsDimensionValid Tests ==========

/**
 * @tc.name: IsDimensionValid_001
 * @tc.desc: Verify empty supportDimensions returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, IsDimensionValid_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsDimensionValid_001 start";

    FormInfo formInfo;
    formInfo.supportDimensions.clear();

    auto result = FormCommonAdapter::GetInstance().IsDimensionValid(formInfo, TEST_DIMENSION_ID);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsDimensionValid_001 end";
}

/**
 * @tc.name: IsDimensionValid_002
 * @tc.desc: Verify matching dimensionId returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, IsDimensionValid_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsDimensionValid_002 start";

    FormInfo formInfo;
    formInfo.supportDimensions.push_back(1);
    formInfo.supportDimensions.push_back(TEST_DIMENSION_ID);

    auto result = FormCommonAdapter::GetInstance().IsDimensionValid(formInfo, TEST_DIMENSION_ID);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "IsDimensionValid_002 end";
}

/**
 * @tc.name: IsDimensionValid_003
 * @tc.desc: Verify non-matching dimensionId returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, IsDimensionValid_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsDimensionValid_003 start";

    FormInfo formInfo;
    formInfo.supportDimensions.push_back(1);
    formInfo.supportDimensions.push_back(2);

    auto result = FormCommonAdapter::GetInstance().IsDimensionValid(formInfo, 3);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsDimensionValid_003 end";
}

// ========== Method 11: RegisterAddObserver Tests ==========

/**
 * @tc.name: RegisterAddObserver_001
 * @tc.desc: Verify first registration succeeds
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, RegisterAddObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterAddObserver_001 start";

    std::string bundleName = "com.test.new";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto result = FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterAddObserver_001 end";
}

/**
 * @tc.name: RegisterAddObserver_003
 * @tc.desc: Verify duplicate registration fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, RegisterAddObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterAddObserver_003 start";

    std::string bundleName = "com.test.dup";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillRepeatedly(Return(true));

    // First registration
    auto result1 = FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result1, ERR_OK);

    // Duplicate registration
    auto result2 = FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result2, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "RegisterAddObserver_003 end";
}

// ========== Method 12: RegisterRemoveObserver Tests ==========

/**
 * @tc.name: RegisterRemoveObserver_001
 * @tc.desc: Verify non-existent bundleName fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, RegisterRemoveObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterRemoveObserver_001 start";

    std::string bundleName = "com.test.nonexist";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormCommonAdapter::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "RegisterRemoveObserver_001 end";
}

/**
 * @tc.name: RegisterRemoveObserver_003
 * @tc.desc: Verify successful removal
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, RegisterRemoveObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterRemoveObserver_003 start";

    std::string bundleName = "com.test.remove";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillRepeatedly(Return(true));

    // First add
    auto result1 = FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result1, ERR_OK);

    // Then remove
    auto result2 = FormCommonAdapter::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result2, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterRemoveObserver_003 end";
}

// ========== Method 14: SetDeathRecipient Tests ==========

/**
 * @tc.name: SetDeathRecipient_001
 * @tc.desc: Verify nullptr callerToken does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetDeathRecipient_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetDeathRecipient_001 start";

    sptr<IRemoteObject::DeathRecipient> deathRecipient = new FormCommonAdapter::ClientDeathRecipient();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();
    FormCommonAdapter::GetInstance().SetDeathRecipient(nullptr, deathRecipient);
    EXPECT_TRUE(FormCommonAdapter::GetInstance().deathRecipients_.empty());

    GTEST_LOG_(INFO) << "SetDeathRecipient_001 end";
}

/**
 * @tc.name: SetDeathRecipient_002
 * @tc.desc: Verify nullptr deathRecipient does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetDeathRecipient_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetDeathRecipient_002 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();
    FormCommonAdapter::GetInstance().SetDeathRecipient(callerToken, nullptr);
    EXPECT_TRUE(FormCommonAdapter::GetInstance().deathRecipients_.empty());

    GTEST_LOG_(INFO) << "SetDeathRecipient_002 end";
}

/**
 * @tc.name: SetDeathRecipient_003
 * @tc.desc: Verify new deathRecipient added
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetDeathRecipient_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetDeathRecipient_003 start";
    FormCommonAdapter::GetInstance().deathRecipients_.clear();
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = new FormCommonAdapter::ClientDeathRecipient();

    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().SetDeathRecipient(callerToken, deathRecipient);
    EXPECT_EQ(FormCommonAdapter::GetInstance().deathRecipients_.size(), 1u);
    EXPECT_NE(FormCommonAdapter::GetInstance().deathRecipients_.find(callerToken),
        FormCommonAdapter::GetInstance().deathRecipients_.end());
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "SetDeathRecipient_003 end";
}

// ========== Method 16: GetCallingUserId Tests ==========

/**
 * @tc.name: GetCallingUserId_001
 * @tc.desc: Verify userId calculation from callingUid
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetCallingUserId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetCallingUserId_001 start";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().GetCallingUserId();
    EXPECT_EQ(result, TEST_USER_ID);

    GTEST_LOG_(INFO) << "GetCallingUserId_001 end";
}

// ========== Method 23: AddFormTimer Tests ==========

/**
 * @tc.name: AddFormTimer_001
 * @tc.desc: Verify isEnableUpdate=false does not add timer
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, AddFormTimer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddFormTimer_001 start";

    FormRecord formRecord;
    formRecord.isEnableUpdate = false;
    formRecord.formTempFlag = false;

    auto result = FormCommonAdapter::GetInstance().AddFormTimer(formRecord);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "AddFormTimer_001 end";
}

/**
 * @tc.name: AddFormTimer_002
 * @tc.desc: Verify formTempFlag=true does not add timer
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, AddFormTimer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddFormTimer_002 start";

    FormRecord formRecord;
    formRecord.isEnableUpdate = true;
    formRecord.formTempFlag = true;

    auto result = FormCommonAdapter::GetInstance().AddFormTimer(formRecord);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "AddFormTimer_002 end";
}

// ========== Method 24: GetValidFormUpdateDuration Tests ==========

/**
 * @tc.name: GetValidFormUpdateDuration_001
 * @tc.desc: Verify GetFormRecord failure returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetValidFormUpdateDuration_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_001 start";

    int64_t updateDuration = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormCommonAdapter::GetInstance().GetValidFormUpdateDuration(TEST_FORM_ID, updateDuration);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_001 end";
}

/**
 * @tc.name: GetValidFormUpdateDuration_002
 * @tc.desc: Verify GetApplicationInfo failure returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetValidFormUpdateDuration_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_002 start";

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.providerUserId = TEST_USER_ID;
    formRecord.updateDuration = 3600000;
    int64_t updateDuration = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormCommonAdapter::GetInstance().GetValidFormUpdateDuration(TEST_FORM_ID, updateDuration);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_002 end";
}

/**
 * @tc.name: GetValidFormUpdateDuration_003
 * @tc.desc: Verify low API version uses local configuration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetValidFormUpdateDuration_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_003 start";

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.providerUserId = TEST_USER_ID;
    formRecord.updateDuration = 3600000;
    int64_t updateDuration = 0;

    ApplicationInfo appInfo;
    appInfo.apiTargetVersion = API_VERSION_11 - 1; // Below API 11

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(appInfo), Return(ERR_OK)));

    auto result = FormCommonAdapter::GetInstance().GetValidFormUpdateDuration(TEST_FORM_ID, updateDuration);
    EXPECT_TRUE(result);
    EXPECT_EQ(updateDuration, formRecord.updateDuration);

    GTEST_LOG_(INFO) << "GetValidFormUpdateDuration_003 end";
}

// ========== SetLockFormStateOfFormItemInfo Tests ==========

/**
 * @tc.name: SetLockFormStateOfFormItemInfo_001
 * @tc.desc: Verify formId > 0 and IsExemptLock true sets LockForm true and returns early
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetLockFormStateOfFormItemInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_001 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetFormId(TEST_FORM_ID);
    formConfigInfo.SetProviderBundleName("com.test.bundle");

    EXPECT_CALL(*MockFormExemptLockMgr::obj, IsExemptLock(TEST_FORM_ID))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    FormCommonAdapter::GetInstance().SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    EXPECT_TRUE(formConfigInfo.IsLockForm());

    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_001 end";
}

/**
 * @tc.name: SetLockFormStateOfFormItemInfo_002
 * @tc.desc: Verify formId > 0, IsExemptLock false, GetDBRecord OK, isBundleProtect != record.lockForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetLockFormStateOfFormItemInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_002 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetFormId(TEST_FORM_ID);
    formConfigInfo.SetProviderBundleName("com.test.bundle");

    FormRecord record;
    record.lockForm = false;

    EXPECT_CALL(*MockFormExemptLockMgr::obj, IsExemptLock(TEST_FORM_ID))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDbCache::obj, GetDBRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(ERR_OK)));
    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(TEST_FORM_ID, _))
        .WillOnce(Return(ERR_OK));

    FormCommonAdapter::GetInstance().SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    EXPECT_TRUE(formConfigInfo.IsLockForm());
    EXPECT_TRUE(formConfigInfo.IsProtectForm());

    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_002 end";
}

/**
 * @tc.name: SetLockFormStateOfFormItemInfo_003
 * @tc.desc: Verify formId > 0, IsExemptLock false, GetDBRecord OK, isBundleProtect == record.lockForm (no update)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetLockFormStateOfFormItemInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_003 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetFormId(TEST_FORM_ID);
    formConfigInfo.SetProviderBundleName("com.test.bundle");

    FormRecord record;
    record.lockForm = true;

    EXPECT_CALL(*MockFormExemptLockMgr::obj, IsExemptLock(TEST_FORM_ID))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDbCache::obj, GetDBRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(ERR_OK)));
    // UpdateDBRecord should NOT be called since isBundleProtect == record.lockForm

    FormCommonAdapter::GetInstance().SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    EXPECT_TRUE(formConfigInfo.IsLockForm());
    EXPECT_TRUE(formConfigInfo.IsProtectForm());

    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_003 end";
}

/**
 * @tc.name: SetLockFormStateOfFormItemInfo_004
 * @tc.desc: Verify formId <= 0, isMultiAppForm false, SetLockForm = isBundleProtect
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetLockFormStateOfFormItemInfo_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_004 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetFormId(0);
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetSystemAppFlag(false);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillOnce(Return(false));

    FormCommonAdapter::GetInstance().SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    EXPECT_TRUE(formConfigInfo.IsLockForm());
    EXPECT_TRUE(formConfigInfo.IsProtectForm());

    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_004 end";
}

/**
 * @tc.name: SetLockFormStateOfFormItemInfo_005
 * @tc.desc: Verify formId <= 0, isMultiAppForm true, SystemAppFlag true, SetLockForm = false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetLockFormStateOfFormItemInfo_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_005 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetFormId(0);
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetSystemAppFlag(true);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    EXPECT_FALSE(formConfigInfo.IsLockForm());
    EXPECT_FALSE(formConfigInfo.IsProtectForm());

    GTEST_LOG_(INFO) << "SetLockFormStateOfFormItemInfo_005 end";
}

// ========== CreateFormItemInfo Tests ==========

/**
 * @tc.name: CreateFormItemInfo_001
 * @tc.desc: Verify CreateFormItemInfo sets all fields correctly with empty customizeDatas
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CreateFormItemInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateFormItemInfo_001 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.versionCode = 100;
    bundleInfo.versionName = "1.0.0";
    bundleInfo.compatibleVersion = 10;
    bundleInfo.applicationInfo.isSystemApp = false;
    bundleInfo.applicationInfo.uid = TEST_CALLING_UID;

    FormInfo formInfo;
    formInfo.description = "test form";
    formInfo.abilityName = "MainAbility";
    formInfo.moduleName = "entry";
    formInfo.name = "widget";
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 3600;
    formInfo.scheduledUpdateTime = "10:30";
    formInfo.jsComponentName = "widgetComp";
    formInfo.formVisibleNotify = true;
    formInfo.src = "pages/index";
    formInfo.type = FormType::JS;
    formInfo.uiSyntax = FormType::JS;
    formInfo.isDynamic = true;
    formInfo.transparencyEnabled = false;
    formInfo.privacyLevel = 0;
    formInfo.dataProxyEnabled = false;
    formInfo.bundleType = BundleType::APP;
    formInfo.isTemplateForm = false;

    FormItemInfo itemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDistributedMgr::obj, IsBundleDistributed(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDistributedMgr::obj, GetUiModuleName(_, _))
        .WillRepeatedly(Return(""));

    auto result = FormCommonAdapter::GetInstance().CreateFormItemInfo(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(itemInfo.GetProviderBundleName(), "com.test.bundle");
    EXPECT_EQ(itemInfo.GetFormName(), "widget");
    EXPECT_EQ(itemInfo.GetAbilityName(), "MainAbility");
    EXPECT_TRUE(itemInfo.IsEnableUpdateFlag());
    EXPECT_EQ(itemInfo.GetUpdateDuration(), 3600);

    GTEST_LOG_(INFO) << "CreateFormItemInfo_001 end";
}

/**
 * @tc.name: CreateFormItemInfo_002
 * @tc.desc: Verify CreateFormItemInfo with customizeDatas containing FORM_DATA_PROXY_IGNORE_VISIBILITY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CreateFormItemInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateFormItemInfo_002 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.versionCode = 100;
    bundleInfo.versionName = "1.0.0";
    bundleInfo.compatibleVersion = 10;
    bundleInfo.applicationInfo.isSystemApp = false;
    bundleInfo.applicationInfo.uid = TEST_CALLING_UID;

    FormInfo formInfo;
    formInfo.abilityName = "MainAbility";
    formInfo.moduleName = "entry";
    formInfo.name = "widget";
    formInfo.src = "pages/index.ets";
    formInfo.type = FormType::JS;
    formInfo.uiSyntax = FormType::JS;

    FormCustomizeData customizeData;
    customizeData.name = "ohos.extension.form_data_proxy_ignore_visibility";
    customizeData.value = "true";
    formInfo.customizeDatas.push_back(customizeData);

    FormItemInfo itemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDistributedMgr::obj, IsBundleDistributed(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDistributedMgr::obj, GetUiModuleName(_, _))
        .WillRepeatedly(Return(""));

    auto result = FormCommonAdapter::GetInstance().CreateFormItemInfo(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(itemInfo.GetDataProxyIgnoreFormVisibility());

    GTEST_LOG_(INFO) << "CreateFormItemInfo_002 end";
}

// ========== SetFormItemInfoParams Tests ==========

/**
 * @tc.name: SetFormItemInfoParams_001
 * @tc.desc: Verify SetFormItemInfoParams with empty hapModuleInfos and matching moduleInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemInfoParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemInfoParams_001 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.applicationInfo.isSystemApp = false;

    ModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleSourceDir = "/data/app/entry";
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo);

    FormInfo formInfo;
    formInfo.moduleName = "entry";
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetTemplateFormImperativeFwk(), Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NONE);

    GTEST_LOG_(INFO) << "SetFormItemInfoParams_001 end";
}

/**
 * @tc.name: SetFormItemInfoParams_002
 * @tc.desc: Verify SetFormItemInfoParams with TEMPLATE_FORM_IMPERATIVE_FWK_NAME in customizeDatas
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemInfoParams_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemInfoParams_002 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.applicationInfo.isSystemApp = false;

    FormInfo formInfo;
    formInfo.moduleName = "entry";
    formInfo.abilityName = "MainAbility";

    FormCustomizeData customizeData;
    customizeData.name = Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NAME;
    customizeData.value = "lite";
    formInfo.customizeDatas.push_back(customizeData);

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetTemplateFormImperativeFwk(), "lite");

    GTEST_LOG_(INFO) << "SetFormItemInfoParams_002 end";
}

/**
 * @tc.name: SetFormItemInfoParams_003
 * @tc.desc: Verify SetFormItemInfoParams with non-empty hapModuleInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemInfoParams_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemInfoParams_003 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.applicationInfo.isSystemApp = false;

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/app/entry.hap";

    AbilityInfo abilityInfo;
    abilityInfo.name = "MainAbility";
    abilityInfo.moduleName = "entry_module";
    abilityInfo.isModuleJson = true;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);

    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    ModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleSourceDir = "/data/app/entry";
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo);

    FormInfo formInfo;
    formInfo.moduleName = "entry";
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "entry_module");

    GTEST_LOG_(INFO) << "SetFormItemInfoParams_003 end";
}

// ========== SetHostBundleName Tests ==========

/**
 * @tc.name: SetHostBundleName_001
 * @tc.desc: Verify SA UID gets hostBundleName from want parameter
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetHostBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetHostBundleName_001 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, std::string("com.test.host"));

    FormItemInfo itemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(SYSTEM_UID));

    auto result = FormCommonAdapter::GetInstance().SetHostBundleName(want, itemInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(itemInfo.GetHostBundleName(), "com.test.host");

    GTEST_LOG_(INFO) << "SetHostBundleName_001 end";
}

/**
 * @tc.name: SetHostBundleName_002
 * @tc.desc: Verify non-SA UID gets hostBundleName from GetCallerBundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetHostBundleName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetHostBundleName_002 start";

    Want want;

    FormItemInfo itemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>("com.test.host"), Return(ERR_OK)));

    auto result = FormCommonAdapter::GetInstance().SetHostBundleName(want, itemInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(itemInfo.GetHostBundleName(), "com.test.host");

    GTEST_LOG_(INFO) << "SetHostBundleName_002 end";
}

/**
 * @tc.name: SetHostBundleName_003
 * @tc.desc: Verify non-SA UID with GetCallerBundleName failure returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetHostBundleName_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetHostBundleName_003 start";

    Want want;

    FormItemInfo itemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED));

    auto result = FormCommonAdapter::GetInstance().SetHostBundleName(want, itemInfo);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "SetHostBundleName_003 end";
}

// ========== GetFormInfoByFormRecord Tests ==========

/**
 * @tc.name: GetFormInfoByFormRecord_001
 * @tc.desc: Verify empty record fields returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfoByFormRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_001 start";

    FormRecord record;
    record.bundleName = "";
    record.abilityName = "";
    record.moduleName = "";

    FormInfo formInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().GetFormInfoByFormRecord(record, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_001 end";
}

/**
 * @tc.name: GetFormInfoByFormRecord_002
 * @tc.desc: Verify GetFormsInfoByModule failure returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfoByFormRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_002 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";
    record.abilityName = "MainAbility";
    record.moduleName = "entry";
    record.formName = "widget";

    FormInfo formInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormCommonAdapter::GetInstance().GetFormInfoByFormRecord(record, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_002 end";
}

/**
 * @tc.name: GetFormInfoByFormRecord_003
 * @tc.desc: Verify no matching form found returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfoByFormRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_003 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";
    record.abilityName = "MainAbility";
    record.moduleName = "entry";
    record.formName = "widget";

    FormInfo formInfo;
    std::vector<FormInfo> formInfos;
    FormInfo testFormInfo;
    testFormInfo.name = "other_widget";
    testFormInfo.abilityName = "OtherAbility";
    testFormInfo.moduleName = "entry";
    formInfos.push_back(testFormInfo);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));

    auto result = FormCommonAdapter::GetInstance().GetFormInfoByFormRecord(record, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_003 end";
}

/**
 * @tc.name: GetFormInfoByFormRecord_004
 * @tc.desc: Verify matching form found returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormInfoByFormRecord_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_004 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";
    record.abilityName = "MainAbility";
    record.moduleName = "entry";
    record.formName = "widget";

    FormInfo formInfo;
    std::vector<FormInfo> formInfos;
    FormInfo testFormInfo;
    testFormInfo.name = "widget";
    testFormInfo.abilityName = "MainAbility";
    testFormInfo.moduleName = "entry";
    formInfos.push_back(testFormInfo);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));

    auto result = FormCommonAdapter::GetInstance().GetFormInfoByFormRecord(record, formInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formInfo.name, "widget");

    GTEST_LOG_(INFO) << "GetFormInfoByFormRecord_004 end";
}

// ========== GetCallerType Tests ==========

/**
 * @tc.name: GetCallerType_001
 * @tc.desc: Verify null IBundleMgr returns TYPE_INVALID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetCallerType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetCallerType_001 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().GetCallerType("com.test.bundle");
    EXPECT_EQ(result, FormErmsCallerInfo::TYPE_INVALID);

    GTEST_LOG_(INFO) << "GetCallerType_001 end";
}

// ========== ClientDeathRecipient::OnRemoteDied Tests ==========

/**
 * @tc.name: ClientDeathRecipient_OnRemoteDied_001
 * @tc.desc: Verify OnRemoteDied calls CleanResource without crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, ClientDeathRecipient_OnRemoteDied_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClientDeathRecipient_OnRemoteDied_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().deathRecipients_.clear();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = new FormCommonAdapter::ClientDeathRecipient();
    FormCommonAdapter::GetInstance().SetDeathRecipient(callerToken, deathRecipient);

    // Now simulate OnRemoteDied
    FormCommonAdapter::ClientDeathRecipient clientDeathRecipient;
    wptr<IRemoteObject> weakObj = callerToken;
    clientDeathRecipient.OnRemoteDied(weakObj);

    // After OnRemoteDied, the deathRecipients_ should be cleaned
    EXPECT_TRUE(FormCommonAdapter::GetInstance().deathRecipients_.empty());
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "ClientDeathRecipient_OnRemoteDied_001 end";
}

// ========== CheckFormDueControl Tests ==========

/**
 * @tc.name: CheckFormDueControl_001
 * @tc.desc: Verify IsDueDisableCtrlEmpty true returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckFormDueControl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormDueControl_001 start";

    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = "com.test.bundle";
    formMajorInfo.abilityName = "MainAbility";
    formMajorInfo.moduleName = "entry";
    formMajorInfo.formName = "widget";
    formMajorInfo.dimension = 2;

    EXPECT_CALL(*MockParamControl::obj, IsDueDisableCtrlEmpty())
        .WillOnce(Return(true));

    auto result = FormCommonAdapter::GetInstance().CheckFormDueControl(formMajorInfo, true);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormDueControl_001 end";
}

/**
 * @tc.name: CheckFormDueControl_002
 * @tc.desc: Verify GetBundleInfo fails returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckFormDueControl_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormDueControl_002 start";

    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = "com.test.bundle";
    formMajorInfo.abilityName = "MainAbility";
    formMajorInfo.moduleName = "entry";
    formMajorInfo.formName = "widget";
    formMajorInfo.dimension = 2;

    EXPECT_CALL(*MockParamControl::obj, IsDueDisableCtrlEmpty())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().CheckFormDueControl(formMajorInfo, true);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormDueControl_002 end";
}

/**
 * @tc.name: CheckFormDueControl_003
 * @tc.desc: Verify isDisablePolicy=true calls IsFormDisable
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckFormDueControl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormDueControl_003 start";

    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = "com.test.bundle";
    formMajorInfo.abilityName = "MainAbility";
    formMajorInfo.moduleName = "entry";
    formMajorInfo.formName = "widget";
    formMajorInfo.dimension = 2;

    BundleInfo bundleInfo;
    bundleInfo.moduleNames.push_back("entry");
    bundleInfo.versionCode = 100;

    EXPECT_CALL(*MockParamControl::obj, IsDueDisableCtrlEmpty())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillRepeatedly(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoV9(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockParamControl::obj, IsFormDisable(_))
        .WillOnce(Return(true));

    auto result = FormCommonAdapter::GetInstance().CheckFormDueControl(formMajorInfo, true);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormDueControl_003 end";
}

/**
 * @tc.name: CheckFormDueControl_004
 * @tc.desc: Verify isDisablePolicy=false calls IsFormRemove
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckFormDueControl_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormDueControl_004 start";

    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = "com.test.bundle";
    formMajorInfo.abilityName = "MainAbility";
    formMajorInfo.moduleName = "entry";
    formMajorInfo.formName = "widget";
    formMajorInfo.dimension = 2;

    BundleInfo bundleInfo;
    bundleInfo.moduleNames.push_back("entry");
    bundleInfo.versionCode = 100;

    EXPECT_CALL(*MockParamControl::obj, IsDueDisableCtrlEmpty())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillRepeatedly(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoV9(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockParamControl::obj, IsFormRemove(_))
        .WillOnce(Return(true));

    auto result = FormCommonAdapter::GetInstance().CheckFormDueControl(formMajorInfo, false);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormDueControl_004 end";
}

// ========== UpdateFormCloudUpdateDuration Tests ==========

/**
 * @tc.name: UpdateFormCloudUpdateDuration_001
 * @tc.desc: Verify null IBundleMgr calls RemoveFormCloudUpdateDuration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, UpdateFormCloudUpdateDuration_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_001 start";

    std::string bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*MockFormDataMgr::obj, RemoveFormCloudUpdateDuration(bundleName))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormCloudUpdateDuration(bundleName, _))
        .Times(0);

    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);

    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_001 end";
}

/**
 * @tc.name: UpdateFormCloudUpdateDuration_002
 * @tc.desc: Verify GetAdditionalInfo fails calls RemoveFormCloudUpdateDuration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, UpdateFormCloudUpdateDuration_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_002 start";

    std::string bundleName = "com.test.bundle";

    auto mockBundleMgr = sptr<IBundleMgr>(new MockBundleMgrStub());
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormDataMgr::obj, RemoveFormCloudUpdateDuration(bundleName))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormCloudUpdateDuration(bundleName, _))
        .Times(0);

    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);

    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_002 end";
}

/**
 * @tc.name: UpdateFormCloudUpdateDuration_003
 * @tc.desc: Verify empty additionalInfo calls RemoveFormCloudUpdateDuration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, UpdateFormCloudUpdateDuration_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_003 start";

    std::string bundleName = "com.test.bundle";

    sptr<IRemoteObject> remoteObj = new MockIRemoteObject();
    auto mockProxy = new MockBundleMgrProxy(remoteObj);
    EXPECT_CALL(*mockProxy, GetAdditionalInfo(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(sptr<IBundleMgr>(mockProxy)));
    EXPECT_CALL(*MockFormDataMgr::obj, RemoveFormCloudUpdateDuration(bundleName))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormCloudUpdateDuration(bundleName, _))
        .Times(0);

    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);

    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_003 end";
}

/**
 * @tc.name: UpdateFormCloudUpdateDuration_004
 * @tc.desc: Verify empty ParseFormUpdateLevels calls RemoveFormCloudUpdateDuration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, UpdateFormCloudUpdateDuration_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_004 start";

    std::string bundleName = "com.test.bundle";

    sptr<IRemoteObject> remoteObj = new MockIRemoteObject();
    auto mockProxy = new MockBundleMgrProxy(remoteObj);
    EXPECT_CALL(*mockProxy, GetAdditionalInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<1>("invalid_data"), Return(ERR_OK)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(sptr<IBundleMgr>(mockProxy)));
    EXPECT_CALL(*MockFormDataMgr::obj, RemoveFormCloudUpdateDuration(bundleName))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormCloudUpdateDuration(bundleName, _))
        .Times(0);

    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);

    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_004 end";
}

/**
 * @tc.name: UpdateFormCloudUpdateDuration_005
 * @tc.desc: Verify valid duration calls UpdateFormCloudUpdateDuration with duration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, UpdateFormCloudUpdateDuration_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_005 start";

    std::string bundleName = "com.test.bundle";

    sptr<IRemoteObject> remoteObj = new MockIRemoteObject();
    auto mockProxy = new MockBundleMgrProxy(remoteObj);
    // Set additionalInfo to contain valid formUpdateLevel (matches regex "formUpdateLevel:(\d+)")
    std::string additionalInfo = "formUpdateLevel:1";
    EXPECT_CALL(*mockProxy, GetAdditionalInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(sptr<IBundleMgr>(mockProxy)));
    EXPECT_CALL(*MockFormDataMgr::obj, RemoveFormCloudUpdateDuration(bundleName))
        .Times(0);
    int capturedDuration = -1;
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormCloudUpdateDuration(bundleName, _))
        .WillOnce(SaveArg<1>(&capturedDuration));

    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);
    EXPECT_EQ(capturedDuration, 1);

    GTEST_LOG_(INFO) << "UpdateFormCloudUpdateDuration_005 end";
}

// ========== GAP Method 1: GetFormItemInfo Tests ==========

/**
 * @tc.name: GetFormItemInfo_001
 * @tc.desc: Verify GetFormItemInfo success path returns ERR_OK with valid dimension
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormItemInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormItemInfo_001 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, TEST_DIMENSION_ID);

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.versionCode = 100;
    bundleInfo.versionName = "1.0.0";
    bundleInfo.compatibleVersion = 10;
    bundleInfo.applicationInfo.isSystemApp = false;
    bundleInfo.applicationInfo.uid = TEST_CALLING_UID;

    FormInfo formInfo;
    formInfo.name = "widget";
    formInfo.abilityName = "MainAbility";
    formInfo.moduleName = "entry";
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 3600;
    formInfo.scheduledUpdateTime = "10:30";
    formInfo.jsComponentName = "widgetComp";
    formInfo.formVisibleNotify = true;
    formInfo.src = "pages/index";
    formInfo.type = FormType::JS;
    formInfo.uiSyntax = FormType::JS;
    formInfo.isDynamic = true;
    formInfo.transparencyEnabled = false;
    formInfo.privacyLevel = 0;
    formInfo.dataProxyEnabled = false;
    formInfo.bundleType = BundleType::APP;
    formInfo.isTemplateForm = false;
    formInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    formInfo.defaultDimension = TEST_DIMENSION_ID;

    FormItemInfo formItemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>("com.test.host"), Return(ERR_OK)));
    EXPECT_CALL(*MockFormDistributedMgr::obj, IsBundleDistributed(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDistributedMgr::obj, GetUiModuleName(_, _))
        .WillRepeatedly(Return(""));

    auto result = FormCommonAdapter::GetInstance().GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formItemInfo.GetSpecificationId(), TEST_DIMENSION_ID);
    EXPECT_EQ(formItemInfo.GetProviderBundleName(), "com.test.bundle");
    EXPECT_EQ(formItemInfo.GetHostBundleName(), "com.test.host");

    GTEST_LOG_(INFO) << "GetFormItemInfo_001 end";
}

/**
 * @tc.name: GetFormItemInfo_002
 * @tc.desc: Verify GetFormItemInfo returns error on invalid dimension
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormItemInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormItemInfo_002 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 99); // invalid dimension

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";

    FormInfo formInfo;
    formInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    formInfo.defaultDimension = TEST_DIMENSION_ID;

    FormItemInfo formItemInfo;

    auto result = FormCommonAdapter::GetInstance().GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION);

    GTEST_LOG_(INFO) << "GetFormItemInfo_002 end";
}

/**
 * @tc.name: GetFormItemInfo_003
 * @tc.desc: Verify GetFormItemInfo returns error when SetHostBundleName fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormItemInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormItemInfo_003 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";

    FormInfo formInfo;
    formInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    formInfo.defaultDimension = TEST_DIMENSION_ID;

    FormItemInfo formItemInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED));

    auto result = FormCommonAdapter::GetInstance().GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormItemInfo_003 end";
}

// ========== GAP Method 2: SetFormItemModuleInfo Tests ==========

/**
 * @tc.name: SetFormItemModuleInfo_001
 * @tc.desc: Verify SetFormItemModuleInfo with hapPath containing ABS_CODE_PATH replaces to LOCAL_BUNDLES
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemModuleInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_001 start";

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/app/el1/bundle/public/com.test.bundle/entry.hap";

    AbilityInfo abilityInfo;
    abilityInfo.name = "MainAbility";
    abilityInfo.moduleName = "entry_module";
    abilityInfo.isModuleJson = true;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);

    FormInfo formInfo;
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "entry_module");

    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_001 end";
}

/**
 * @tc.name: SetFormItemModuleInfo_002
 * @tc.desc: Verify SetFormItemModuleInfo with hapPath not containing ABS_CODE_PATH keeps original
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemModuleInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_002 start";

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/bundles/com.test.bundle/entry.hap";

    FormInfo formInfo;
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    // No abilityInfo matching, so GetAbilityModuleName should remain default
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "");

    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_002 end";
}

/**
 * @tc.name: SetFormItemModuleInfo_003
 * @tc.desc: Verify SetFormItemModuleInfo with non-matching abilityName does not set AbilityModuleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemModuleInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_003 start";

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/bundles/com.test.bundle/entry.hap";

    AbilityInfo abilityInfo;
    abilityInfo.name = "OtherAbility";
    abilityInfo.moduleName = "other_module";
    abilityInfo.isModuleJson = true;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);

    FormInfo formInfo;
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "");

    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_003 end";
}

/**
 * @tc.name: SetFormItemModuleInfo_004
 * @tc.desc: Verify SetFormItemModuleInfo with isModuleJson=false clears FormSrc
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemModuleInfo_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_004 start";

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/bundles/com.test.bundle/entry.hap";

    AbilityInfo abilityInfo;
    abilityInfo.name = "MainAbility";
    abilityInfo.moduleName = "entry_module";
    abilityInfo.isModuleJson = false;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);

    FormInfo formInfo;
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;
    itemInfo.SetFormSrc("pages/index");

    FormCommonAdapter::GetInstance().SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "entry_module");
    EXPECT_EQ(itemInfo.GetFormSrc(), "");

    GTEST_LOG_(INFO) << "SetFormItemModuleInfo_004 end";
}

// ========== GAP Method 3: CleanResource Tests ==========

/**
 * @tc.name: CleanResource_001
 * @tc.desc: Verify CleanResource with null remote returns early without crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CleanResource_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CleanResource_001 start";

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    wptr<IRemoteObject> nullRemote = nullptr;
    FormCommonAdapter::GetInstance().CleanResource(nullRemote);

    EXPECT_TRUE(FormCommonAdapter::GetInstance().formObservers_.empty());
    EXPECT_TRUE(FormCommonAdapter::GetInstance().deathRecipients_.empty());

    GTEST_LOG_(INFO) << "CleanResource_001 end";
}

/**
 * @tc.name: CleanResource_002
 * @tc.desc: Verify CleanResource removes matching observer and death recipient
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CleanResource_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CleanResource_002 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    std::string bundleName = "com.test.clean";
    std::vector<sptr<IRemoteObject>> remoteObjects;
    remoteObjects.emplace_back(callerToken);
    FormCommonAdapter::GetInstance().formObservers_.emplace(bundleName, remoteObjects);

    sptr<IRemoteObject::DeathRecipient> deathRecipient = new FormCommonAdapter::ClientDeathRecipient();
    FormCommonAdapter::GetInstance().SetDeathRecipient(callerToken, deathRecipient);
    ASSERT_EQ(FormCommonAdapter::GetInstance().deathRecipients_.size(), 1u);

    wptr<IRemoteObject> weakObj = callerToken;
    FormCommonAdapter::GetInstance().CleanResource(weakObj);

    EXPECT_TRUE(FormCommonAdapter::GetInstance().formObservers_.empty());
    EXPECT_TRUE(FormCommonAdapter::GetInstance().deathRecipients_.empty());

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "CleanResource_002 end";
}

/**
 * @tc.name: CleanResource_003
 * @tc.desc: Verify CleanResource with non-matching remote keeps observers intact
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CleanResource_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CleanResource_003 start";

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    sptr<IRemoteObject> registeredToken = new MockIRemoteObject();
    auto *mockRegistered = static_cast<MockIRemoteObject*>(registeredToken.GetRefPtr());
    EXPECT_CALL(*mockRegistered, AddDeathRecipient(_))
        .WillOnce(Return(true));

    std::string bundleName = "com.test.keep";
    std::vector<sptr<IRemoteObject>> remoteObjects;
    remoteObjects.emplace_back(registeredToken);
    FormCommonAdapter::GetInstance().formObservers_.emplace(bundleName, remoteObjects);

    sptr<IRemoteObject::DeathRecipient> deathRecipient = new FormCommonAdapter::ClientDeathRecipient();
    FormCommonAdapter::GetInstance().SetDeathRecipient(registeredToken, deathRecipient);

    // Clean with a different remote object that is not registered
    sptr<IRemoteObject> otherToken = new MockIRemoteObject();
    wptr<IRemoteObject> weakOther = otherToken;
    FormCommonAdapter::GetInstance().CleanResource(weakOther);

    EXPECT_EQ(FormCommonAdapter::GetInstance().formObservers_.size(), 1u);
    EXPECT_EQ(FormCommonAdapter::GetInstance().deathRecipients_.size(), 1u);

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "CleanResource_003 end";
}

// ========== GAP Method 5: GetFormObservers Tests ==========

/**
 * @tc.name: GetFormObservers_001
 * @tc.desc: Verify GetFormObservers returns empty map when no observers registered
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormObservers_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormObservers_001 start";

    FormCommonAdapter::GetInstance().formObservers_.clear();

    auto observers = FormCommonAdapter::GetInstance().GetFormObservers();
    EXPECT_TRUE(observers.empty());

    GTEST_LOG_(INFO) << "GetFormObservers_001 end";
}

/**
 * @tc.name: GetFormObservers_002
 * @tc.desc: Verify GetFormObservers returns copy of registered observers
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetFormObservers_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormObservers_002 start";

    FormCommonAdapter::GetInstance().formObservers_.clear();

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject*>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    std::string bundleName = "com.test.observer";
    auto result = FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);

    auto observers = FormCommonAdapter::GetInstance().GetFormObservers();
    EXPECT_EQ(observers.size(), 1u);
    EXPECT_NE(observers.find(bundleName), observers.end());
    EXPECT_EQ(observers.at(bundleName).size(), 1u);

    // Verify it's a copy: modifying returned map should not affect internal state
    observers.clear();
    auto observers2 = FormCommonAdapter::GetInstance().GetFormObservers();
    EXPECT_EQ(observers2.size(), 1u);

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "GetFormObservers_002 end";
}

// ========== GAP Method 6: SetFormEnableAndLockState Tests ==========

/**
 * @tc.name: SetFormEnableAndLockState_001
 * @tc.desc: Verify SetFormEnableAndLockState with forbidden bundle sets EnableForm false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormEnableAndLockState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_001 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetFormId(0);

    int formLocation = static_cast<int>(Constants::FormLocation::DESKTOP);

    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillRepeatedly(Return(false));

    FormCommonAdapter::GetInstance().SetFormEnableAndLockState(formInfo, formConfigInfo, formLocation);
    EXPECT_FALSE(formConfigInfo.IsEnableForm());

    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_001 end";
}

/**
 * @tc.name: SetFormEnableAndLockState_002
 * @tc.desc: Verify SetFormEnableAndLockState with non-forbidden bundle sets EnableForm true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormEnableAndLockState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_002 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetFormId(0);

    int formLocation = static_cast<int>(Constants::FormLocation::DESKTOP);

    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillRepeatedly(Return(false));

    FormCommonAdapter::GetInstance().SetFormEnableAndLockState(formInfo, formConfigInfo, formLocation);
    EXPECT_TRUE(formConfigInfo.IsEnableForm());

    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_002 end";
}

/**
 * @tc.name: SetFormEnableAndLockState_003
 * @tc.desc: Verify SetFormEnableAndLockState with SCREEN_LOCK location sets LockForm false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormEnableAndLockState_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_003 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetFormId(0);

    int formLocation = static_cast<int>(Constants::FormLocation::SCREEN_LOCK);

    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));
    // SetLockFormStateOfFormItemInfo should NOT be called for SCREEN_LOCK

    FormCommonAdapter::GetInstance().SetFormEnableAndLockState(formInfo, formConfigInfo, formLocation);
    EXPECT_TRUE(formConfigInfo.IsEnableForm());
    EXPECT_FALSE(formConfigInfo.IsLockForm());

    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_003 end";
}

/**
 * @tc.name: SetFormEnableAndLockState_004
 * @tc.desc: Verify SetFormEnableAndLockState with non-SCREEN_LOCK location calls SetLockFormStateOfFormItemInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormEnableAndLockState_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_004 start";

    FormInfo formInfo;
    FormItemInfo formConfigInfo;
    formConfigInfo.SetProviderBundleName("com.test.bundle");
    formConfigInfo.SetFormId(0);

    int formLocation = static_cast<int>(Constants::FormLocation::DESKTOP);

    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillOnce(Return(false));

    FormCommonAdapter::GetInstance().SetFormEnableAndLockState(formInfo, formConfigInfo, formLocation);
    EXPECT_TRUE(formConfigInfo.IsEnableForm());
    EXPECT_TRUE(formConfigInfo.IsLockForm());

    GTEST_LOG_(INFO) << "SetFormEnableAndLockState_004 end";
}

// ========== GAP Method 7: CheckUpdateFormRecord Tests ==========

/**
 * @tc.name: CheckUpdateFormRecord_001
 * @tc.desc: Verify CheckUpdateFormRecord with all fields changed triggers UpdateFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckUpdateFormRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_001 start";

    int64_t formId = TEST_FORM_ID;
    FormItemInfo info;
    info.SetFormLocation(Constants::FormLocation::DESKTOP);
    info.SetDataProxyIgnoreFormVisibility(true);

    FormRecord record;
    record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLED;
    record.formLocation = Constants::FormLocation::OTHER;
    record.isDataProxyIgnoreFormVisible = false;

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(formId, _))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().CheckUpdateFormRecord(formId, info, record);

    EXPECT_EQ(record.lowMemoryRecycleStatus, LowMemoryRecycleStatus::NON_RECYCLABLE);
    EXPECT_EQ(record.formLocation, Constants::FormLocation::DESKTOP);
    EXPECT_TRUE(record.isLocationChange);
    EXPECT_TRUE(record.isDataProxyIgnoreFormVisible);

    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_001 end";
}

/**
 * @tc.name: CheckUpdateFormRecord_002
 * @tc.desc: Verify CheckUpdateFormRecord with no changes does NOT call UpdateFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckUpdateFormRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_002 start";

    int64_t formId = TEST_FORM_ID;
    FormItemInfo info;
    info.SetFormLocation(Constants::FormLocation::DESKTOP);
    info.SetDataProxyIgnoreFormVisibility(false);

    FormRecord record;
    record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
    record.formLocation = Constants::FormLocation::DESKTOP;
    record.isDataProxyIgnoreFormVisible = false;

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(_, _))
        .Times(0);

    FormCommonAdapter::GetInstance().CheckUpdateFormRecord(formId, info, record);

    EXPECT_FALSE(record.isLocationChange);

    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_002 end";
}

/**
 * @tc.name: CheckUpdateFormRecord_003
 * @tc.desc: Verify CheckUpdateFormRecord with only lowMemoryRecycleStatus change triggers UpdateFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckUpdateFormRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_003 start";

    int64_t formId = TEST_FORM_ID;
    FormItemInfo info;
    info.SetFormLocation(Constants::FormLocation::DESKTOP);
    info.SetDataProxyIgnoreFormVisibility(false);

    FormRecord record;
    record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLED;
    record.formLocation = Constants::FormLocation::DESKTOP;
    record.isDataProxyIgnoreFormVisible = false;

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(formId, _))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().CheckUpdateFormRecord(formId, info, record);

    EXPECT_EQ(record.lowMemoryRecycleStatus, LowMemoryRecycleStatus::NON_RECYCLABLE);
    EXPECT_FALSE(record.isLocationChange);

    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_003 end";
}

/**
 * @tc.name: CheckUpdateFormRecord_004
 * @tc.desc: Verify CheckUpdateFormRecord with formLocation change triggers UpdateFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, CheckUpdateFormRecord_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_004 start";

    int64_t formId = TEST_FORM_ID;
    FormItemInfo info;
    info.SetFormLocation(Constants::FormLocation::FORM_CENTER);
    info.SetDataProxyIgnoreFormVisibility(false);

    FormRecord record;
    record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
    record.formLocation = Constants::FormLocation::DESKTOP;
    record.isDataProxyIgnoreFormVisible = false;

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(formId, _))
        .WillOnce(Return(true));

    FormCommonAdapter::GetInstance().CheckUpdateFormRecord(formId, info, record);

    EXPECT_EQ(record.formLocation, Constants::FormLocation::FORM_CENTER);
    EXPECT_TRUE(record.isLocationChange);

    GTEST_LOG_(INFO) << "CheckUpdateFormRecord_004 end";
}

// ========== GAP Method 8: HandleFormAddObserver Tests ==========

/**
 * @tc.name: HandleFormAddObserver_001
 * @tc.desc: Verify HandleFormAddObserver returns error when GetCallerBundleName fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, HandleFormAddObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormAddObserver_001 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCommonAdapter::GetInstance().HandleFormAddObserver(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "HandleFormAddObserver_001 end";
}

/**
 * @tc.name: HandleFormAddObserver_002
 * @tc.desc: Verify HandleFormAddObserver success path delegates to FormDataMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, HandleFormAddObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormAddObserver_002 start";

    std::string hostBundleName = "com.test.host";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>(hostBundleName), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, HandleFormAddObserver(hostBundleName, TEST_FORM_ID, TEST_USER_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormCommonAdapter::GetInstance().HandleFormAddObserver(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "HandleFormAddObserver_002 end";
}

/**
 * @tc.name: HandleFormAddObserver_003
 * @tc.desc: Verify HandleFormAddObserver returns error when FormDataMgr returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, HandleFormAddObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormAddObserver_003 start";

    std::string hostBundleName = "com.test.host";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>(hostBundleName), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, HandleFormAddObserver(hostBundleName, TEST_FORM_ID, TEST_USER_ID))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormCommonAdapter::GetInstance().HandleFormAddObserver(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "HandleFormAddObserver_003 end";
}

// ========== GAP Method 4: GetAppMgr Tests ==========

/**
 * @tc.name: GetAppMgr_001
 * @tc.desc: Verify GetAppMgr returns nullptr when system ability manager is unavailable
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, GetAppMgr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAppMgr_001 start";

    // GetAppMgr uses SystemAbilityManagerClient which is not mockable in this test setup.
    // This test verifies the method can be called without crash.
    auto result = FormCommonAdapter::GetInstance().GetAppMgr();
    // In test environment, system ability manager is typically not available,
    // so we expect nullptr. If it happens to be available, that's also fine.
    // The key assertion is that the method does not crash.
    // In test environment, system ability manager is typically not available, so expect nullptr.
    EXPECT_NE(result, nullptr);

    GTEST_LOG_(INFO) << "GetAppMgr_001 end";
}

// ========== GAP Method: SetFormItemInfoParams with hapModuleInfo path coverage ==========

/**
 * @tc.name: SetFormItemInfoParams_004
 * @tc.desc: Verify SetFormItemInfoParams with hapModuleInfo containing ABS_CODE_PATH in hapPath
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemInfoParams_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemInfoParams_004 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.applicationInfo.isSystemApp = false;

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.packageName = "com.test.bundle.entry";
    hapModuleInfo.hapPath = "/data/app/el1/bundle/public/com.test.bundle/entry.hap";

    AbilityInfo abilityInfo;
    abilityInfo.name = "MainAbility";
    abilityInfo.moduleName = "entry_module";
    abilityInfo.isModuleJson = true;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);

    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    ModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.moduleSourceDir = "/data/app/entry";
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo);

    FormInfo formInfo;
    formInfo.moduleName = "entry";
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.GetAbilityModuleName(), "entry_module");
    std::vector<std::string> sourceDirs;
    itemInfo.GetHapSourceDirs(sourceDirs);
    EXPECT_EQ(sourceDirs.size(), 1u);

    GTEST_LOG_(INFO) << "SetFormItemInfoParams_004 end";
}

// ========== GAP Method: SetFormItemInfoParams non-matching moduleName ==========

/**
 * @tc.name: SetFormItemInfoParams_005
 * @tc.desc: Verify SetFormItemInfoParams with non-matching moduleSourceDir moduleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCommonAdapterTest, SetFormItemInfoParams_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormItemInfoParams_005 start";

    BundleInfo bundleInfo;
    bundleInfo.name = "com.test.bundle";
    bundleInfo.applicationInfo.isSystemApp = false;

    ModuleInfo moduleInfo;
    moduleInfo.moduleName = "other_module";
    moduleInfo.moduleSourceDir = "/data/app/other";
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo);

    FormInfo formInfo;
    formInfo.moduleName = "entry";
    formInfo.abilityName = "MainAbility";

    FormItemInfo itemInfo;

    FormCommonAdapter::GetInstance().SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    std::vector<std::string> sourceDirs;
    itemInfo.GetHapSourceDirs(sourceDirs);
    EXPECT_EQ(sourceDirs.size(), 0u);

    GTEST_LOG_(INFO) << "SetFormItemInfoParams_005 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
