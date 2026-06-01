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

}  // namespace AppExecFwk
}  // namespace OHOS
