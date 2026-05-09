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
#include "form_mgr/form_query_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "want.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_state_info.h"
#include "running_form_info.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_ams_helper.h"
#include "mock_form_timer_mgr.h"
#include "mock_form_db_cache.h"
#include "mock_ipc_skeleton.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int32_t TEST_DIMENSION_ID = 2;
}

class FmsFormQueryAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormQueryAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormAmsHelper::obj = std::make_shared<MockFormAmsHelper>();
    MockFormTimerMgr::obj = std::make_shared<MockFormTimerMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormQueryAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    MockFormAmsHelper::obj = nullptr;
    MockFormTimerMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
}

void FmsFormQueryAdapterTest::SetUp()
{
}

void FmsFormQueryAdapterTest::TearDown()
{
}

// ========== GetAllFormsInfo Tests ==========

/**
 * @tc.name: GetAllFormsInfo_001
 * @tc.desc: Verify FormInfoMgr::GetAllFormsInfo returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetAllFormsInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAllFormsInfo_001 start";

    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetAllFormsInfo(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetAllFormsInfo_001 end";
}

/**
 * @tc.name: GetAllFormsInfo_002
 * @tc.desc: Verify FormInfoMgr::GetAllFormsInfo returns ERR_OK with data
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetAllFormsInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAllFormsInfo_002 start";

    std::vector<FormInfo> formInfos;
    FormInfo formInfo;
    formInfo.name = "widget";
    std::vector<FormInfo> testInfos = {formInfo};

    EXPECT_CALL(*MockFormInfoMgr::obj, GetAllFormsInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(testInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formInfos.size(), 1u);

    GTEST_LOG_(INFO) << "GetAllFormsInfo_002 end";
}

// ========== GetFormsInfoByApp Tests ==========

/**
 * @tc.name: GetFormsInfoByApp_001
 * @tc.desc: Verify FormInfoMgr::GetFormsInfoByBundle returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByApp_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByApp_001 start";

    std::string bundleName = "com.test.bundle";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByBundle(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormsInfoByApp_001 end";
}

/**
 * @tc.name: GetFormsInfoByApp_002
 * @tc.desc: Verify GetFormsInfoByBundle returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByApp_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByApp_002 start";

    std::string bundleName = "com.test.bundle";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByBundle(_, _, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormsInfoByApp_002 end";
}

// ========== GetFormsInfoByModule Tests ==========

/**
 * @tc.name: GetFormsInfoByModule_001
 * @tc.desc: Verify FormInfoMgr::GetFormsInfoByModule returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByModule_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule_001 start";

    std::string bundleName = "com.test.bundle";
    std::string moduleName = "entry";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormsInfoByModule_001 end";
}

/**
 * @tc.name: GetFormsInfoByModule_002
 * @tc.desc: Verify GetFormsInfoByModule returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByModule_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule_002 start";

    std::string bundleName = "com.test.bundle";
    std::string moduleName = "entry";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormsInfoByModule_002 end";
}

// ========== GetFormsInfoByFilter Tests ==========

/**
 * @tc.name: GetFormsInfoByFilter_001
 * @tc.desc: Verify FormInfoMgr::GetFormsInfoByFilter returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByFilter_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByFilter_001 start";

    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByFilter(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormsInfoByFilter_001 end";
}

/**
 * @tc.name: GetFormsInfoByFilter_002
 * @tc.desc: Verify GetFormsInfoByFilter returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsInfoByFilter_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByFilter_002 start";

    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByFilter(_, _, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormsInfoByFilter_002 end";
}

// ========== GetFormInstanceById Tests ==========

/**
 * @tc.name: GetFormInstanceById_001
 * @tc.desc: Verify FormDataMgr::GetFormInstanceById (2-param) returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormInstanceById_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInstanceById_001 start";

    FormInstance formInstance;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormInstanceById2(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().GetFormInstanceById(TEST_FORM_ID, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInstanceById_001 end";
}

/**
 * @tc.name: GetFormInstanceById_002
 * @tc.desc: Verify FormDataMgr::GetFormInstanceById (3-param) returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormInstanceById_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInstanceById_002 start";

    FormInstance formInstance;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormInstanceById3(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().GetFormInstanceById(
        TEST_FORM_ID, true, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInstanceById_002 end";
}

// ========== GetRunningFormInfos Tests ==========

/**
 * @tc.name: GetRunningFormInfos_001
 * @tc.desc: Verify FormDataMgr::GetRunningFormInfos returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetRunningFormInfos_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetRunningFormInfos_001 start";

    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_CALL(*MockFormDataMgr::obj, GetRunningFormInfos(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().GetRunningFormInfos(
        false, runningFormInfos, TEST_USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetRunningFormInfos_001 end";
}

// ========== GetAllTemplateFormsInfo Tests ==========

/**
 * @tc.name: GetAllTemplateFormsInfo_001
 * @tc.desc: Verify FormInfoMgr::GetAllTemplateFormsInfo returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetAllTemplateFormsInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAllTemplateFormsInfo_001 start";

    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetAllTemplateFormsInfo(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetAllTemplateFormsInfo(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetAllTemplateFormsInfo_001 end";
}

// ========== GetTemplateFormsInfoByApp Tests ==========

/**
 * @tc.name: GetTemplateFormsInfoByApp_001
 * @tc.desc: Verify FormInfoMgr::GetTemplateFormsInfoByBundle returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetTemplateFormsInfoByApp_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetTemplateFormsInfoByApp_001 start";

    std::string bundleName = "com.test.bundle";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetTemplateFormsInfoByBundle(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetTemplateFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetTemplateFormsInfoByApp_001 end";
}

// ========== GetTemplateFormsInfoByModule Tests ==========

/**
 * @tc.name: GetTemplateFormsInfoByModule_001
 * @tc.desc: Verify FormInfoMgr::GetTemplateFormsInfoByModule returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetTemplateFormsInfoByModule_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetTemplateFormsInfoByModule_001 start";

    std::string bundleName = "com.test.bundle";
    std::string moduleName = "entry";
    std::vector<FormInfo> formInfos;
    EXPECT_CALL(*MockFormInfoMgr::obj, GetTemplateFormsInfoByModule(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetTemplateFormsInfoByModule(
        bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetTemplateFormsInfoByModule_001 end";
}

// ========== GetFormsCount Tests ==========

/**
 * @tc.name: GetFormsCount_001
 * @tc.desc: Verify isTempFormFlag=true calls GetTempFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsCount_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsCount_001 start";

    int32_t formCount = 0;
    EXPECT_CALL(*MockFormDataMgr::obj, GetTempFormsCount(_))
        .WillOnce(Return(ERR_OK));

    auto result = FormQueryAdapter::GetInstance().GetFormsCount(true, formCount);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormsCount_001 end";
}

/**
 * @tc.name: GetFormsCount_002
 * @tc.desc: Verify isTempFormFlag=false calls GetCastFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormsCount_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormsCount_002 start";

    int32_t formCount = 0;
    EXPECT_CALL(*MockFormDataMgr::obj, GetCastFormsCount(_))
        .WillOnce(Return(ERR_OK));

    auto result = FormQueryAdapter::GetInstance().GetFormsCount(false, formCount);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "GetFormsCount_002 end";
}

// ========== GetHostFormsCount Tests ==========

/**
 * @tc.name: GetHostFormsCount_001
 * @tc.desc: Verify FormDataMgr::GetHostFormsCount returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetHostFormsCount_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetHostFormsCount_001 start";

    std::string bundleName = "com.test.bundle";
    int32_t formCount = 0;
    EXPECT_CALL(*MockFormDataMgr::obj, GetHostFormsCount(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().GetHostFormsCount(bundleName, formCount);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetHostFormsCount_001 end";
}

// ========== GetRunningFormInfosByBundleName Tests ==========

/**
 * @tc.name: GetRunningFormInfosByBundleName_001
 * @tc.desc: Verify FormDataMgr::GetRunningFormInfosByBundleName returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetRunningFormInfosByBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetRunningFormInfosByBundleName_001 start";

    std::string bundleName = "com.test.bundle";
    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_CALL(*MockFormDataMgr::obj, GetRunningFormInfosByBundleName(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().GetRunningFormInfosByBundleName(
        bundleName, false, runningFormInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetRunningFormInfosByBundleName_001 end";
}

// ========== GetFormInstancesByFilter Tests ==========

/**
 * @tc.name: GetFormInstancesByFilter_001
 * @tc.desc: Verify FormDataMgr::GetFormInstancesByFilter returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, GetFormInstancesByFilter_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormInstancesByFilter_001 start";

    FormInstancesFilter filter;
    std::vector<FormInstance> formInstances;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormInstancesByFilter(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().GetFormInstancesByFilter(filter, formInstances);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "GetFormInstancesByFilter_001 end";
}

// ========== AcquireFormStateCheck Tests ==========

/**
 * @tc.name: AcquireFormStateCheck_001
 * @tc.desc: Verify empty bundleName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_001 start";

    std::string bundleName;
    std::string abilityName = "MainAbility";
    Want want;
    std::string provider;

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_001 end";
}

/**
 * @tc.name: AcquireFormStateCheck_002
 * @tc.desc: Verify empty abilityName returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_002 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName;
    Want want;
    std::string provider;

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_002 end";
}

/**
 * @tc.name: AcquireFormStateCheck_003
 * @tc.desc: Verify empty moduleName from want returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_003 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName = "MainAbility";
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    std::string provider;

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_003 end";
}

/**
 * @tc.name: AcquireFormStateCheck_004
 * @tc.desc: Verify empty formName from want returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_004 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName = "MainAbility";
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    std::string provider;

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_004 end";
}

/**
 * @tc.name: AcquireFormStateCheck_005
 * @tc.desc: Verify GetFormsInfoByModuleWithoutCheck fails propagates error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_005 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName = "MainAbility";
    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    std::string provider;

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_005 end";
}

/**
 * @tc.name: AcquireFormStateCheck_006
 * @tc.desc: Verify no matching formInfo returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_006 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName = "MainAbility";
    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    std::string provider;

    // Return FormInfo that does NOT match
    FormInfo mismatchFormInfo;
    mismatchFormInfo.abilityName = "OtherAbility";
    mismatchFormInfo.name = "otherWidget";
    mismatchFormInfo.supportDimensions.push_back(1);
    std::vector<FormInfo> formInfos = {mismatchFormInfo};

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_006 end";
}

/**
 * @tc.name: AcquireFormStateCheck_007
 * @tc.desc: Verify full success path returns ERR_OK and provider contains "::"
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormStateCheck_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormStateCheck_007 start";

    std::string bundleName = "com.test.bundle";
    std::string abilityName = "MainAbility";
    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    std::string provider;

    FormInfo matchFormInfo;
    matchFormInfo.abilityName = "MainAbility";
    matchFormInfo.name = "widget";
    matchFormInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    std::vector<FormInfo> formInfos = {matchFormInfo};

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormQueryAdapter::GetInstance().AcquireFormStateCheck(
        bundleName, abilityName, want, provider);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(provider.find("::") != std::string::npos);

    GTEST_LOG_(INFO) << "AcquireFormStateCheck_007 end";
}

// ========== AcquireFormState Tests ==========

/**
 * @tc.name: AcquireFormState_001
 * @tc.desc: Verify nullptr callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormState_001 start";

    Want want;
    FormStateInfo stateInfo;

    auto result = FormQueryAdapter::GetInstance().AcquireFormState(
        want, nullptr, stateInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormState_001 end";
}

/**
 * @tc.name: AcquireFormState_002
 * @tc.desc: Verify AcquireFormStateCheck fails propagates error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormState_002 start";

    Want want;
    // Empty bundleName/abilityName via element will cause AcquireFormStateCheck to fail
    FormStateInfo stateInfo;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormQueryAdapter::GetInstance().AcquireFormState(
        want, callerToken, stateInfo);
    // bundleName and abilityName are empty, AcquireFormStateCheck returns ERR_APPEXECFWK_FORM_INVALID_PARAM
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AcquireFormState_002 end";
}

/**
 * @tc.name: AcquireFormState_003
 * @tc.desc: Verify AcquireFormStateCheck fails with GetFormsInfoByModuleWithoutCheck error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormState_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormState_003 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    FormStateInfo stateInfo;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormQueryAdapter::GetInstance().AcquireFormState(
        want, callerToken, stateInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormState_003 end";
}

/**
 * @tc.name: AcquireFormState_004
 * @tc.desc: Verify ConnectServiceAbility fails returns ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormState_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormState_004 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    FormStateInfo stateInfo;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormInfo matchFormInfo;
    matchFormInfo.abilityName = "MainAbility";
    matchFormInfo.name = "widget";
    matchFormInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    std::vector<FormInfo> formInfos = {matchFormInfo};

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .Times(2)
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormStateRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED));

    auto result = FormQueryAdapter::GetInstance().AcquireFormState(
        want, callerToken, stateInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormState_004 end";
}

/**
 * @tc.name: AcquireFormState_005
 * @tc.desc: Verify ConnectServiceAbility success returns ERR_OK and stateInfo is DEFAULT
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormState_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormState_005 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    FormStateInfo stateInfo;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormInfo matchFormInfo;
    matchFormInfo.abilityName = "MainAbility";
    matchFormInfo.name = "widget";
    matchFormInfo.supportDimensions.push_back(TEST_DIMENSION_ID);
    std::vector<FormInfo> formInfos = {matchFormInfo};

    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModuleWithoutCheck(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(formInfos), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .Times(2)
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormStateRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormQueryAdapter::GetInstance().AcquireFormState(
        want, callerToken, stateInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(stateInfo.state, FormState::DEFAULT);

    GTEST_LOG_(INFO) << "AcquireFormState_005 end";
}

// ========== AcquireFormData Tests ==========

/**
 * @tc.name: AcquireFormData_001
 * @tc.desc: Verify GetFormRecord fails returns ERR_APPEXECFWK_FORM_GET_INFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormData_001 start";

    AAFwk::WantParams formData;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormQueryAdapter::GetInstance().AcquireFormData(
        TEST_FORM_ID, 0, callerToken, formData);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormData_001 end";
}

/**
 * @tc.name: AcquireFormData_002
 * @tc.desc: Verify AcquireFormData succeeds with empty moduleName, ConnectServiceAbility returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormData_002 start";

    AAFwk::WantParams formData;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "";  // empty moduleName branch

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormAcquireDataRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormQueryAdapter::GetInstance().AcquireFormData(
        TEST_FORM_ID, 0, callerToken, formData);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "AcquireFormData_002 end";
}

/**
 * @tc.name: AcquireFormData_003
 * @tc.desc: Verify AcquireFormData succeeds with non-empty moduleName, ConnectServiceAbility returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormData_003 start";

    AAFwk::WantParams formData;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "entry";  // non-empty moduleName branch

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormAcquireDataRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormQueryAdapter::GetInstance().AcquireFormData(
        TEST_FORM_ID, 0, callerToken, formData);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "AcquireFormData_003 end";
}

/**
 * @tc.name: AcquireFormData_004
 * @tc.desc: Verify ConnectServiceAbility fails returns ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormData_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormData_004 start";

    AAFwk::WantParams formData;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "entry";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormAcquireDataRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().AcquireFormData(
        TEST_FORM_ID, 0, callerToken, formData);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormData_004 end";
}

/**
 * @tc.name: AcquireFormData_005
 * @tc.desc: Verify empty moduleName with ConnectServiceAbility fails returns ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormQueryAdapterTest, AcquireFormData_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireFormData_005 start";

    AAFwk::WantParams formData;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord formRecord;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "";  // empty moduleName - skip SetModuleName branch

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, CreateFormAcquireDataRecord(_, _, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormQueryAdapter::GetInstance().AcquireFormData(
        TEST_FORM_ID, 0, callerToken, formData);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    GTEST_LOG_(INFO) << "AcquireFormData_005 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
