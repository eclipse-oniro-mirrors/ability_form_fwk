/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include <map>
#include <string>
#include <thread>

#include "appexecfwk_errors.h"
#define private public
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_item_info.h"
#undef private
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_proxy_record.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_record/form_record.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
    OHOS::ErrCode g_mockGetApplicationInfo = OHOS::ERR_OK;
}

void MockGetApplicationInfo(OHOS::ErrCode mockRet)
{
    g_mockGetApplicationInfo = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

ErrCode FormBmsHelper::GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo)
{
    return g_mockGetApplicationInfo;
}
} // namespace AppExecFwk
} // namespace OHOS

namespace {
const std::string FORM_BUNDLE_NAME = "com.form.service";
const std::string PARAM_MODULE_NAME = "com.form.app.test.ability";
const std::string FORM_ABILITY_NAME = "com.form.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";
const int32_t PARAM_FORM_DIMENSION_VALUE = 1;
const int CALLING_UID = 0;

class FmsFormDataProxyMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDataProxyMgrTest::SetUpTestCase()
{}

void FmsFormDataProxyMgrTest::TearDownTestCase()
{}

void FmsFormDataProxyMgrTest::SetUp()
{}

void FmsFormDataProxyMgrTest::TearDown()
{}

/**
 * @tc.name: FmsFormDataProxyMgrTest_001
 * @tc.desc: Verify functionName SubscribeFormData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    int32_t userId = 100;
    uint32_t ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_OK);
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    // Set cache
    FormItemInfo record1;
    record1.SetFormId(formId);
    record1.SetProviderBundleName(FORM_BUNDLE_NAME);
    record1.SetModuleName(PARAM_MODULE_NAME);
    record1.SetAbilityName(FORM_ABILITY_NAME);
    record1.SetFormName(PARAM_FORM_NAME);
    record1.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record1.SetTemporaryFlag(false);
    FormRecord formRecord2 = FormDataMgr::GetInstance().AllotFormRecord(record1, CALLING_UID);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_OK);

    formRecord2.isDataProxy = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord2);
    MockGetApplicationInfo(ERR_OK + 1);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_001 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_002
 * @tc.desc: Verify functionName ConsumeFormDataProxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_002 start";
    int64_t formId = 1;
    std::vector<FormDataProxy> formDataProxies;
    std::vector<FormDataProxy> getFormDataProxies;

    FormDataProxyMgr::GetInstance().formDataProxiesMap_.clear();
    bool ret = FormDataProxyMgr::GetInstance().ConsumeFormDataProxies(formId, getFormDataProxies);
    EXPECT_EQ(ret, false);

    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    FormDataProxyMgr::GetInstance().ProduceFormDataProxies(formId, formDataProxies);
    EXPECT_EQ(FormDataProxyMgr::GetInstance().formDataProxiesMap_.size(), 1);

    ret = FormDataProxyMgr::GetInstance().ConsumeFormDataProxies(formId, getFormDataProxies);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_002 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_003
 * @tc.desc: Verify functionName SubscribeFormData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_003 start";
    FormDataProxyMgr formDataProxyMgr;
    FormRecord formRecord;
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);

    // Set cache
    FormItemInfo record1;
    record1.SetFormId(formId);
    record1.SetProviderBundleName(FORM_BUNDLE_NAME);
    record1.SetModuleName(PARAM_MODULE_NAME);
    record1.SetAbilityName(FORM_ABILITY_NAME);
    record1.SetFormName(PARAM_FORM_NAME);
    record1.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record1.SetTemporaryFlag(false);
    FormRecord formRecord2 = FormDataMgr::GetInstance().AllotFormRecord(record1, CALLING_UID);
    formRecord2.isDataProxy = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord2);
    MockGetApplicationInfo(ERR_OK + 1);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = nullptr;
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    int32_t userId = 100;
    auto ret = formDataProxyMgr.SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord2.bundleName, formRecord2.uiSyntax, 0, formRecord2.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    ret = formDataProxyMgr.SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_003 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_004
 * @tc.desc: Verify functionName UnsubscribeFormData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_004 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    formDataProxyMgr.UnsubscribeFormData(formId);
    auto ret = formDataProxyMgr.UnsubscribeFormData(formId);
    EXPECT_EQ(ret, ERR_OK);
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = nullptr;
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    ret = formDataProxyMgr.UnsubscribeFormData(formId);
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    ret = formDataProxyMgr.UnsubscribeFormData(formId);
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_004 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_005
 * @tc.desc: Verify formDataProxyRecordMap_ related functions.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_005 start";
    FormDataProxyMgr formDataProxyMgr;
    std::vector<FormDataProxy> formDataProxies;
    std::vector<int64_t> formIds = {1};
    int64_t formId = 1;
    std::vector<std::string> subscribedKeys;
    int32_t count = 1;
    formDataProxyMgr.EnableSubscribeFormData(formIds);
    formDataProxyMgr.UpdateSubscribeFormData(formId, formDataProxies);
    formDataProxyMgr.DisableSubscribeFormData(formIds);
    formDataProxyMgr.GetFormSubscribeInfo(formId, subscribedKeys, count);
    auto ret = formDataProxyMgr.formDataProxyRecordMap_.find(formId);
    EXPECT_EQ(ret, formDataProxyMgr.formDataProxyRecordMap_.end());
    FormItemInfo record;
    record.SetFormId(formId);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = nullptr;
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    formDataProxyMgr.EnableSubscribeFormData(formIds);
    formDataProxyMgr.UpdateSubscribeFormData(formId, formDataProxies);
    formDataProxyMgr.DisableSubscribeFormData(formIds);
    formDataProxyMgr.GetFormSubscribeInfo(formId, subscribedKeys, count);
    auto iter = formDataProxyMgr.formDataProxyRecordMap_.find(formId);
    EXPECT_EQ(iter->second, nullptr);
    formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    formDataProxyMgr.EnableSubscribeFormData(formIds);
    formDataProxyMgr.UpdateSubscribeFormData(formId, formDataProxies);
    formDataProxyMgr.DisableSubscribeFormData(formIds);
    formDataProxyMgr.GetFormSubscribeInfo(formId, subscribedKeys, count);
    iter = formDataProxyMgr.formDataProxyRecordMap_.find(formId);
    EXPECT_NE(iter->second, nullptr);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_005 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_006
 * @tc.desc: Verify RetrySubscribeProxy functions.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_006 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);

    // Set cache
    FormItemInfo formItem;
    formItem.SetFormId(formId);
    formItem.SetProviderBundleName(FORM_BUNDLE_NAME);
    formItem.SetModuleName(PARAM_MODULE_NAME);
    formItem.SetAbilityName(FORM_ABILITY_NAME);
    formItem.SetFormName(PARAM_FORM_NAME);
    formItem.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    formItem.SetTemporaryFlag(false);
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(formItem, CALLING_UID);
    formRecord.isDataProxy = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    formDataProxyMgr.RetrySubscribeProxy(formId, formDataProxies, 0, want, 0);
    formDataProxyMgr.RetrySubscribeProxy(formId, formDataProxies, 0, want, 0);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_006 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_007
 * @tc.desc: Verify functionName GetFormDataProxyRecord.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_007 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;

    auto recordPtr = formDataProxyMgr.GetFormDataProxyRecord(formId);
    EXPECT_EQ(recordPtr, nullptr);
 
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    recordPtr = formDataProxyMgr.GetFormDataProxyRecord(formId);
    EXPECT_NE(recordPtr, nullptr);
    EXPECT_EQ(recordPtr, formDataProxyRecordPtr);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_007 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_008
 * @tc.desc: Verify functionName UnsubscribeFormData with multiple forms.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_008 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    
    FormItemInfo record1;
    record1.SetFormId(formId1);
    record1.SetProviderBundleName(FORM_BUNDLE_NAME);
    record1.SetModuleName(PARAM_MODULE_NAME);
    record1.SetAbilityName(FORM_ABILITY_NAME);
    record1.SetFormName(PARAM_FORM_NAME);
    record1.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record1.SetTemporaryFlag(false);
    
    FormRecord formRecord1 = FormDataMgr::GetInstance().AllotFormRecord(record1, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr1 = std::make_shared<FormDataProxyRecord>(
        formId1, formRecord1.bundleName, formRecord1.uiSyntax, 0, formRecord1.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId1] = formDataProxyRecordPtr1;
    
    FormItemInfo record2;
    record2.SetFormId(formId2);
    record2.SetProviderBundleName(FORM_BUNDLE_NAME);
    record2.SetModuleName(PARAM_MODULE_NAME);
    record2.SetAbilityName(FORM_ABILITY_NAME);
    record2.SetFormName(PARAM_FORM_NAME);
    record2.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record2.SetTemporaryFlag(false);
    
    FormRecord formRecord2 = FormDataMgr::GetInstance().AllotFormRecord(record2, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr2 = std::make_shared<FormDataProxyRecord>(
        formId2, formRecord2.bundleName, formRecord2.uiSyntax, 0, formRecord2.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId2] = formDataProxyRecordPtr2;
    
    EXPECT_EQ(formDataProxyMgr.formDataProxyRecordMap_.size(), 2);
    
    formDataProxyMgr.UnsubscribeFormData(formId1);
    EXPECT_EQ(formDataProxyMgr.formDataProxyRecordMap_.size(), 1);
    
    formDataProxyMgr.UnsubscribeFormData(formId2);
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_008 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_009
 * @tc.desc: Verify functionName EnableSubscribeFormData and DisableSubscribeFormData with multiple forms.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_009 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    
    FormItemInfo record1;
    record1.SetFormId(formId1);
    record1.SetProviderBundleName(FORM_BUNDLE_NAME);
    record1.SetModuleName(PARAM_MODULE_NAME);
    record1.SetAbilityName(FORM_ABILITY_NAME);
    record1.SetFormName(PARAM_FORM_NAME);
    record1.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record1.SetTemporaryFlag(false);
    
    FormRecord formRecord1 = FormDataMgr::GetInstance().AllotFormRecord(record1, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr1 = std::make_shared<FormDataProxyRecord>(
        formId1, formRecord1.bundleName, formRecord1.uiSyntax, 0, formRecord1.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId1] = formDataProxyRecordPtr1;
    
    FormItemInfo record2;
    record2.SetFormId(formId2);
    record2.SetProviderBundleName(FORM_BUNDLE_NAME);
    record2.SetModuleName(PARAM_MODULE_NAME);
    record2.SetAbilityName(FORM_ABILITY_NAME);
    record2.SetFormName(PARAM_FORM_NAME);
    record2.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record2.SetTemporaryFlag(false);
    
    FormRecord formRecord2 = FormDataMgr::GetInstance().AllotFormRecord(record2, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr2 = std::make_shared<FormDataProxyRecord>(
        formId2, formRecord2.bundleName, formRecord2.uiSyntax, 0, formRecord2.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId2] = formDataProxyRecordPtr2;
    
    std::vector<int64_t> formIds = {formId1, formId2};
    formDataProxyMgr.EnableSubscribeFormData(formIds);
    formDataProxyMgr.DisableSubscribeFormData(formIds);
    
    EXPECT_EQ(formDataProxyMgr.formDataProxyRecordMap_.size(), 2);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_009 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_010
 * @tc.desc: Verify functionName ProduceFormDataProxies and ConsumeFormDataProxies with multiple forms.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_010 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    
    std::vector<FormDataProxy> formDataProxies1;
    FormDataProxy formDataProxy1("test1", "0001");
    formDataProxies1.push_back(formDataProxy1);
    
    std::vector<FormDataProxy> formDataProxies2;
    FormDataProxy formDataProxy2("test2", "0002");
    formDataProxies2.push_back(formDataProxy2);
    
    formDataProxyMgr.ProduceFormDataProxies(formId1, formDataProxies1);
    formDataProxyMgr.ProduceFormDataProxies(formId2, formDataProxies2);
    
    EXPECT_EQ(formDataProxyMgr.formDataProxiesMap_.size(), 2);
    
    std::vector<FormDataProxy> getFormDataProxies1;
    bool ret1 = formDataProxyMgr.ConsumeFormDataProxies(formId1, getFormDataProxies1);
    EXPECT_TRUE(ret1);
    EXPECT_EQ(getFormDataProxies1.size(), 1);
    EXPECT_EQ(formDataProxyMgr.formDataProxiesMap_.size(), 1);
    
    std::vector<FormDataProxy> getFormDataProxies2;
    bool ret2 = formDataProxyMgr.ConsumeFormDataProxies(formId2, getFormDataProxies2);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(getFormDataProxies2.size(), 1);
    EXPECT_TRUE(formDataProxyMgr.formDataProxiesMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_010 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_011
 * @tc.desc: Verify functionName UpdateSubscribeFormData with valid and invalid formId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_011 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0001");
    formDataProxies.push_back(formDataProxy);
    
    formDataProxyMgr.UpdateSubscribeFormData(formId, formDataProxies);
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    formDataProxyMgr.UpdateSubscribeFormData(formId, formDataProxies);
    EXPECT_FALSE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_011 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_012
 * @tc.desc: Verify functionName GetFormSubscribeInfo with valid and invalid formId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_012 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    
    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    
    formDataProxyMgr.GetFormSubscribeInfo(formId, subscribedKeys, count);
    EXPECT_EQ(subscribedKeys.size(), 0);
    EXPECT_EQ(count, 0);
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    subscribedKeys.clear();
    count = 0;
    formDataProxyMgr.GetFormSubscribeInfo(formId, subscribedKeys, count);
    EXPECT_EQ(subscribedKeys.size(), 0);
    EXPECT_EQ(count, 0);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_012 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_013
 * @tc.desc: Verify functionName SubscribeFormData with empty formDataProxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_013 start";
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    int32_t userId = 100;
    
    auto ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_OK);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_013 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_014
 * @tc.desc: Verify functionName SubscribeFormData with non-data proxy form.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_014 start";
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    int32_t userId = 100;
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    formRecord.isDataProxy = false;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord);
    
    auto ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, userId);
    EXPECT_EQ(ret, ERR_OK);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_014 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_015
 * @tc.desc: Verify thread safety with concurrent ProduceFormDataProxies calls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_015 start";
    FormDataProxyMgr formDataProxyMgr;
    const int threadCount = 10;
    const int64_t baseFormId = 1000;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([&formDataProxyMgr, baseFormId, i]() {
            int64_t formId = baseFormId + i;
            std::vector<FormDataProxy> formDataProxies;
            FormDataProxy formDataProxy("test_" + std::to_string(i), std::to_string(i));
            formDataProxies.push_back(formDataProxy);
            formDataProxyMgr.ProduceFormDataProxies(formId, formDataProxies);
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(formDataProxyMgr.formDataProxiesMap_.size(), threadCount);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_015 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_016
 * @tc.desc: Verify thread safety with concurrent ConsumeFormDataProxies calls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_016 start";
    FormDataProxyMgr formDataProxyMgr;
    const int threadCount = 5;
    const int64_t baseFormId = 2000;
    std::vector<std::thread> produceThreads;
    std::vector<std::thread> consumeThreads;
    std::atomic<int> successCount{0};
    
    for (int i = 0; i < threadCount; i++) {
        int64_t formId = baseFormId + i;
        std::vector<FormDataProxy> formDataProxies;
        FormDataProxy formDataProxy("test_" + std::to_string(i), std::to_string(i));
        formDataProxies.push_back(formDataProxy);
        formDataProxyMgr.ProduceFormDataProxies(formId, formDataProxies);
    }
    
    for (int i = 0; i < threadCount; i++) {
        consumeThreads.emplace_back([&formDataProxyMgr, baseFormId, i, &successCount]() {
            int64_t formId = baseFormId + i;
            std::vector<FormDataProxy> formDataProxies;
            bool ret = formDataProxyMgr.ConsumeFormDataProxies(formId, formDataProxies);
            if (ret) {
                successCount++;
            }
        });
    }
    
    for (auto& thread : consumeThreads) {
        thread.join();
    }
    
    EXPECT_EQ(successCount.load(), threadCount);
    EXPECT_TRUE(formDataProxyMgr.formDataProxiesMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_016 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_017
 * @tc.desc: Verify UnsubscribeFormDataById clears record properly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_017 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    EXPECT_FALSE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    formDataProxyMgr.UnsubscribeFormDataById(formId);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    formDataProxyMgr.UnsubscribeFormDataById(formId);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_017 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_018
 * @tc.desc: Verify RetrySubscribeProxy with zero retry times.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_018 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    uint32_t tokenId = 0;
    AAFwk::Want want;
    int32_t leftRetryTimes = 0;
    
    formDataProxyMgr.RetrySubscribeProxy(formId, formDataProxies, tokenId, want, leftRetryTimes);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_018 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_019
 * @tc.desc: Verify RetrySubscribeProxy with positive retry times.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_019 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 999;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    uint32_t tokenId = 0;
    AAFwk::Want want;
    int32_t leftRetryTimes = 1;
    
    formDataProxyMgr.RetrySubscribeProxy(formId, formDataProxies, tokenId, want, leftRetryTimes);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_019 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_020
 * @tc.desc: Verify thread safety with concurrent GetFormDataProxyRecord calls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_020 start";
    FormDataProxyMgr formDataProxyMgr;
    const int threadCount = 10;
    const int64_t formId = 1;
    std::vector<std::thread> threads;
    std::atomic<int> foundCount{0};
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([&formDataProxyMgr, formId, &foundCount]() {
            auto recordPtr = formDataProxyMgr.GetFormDataProxyRecord(formId);
            if (recordPtr != nullptr) {
                foundCount++;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(foundCount.load(), threadCount);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_020 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_021
 * @tc.desc: Verify thread safety with concurrent UnsubscribeFormDataById calls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_021 start";
    FormDataProxyMgr formDataProxyMgr;
    const int threadCount = 5;
    const int64_t baseFormId = 3000;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < threadCount; i++) {
        int64_t formId = baseFormId + i;
        FormItemInfo record;
        record.SetFormId(formId);
        record.SetProviderBundleName(FORM_BUNDLE_NAME);
        record.SetModuleName(PARAM_MODULE_NAME);
        record.SetAbilityName(FORM_ABILITY_NAME);
        record.SetFormName(PARAM_FORM_NAME);
        record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
        record.SetTemporaryFlag(false);
        
        FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
        std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
            formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
        formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    }
    
    EXPECT_EQ(formDataProxyMgr.formDataProxyRecordMap_.size(), threadCount);
    
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([&formDataProxyMgr, baseFormId, i]() {
            formDataProxyMgr.UnsubscribeFormDataById(baseFormId + i);
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_021 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_022
 * @tc.desc: Verify ConsumeFormDataProxies returns false for non-existent formId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_022 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 9999;
    std::vector<FormDataProxy> formDataProxies;
    
    formDataProxyMgr.formDataProxiesMap_.clear();
    
    bool ret = formDataProxyMgr.ConsumeFormDataProxies(formId, formDataProxies);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(formDataProxies.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_022 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_023
 * @tc.desc: Verify EnableSubscribeFormData with empty formIds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_023 start";
    FormDataProxyMgr formDataProxyMgr;
    std::vector<int64_t> emptyFormIds;
    
    formDataProxyMgr.EnableSubscribeFormData(emptyFormIds);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_023 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_024
 * @tc.desc: Verify DisableSubscribeFormData with empty formIds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_024 start";
    FormDataProxyMgr formDataProxyMgr;
    std::vector<int64_t> emptyFormIds;
    
    formDataProxyMgr.DisableSubscribeFormData(emptyFormIds);
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_024 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_025
 * @tc.desc: Verify RetryFailureSubscribes with empty map.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_025 start";
    FormDataProxyMgr formDataProxyMgr;
    
    formDataProxyMgr.formDataProxyRecordMap_.clear();
    formDataProxyMgr.RetryFailureSubscribes();
    
    EXPECT_TRUE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_025 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_026
 * @tc.desc: Verify UpdateSubscribeFormData with empty formDataProxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_026 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    std::vector<FormDataProxy> emptyFormDataProxies;
    
    FormItemInfo record;
    record.SetFormId(formId);
    record.SetProviderBundleName(FORM_BUNDLE_NAME);
    record.SetModuleName(PARAM_MODULE_NAME);
    record.SetAbilityName(FORM_ABILITY_NAME);
    record.SetFormName(PARAM_FORM_NAME);
    record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record.SetTemporaryFlag(false);
    
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
    std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
    formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    
    formDataProxyMgr.UpdateSubscribeFormData(formId, emptyFormDataProxies);
    
    EXPECT_FALSE(formDataProxyMgr.formDataProxyRecordMap_.empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_026 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_027
 * @tc.desc: Verify ProduceFormDataProxies with empty formDataProxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_027 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t formId = 1;
    std::vector<FormDataProxy> emptyFormDataProxies;
    
    formDataProxyMgr.ProduceFormDataProxies(formId, emptyFormDataProxies);
    
    EXPECT_EQ(formDataProxyMgr.formDataProxiesMap_.size(), 1);
    EXPECT_TRUE(formDataProxyMgr.formDataProxiesMap_[formId].empty());
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_027 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_028
 * @tc.desc: Verify GetFormSubscribeInfo with invalid formId (negative).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_028 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t invalidFormId = -1;
    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    
    formDataProxyMgr.GetFormSubscribeInfo(invalidFormId, subscribedKeys, count);
    
    EXPECT_TRUE(subscribedKeys.empty());
    EXPECT_EQ(count, 0);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_028 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_029
 * @tc.desc: Verify GetFormDataProxyRecord with invalid formId (negative).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_029 start";
    FormDataProxyMgr formDataProxyMgr;
    int64_t invalidFormId = -999;
    
    auto recordPtr = formDataProxyMgr.GetFormDataProxyRecord(invalidFormId);
    
    EXPECT_EQ(recordPtr, nullptr);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_029 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_030
 * @tc.desc: Verify thread safety with concurrent EnableSubscribeFormData and DisableSubscribeFormData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_030 start";
    FormDataProxyMgr formDataProxyMgr;
    const int threadCount = 5;
    const int64_t baseFormId = 4000;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < threadCount; i++) {
        int64_t formId = baseFormId + i;
        FormItemInfo record;
        record.SetFormId(formId);
        record.SetProviderBundleName(FORM_BUNDLE_NAME);
        record.SetModuleName(PARAM_MODULE_NAME);
        record.SetAbilityName(FORM_ABILITY_NAME);
        record.SetFormName(PARAM_FORM_NAME);
        record.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
        record.SetTemporaryFlag(false);
        
        FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(record, CALLING_UID);
        std::shared_ptr<FormDataProxyRecord> formDataProxyRecordPtr = std::make_shared<FormDataProxyRecord>(
            formId, formRecord.bundleName, formRecord.uiSyntax, 0, formRecord.uid);
        formDataProxyMgr.formDataProxyRecordMap_[formId] = formDataProxyRecordPtr;
    }
    
    std::vector<int64_t> formIds;
    for (int i = 0; i < threadCount; i++) {
        formIds.push_back(baseFormId + i);
    }
    
    for (int i = 0; i < threadCount; i++) {
        threads.emplace_back([&formDataProxyMgr, formIds]() {
            formDataProxyMgr.EnableSubscribeFormData(formIds);
        });
        threads.emplace_back([&formDataProxyMgr, formIds]() {
            formDataProxyMgr.DisableSubscribeFormData(formIds);
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(formDataProxyMgr.formDataProxyRecordMap_.size(), threadCount);
    
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_030 end";
}
}
