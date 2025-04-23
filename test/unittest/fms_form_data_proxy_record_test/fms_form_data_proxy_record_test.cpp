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
#include <map>
#include <string>
#include <thread>

#include "appexecfwk_errors.h"
#include "data_proxy_observer_stub.h"
#include "datashare_log.h"
#include "datashare_helper.h"
#define private public
#include "data_center/form_data_proxy_record.h"
#include "data_center/form_info/form_item_info.h"
#undef private
#include "bms_mgr/form_bms_helper.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_form_data_proxy_record_test.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string TEST_DATA_URI = "com.form.app.test.uri";
const std::string TEST_REQUIRED_READ_PERMISSON = "com.form.app.test.READ_PERMISSION";
const std::string TEST_REQUIRED_WRITE_PERMISSON = "com.form.app.test.WRITE_PERMISSION";
const std::string TEST_PROXY_SUBSCRIBE_ID = "12345678";

class FmsFormDataProxyRecordTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDataProxyRecordTest::SetUpTestCase()
{}

void FmsFormDataProxyRecordTest::TearDownTestCase()
{}

void FmsFormDataProxyRecordTest::SetUp()
{}

void FmsFormDataProxyRecordTest::TearDown()
{}

/**
 * @tc.number: FmsFormDataProxyRecordTest_001
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_002
 * @tc.name: OnRdbDataChange
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_002 start";

    DataShare::RdbChangeNode changeNode;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    formDataProxyRecord.OnRdbDataChange(changeNode);
    GTEST_LOG_(INFO) << "FmsFormDataMgr_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_003
 * @tc.name: OnPublishedDataChange
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_003 start";

    DataShare::PublishedDataChangeNode changeNode;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    formDataProxyRecord.OnPublishedDataChange(changeNode);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_003 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_006
 * @tc.desc: test SubscribeRdbFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_006 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_006 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_008
 * @tc.desc: test SubscribeRdbFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_008 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_008 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_010
 * @tc.desc: test UnsubscribeFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_010 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.UnsubscribeFormData();
    EXPECT_EQ(ret, formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap));
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_010 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_011
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_011 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_011 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_012
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_012 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    formDataProxyRecord.ParseFormDataProxies(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_012 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_013
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_013 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap subscribeMap;
    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    formDataProxyRecord.ConvertSubscribeMapToRequests(subscribeMap, formDataProxyRequests);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_013 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_014
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_014 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::PublishedDataItem> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    formDataProxyRecord.UpdatePublishedDataForm(data);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_014 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_015
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_015 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    formDataProxyRecord.UpdateRdbDataForm(data);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_015 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_016
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_015 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;
    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    formDataProxyRecord.UnsubscribeFormData(originRdbMap, originPublishMap);
    formDataProxyRecord.SubscribeRdbFormData(newRdbMap);
    formDataProxyRecord.SubscribePublishFormData(newPublishMap);
    formDataProxyRecord.UpdateSubscribeFormData(formDataProxies);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_016 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_016
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_017 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;
    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_017 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_018
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_018 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.EnableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_018 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_019
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_019 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.DisableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_019 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_020
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_020 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_020 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_021
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_021 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_021 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_022
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_022 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_022 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_023
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_023 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_023 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_024
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_024 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    node.ashmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_024 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_025
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_025 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    formAshmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_025 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_026
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_026 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    const DataShare::PublishedDataItem data;
    formRecord.uiSyntax = FormType::JS;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_026 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_027
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_027 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_027 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_028
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_028 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_028 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_029
 * @tc.desc: test GetFormSubscribedInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_029 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    formDataProxyRecord.GetFormSubscribeInfo(subscribedKeys, count);
    EXPECT_EQ(count, formDataProxyRecord.receivedDataCount_);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_029 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_030
 * @tc.desc: test AddSubscribeSuccessKey function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_030 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::string errorUri = "this is a error uri";
    FormDataProxyRecord::SubscribeResultRecord errorRecord{errorUri, 1, 1, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 0);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);

    std::string correctUri = "this is a correct uri?";
    FormDataProxyRecord::SubscribeResultRecord successRecord{correctUri, 1, 0, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 1);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_03 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_031
 * @tc.desc: test SubscribeFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_031 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_031 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_032
 * @tc.desc: test RegisterPermissionListener&&UnRegisterPermissionListener function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_032 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    formDataProxyRecord.UnRegisterPermissionListener();
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_032 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_033
 * @tc.desc: test PermStateChangeCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_033 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    int32_t permStateChangeType = 1;
    std::string permissionName;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    permStateChangeType = 0;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_033 end";
}


/**
 * @tc.name: FmsFormDataProxyRecordTest_034
 * @tc.desc: test RegisterPermissionListener function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_034 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_034 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_035
 * @tc.desc: test RetryFailureSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_035 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    formDataProxyRecord.RetryFailureSubscribes();
    formDataProxyRecord.dataShareHelper_ = nullptr;
    formDataProxyRecord.RetryFailureSubscribes();
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_035 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_036
 * @tc.desc: test RemoveSubscribeResultRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_036 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_036 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_037
 * @tc.desc: test PrintSubscribeState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_037 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    const int64_t subscribeId2 = 2;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId2, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_037 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_038
 * @tc.desc: test RetryFailureRdbSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_038 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    formDataProxyRecord.RetryFailureRdbSubscribes(record);
    record.uri = "";
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_038 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_040
 * @tc.desc: test PermStateChangeCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_040 start";
    FormRecord formRecord;
    int64_t formId = 1;
    MockGetFormRecord(true);
    bool result = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    EXPECT_TRUE(result);
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    int32_t userId = 0;
    OHOS::AppExecFwk::ProxyData proxyData;
    proxyData.uri = TEST_DATA_URI;
    proxyData.requiredReadPermission = TEST_REQUIRED_READ_PERMISSON;
    proxyData.requiredWritePermission = TEST_REQUIRED_WRITE_PERMISSON;
    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.emplace_back(TEST_DATA_URI, TEST_PROXY_SUBSCRIBE_ID);
    MockGetCurrentAccountIdRet(userId);
    MockGetAllProxyDataInfos(true, proxyData);
    int32_t ret = 0;
    MockRegisterPermStateChangeCallback(ret);
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    MockConnectServiceAbility(true);
    int32_t permStateChangeType = 0;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, TEST_REQUIRED_READ_PERMISSON);
    MockConnectServiceAbility(false);
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, TEST_REQUIRED_READ_PERMISSON);
    formDataProxyRecord.UnRegisterPermissionListener();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_040 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_041
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_041 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_041 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_042
 * @tc.name: OnRdbDataChange
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_042 start";

    DataShare::RdbChangeNode changeNode;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    formDataProxyRecord.OnRdbDataChange(changeNode);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_042 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_043
 * @tc.name: OnPublishedDataChange
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_043 start";

    DataShare::PublishedDataChangeNode changeNode;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    formDataProxyRecord.OnPublishedDataChange(changeNode);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_043 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_044
 * @tc.desc: test SubscribeRdbFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_044 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_044 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_045
 * @tc.desc: test SubscribeRdbFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_045 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_045 end";
}

/**
 * @tc.name: FmsFormDataProxyRecordTest_046
 * @tc.desc: test UnsubscribeFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_046 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.UnsubscribeFormData();
    EXPECT_EQ(ret, formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap));
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_046 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_047
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_047 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_047 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_048
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_048 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    formDataProxyRecord.ParseFormDataProxies(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_048 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_049
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_049 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap subscribeMap;
    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    formDataProxyRecord.ConvertSubscribeMapToRequests(subscribeMap, formDataProxyRequests);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_049 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_050
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_050 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::PublishedDataItem> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    formDataProxyRecord.UpdatePublishedDataForm(data);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_050 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_051
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_051 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    formDataProxyRecord.UpdateRdbDataForm(data);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_051 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_075
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_075, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_075 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;
    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    formDataProxyRecord.UnsubscribeFormData(originRdbMap, originPublishMap);
    formDataProxyRecord.SubscribeRdbFormData(newRdbMap);
    formDataProxyRecord.SubscribePublishFormData(newPublishMap);
    formDataProxyRecord.UpdateSubscribeFormData(formDataProxies);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_075 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_052
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_052 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;
    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_052 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_053
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_053, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_053 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.EnableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_053 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_054
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_054, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_054 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.DisableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_054 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_055
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_055, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_055 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_055 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_056
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_056, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_056 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_056 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_057
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_057, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_057 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_057 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_058
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_058, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_058 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_058 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_059
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_059 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    node.ashmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_059 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_060
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_060 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    formAshmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_060 end";
}
 
/**
* @tc.number: FmsFormDataProxyRecordTest_061
* @tc.name: PrepareImageData
* @tc.desc: Verify that the return value is correct.
* @tc.details:
*      temporaryFlag is true, and tempForms is empty, then create a tempForm.
*      formRecords_ is empty, then create formRecords.
*/
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_061, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_061 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    const DataShare::PublishedDataItem data;
    formRecord.uiSyntax = FormType::JS;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_061 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_062
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_062, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_062 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_062 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_063
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_063, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_063 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_063 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_064
 * @tc.desc: test GetFormSubscribedInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_064, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_064 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    formDataProxyRecord.GetFormSubscribeInfo(subscribedKeys, count);
    EXPECT_EQ(count, formDataProxyRecord.receivedDataCount_);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_064 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_065
 * @tc.desc: test AddSubscribeSuccessKey function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_065, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_065 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::string errorUri = "this is a error uri";
    FormDataProxyRecord::SubscribeResultRecord errorRecord{errorUri, 1, 1, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 0);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);

    std::string correctUri = "this is a correct uri?";
    FormDataProxyRecord::SubscribeResultRecord successRecord{correctUri, 1, 0, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 1);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_065 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_066
 * @tc.desc: test SubscribeFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_066, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_066 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_066 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_067
 * @tc.desc: test RegisterPermissionListener&&UnRegisterPermissionListener function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_067, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_067 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    formDataProxyRecord.UnRegisterPermissionListener();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_067 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_068
 * @tc.desc: test PermStateChangeCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_068, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_068 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    int32_t permStateChangeType = 1;
    std::string permissionName;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    permStateChangeType = 0;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_068 end";
}
 
 
/**
* @tc.name: FmsFormDataProxyRecordTest_069
* @tc.desc: test RegisterPermissionListener function.
* @tc.type: FUNC
*/
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_069, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_069 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_069 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_070
 * @tc.desc: test RetryFailureSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_070, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_070 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    formDataProxyRecord.RetryFailureSubscribes();
    formDataProxyRecord.dataShareHelper_ = nullptr;
    formDataProxyRecord.RetryFailureSubscribes();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_070 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_071
 * @tc.desc: test RemoveSubscribeResultRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_071, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_071 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_071 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_072
 * @tc.desc: test PrintSubscribeState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_072, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_072 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    const int64_t subscribeId2 = 2;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId2, true);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_072 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_073
 * @tc.desc: test RetryFailureRdbSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_073, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_073 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    formDataProxyRecord.RetryFailureRdbSubscribes(record);
    record.uri = "";
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_073 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_074
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_074, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_074 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.EnableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_074 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_175
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_175, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_175 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);
    formDataProxyRecord.DisableSubscribeFormData();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_175 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_076
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_076, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_076 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_076 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_077
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_077, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_077 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_077 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_078
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_078, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_078 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_078 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_079
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_079, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_079 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_079 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_080
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_080, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_080 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    node.ashmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_080 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_081
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_081, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_081 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    formAshmem = nullptr;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_081 end";
}
 
/**
* @tc.number: FmsFormDataProxyRecordTest_082
* @tc.name: PrepareImageData
* @tc.desc: Verify that the return value is correct.
* @tc.details:
*      temporaryFlag is true, and tempForms is empty, then create a tempForm.
*      formRecords_ is empty, then create formRecords.
*/
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_082, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_082 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    const DataShare::PublishedDataItem data;
    formRecord.uiSyntax = FormType::JS;
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_082 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_083
 * @tc.name: PrepareImageData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_083, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_083 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const DataShare::PublishedDataItem data;
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_083 end";
}
 
/**
 * @tc.number: FmsFormDataProxyRecordTest_084
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_084, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_084 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, false);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_084 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_085
 * @tc.desc: test GetFormSubscribedInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_085, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_085 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    formDataProxyRecord.GetFormSubscribeInfo(subscribedKeys, count);
    EXPECT_EQ(count, formDataProxyRecord.receivedDataCount_);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_085 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_086
 * @tc.desc: test AddSubscribeSuccessKey function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_086, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_086 start";
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::string errorUri = "this is a error uri";
    FormDataProxyRecord::SubscribeResultRecord errorRecord{errorUri, 1, 1, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(errorRecord, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 0);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);

    std::string correctUri = "this is a correct uri?";
    FormDataProxyRecord::SubscribeResultRecord successRecord{correctUri, 1, 0, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, false);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    formDataProxyRecord.AddSubscribeResultRecord(successRecord, true);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);
    EXPECT_EQ(subscribedKeys.size(), 1);
    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_086 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_087
 * @tc.desc: test SubscribeFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_087, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_087 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_087 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_088
 * @tc.desc: test RegisterPermissionListener&&UnRegisterPermissionListener function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_088, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_088 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    formDataProxyRecord.UnRegisterPermissionListener();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_088 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_089
 * @tc.desc: test PermStateChangeCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_089, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_089 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    int32_t permStateChangeType = 1;
    std::string permissionName;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    permStateChangeType = 0;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, permissionName);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_089 end";
}
 
 
/**
* @tc.name: FmsFormDataProxyRecordTest_090
* @tc.desc: test RegisterPermissionListener function.
* @tc.type: FUNC
*/
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_090, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_090 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_090 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_091
 * @tc.desc: test RetryFailureSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_091, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_091 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    formDataProxyRecord.RetryFailureSubscribes();
    formDataProxyRecord.dataShareHelper_ = nullptr;
    formDataProxyRecord.RetryFailureSubscribes();
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_091 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_092
 * @tc.desc: test RemoveSubscribeResultRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_092, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_092 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.RemoveSubscribeResultRecord(uriString, subscribeId, true);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_092 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_093
 * @tc.desc: test PrintSubscribeState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_093, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_093 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId, true);
    const int64_t subscribeId2 = 2;
    formDataProxyRecord.PrintSubscribeState(uriString, subscribeId2, true);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_093 end";
}
 
/**
 * @tc.name: FmsFormDataProxyRecordTest_094
 * @tc.desc: test RetryFailureRdbSubscribes function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_094, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_094 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    int32_t uid = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, uid);
    std::string uriString = "testUri";
    const int64_t subscribeId = 1;
    FormDataProxyRecord::SubscribeResultRecord record;
    record.subscribeId = subscribeId;
    record.uri = uriString;
    record.ret = 0;
    record.retry = false;
    record.retryRet = 0;
    formDataProxyRecord.RetryFailureRdbSubscribes(record);
    record.uri = "";
    std::map<int64_t, FormDataProxyRecord::SubscribeResultRecord> records;
    records.emplace(subscribeId, record);
    formDataProxyRecord.rdbSubscribeResultMap_.emplace(uriString, records);
    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);
    EXPECT_EQ(subscribedKeys.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_094 end";
}
  
/**
 * @tc.name: FmsFormDataProxyRecordTest_039
 * @tc.desc: test PermStateChangeCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_039 start";
    FormRecord formRecord;
    int64_t formId = 1;
    MockGetFormRecord(true);
    bool result = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    EXPECT_TRUE(result);
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    int32_t userId = 0;
    OHOS::AppExecFwk::ProxyData proxyData;
    proxyData.uri = TEST_DATA_URI;
    proxyData.requiredReadPermission = TEST_REQUIRED_READ_PERMISSON;
    proxyData.requiredWritePermission = TEST_REQUIRED_WRITE_PERMISSON;
    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.emplace_back(TEST_DATA_URI, TEST_PROXY_SUBSCRIBE_ID);
    MockGetCurrentAccountIdRet(userId);
    MockGetAllProxyDataInfos(true, proxyData);
    int32_t ret = 0;
    MockRegisterPermStateChangeCallback(ret);
    formDataProxyRecord.RegisterPermissionListener(formDataProxies);
    MockConnectServiceAbility(true);
    int32_t permStateChangeType = 0;
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, TEST_REQUIRED_READ_PERMISSON);
    MockConnectServiceAbility(false);
    formDataProxyRecord.PermStateChangeCallback(permStateChangeType, TEST_REQUIRED_READ_PERMISSON);
    formDataProxyRecord.UnRegisterPermissionListener();
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_039 end";
}
}
