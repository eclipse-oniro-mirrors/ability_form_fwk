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
    std::vector<std::string> data_;
    data_.push_back(R"({"string": "hello"})");
    changeNode.data_ = data_;
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
