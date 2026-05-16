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
#include "mock_form_mgr_adapter_facade.h"
#include "form_provider_data.h"
#include "want.h"

using namespace testing;
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

/**
 * @tc.number: FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_001
 * @tc.name: RetryFailurePublishedSubscribes_Success
 * @tc.desc: Verify that when record.ret == 0, function returns directly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeResultRecord record{"testUri", formId, 0, false, 0};
    formDataProxyRecord.RetryFailurePublishedSubscribes(record);

    EXPECT_FALSE(record.retry);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_002
 * @tc.name: RetryFailurePublishedSubscribes_ShouldRetry
 * @tc.desc: Verify that when record.ret != 0 and record.retry == false, retry flag is set to true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    auto formDataProxyRecord = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeResultRecord record{"testUri", formId, -1, false, 0};
    formDataProxyRecord->RetryFailurePublishedSubscribes(record);

    EXPECT_TRUE(record.retry);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailurePublishedSubscribes_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_001
 * @tc.name: RetryFailureRdbSubscribes_Success
 * @tc.desc: Verify that when record.ret == 0, function returns directly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeResultRecord record{"testUri", formId, 0, false, 0};
    formDataProxyRecord.RetryFailureRdbSubscribes(record);

    EXPECT_FALSE(record.retry);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_002
 * @tc.name: RetryFailureRdbSubscribes_ShouldRetry
 * @tc.desc: Verify that when record.ret != 0 and record.retry == false, retry flag is set to true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    auto formDataProxyRecord = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeResultRecord record{"testUri", formId, -1, false, 0};
    formDataProxyRecord->RetryFailureRdbSubscribes(record);

    EXPECT_TRUE(record.retry);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RetryFailureRdbSubscribes_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_PrepareImageData_001
 * @tc.name: PrepareImageData_NullAshmem
 * @tc.desc: Verify that PrepareImageData returns false when ashmem is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_PrepareImageData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    DataShare::PublishedDataItem data;
    data.key_ = "testImage";
    DataShare::AshmemNode ashmemNode;
    ashmemNode.ashmem = nullptr;
    data.value_ = ashmemNode;

    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);

    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_PrepareImageData_002
 * @tc.name: PrepareImageData_NonJS
 * @tc.desc: Verify that PrepareImageData can be called for non-JS card type.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_PrepareImageData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_002 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    DataShare::PublishedDataItem data;
    data.key_ = "testImage";
    DataShare::AshmemNode ashmemNode;
    ashmemNode.ashmem = nullptr;
    data.value_ = ashmemNode;

    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);

    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_PrepareImageData_003
 * @tc.name: PrepareImageData_JS
 * @tc.desc: Verify that PrepareImageData can be called for JS card type.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_PrepareImageData_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_003 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    DataShare::PublishedDataItem data;
    data.key_ = "testImage";
    DataShare::AshmemNode ashmemNode;
    ashmemNode.ashmem = nullptr;
    data.value_ = ashmemNode;

    nlohmann::json jsonObj;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;

    bool ret = formDataProxyRecord.PrepareImageData(data, jsonObj, imageDataMap);

    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrepareImageData_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_SetPublishSubsState_001
 * @tc.name: SetPublishSubsState_NullHelper
 * @tc.desc: Verify that SetPublishSubsState returns error when dataShareHelper_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_SetPublishSubsState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SetPublishSubsState_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    formDataProxyRecord.dataShareHelper_ = nullptr;

    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("testId");
    publishSubscribeMap["testUri"] = subscribeIds;

    ErrCode ret = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, true);

    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SetPublishSubsState_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_SetRdbSubsState_001
 * @tc.name: SetRdbSubsState_NullHelper
 * @tc.desc: Verify that SetRdbSubsState returns error when dataShareHelper_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_SetRdbSubsState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SetRdbSubsState_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    formDataProxyRecord.dataShareHelper_ = nullptr;

    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("testId");
    rdbSubscribeMap["testUri"] = subscribeIds;

    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, true);

    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SetRdbSubsState_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdateSubscribeMap_001
 * @tc.name: UpdateSubscribeMap_RdbKeyExists
 * @tc.desc: Verify that UpdateSubscribeMap handles existing rdb keys correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdateSubscribeMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    // Pre-populate rdbSubscribeMap_
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("oldSubscribeId");
    formDataProxyRecord.rdbSubscribeMap_["testUri"] = subscribeIds;

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("testUri", "newSubscribeId"));

    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;

    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);

    EXPECT_EQ(originRdbMap.size(), 1);
    EXPECT_EQ(newRdbMap.size(), 1);
    EXPECT_EQ(newRdbMap["testUri"].count("newSubscribeId"), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdateSubscribeMap_002
 * @tc.name: UpdateSubscribeMap_RdbKeyNotExists
 * @tc.desc: Verify that UpdateSubscribeMap handles non-existing rdb keys correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdateSubscribeMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("testUri", "newSubscribeId"));

    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;

    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);

    EXPECT_EQ(originRdbMap.size(), 0);
    EXPECT_EQ(newRdbMap.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdateSubscribeMap_003
 * @tc.name: UpdateSubscribeMap_PublishKeyExists
 * @tc.desc: Verify that UpdateSubscribeMap handles existing publish keys correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdateSubscribeMap_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_003 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("oldSubscribeId");
    formDataProxyRecord.publishSubscribeMap_["testUri"] = subscribeIds;

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("testUri", "newSubscribeId"));

    FormDataProxyRecord::SubscribeMap originRdbMap;
    FormDataProxyRecord::SubscribeMap newRdbMap;
    FormDataProxyRecord::SubscribeMap originPublishMap;
    FormDataProxyRecord::SubscribeMap newPublishMap;

    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);

    EXPECT_EQ(originPublishMap.size(), 1);
    EXPECT_EQ(newPublishMap.size(), 1);
    EXPECT_EQ(newPublishMap["testUri"].count("newSubscribeId"), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateSubscribeMap_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdatePublishedDataForm_001
 * @tc.name: UpdatePublishedDataForm_ValidJson
 * @tc.desc: Verify that UpdatePublishedDataForm handles valid JSON correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdatePublishedDataForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_001 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.isDistributedForm = false;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<DataShare::PublishedDataItem> data;
    DataShare::PublishedDataItem item;
    item.key_ = "testKey";
    std::string jsonStr = R"({"name": "test", "value": 123})";
    item.value_ = jsonStr;
    data.emplace_back(std::move(item));

    MockGetFormRecord(true);

    auto mockFacade = std::make_shared<MockFormMgrAdapterFacade>();
    MockFormMgrAdapterFacade::obj = mockFacade;
    EXPECT_CALL(*mockFacade, UpdateForm(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));

    formDataProxyRecord.UpdatePublishedDataForm(data);

    MockFormMgrAdapterFacade::obj = nullptr;

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdatePublishedDataForm_002
 * @tc.name: UpdatePublishedDataForm_InvalidJson
 * @tc.desc: Verify that UpdatePublishedDataForm skips invalid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdatePublishedDataForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_002 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.isDistributedForm = false;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<DataShare::PublishedDataItem> data;
    DataShare::PublishedDataItem item;
    item.key_ = "testKey";
    std::string invalidJson = "{invalid json";
    item.value_ = invalidJson;
    data.emplace_back(std::move(item));

    MockGetFormRecord(true);

    auto mockFacade = std::make_shared<MockFormMgrAdapterFacade>();
    MockFormMgrAdapterFacade::obj = mockFacade;
    EXPECT_CALL(*mockFacade, UpdateForm(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));

    formDataProxyRecord.UpdatePublishedDataForm(data);

    MockFormMgrAdapterFacade::obj = nullptr;

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdatePublishedDataForm_003
 * @tc.name: UpdatePublishedDataForm_WithImageData
 * @tc.desc: Verify that UpdatePublishedDataForm handles imageDataMap correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdatePublishedDataForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_003 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.isDistributedForm = false;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    auto formDataProxyRecord = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<DataShare::PublishedDataItem> data;
    DataShare::PublishedDataItem item1;
    item1.key_ = "textKey";
    item1.value_ = R"({"text": "value"})";
    data.emplace_back(std::move(item1));

    MockGetFormRecord(true);

    auto mockFacade = std::make_shared<MockFormMgrAdapterFacade>();
    MockFormMgrAdapterFacade::obj = mockFacade;
    EXPECT_CALL(*mockFacade, UpdateForm(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));

    formDataProxyRecord->receivedDataCount_ = INT32_MAX - 1;
    formDataProxyRecord->UpdatePublishedDataForm(data);

    EXPECT_EQ(formDataProxyRecord->receivedDataCount_, INT32_MAX);

    MockFormMgrAdapterFacade::obj = nullptr;

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdatePublishedDataForm_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UpdateRdbDataForm_001
 * @tc.name: UpdateRdbDataForm_ValidData
 * @tc.desc: Verify that UpdateRdbDataForm handles valid data correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UpdateRdbDataForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateRdbDataForm_001 start";
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    auto formDataProxyRecord = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<std::string> data;
    data.push_back(R"({"key1": "value1"})");
    data.push_back(R"({"key2": "value2"})");

    MockGetFormRecord(true);

    auto mockFacade = std::make_shared<MockFormMgrAdapterFacade>();
    MockFormMgrAdapterFacade::obj = mockFacade;
    EXPECT_CALL(*mockFacade, UpdateForm(_, _, _, _))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));

    formDataProxyRecord->receivedDataCount_ = 0;
    formDataProxyRecord->UpdateRdbDataForm(data);

    EXPECT_EQ(formDataProxyRecord->receivedDataCount_, 1);

    MockFormMgrAdapterFacade::obj = nullptr;

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UpdateRdbDataForm_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_001
 * @tc.name: ConvertSubscribeMapToRequests_ValidSubscribeId
 * @tc.desc: Verify that ConvertSubscribeMapToRequests handles valid subscribeId correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeMap subscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("12345");
    subscribeIds.insert("67890");
    subscribeMap["testUri"] = subscribeIds;

    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    formDataProxyRecord.ConvertSubscribeMapToRequests(subscribeMap, formDataProxyRequests);

    EXPECT_EQ(formDataProxyRequests.size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_002
 * @tc.name: ConvertSubscribeMapToRequests_InvalidSubscribeId
 * @tc.desc: Verify that ConvertSubscribeMapToRequests uses default formId when subscribeId conversion fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeMap subscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("invalid_id");
    subscribeIds.insert("12345");
    subscribeMap["testUri"] = subscribeIds;

    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    formDataProxyRecord.ConvertSubscribeMapToRequests(subscribeMap, formDataProxyRequests);

    EXPECT_EQ(formDataProxyRequests.size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_003
 * @tc.name: ConvertSubscribeMapToRequests_MultipleSubscribes
 * @tc.desc: Verify that ConvertSubscribeMapToRequests handles multiple subscribeIds correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_003 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    FormDataProxyRecord::SubscribeMap subscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("12345");
    subscribeIds.insert("67890");
    subscribeIds.insert("99999");
    subscribeMap["testUri"] = subscribeIds;

    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    formDataProxyRecord.ConvertSubscribeMapToRequests(subscribeMap, formDataProxyRequests);

    EXPECT_EQ(formDataProxyRequests.size(), 3);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ConvertSubscribeMapToRequests_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_001
 * @tc.name: ParseFormDataProxiesIntoSubscribeMap_KeyCheckingFound
 * @tc.desc: Verify that ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys filters by expectedKeys.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_001,
    TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("uri1", "sub1"));
    formDataProxies.push_back(FormDataProxy("uri2", "sub2"));
    formDataProxies.push_back(FormDataProxy("uri3", "sub3"));

    std::unordered_set<std::string> expectedKeys;
    expectedKeys.insert("uri1");
    expectedKeys.insert("uri3");

    FormDataProxyRecord::SubscribeMap subscribeMap;
    formDataProxyRecord.ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
        formDataProxies, expectedKeys, true, subscribeMap);

    EXPECT_EQ(subscribeMap.size(), 2);
    EXPECT_EQ(subscribeMap.count("uri1"), 1);
    EXPECT_EQ(subscribeMap.count("uri3"), 1);
    EXPECT_EQ(subscribeMap.count("uri2"), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_002
 * @tc.name: ParseFormDataProxiesIntoSubscribeMap_NoKeyChecking
 * @tc.desc: Verify that ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys processes all
 *          when keyCheckingNeeded is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_002,
    TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("uri1", "sub1"));
    formDataProxies.push_back(FormDataProxy("uri2", "sub2"));

    std::unordered_set<std::string> expectedKeys;
    expectedKeys.insert("uri1");

    FormDataProxyRecord::SubscribeMap subscribeMap;
    formDataProxyRecord.ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
        formDataProxies, expectedKeys, false, subscribeMap);

    EXPECT_EQ(subscribeMap.size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_003
 * @tc.name: ParseFormDataProxiesIntoSubscribeMap_EmptySubscribeId
 * @tc.desc: Verify that ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys uses formId when subscribeId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_003,
    TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_003 start";
    FormRecord formRecord;
    int64_t formId = 123;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("uri1", ""));

    std::unordered_set<std::string> expectedKeys;

    FormDataProxyRecord::SubscribeMap subscribeMap;
    formDataProxyRecord.ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
        formDataProxies, expectedKeys, false, subscribeMap);

    EXPECT_EQ(subscribeMap.size(), 1);
    EXPECT_EQ(subscribeMap["uri1"].count(std::to_string(formId)), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_004
 * @tc.name: ParseFormDataProxiesIntoSubscribeMap_ExistingKey
 * @tc.desc: Verify that ParseFormDataProxiesIntoSubscribeMap handles existing key.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_004,
    TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_004 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("uri1", "sub1"));
    formDataProxies.push_back(FormDataProxy("uri1", "sub2"));

    std::unordered_set<std::string> expectedKeys;

    FormDataProxyRecord::SubscribeMap subscribeMap;
    formDataProxyRecord.ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
        formDataProxies, expectedKeys, false, subscribeMap);

    EXPECT_EQ(subscribeMap.size(), 1);
    EXPECT_EQ(subscribeMap["uri1"].size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_ParseFormDataProxiesIntoSubscribeMap_004 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UnsubscribeFormData_001
 * @tc.name: UnsubscribeFormData_NullHelper
 * @tc.desc: Verify that UnsubscribeFormData returns error when dataShareHelper_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UnsubscribeFormData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UnsubscribeFormData_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    formDataProxyRecord.dataShareHelper_ = nullptr;

    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("testId");
    rdbSubscribeMap["testUri"] = subscribeIds;

    FormDataProxyRecord::SubscribeMap publishSubscribeMap;

    ErrCode ret = formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap);

    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UnsubscribeFormData_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_SubscribePublishFormData_001
 * @tc.name: SubscribePublishFormData_NullHelper
 * @tc.desc: Verify that SubscribePublishFormData returns error when dataShareHelper_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_SubscribePublishFormData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SubscribePublishFormData_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    formDataProxyRecord.dataShareHelper_ = nullptr;

    FormDataProxyRecord::SubscribeMap publishSubscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("testId");
    publishSubscribeMap["testUri"] = subscribeIds;

    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);

    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SubscribePublishFormData_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_SubscribeRdbFormData_001
 * @tc.name: SubscribeRdbFormData_NullHelper
 * @tc.desc: Verify that SubscribeRdbFormData returns error when dataShareHelper_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_SubscribeRdbFormData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SubscribeRdbFormData_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    formDataProxyRecord.dataShareHelper_ = nullptr;

    FormDataProxyRecord::SubscribeMap rdbSubscribeMap;
    std::unordered_set<std::string> subscribeIds;
    subscribeIds.insert("testId");
    rdbSubscribeMap["testUri"] = subscribeIds;

    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);

    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_SubscribeRdbFormData_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_UnregisterPermissionListener_001
 * @tc.name: UnregisterPermissionListener_WithCallback
 * @tc.desc: Verify that UnregisterPermissionListener cleans up callbackPtr_.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_UnregisterPermissionListener_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UnregisterPermissionListener_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    auto formDataProxyRecord = std::make_shared<FormDataProxyRecord>(
        formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::vector<FormDataProxy> formDataProxies;
    formDataProxies.push_back(FormDataProxy("testUri", "12345"));

    // Register permission listener first to set up callbackPtr_
    MockGetCurrentAccountIdRet(0);
    OHOS::AppExecFwk::ProxyData proxyData;
    proxyData.uri = "testUri";
    proxyData.requiredReadPermission = TEST_REQUIRED_READ_PERMISSON;
    proxyData.requiredWritePermission = TEST_REQUIRED_WRITE_PERMISSON;
    MockGetAllProxyDataInfos(false, proxyData);
    formDataProxyRecord->RegisterPermissionListener(formDataProxies);

    // Call UnregisterPermissionListener and verify it cleans up correctly
    formDataProxyRecord->UnRegisterPermissionListener();

    // Verify callbackPtr_ is nullptr after unregistering
    EXPECT_EQ(formDataProxyRecord->callbackPtr_, nullptr);

    // Verify multiple calls to UnregisterPermissionListener work correctly (no crash)
    formDataProxyRecord->UnRegisterPermissionListener();
    EXPECT_EQ(formDataProxyRecord->callbackPtr_, nullptr);

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_UnregisterPermissionListener_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_AddSubscribeResultRecord_001
 * @tc.name: AddSubscribeResultRecord_NewUri
 * @tc.desc: Verify that AddSubscribeResultRecord handles new URI correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_AddSubscribeResultRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_AddSubscribeResultRecord_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId = 100;
    FormDataProxyRecord::SubscribeResultRecord record{uri, subscribeId, 0, false, 0};

    formDataProxyRecord.AddSubscribeResultRecord(record, true);

    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_.size(), 1);
    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_[uri].size(), 1);
    EXPECT_TRUE(formDataProxyRecord.rdbSubscribeResultMap_[uri].count(subscribeId) > 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_AddSubscribeResultRecord_001 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_AddSubscribeResultRecord_002
 * @tc.name: AddSubscribeResultRecord_ExistingUri
 * @tc.desc: Verify that AddSubscribeResultRecord handles existing URI correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_AddSubscribeResultRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_AddSubscribeResultRecord_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId1 = 100;
    int64_t subscribeId2 = 200;

    FormDataProxyRecord::SubscribeResultRecord record1{uri, subscribeId1, 0, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(record1, true);

    FormDataProxyRecord::SubscribeResultRecord record2{uri, subscribeId2, 0, false, 0};
    formDataProxyRecord.AddSubscribeResultRecord(record2, true);

    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_.size(), 1);
    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_[uri].size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_AddSubscribeResultRecord_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_002
 * @tc.name: RemoveSubscribeResultRecord_UriNotExists
 * @tc.desc: Verify that RemoveSubscribeResultRecord handles non-existing URI.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId = 100;

    formDataProxyRecord.RemoveSubscribeResultRecord(uri, subscribeId, true);

    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_003
 * @tc.name: RemoveSubscribeResultRecord_SubscribeIdNotExists
 * @tc.desc: Verify that RemoveSubscribeResultRecord handles non-existing subscribeId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_003 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId1 = 100;
    int64_t subscribeId2 = 200;

    FormDataProxyRecord::SubscribeResultRecord record{uri, subscribeId1, 0, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri][subscribeId1] = record;

    formDataProxyRecord.RemoveSubscribeResultRecord(uri, subscribeId2, true);

    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_.size(), 1);
    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_[uri].size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_004
 * @tc.name: RemoveSubscribeResultRecord_EmptyAfterRemove
 * @tc.desc: Verify that RemoveSubscribeResultRecord removes URI when empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_004 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId = 100;

    FormDataProxyRecord::SubscribeResultRecord record{uri, subscribeId, 0, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri][subscribeId] = record;

    formDataProxyRecord.RemoveSubscribeResultRecord(uri, subscribeId, true);

    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_RemoveSubscribeResultRecord_004 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_PrintSubscribeState_002
 * @tc.name: PrintSubscribeState_SubscribeIdNotExists
 * @tc.desc: Verify that PrintSubscribeState handles non-existing subscribeId without crash.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_PrintSubscribeState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrintSubscribeState_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri = "testUri";
    int64_t subscribeId1 = 100;
    int64_t subscribeId2 = 200;

    // Set up test data with one subscription
    FormDataProxyRecord::SubscribeResultRecord record{uri, subscribeId1, 0, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri][subscribeId1] = record;
    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_[uri].size(), 1);

    // Verify function handles non-existing subscribeId correctly
    formDataProxyRecord.PrintSubscribeState(uri, subscribeId2, true);

    // Verify the original record is still intact
    EXPECT_EQ(formDataProxyRecord.rdbSubscribeResultMap_[uri].size(), 1);
    EXPECT_TRUE(formDataProxyRecord.rdbSubscribeResultMap_[uri].count(subscribeId1) > 0);

    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_PrintSubscribeState_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_GetFormSubscribeKeys_002
 * @tc.name: GetFormSubscribeKeys_WithValidRecords
 * @tc.desc: Verify that GetFormSubscribeKeys extracts keys correctly from valid records.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_GetFormSubscribeKeys_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_GetFormSubscribeKeys_002 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri1 = "testUri1?user=1&srcToken=1";
    std::string uri2 = "testUri2?user=1&srcToken=1";
    int64_t subscribeId = 100;

    FormDataProxyRecord::SubscribeResultRecord record1{uri1, subscribeId, 0, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri1][subscribeId] = record1;

    FormDataProxyRecord::SubscribeResultRecord record2{uri2, subscribeId, 0, false, 0};
    formDataProxyRecord.publishSubscribeResultMap_[uri2][subscribeId] = record2;

    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);

    EXPECT_EQ(subscribedKeys.size(), 1);
    EXPECT_EQ(subscribedKeys[0], "testUri1");

    subscribedKeys.clear();
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, false);

    EXPECT_EQ(subscribedKeys.size(), 1);
    EXPECT_EQ(subscribedKeys[0], "testUri2");
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_GetFormSubscribeKeys_002 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_GetFormSubscribeKeys_003
 * @tc.name: GetFormSubscribeKeys_WithFailedRecords
 * @tc.desc: Verify that GetFormSubscribeKeys skips failed records.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_GetFormSubscribeKeys_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_GetFormSubscribeKeys_003 start";
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);

    std::string uri1 = "testUri1?user=1&srcToken=1";
    std::string uri2 = "testUri2?user=1&srcToken=1";
    int64_t subscribeId = 100;

    FormDataProxyRecord::SubscribeResultRecord record1{uri1, subscribeId, -1, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri1][subscribeId] = record1;

    FormDataProxyRecord::SubscribeResultRecord record2{uri2, subscribeId, 0, false, 0};
    formDataProxyRecord.rdbSubscribeResultMap_[uri2][subscribeId] = record2;

    std::vector<std::string> subscribedKeys;
    formDataProxyRecord.GetFormSubscribeKeys(subscribedKeys, true);

    EXPECT_EQ(subscribedKeys.size(), 1);
    EXPECT_EQ(subscribedKeys[0], "testUri2");
    GTEST_LOG_(INFO) << "FmsFormDataProxyRecordTest_GetFormSubscribeKeys_003 end";
}
}
