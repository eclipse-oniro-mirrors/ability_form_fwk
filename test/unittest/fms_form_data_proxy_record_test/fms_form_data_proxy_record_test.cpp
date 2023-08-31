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
#include "form_data_proxy_record.h"
#include "form_item_info.h"
#undef private
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_record.h"
#include "form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"


using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
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

    FormItemInfo formItemInfo;
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
    FormItemInfo formItemInfo;
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
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    formDataProxyRecord.OnPublishedDataChange(changeNode);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_003 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_004
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_004 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    ErrCode ret = formDataProxyRecord.SubscribeFormData(formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_004 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_005
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: dataShareHelper is empty.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_005 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, "", formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> rdbSubscribeMap;
    // std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    std::shared_ptr<DataShare::DataShareHelper> datashareHelper = nullptr;

    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_005 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_006
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: rdbSubscribeMap is empty.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_006 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> rdbSubscribeMap;
    rdbSubscribeMap.empty();
    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_006 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_007
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: rdbSubscribeMap and dataShareHelper is exist.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_007 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    std::string bundleName = "this is a bundleName";
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> rdbSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;

    ErrCode ret = formDataProxyRecord.SubscribeRdbFormData(rdbSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_007 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_008
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: dataShareHelper is empty.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_008 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    std::map<std::string, std::string> publishSubscribeMap;

    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_008 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_009
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: publishSubscribeMap is empty.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_009 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> publishSubscribeMap;
    publishSubscribeMap.empty();

    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_009 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_010
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_010 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> publishSubscribeMap;
    std::map<std::string, std::string> rdbSubscribeMap;

    publishSubscribeMap.empty();
    // auto formDataRecord = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> publishSubscribeMap;
    std::map<std::string, std::string> rdbSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> publishSubscribeMap;

    const std::vector<FormDataProxy> formDataProxies;

    publishSubscribeMap.empty();
    // auto formDataRecord = nullptr;

    formDataProxyRecord.ParseFormDataProxies(formDataProxies);
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> subscribeMap;
    std::vector<FormDataProxyRecord::FormDataProxyRequest> formDataProxyRequests;
    std::map<std::string, std::string> publishSubscribeMap;

    publishSubscribeMap.empty();
    // auto formDataRecord = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::PublishedDataItem> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    std::map<std::string, std::string> publishSubscribeMap;

    publishSubscribeMap.empty();
    // auto formDataRecord = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<std::string> data;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    std::map<std::string, std::string> publishSubscribeMap;

    publishSubscribeMap.empty();
    // auto formDataRecord = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    std::map<std::string, std::string> originRdbMap;
    std::map<std::string, std::string> newRdbMap;
    std::map<std::string, std::string> originPublishMap;
    std::map<std::string, std::string> newPublishMap;
    formDataProxyRecord.UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    formDataProxyRecord.UnsubscribeFormData(originRdbMap, originPublishMap);
    formDataProxyRecord.SubscribeRdbFormData(newRdbMap);
    formDataProxyRecord.SubscribePublishFormData(newPublishMap);
    // auto formDataRecord = nullptr;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;

    std::map<std::string, std::string> originRdbMap;
    std::map<std::string, std::string> newRdbMap;
    std::map<std::string, std::string> originPublishMap;
    std::map<std::string, std::string> newPublishMap;

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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    std::map<std::string, std::string> rdbSubscribeMap;
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    std::map<std::string, std::string> rdbSubscribeMap;
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> rdbSubscribeMap;
    bool subsState = true;

    formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, subsState);
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> rdbSubscribeMap;
    bool subsState = false;
    rdbSubscribeMap.empty();

    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, subsState);
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::OperationResult> ret;
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    bool subsState = false;

    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, subsState);
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

    FormItemInfo formItemInfo;
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

    FormItemInfo formItemInfo;
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

    FormItemInfo formItemInfo;
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

    // const DataShare::RdbChangeNode changeNode;
    FormItemInfo formItemInfo;
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

    FormItemInfo formItemInfo;
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

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    bool subsState = false;

    ErrCode ret = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, subsState);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_028 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_029
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_029 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::OperationResult> ret;
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    bool subsState = true;

    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, subsState);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_029 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_030
 * @tc.name: SetPublishSubsState
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_030 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::vector<DataShare::OperationResult> ret;
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> publishSubscribeMap;
    bool subsState = true;
    publishSubscribeMap.empty();

    ErrCode result = formDataProxyRecord.SetPublishSubsState(publishSubscribeMap, subsState);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_030 end";
}


/**
 * @tc.number: FmsFormDataProxyRecordTest_031
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: publishSubscribeMap is empty.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_031 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    std::map<std::string, std::string> publishSubscribeMap;

    ErrCode ret = formDataProxyRecord.SubscribePublishFormData(publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_031 end";
}


/**
 * @tc.number: FmsFormDataProxyRecordTest_032
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_032 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    std::map<std::string, std::string> publishSubscribeMap;
    std::map<std::string, std::string> rdbSubscribeMap;

    ErrCode ret = formDataProxyRecord.UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_032 end";
}


/**
 * @tc.number: FmsFormDataProxyRecordTest_033
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_033 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> rdbSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = nullptr;
    bool subsState = false;

    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, subsState);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_033 end";
}

/**
 * @tc.number: FmsFormDataProxyRecordTest_034
 * @tc.name: SubscribePublishFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataProxyRecordTest, FmsFormDataProxyRecordTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_034 start";

    FormItemInfo formItemInfo;
    FormRecord formRecord;
    int64_t formId = 1;
    uint32_t tokenId = 1;
    FormDataProxyRecord formDataProxyRecord(formId, formRecord.bundleName, formRecord.uiSyntax, tokenId, 1);
    const std::vector<FormDataProxy> formDataProxies;
    std::map<std::string, std::string> rdbSubscribeMap;
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper;
    bool subsState = false;

    ErrCode ret = formDataProxyRecord.SetRdbSubsState(rdbSubscribeMap, subsState);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_034 end";
}
}