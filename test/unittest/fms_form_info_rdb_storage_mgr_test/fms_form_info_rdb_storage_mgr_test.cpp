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

#include "form_info_rdb_storage_mgr.h"
#include "form_mgr_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
void MockQueryData(bool mockRet);
void MockInit(bool mockRet);
void MockInsertData(bool mockRet);
void MockDeleteData(bool mockRet);
void MockFormRdbDataMgrInit(bool mockRet);

class FmsFormInfoRdbStorageMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void FmsFormInfoRdbStorageMgrTest::SetUpTestCase()
{}

void FmsFormInfoRdbStorageMgrTest::TearDownTestCase()
{}

void FmsFormInfoRdbStorageMgrTest::SetUp()
{}

void FmsFormInfoRdbStorageMgrTest::TearDown()
{}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_001
 * @tc.desc: Test UpdateBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_001, TestSize.Level0)
{
    std::string bundleName = "testKey";
    std::string formInfoStorages = "formInfo";
    auto result = FormInfoRdbStorageMgr::GetInstance().UpdateBundleFormInfos(bundleName, formInfoStorages);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_002
 * @tc.desc: Test UpdateBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_002, TestSize.Level0)
{
    std::string bundleName = "";
    std::string formInfoStorages = "";
    auto result = FormInfoRdbStorageMgr::GetInstance().UpdateBundleFormInfos(bundleName, formInfoStorages);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_003
 * @tc.desc: Test LoadFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_003, TestSize.Level0)
{
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_004
 * @tc.desc: Test RemoveBundleFormInfos fail
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_004, TestSize.Level0)
{
    std::string bundleName = "";
    auto result = FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_005
 * @tc.desc: Test RemoveBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_005, TestSize.Level0)
{
    std::string bundleName = "testKey";
    auto result = FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_006
 * @tc.desc: Test ModifyStorageFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_006, TestSize.Level0)
{
    const int64_t formId = 1;
    InnerFormInfo innerFormInfo;
    innerFormInfo.SetFormId(formId);
    auto result = FormInfoRdbStorageMgr::GetInstance().ModifyStorageFormData(innerFormInfo);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_007
 * @tc.desc: Test LoadFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_007, TestSize.Level0)
{
    std::vector<InnerFormInfo> innerFormInfos;
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadFormData(innerFormInfos);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_008
 * @tc.desc: Test DeleteStorageFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_008, TestSize.Level0)
{
    std::string formId = "formId_1";
    auto result = FormInfoRdbStorageMgr::GetInstance().DeleteStorageFormData(formId);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_009
 * @tc.desc: Test LoadFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_009, TestSize.Level0)
{
    std::vector<InnerFormInfo> innerFormInfos;
    FormRdbConfig formRdbConfig;
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    MockQueryData(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    result = FormInfoRdbStorageMgr::GetInstance().LoadFormData(innerFormInfos);
    MockQueryData(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_010
 * @tc.desc: Test SaveStorageFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_010, TestSize.Level0)
{
    InnerFormInfo innerFormInfos;
    FormRdbConfig formRdbConfig;
    MockInsertData(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().SaveStorageFormData(innerFormInfos);
    MockInsertData(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_011
 * @tc.desc: Test DeleteStorageFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_011, TestSize.Level0)
{
    std::string formId;
    FormRdbConfig formRdbConfig;
    MockDeleteData(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().DeleteStorageFormData(formId);
    MockDeleteData(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_012
 * @tc.desc: Test LoadStatusData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_012, TestSize.Level0)
{
    std::string formId = "1";
    std::string statusData;
    MockQueryData(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadStatusData(formId, statusData);
    MockQueryData(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_013
 * @tc.desc: Test CheckRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_013, TestSize.Level0)
{
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    MockInit(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    MockInit(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormInfoRdbStorageMgrTest_014
 * @tc.desc: Test LoadFormData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoRdbStorageMgrTest, FmsFormInfoRdbStorageMgrTest_014, TestSize.Level0)
{
    std::string formId;
    std::string statusData;
    std::vector<InnerFormInfo> innerFormInfos;
    MockInit(false);
    auto result = FormInfoRdbStorageMgr::GetInstance().LoadFormData(innerFormInfos);
    MockInit(true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}
}
}