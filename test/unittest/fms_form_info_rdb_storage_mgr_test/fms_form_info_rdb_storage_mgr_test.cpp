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
}
}