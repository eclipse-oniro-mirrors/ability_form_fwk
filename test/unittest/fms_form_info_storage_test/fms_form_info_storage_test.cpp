/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "form_info.h"
#include "form_info_storage.h"
#include "form_mgr_errors.h"
#include "nlohmann/json.hpp"
#undef public
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class FmsFormInfoStorageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AAFwk::FormInfoStorage> formInfoStorage_;
};

void FmsFormInfoStorageTest::SetUpTestCase()
{}

void FmsFormInfoStorageTest::TearDownTestCase()
{}

void FmsFormInfoStorageTest::SetUp()
{
    formInfoStorage_ = std::make_shared<AAFwk::FormInfoStorage>();
}

void FmsFormInfoStorageTest::TearDown()
{
    formInfoStorage_ = nullptr;
}

/*
* @tc.name: FmsFormInfoStorageTest_001
* @tc.desc: Test function FormInfoStorage is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_001 start";
    int32_t userId = 1;
    AppExecFwk::FormInfo formInfo = {};
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfos.emplace_back(formInfo);
    EXPECT_FALSE(formInfos.empty());
    AAFwk::FormInfoStorage formInfoStorage(userId, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_001 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_002
* @tc.desc: Test function GetAllFormsInfo is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_002 start";
    int32_t userId = -1;
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->FormInfoStorage::GetAllFormsInfo(userId, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_002 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_003
* @tc.desc: Test function GetAllFormsInfo is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_003 start";
    int32_t userId = 1;
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->FormInfoStorage::GetAllFormsInfo(userId, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_003 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_004
* @tc.desc: Test function GetAllFormsInfo is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_004 start";
    int32_t userId = 1;
    AppExecFwk::FormInfo formInfo1 = {};
    AppExecFwk::FormInfo formInfo2 = {};
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->userId = 0;
    formInfoStorage_->formInfos.emplace_back(formInfo1);
    formInfoStorage_->formInfos.emplace_back(formInfo2);
    formInfoStorage_->FormInfoStorage::GetAllFormsInfo(userId, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_004 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_005
* @tc.desc: Test function GetFormsInfoByModule is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_005 start";
    int32_t userId = 1;
    std::string moduleName = "entry";
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->FormInfoStorage::GetFormsInfoByModule(userId, moduleName, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_005 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_006
* @tc.desc: Test function GetFormsInfoByModule is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_006 start";
    int32_t userId = -1;
    std::string moduleName = "entry";
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->FormInfoStorage::GetFormsInfoByModule(userId, moduleName, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_006 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_007
* @tc.desc: Test function GetFormsInfoByModule is called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_007 start";
    int32_t userId = 1;
    std::string moduleName = "entry";
    AppExecFwk::FormInfo formInfo1 = {};
    AppExecFwk::FormInfo formInfo2 = {};
    formInfo1.moduleName = "entry";
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfoStorage_->userId = 0;
    formInfoStorage_->formInfos.emplace_back(formInfo1);
    formInfoStorage_->formInfos.emplace_back(formInfo2);
    formInfoStorage_->FormInfoStorage::GetFormsInfoByModule(userId, moduleName, formInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_007 end";
}

/*
* @tc.name: FmsFormInfoStorageTest_008
* @tc.desc: Test function to_json and from_json are called
* @tc.type: FUNC
*/
HWTEST_F(FmsFormInfoStorageTest, FmsFormInfoStorageTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_008 start";
    nlohmann::json jsonObject;
    AAFwk::FormInfoStorage formInfoStorage;
    AppExecFwk::FormInfo formInfo = {};
    std::vector<AppExecFwk::FormInfo> formInfos;
    formInfos.emplace_back(formInfo);
    EXPECT_FALSE(formInfos.empty());
    to_json(jsonObject, formInfoStorage);
    from_json(jsonObject, formInfoStorage);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageTest_008 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS