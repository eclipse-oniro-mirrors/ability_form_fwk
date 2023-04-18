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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#define private public
#define protected public
#include "form_info_storage_mgr.h"
#include "distributed_kv_data_manager.h"
#include "hilog_wrapper.h"
#include "nlohmann/json.hpp"
#include "kvstore.h"
#include "form_mgr_errors.h"
#include "mock_single_kv_store.h"
#include "distributed_kv_data_manager.h"
#undef private
#undef protected

using namespace testing::ext;

extern void MockGetSingleKvStore(bool mockRet);
extern void MockGetKvStore(bool mockRet);

namespace OHOS {

namespace AppExecFwk {

class FmsFormInfoStorageMgrTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FmsFormInfoStorageMgrTest::SetUpTestCase() {}

void FmsFormInfoStorageMgrTest::TearDownTestCase() {}

void FmsFormInfoStorageMgrTest::SetUp() {}

void FmsFormInfoStorageMgrTest::TearDown() {}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_001
 * @tc.desc: Verify that the GetKvStore interface executes as expected and returns SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_001 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    EXPECT_EQ(DistributedKv::Status::SUCCESS, formInfoStorageMgr.GetKvStore());
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_001 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_002
 * @tc.desc: Verify that the GetKvStore interface executes as expected and returns INVALID_ARGUMENT.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_002 start";
    MockGetSingleKvStore(false);
    FormInfoStorageMgr formInfoStorageMgr;
    EXPECT_EQ(DistributedKv::Status::INVALID_ARGUMENT, formInfoStorageMgr.GetKvStore());
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_002 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_003
 * @tc.desc: Verify that the CheckKvStore interface executes as expected and returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_003 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    bool ret = true;
    ret  = formInfoStorageMgr.CheckKvStore();
    EXPECT_TRUE(!ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_003 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_004
 * @tc.desc: Verify that the CheckKvStore interface executes as expected and returns true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_004 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    bool ret = false;
    ret  = formInfoStorageMgr.CheckKvStore();
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_004 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_005
 * @tc.desc: Verify that the ResetKvStore interface executes as expected and returns true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_005 start";
    MockGetSingleKvStore(true);
    MockGetKvStore(false);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    bool ret = false;
    ret  = formInfoStorageMgr.ResetKvStore();
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_005 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_006
 * @tc.desc: Verify that the ResetKvStore interface executes as expected and returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_006 start";
    MockGetSingleKvStore(true);
    MockGetKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    bool ret = false;
    ret  = formInfoStorageMgr.ResetKvStore();
    EXPECT_TRUE(!ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_006 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_007
 * @tc.desc: Verify that the GetEntries interface executes as expected and returns ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_007 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    const std::string keyPrefix = "";
    std::vector<DistributedKv::Entry> allEntries;
    EXPECT_EQ(formInfoStorageMgr.GetEntries(keyPrefix, allEntries), DistributedKv::Status::ERROR);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_007 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_008
 * @tc.desc: Verify that the GetEntries interface executes as expected and returns SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_008 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string keyPrefix = "";
    std::vector<DistributedKv::Entry> allEntries;
    EXPECT_EQ(formInfoStorageMgr.GetEntries(keyPrefix, allEntries), DistributedKv::Status::SUCCESS);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_008 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_009
 * @tc.desc: Verify that the SaveEntries interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_009 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    std::vector<DistributedKv::Entry> allEntries;
    std::vector<InnerFormInfo> innerFormInfos;
    formInfoStorageMgr.SaveEntries(allEntries, innerFormInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_009 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_010
 * @tc.desc: Verify that the SaveEntries interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_010 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Entry allEntrie = {};
    allEntries.emplace_back(allEntrie);
    std::vector<InnerFormInfo> innerFormInfos;
    formInfoStorageMgr.SaveEntries(allEntries, innerFormInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_010 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_011
 * @tc.desc: Verify that the LoadFormInfos interface executes as expected and returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_011 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    EXPECT_EQ(formInfoStorageMgr.LoadFormInfos(formInfoStorages), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_011 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_012
 * @tc.desc: Verify that the TryTwice interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_012 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    ASSERT_NE(nullptr, kvStorePtr);
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    auto func = [](){ return DistributedKv::Status::IPC_ERROR; };
    std::function<DistributedKv::Status()> f = func;
    formInfoStorageMgr.TryTwice(f);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_012 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_013
 * @tc.desc: Verify that the TryTwice interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_013 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    ASSERT_NE(nullptr, kvStorePtr);
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    auto func = [](){ return DistributedKv::Status::SUCCESS; };
    std::function<DistributedKv::Status()> f = func;
    formInfoStorageMgr.TryTwice(f);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_013 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_014
 * @tc.desc: 1.Verify that the RemoveBundleFormInfos interface executes as expected.
 *           2.The interface return value isERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_014 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "";
    EXPECT_EQ(formInfoStorageMgr.RemoveBundleFormInfos(bundleName), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_014 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_015
 * @tc.desc: 1.Verify that the RemoveBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_015 start";
    MockGetSingleKvStore(true);
    const std::string bundleName = "com.form.start";
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    EXPECT_EQ(formInfoStorageMgr.RemoveBundleFormInfos(bundleName), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_015 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_016
 * @tc.desc: 1.Verify that the RemoveBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_016 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "com.form.start";
    EXPECT_EQ(formInfoStorageMgr.RemoveBundleFormInfos(bundleName), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_016 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_017
 * @tc.desc: 1.Verify that the LoadFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_017 start";
    MockGetSingleKvStore(true);
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::ERROR;
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    EXPECT_EQ(formInfoStorageMgr.LoadFormInfos(formInfoStorages), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_017 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_018
 * @tc.desc: 1.Verify that the RemoveBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_018 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "com.form.start";
    EXPECT_EQ(formInfoStorageMgr.RemoveBundleFormInfos(bundleName), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_018 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_019
 * @tc.desc: 1.Verify that the UpdateBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_019 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "";
    const std::string formInfoStorages = "";
    EXPECT_EQ(
        formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorages), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_019 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_020
 * @tc.desc: 1.Verify that the UpdateBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_020 start";
    MockGetSingleKvStore(true);
    const std::string bundleName = "com.form.start";
    const std::string formInfoStorages = "";
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    EXPECT_EQ(
        formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorages), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_020 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_021
 * @tc.desc: 1.Verify that the UpdateBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_021 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "com.form.start";
    const std::string formInfoStorages = "";
    EXPECT_EQ(formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorages), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_021 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_022
 * @tc.desc: 1.Verify that the UpdateBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_022 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "com.form.start";
    const std::string formInfoStorages = "";
    EXPECT_EQ(
        formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorages), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_022 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_023
 * @tc.desc: 1.Verify that the UpdateBundleFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_023 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Put_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string bundleName = "com.form.start";
    const std::string formInfoStorages = "";
    EXPECT_EQ(
        formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorages), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_023 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_024
 * @tc.desc: 1.Verify that the LoadFormData interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_024 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    std::vector<InnerFormInfo> innerFormInfos;
    EXPECT_EQ(formInfoStorageMgr.LoadFormData(innerFormInfos), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_024 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_025
 * @tc.desc: 1.Verify that the LoadFormData interface executes as expected.
 *           2.The interface return value true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_025 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<InnerFormInfo> innerFormInfos;
    EXPECT_TRUE(formInfoStorageMgr.LoadFormData(innerFormInfos));
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_025 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_026
 * @tc.desc: 1.Verify that the LoadFormData interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_026 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::SUCCESS;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<InnerFormInfo> innerFormInfos;
    EXPECT_EQ(formInfoStorageMgr.LoadFormData(innerFormInfos), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_026 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_027
 * @tc.desc: 1.Verify that the GetStorageFormInfoById interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_027 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    const std::string formId = "";
    InnerFormInfo innerFormInfo;
    EXPECT_EQ(
        formInfoStorageMgr.GetStorageFormInfoById(formId, innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_027 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_028
 * @tc.desc: 1.Verify that the GetStorageFormInfoById interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_028 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::SUCCESS;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string formId = "";
    InnerFormInfo innerFormInfo;
    EXPECT_EQ(
        formInfoStorageMgr.GetStorageFormInfoById(formId, innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_028 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_029
 * @tc.desc: 1.Verify that the GetStorageFormInfoById interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_029 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string formId = "";
    InnerFormInfo innerFormInfo;
    EXPECT_EQ(
        formInfoStorageMgr.GetStorageFormInfoById(formId, innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_029 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_030
 * @tc.desc: 1.Verify that the SaveStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_030 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    const InnerFormInfo innerFormInfo;
    EXPECT_EQ(formInfoStorageMgr.SaveStorageFormInfo(innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_030 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_031
 * @tc.desc: 1.Verify that the SaveStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_031 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Put_ = DistributedKv::Status::SUCCESS;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const InnerFormInfo innerFormInfo;
    EXPECT_EQ(formInfoStorageMgr.SaveStorageFormInfo(innerFormInfo), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_031 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_032
 * @tc.desc: 1.Verify that the SaveStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_032 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Put_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const InnerFormInfo innerFormInfo;
    EXPECT_EQ(formInfoStorageMgr.SaveStorageFormInfo(innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_032 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_033
 * @tc.desc: 1.Verify that the DeleteStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_033 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    const std::string formId = "";
    EXPECT_EQ(formInfoStorageMgr.DeleteStorageFormInfo(formId), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_033 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_034
 * @tc.desc: 1.Verify that the DeleteStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_034 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::SUCCESS;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string formId = "";
    EXPECT_EQ(formInfoStorageMgr.DeleteStorageFormInfo(formId), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_034 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_035
 * @tc.desc: 1.Verify that the DeleteStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_035 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const std::string formId = "";
    EXPECT_EQ(formInfoStorageMgr.DeleteStorageFormInfo(formId), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_035 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_036
 * @tc.desc: 1.Verify that the ModifyStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_036 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::SUCCESS;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const InnerFormInfo innerFormInfo;
    EXPECT_EQ(formInfoStorageMgr.ModifyStorageFormInfo(innerFormInfo), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_036 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_037
 * @tc.desc: 1.Verify that the ModifyStorageFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_037 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->Delete_ = DistributedKv::Status::ERROR;
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    const InnerFormInfo innerFormInfo;
    EXPECT_EQ(formInfoStorageMgr.ModifyStorageFormInfo(innerFormInfo), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_037 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_038
 * @tc.desc: 1.Verify that the LoadFormInfos interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_038 start";
    MockGetSingleKvStore(true);
    std::shared_ptr<MockSingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    kvStorePtr->GetEntries_ = DistributedKv::Status::ERROR;
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    EXPECT_EQ(formInfoStorageMgr.LoadFormInfos(formInfoStorages), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_038 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_039
 * @tc.desc: Verify that the CheckKvStore interface executes as expected and returns true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_039 start";
    MockGetSingleKvStore(true);
    MockGetKvStore(false);
    FormInfoStorageMgr formInfoStorageMgr;
    formInfoStorageMgr.kvStorePtr_ = nullptr;
    bool ret = false;
    ret  = formInfoStorageMgr.CheckKvStore();
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_039 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_040
 * @tc.desc: Verify that the CheckKvStore interface executes as expected and returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_040 start";
    MockGetSingleKvStore(false);
    MockGetKvStore(false);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    bool ret = false;
    ret  = formInfoStorageMgr.ResetKvStore();
    EXPECT_TRUE(!ret);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_040 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_041
 * @tc.desc: Verify that the OnRemoteDied interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_041, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_041 start";
    KvStoreDeathRecipientCallbackFormInfoStorage kvStoreDeathRecipientCallbackFormInfoStorage;
    kvStoreDeathRecipientCallbackFormInfoStorage.OnRemoteDied();
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_041 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_042
 * @tc.desc: Verify that the OnRemoteDied interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_042, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_042 start";
    KvStoreDeathRecipientCallbackFormInfoStorage kvStoreDeathRecipientCallbackFormInfoStorage;
    MockGetSingleKvStore(true);
    MockGetKvStore(false);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    kvStoreDeathRecipientCallbackFormInfoStorage.OnRemoteDied();
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_042 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_043
 * @tc.desc: Verify that the SaveEntries interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_043, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_043 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Entry allEntrie = {};
    allEntries.emplace_back(allEntrie);
    std::vector<InnerFormInfo> innerFormInfos;
    formInfoStorageMgr.SaveEntries(allEntries, innerFormInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_043 end";
}

/**
 * @tc.name: FmsFormInfoStorageMgrTest_044
 * @tc.desc: Verify that the SaveEntries interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInfoStorageMgrTest, FmsFormInfoStorageMgrTest_044, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_044 start";
    MockGetSingleKvStore(true);
    FormInfoStorageMgr formInfoStorageMgr;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
    formInfoStorageMgr.kvStorePtr_ = kvStorePtr;
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Entry allEntrie = {};
    allEntrie.value = "com.form.start";
    allEntries.emplace_back(allEntrie);
    std::vector<InnerFormInfo> innerFormInfos;
    formInfoStorageMgr.SaveEntries(allEntries, innerFormInfos);
    GTEST_LOG_(INFO) << "FmsFormInfoStorageMgrTest_044 end";
}
} // namespace AppExecFwk
} // namespace OHOS
