/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "running_form_info.h"
#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class FmsRunningFormInfoTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsRunningFormInfoTest::SetUpTestCase() {}

void FmsRunningFormInfoTest::TearDownTestCase() {}

void FmsRunningFormInfoTest::SetUp() {}

void FmsRunningFormInfoTest::TearDown() {}

/**
 * @tc.name: FmsRunningFormInfoTest_002
 * @tc.desc: text the RunningFormInfo::Marshalling
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsRunningFormInfoTest, FmsRunningFormInfoTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_002 start";
    RunningFormInfo runningFormInfo;
    Parcel parcel;
    auto result = runningFormInfo.Marshalling(parcel);

    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_002 end";
}

/**
 * @tc.name: FmsRunningFormInfoTest_003
 * @tc.desc: Verify isColorModeRefreshEnabled round-trips through Marshalling/ReadFromParcel when true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRunningFormInfoTest, FmsRunningFormInfoTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_003 start";

    RunningFormInfo src;
    src.isColorModeRefreshEnabled = true;
    Parcel parcel;
    EXPECT_TRUE(src.Marshalling(parcel));

    RunningFormInfo *dst = RunningFormInfo::Unmarshalling(parcel);
    ASSERT_NE(dst, nullptr);
    EXPECT_TRUE(dst->isColorModeRefreshEnabled);
    delete dst;

    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_003 end";
}

/**
 * @tc.name: FmsRunningFormInfoTest_004
 * @tc.desc: Verify isColorModeRefreshEnabled round-trips through Marshalling/ReadFromParcel when false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRunningFormInfoTest, FmsRunningFormInfoTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_004 start";

    RunningFormInfo src;
    src.isColorModeRefreshEnabled = false;
    Parcel parcel;
    EXPECT_TRUE(src.Marshalling(parcel));

    RunningFormInfo *dst = RunningFormInfo::Unmarshalling(parcel);
    ASSERT_NE(dst, nullptr);
    EXPECT_FALSE(dst->isColorModeRefreshEnabled);
    delete dst;

    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_004 end";
}

/**
 * @tc.name: FmsRunningFormInfoTest_005
 * @tc.desc: Verify isColorModeRefreshEnabled defaults to false in ReadFromParcel.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRunningFormInfoTest, FmsRunningFormInfoTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_005 start";

    RunningFormInfo src;
    EXPECT_FALSE(src.isColorModeRefreshEnabled);
    Parcel parcel;
    EXPECT_TRUE(src.Marshalling(parcel));

    RunningFormInfo dst;
    EXPECT_TRUE(dst.ReadFromParcel(parcel));
    EXPECT_FALSE(dst.isColorModeRefreshEnabled);

    GTEST_LOG_(INFO) << "FmsRunningFormInfoTest_005 end";
}
} // namespace AppExecFwk
} // namespace OHOS
