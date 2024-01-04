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
#include "gmock/gmock.h"
#include <string>
#include <thread>
#include "string_ex.h"

#define private public
#define protected public
#include "form_instance.h"
#include "form_instances_filter.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AppExecFwk {

class FmsFormInstanceTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormInstanceTest::SetUpTestCase() {}

void FmsFormInstanceTest::TearDownTestCase() {}

void FmsFormInstanceTest::SetUp() {}

void FmsFormInstanceTest::TearDown() {}

/**
 * @tc.name: FmsFormInstanceTest_0100
 * @tc.desc: text the FormInstance::ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0100 start";

    FormInstance formInstance;
    Parcel parcel;
    auto result = formInstance.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0100 end";
}

/**
 * @tc.name: FmsFormInstanceTest_0200
 * @tc.desc: text the FormInstance::Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0200 start";
    Parcel parcel;
    FormInstance formInstance;
    auto result = formInstance.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0200 end";
}

/**
 * @tc.name: FmsFormInstanceTest_0300
 * @tc.desc: text the FormInstance::Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0300 start";

    FormInstance formInstance;
    Parcel parcel;
    auto result = formInstance.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0300 end";
}

/**
 * @tc.name: FmsFormInstanceTest_0400
 * @tc.desc: text the FormInstancesFilter::Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0400, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0400 start";

    FormInstancesFilter formInstanceFilter;
    Parcel parcel;
    auto result = formInstanceFilter.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0400 end";
}

/**
 * @tc.name: FmsFormInstanceTest_0500
 * @tc.desc: text the FormInstancesFilter::Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0500, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0500 start";
    FormInstancesFilter formInstanceFilter;
    Parcel parcel;
    auto result = formInstanceFilter.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0500 end";
}

/**
 * @tc.name: FmsFormInstanceTest_0600
 * @tc.desc: text the FormInstancesFilter::ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormInstanceTest, FmsFormInstanceTest_0600, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0600 start";
    FormInstancesFilter formInstanceFilter;
    Parcel parcel;
    auto result = formInstanceFilter.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormInstanceTest_0600 end";
}
} // namespace AppExecFwk
} // namespace OHOS