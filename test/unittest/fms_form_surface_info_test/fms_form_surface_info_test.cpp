/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "form_surface_info.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AppExecFwk {

class FmsFormSurfaceInfoTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormSurfaceInfoTest::SetUpTestCase() {}

void FmsFormSurfaceInfoTest::TearDownTestCase() {}

void FmsFormSurfaceInfoTest::SetUp() {}

void FmsFormSurfaceInfoTest::TearDown() {}

/**
* @tc.name: FmsFormSurfaceInfoTest_0100
* @tc.desc: test the FormSurfaceInfo::ReadFromParcel
* @tc.type: FUNC
*/
HWTEST_F(FmsFormSurfaceInfoTest, FmsFormSurfaceInfoTest_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0100 start";

    FormSurfaceInfo formSurfaceInfo;
    Parcel parcel;
    auto result = formSurfaceInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0100 end";
}

/**
* @tc.name: FmsFormSurfaceInfoTest_0200
* @tc.desc: text the FormSurfaceInfo::Marshalling
* @tc.type: FUNC
*/
HWTEST_F(FmsFormSurfaceInfoTest, FmsFormSurfaceInfoTest_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0200 start";
    Parcel parcel;
    FormSurfaceInfo formSurfaceInfo;
    auto result = formSurfaceInfo.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0200 end";
}

/**
* @tc.name: FmsFormSurfaceInfoTest_0300
* @tc.desc: text the FormSurfaceInfo::Unmarshalling
* @tc.type: FUNC
*/
HWTEST_F(FmsFormSurfaceInfoTest, FmsFormSurfaceInfoTest_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0300 start";

    FormSurfaceInfo formSurfaceInfo;
    Parcel parcel;
    auto result = formSurfaceInfo.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormSurfaceInfoTest_0300 end";
}
} // namespace AppExecFwk
} // namespace OHOS
