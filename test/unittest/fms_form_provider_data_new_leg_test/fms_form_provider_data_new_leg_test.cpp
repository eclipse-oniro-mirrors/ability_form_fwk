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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#define private public
#include "form_provider_data.h"
#undef private
#include "form_ashmem.h"
#include "hilog_wrapper.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int32_t AGE = 10;

class FmsFormProviderDataNewLegTest : public testing::Test {
public:
    void SetUp();
    bool InitJsonData();

    nlohmann::json jsonData_;
};
void FmsFormProviderDataNewLegTest::SetUp() {}

bool FmsFormProviderDataNewLegTest::InitJsonData()
{
    nlohmann::json tmpJson;
    tmpJson["name"] = "li";
    tmpJson["age"] = AGE;
    jsonData_["0"] = tmpJson;
    return true;
}

/**
 * @tc.name: FmsFormProviderDataNewLegTest_001
 * @tc.desc: Verify the WriteImageDataToParcel function and WriteToAshmem is false.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FmsFormProviderDataNewLegTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_001 start";
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    Parcel parcel;
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
    EXPECT_EQ(false, formProviderData.WriteImageDataToParcel(parcel, picName, data, 1));
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_001 end";
}

/**
 * @tc.name: FmsFormProviderDataNewLegTest_002
 * @tc.desc: Verify the ConvertRawImageData function and WriteToAshmem is false.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FmsFormProviderDataNewLegTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_002 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_EQ(false, formProviderData.ConvertRawImageData());
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_002 end";
}
}