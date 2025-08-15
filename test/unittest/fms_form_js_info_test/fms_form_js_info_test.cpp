/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "form_js_info.h"
#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
extern void MockConvertRawImageData(bool mockRet);
extern void MockGetImageDataMap(bool mockRet);

class FmsFormJsInfoTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormJsInfoTest::SetUpTestCase() {}

void FmsFormJsInfoTest::TearDownTestCase() {}

void FmsFormJsInfoTest::SetUp() {}

void FmsFormJsInfoTest::TearDown() {}

/**
 * @tc.name: FmsFormJsInfoTest_001
 * @tc.desc: text the FormJsInfo::ConvertRawImageData function executed as expected with
 *           FormProviderData::ConvertRawImageData is false.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_001 start";
    FormJsInfo formJsInfo;
    // mock ConvertRawImageData is false
    MockConvertRawImageData(false);
    EXPECT_EQ(false, formJsInfo.ConvertRawImageData());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_001 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_002
 * @tc.desc: text the FormJsInfo::ConvertRawImageData function executed as expected with
 *           formProviderData.GetImageDataMap() size is 130.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_002 start";
    FormJsInfo formJsInfo;
    // mock ConvertRawImageData is true
    MockConvertRawImageData(true);
    // GetImageDataMap size is 130
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    int32_t a = 1;
    int32_t maxNumber = 130;
    for (int32_t i = 0; i < maxNumber; i++) {
        imageDataMap.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
    }
    formJsInfo.formProviderData.SetImageDataMap(imageDataMap);
    EXPECT_EQ(false, formJsInfo.ConvertRawImageData());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_002 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_003
 * @tc.desc: text the FormJsInfo::ConvertRawImageData function executed as expected with
 *           formProviderData.GetImageDataMap() size is 100, the case is success.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_003 start";
    FormJsInfo formJsInfo;
    // mock ConvertRawImageData is true
    MockConvertRawImageData(true);
    // mock GetImageDataMap size is 110
    MockGetImageDataMap(false);
    EXPECT_EQ(true, formJsInfo.ConvertRawImageData());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_003 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_004
 * @tc.desc: text the FormJsInfo::ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_004 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    auto result = formJsInfo.ReadFromParcel(parcel);

    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_004 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_005
 * @tc.desc: text the FormJsInfo::Marshalling
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_005 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    auto result = formJsInfo.Marshalling(parcel);

    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_005 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_006
 * @tc.desc: text the FormJsInfo::Unmarshalling
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_006 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    auto result = formJsInfo.Unmarshalling(parcel);

    EXPECT_TRUE(result == nullptr);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_006 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_007
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_007 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);

    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_007 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_008
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_008 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    FormProviderData forProviderData;
    int32_t imageDataState = 1;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    forProviderData.SetImageDataState(imageDataState);
    forProviderData.SetImageDataMap(imageDataMap);
    auto result = formJsInfo.WriteImageData(parcel);

    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_008 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_009
 * @tc.desc: text the FormJsInfo::ReadImageData and formAshmem is nullptr
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_009 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    formJsInfo.ReadImageData(parcel);

    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_009 end";
}

/**
 * @tc.name: FmsFormJsInfoTest_010
 * @tc.desc: text the FormJsInfo::CopyFormJsInfoWithoutFormData
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormJsInfoTest, FmsFormJsInfoTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_010 start";
    FormJsInfo formJsInfo;
    formJsInfo.formSrc = "123456";
    FormJsInfo copyFormJsInfo = formJsInfo.CopyFormJsInfoWithoutFormData();
    EXPECT_EQ(copyFormJsInfo.formSrc, "");
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest_010 end";
}
} // namespace AppExecFwk
} // namespace OHOS
