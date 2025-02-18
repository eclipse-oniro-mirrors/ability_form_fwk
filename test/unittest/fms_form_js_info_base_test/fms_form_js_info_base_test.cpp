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
#include "string_ex.h"

#define private public
#define protected public
#include "form_js_info.h"
#include "form_provider_data.h"
#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
extern void MockConvertRawImageData(bool mockRet);
extern void MockGetImageDataMap(bool mockRet);

class FmsFormJsInfoBaseTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormJsInfoBaseTest::SetUpTestCase() {}

void FmsFormJsInfoBaseTest::TearDownTestCase() {}

void FmsFormJsInfoBaseTest::SetUp() {}

void FmsFormJsInfoBaseTest::TearDown() {}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0100
 * @tc.desc: text the FormJsInfo::ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0100 start";

    FormJsInfo formJsInfo;
    Parcel parcel;
    // write formId
    parcel.WriteInt64(10);
    std::string formName = "formName";
    std::string bundleName = "bundleName";;
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    parcel.WriteString16(Str8ToStr16(formName));
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(abilityName));
    parcel.WriteString16(Str8ToStr16(moduleName));
    parcel.WriteBool(true);
    std::string jsFormCodePath = "jsFormCodePath";
    std::string formData = "formData";
    std::string formSrc = "formSrc";
    parcel.WriteString16(Str8ToStr16(jsFormCodePath));
    parcel.WriteString16(Str8ToStr16(formData));
    parcel.WriteString16(Str8ToStr16(formSrc));
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteUint32(10);
    std::string versionName = "versionName";
    parcel.WriteString16(Str8ToStr16(versionName));
    parcel.WriteUint32(10);
    parcel.WriteInt32(10);
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    std::string jsonData = "{ \"abc\" : \"def\"}";
    auto formProviderData = new FormProviderData(jsonData);
    EXPECT_TRUE(parcel.WriteParcelable(formProviderData));
    auto result = formJsInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0100 end";
    delete formProviderData;
    formProviderData = nullptr;
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0200
 * @tc.desc: text the FormJsInfo::ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0200 start";

    FormJsInfo formJsInfo;
    Parcel parcel;
    // write formId
    parcel.WriteInt64(10);
    std::string formName = "formName";
    std::string bundleName = "bundleName";;
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    parcel.WriteString16(Str8ToStr16(formName));
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(abilityName));
    parcel.WriteString16(Str8ToStr16(moduleName));
    parcel.WriteBool(true);
    std::string jsFormCodePath = "jsFormCodePath";
    std::string formData = "formData";
    std::string formSrc = "formSrc";
    parcel.WriteString16(Str8ToStr16(jsFormCodePath));
    parcel.WriteString16(Str8ToStr16(formData));
    parcel.WriteString16(Str8ToStr16(formSrc));
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteUint32(10);
    std::string versionName = "versionName";
    parcel.WriteString16(Str8ToStr16(versionName));
    parcel.WriteUint32(10);
    parcel.WriteInt32(10);
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    auto result = formJsInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0200 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0300
 * @tc.desc: text the FormJsInfo::Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0300 start";

    FormJsInfo formJsInfo;
    Parcel parcel;
    // write formId
    parcel.WriteInt64(10);
    std::string formName = "formName";
    std::string bundleName = "bundleName";;
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    parcel.WriteString16(Str8ToStr16(formName));
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(abilityName));
    parcel.WriteString16(Str8ToStr16(moduleName));
    parcel.WriteBool(true);
    std::string jsFormCodePath = "jsFormCodePath";
    std::string formData = "formData";
    std::string formSrc = "formSrc";
    parcel.WriteString16(Str8ToStr16(jsFormCodePath));
    parcel.WriteString16(Str8ToStr16(formData));
    parcel.WriteString16(Str8ToStr16(formSrc));
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteUint32(10);
    std::string versionName = "versionName";
    parcel.WriteString16(Str8ToStr16(versionName));
    parcel.WriteUint32(10);
    parcel.WriteInt32(10);
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    std::string jsonData = "{ \"abc\" : \"def\"}";
    auto formProviderData = new FormProviderData(jsonData);
    EXPECT_TRUE(parcel.WriteParcelable(formProviderData));
    auto result = formJsInfo.Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0300 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0400
 * @tc.desc: text the FormJsInfo::Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0400, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0400 start";

    FormJsInfo formJsInfo;
    Parcel parcel;
    // write formId
    parcel.WriteInt64(10);
    std::string formName = "formName";
    std::string bundleName = "bundleName";;
    std::string abilityName = "abilityName";
    std::string moduleName = "moduleName";
    parcel.WriteString16(Str8ToStr16(formName));
    parcel.WriteString16(Str8ToStr16(bundleName));
    parcel.WriteString16(Str8ToStr16(abilityName));
    parcel.WriteString16(Str8ToStr16(moduleName));
    parcel.WriteBool(true);
    std::string jsFormCodePath = "jsFormCodePath";
    std::string formData = "formData";
    std::string formSrc = "formSrc";
    parcel.WriteString16(Str8ToStr16(jsFormCodePath));
    parcel.WriteString16(Str8ToStr16(formData));
    parcel.WriteString16(Str8ToStr16(formSrc));
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteUint32(10);
    std::string versionName = "versionName";
    parcel.WriteString16(Str8ToStr16(versionName));
    parcel.WriteUint32(10);
    parcel.WriteInt32(10);
    parcel.WriteInt32(10);
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    auto result = formJsInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0300 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0500
 * @tc.desc: text the FormJsInfo::Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0500, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0500 start";

    FormJsInfo formJsInfo;
    Parcel parcel;
    auto result = formJsInfo.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0500 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0600
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0600, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0600 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0600 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0700
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0700, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0700 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_NO_OPERATION;
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0700 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0800
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0800, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0800 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_REMOVED;
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0800 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_0900
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_0900, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0900 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    int32_t maxNumber = 130;
    int32_t a = 1;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    for (int32_t i = 0; i < maxNumber; i++) {
        formJsInfo.formProviderData.imageDataMap_.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
    }
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_0900 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1000
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1000, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1000 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = -999;
    int32_t maxNumber = 130;
    int32_t a = 1;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    for (int32_t i = 0; i < maxNumber; i++) {
        formJsInfo.formProviderData.imageDataMap_.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
    }
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1000 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1100
 * @tc.desc: text the FormJsInfo::WriteImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1100 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    int32_t a = 1;
    sptr<FormAshmem> formAshmem = nullptr;
    for (int32_t i = 0; i < 10; i++) {
        formJsInfo.formProviderData.imageDataMap_.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
    }
    Parcel parcel;
    auto result = formJsInfo.WriteImageData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1100 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1200
 * @tc.desc: text the FormJsInfo::ReadImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1200 start";
    FormJsInfo formJsInfo;
    FormAshmem *formAshmem;
    Parcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(129);
    parcel.WriteParcelable(formAshmem);
    parcel.WriteString16(Str8ToStr16("picName"));
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1200 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1300
 * @tc.desc: text the FormJsInfo::ReadImageData and formAshmem is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1300 start";
    FormJsInfo formJsInfo;
    formJsInfo.formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    FormAshmem *formAshmem = new FormAshmem();
    char* data = new char[4];
    formAshmem->WriteToAshmem("test", data, 4);
    Parcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(127);
    parcel.WriteParcelable(formAshmem);
    parcel.WriteString16(Str8ToStr16("picName"));
    formJsInfo.ReadImageData(parcel);
    EXPECT_FALSE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1300 end";
    delete[] data;
    data = nullptr;
    delete formAshmem;
    formAshmem = nullptr;
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1400
 * @tc.desc: text the FormJsInfo::ReadImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1400, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1400 start";
    FormJsInfo formJsInfo;
    FormAshmem *formAshmem;
    Parcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    parcel.WriteInt32(127);
    parcel.WriteParcelable(formAshmem);
    parcel.WriteString16(Str8ToStr16("picName"));
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1400 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1400
 * @tc.desc: text the FormJsInfo::ReadImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1500, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1500 start";
    FormJsInfo formJsInfo;
    FormAshmem *formAshmem;
    Parcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_REMOVED);
    parcel.WriteInt32(127);
    parcel.WriteParcelable(formAshmem);
    parcel.WriteString16(Str8ToStr16("picName"));
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1500 end";
}

/**
 * @tc.name: FmsFormJsInfoBaseTest_1600
 * @tc.desc: text the FormJsInfo::ReadImageData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoBaseTest, FmsFormJsInfoBaseTest_1600, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1600 start";
    FormJsInfo formJsInfo;
    Parcel parcel;
    FormAshmem *formAshmem;
    parcel.WriteInt32(127);
    parcel.WriteInt32(127);
    parcel.WriteParcelable(formAshmem);
    parcel.WriteString16(Str8ToStr16("picName"));
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoBaseTest_1600 end";
}
} // namespace AppExecFwk
} // namespace OHOS
