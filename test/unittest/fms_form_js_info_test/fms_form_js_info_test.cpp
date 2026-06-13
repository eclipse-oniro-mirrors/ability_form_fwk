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
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#undef private
#undef protected
#include "string_ex.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t BIG_DATA = 32 * 1024; // 32K
}
extern void MockConvertRawImageData(bool mockRet);
extern void MockGetImageDataMap(bool mockRet);

class FmsFormJsInfoTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    std::string CreateBigFormData(int32_t size);
};
void FmsFormJsInfoTest::SetUpTestCase() {}

void FmsFormJsInfoTest::TearDownTestCase() {}

void FmsFormJsInfoTest::SetUp() {}

void FmsFormJsInfoTest::TearDown() {}

std::string FmsFormJsInfoTest::CreateBigFormData(int32_t size)
{
    return std::string(size, 'A');
}

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

    EXPECT_TRUE(result);
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
    FormJsInfo writeJsInfo;
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WriteImageData(parcel));
    int32_t readState = parcel.ReadInt32();
    EXPECT_EQ(readState, FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    FormJsInfo readJsInfo;
    readJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(readJsInfo.imageDataMap.empty());
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
    FormJsInfo writeJsInfo;
    MessageParcel parcel;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    writeJsInfo.formProviderData.SetImageDataState(FormProviderData::IMAGE_DATA_STATE_ADDED);
    writeJsInfo.formProviderData.SetImageDataMap(imageDataMap);
    EXPECT_TRUE(writeJsInfo.WriteImageData(parcel));
    FormJsInfo readJsInfo;
    readJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(readJsInfo.imageDataMap.empty());
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

/**
 * @tc.name: WriteFormData_SmallData_001
 * @tc.desc: Verify WriteFormData with formData length <= BIG_DATA uses parcel.WriteString16.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteFormData_SmallData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteFormData_SmallData_001";
    FormJsInfo formJsInfo;
    formJsInfo.formData = "small_data";
    MessageParcel parcel;
    EXPECT_TRUE(formJsInfo.WriteFormData(parcel));
    int32_t writtenLength = parcel.ReadInt32();
    EXPECT_EQ(writtenLength, static_cast<int32_t>(formJsInfo.formData.length()));
    std::string readData = Str16ToStr8(parcel.ReadString16());
    EXPECT_EQ(readData, formJsInfo.formData);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteFormData_SmallData_001";
}

/**
 * @tc.name: WriteFormData_BigData_001
 * @tc.desc: Verify WriteFormData with formData length > BIG_DATA uses ashmem path.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteFormData_BigData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteFormData_BigData_001";
    FormJsInfo formJsInfo;
    std::string bigData = CreateBigFormData(BIG_DATA + 1);
    formJsInfo.formData = bigData;
    MessageParcel parcel;
    EXPECT_TRUE(formJsInfo.WriteFormData(parcel));
    int32_t writtenLength = parcel.ReadInt32();
    EXPECT_EQ(writtenLength, static_cast<int32_t>(bigData.length()));
    FormJsInfo readJsInfo;
    std::string outFormData;
    EXPECT_TRUE(readJsInfo.ReadAshmemFormData(parcel, writtenLength, outFormData));
    EXPECT_EQ(outFormData, bigData);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteFormData_BigData_001";
}

/**
 * @tc.name: WriteAshmemFormData_NullPtr_001
 * @tc.desc: Verify WriteAshmemFormData returns false when dataPtr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteAshmemFormData_NullPtr_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteAshmemFormData_NullPtr_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    EXPECT_FALSE(formJsInfo.WriteAshmemFormData(parcel, BIG_DATA + 1, nullptr));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteAshmemFormData_NullPtr_001";
}

/**
 * @tc.name: WriteAshmemFormData_NegativeSize_001
 * @tc.desc: Verify WriteAshmemFormData returns false when size <= 0.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteAshmemFormData_NegativeSize_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteAshmemFormData_NegativeSize_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    std::string data = "test";
    EXPECT_FALSE(formJsInfo.WriteAshmemFormData(parcel, 0, data.c_str()));
    EXPECT_FALSE(formJsInfo.WriteAshmemFormData(parcel, -1, data.c_str()));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteAshmemFormData_NegativeSize_001";
}

/**
 * @tc.name: WriteAshmemFormData_Success_001
 * @tc.desc: Verify WriteAshmemFormData succeeds with valid big data.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteAshmemFormData_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteAshmemFormData_Success_001";
    FormJsInfo formJsInfo;
    std::string bigData = CreateBigFormData(BIG_DATA + 1);
    MessageParcel parcel;
    EXPECT_TRUE(formJsInfo.WriteAshmemFormData(parcel, static_cast<int32_t>(bigData.size()), bigData.c_str()));
    FormJsInfo readJsInfo;
    std::string outFormData;
    EXPECT_TRUE(readJsInfo.ReadAshmemFormData(parcel, static_cast<int32_t>(bigData.size()), outFormData));
    EXPECT_EQ(outFormData, bigData);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteAshmemFormData_Success_001";
}

/**
 * @tc.name: WriteFdToParcel_InvalidFd_001
 * @tc.desc: Verify WriteFdToParcel returns false when fd < 0.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteFdToParcel_InvalidFd_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteFdToParcel_InvalidFd_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    EXPECT_FALSE(formJsInfo.WriteFdToParcel(parcel, -1));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteFdToParcel_InvalidFd_001";
}

/**
 * @tc.name: WriteFdToParcel_Success_001
 * @tc.desc: Verify WriteFdToParcel succeeds with valid fd.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteFdToParcel_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteFdToParcel_Success_001";
    FormJsInfo formJsInfo;
    int fd = AshmemCreate("WriteFdToParcel_Test", 4096);
    ASSERT_GE(fd, 0);
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    MessageParcel parcel;
    EXPECT_TRUE(formJsInfo.WriteFdToParcel(parcel, fd));
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteFdToParcel_Success_001";
}

/**
 * @tc.name: ReadFdFromParcel_NullDescriptor_001
 * @tc.desc: Verify ReadFdFromParcel returns -1 when parcel has no IPCFileDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadFdFromParcel_NullDescriptor_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadFdFromParcel_NullDescriptor_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    int fd = formJsInfo.ReadFdFromParcel(parcel);
    EXPECT_LT(fd, 0);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadFdFromParcel_NullDescriptor_001";
}

/**
 * @tc.name: ReadFdFromParcel_Success_001
 * @tc.desc: Verify ReadFdFromParcel succeeds when parcel contains valid IPCFileDescriptor.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadFdFromParcel_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadFdFromParcel_Success_001";
    FormJsInfo writeJsInfo;
    int fd = AshmemCreate("ReadFdFromParcel_Test", 4096);
    ASSERT_GE(fd, 0);
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WriteFdToParcel(parcel, fd));

    FormJsInfo readJsInfo;
    int readFd = readJsInfo.ReadFdFromParcel(parcel);
    EXPECT_GE(readFd, 0);
    if (readFd >= 0) {
        fdsan_exchange_owner_tag(readFd, 0, Constants::FORM_DOMAIN_ID);
        fdsan_close_with_tag(readFd, Constants::FORM_DOMAIN_ID);
    }
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadFdFromParcel_Success_001";
}

/**
 * @tc.name: ReadAshmemFormData_ReadFdFail_001
 * @tc.desc: Verify ReadAshmemFormData returns false when ReadFdFromParcel fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadAshmemFormData_ReadFdFail_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadAshmemFormData_ReadFdFail_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    std::string outFormData;
    EXPECT_FALSE(formJsInfo.ReadAshmemFormData(parcel, BIG_DATA + 1, outFormData));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadAshmemFormData_ReadFdFail_001";
}

/**
 * @tc.name: ReadAshmemFormData_NegativeLength_001
 * @tc.desc: Verify ReadAshmemFormData returns false when formDataLength <= 0.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadAshmemFormData_NegativeLength_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadAshmemFormData_NegativeLength_001";
    FormJsInfo writeJsInfo;
    std::string bigData = CreateBigFormData(BIG_DATA + 1);
    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.WriteFormData(parcel));

    FormJsInfo readJsInfo;
    std::string outFormData;
    parcel.ReadInt32();
    EXPECT_FALSE(readJsInfo.ReadAshmemFormData(parcel, -1, outFormData));
    EXPECT_FALSE(readJsInfo.ReadAshmemFormData(parcel, 0, outFormData));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadAshmemFormData_NegativeLength_001";
}

/**
 * @tc.name: ReadAshmemFormData_OverMaxLength_001
 * @tc.desc: Verify ReadAshmemFormData returns false when formDataLength > MAX_FORM_DATA_BUFFER_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadAshmemFormData_OverMaxLength_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadAshmemFormData_OverMaxLength_001";
    FormJsInfo writeJsInfo;
    std::string bigData = CreateBigFormData(BIG_DATA + 1);
    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.WriteFormData(parcel));

    FormJsInfo readJsInfo;
    std::string outFormData;
    parcel.ReadInt32();
    int32_t overMax = 32 * 1024 * 1024 + 1;
    EXPECT_FALSE(readJsInfo.ReadAshmemFormData(parcel, overMax, outFormData));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadAshmemFormData_OverMaxLength_001";
}

/**
 * @tc.name: ReadAshmemFormData_Success_001
 * @tc.desc: Verify ReadAshmemFormData succeeds and outFormData matches written data.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadAshmemFormData_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadAshmemFormData_Success_001";
    FormJsInfo writeJsInfo;
    std::string bigData = CreateBigFormData(BIG_DATA + 1);
    writeJsInfo.formData = bigData;
    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.WriteFormData(parcel));

    FormJsInfo readJsInfo;
    std::string outFormData;
    int32_t writtenLength = parcel.ReadInt32();
    EXPECT_TRUE(readJsInfo.ReadAshmemFormData(parcel, writtenLength, outFormData));
    EXPECT_EQ(outFormData, bigData);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadAshmemFormData_Success_001";
}

/**
 * @tc.name: Marshalling_Unmarshalling_SmallData_001
 * @tc.desc: Verify Marshalling and Unmarshalling round-trip with small formData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, Marshalling_Unmarshalling_SmallData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin Marshalling_Unmarshalling_SmallData_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formId = 100;
    writeJsInfo.formName = "testForm";
    writeJsInfo.bundleName = "com.test";
    writeJsInfo.abilityName = "MainAbility";
    writeJsInfo.moduleName = "entry";
    writeJsInfo.formData = "small_form_data";
    writeJsInfo.formSrc = "formSrc";
    writeJsInfo.formWindow.designWidth = 720;
    writeJsInfo.formWindow.autoDesignWidth = true;
    writeJsInfo.versionCode = 1;
    writeJsInfo.versionName = "1.0";
    writeJsInfo.compatibleVersion = 1;
    writeJsInfo.isDynamic = false;
    writeJsInfo.transparencyEnabled = true;

    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.Marshalling(parcel));

    std::unique_ptr<FormJsInfo> readJsInfo(FormJsInfo::Unmarshalling(parcel));
    ASSERT_NE(readJsInfo, nullptr);
    EXPECT_EQ(readJsInfo->formId, writeJsInfo.formId);
    EXPECT_EQ(readJsInfo->formName, writeJsInfo.formName);
    EXPECT_EQ(readJsInfo->bundleName, writeJsInfo.bundleName);
    EXPECT_EQ(readJsInfo->abilityName, writeJsInfo.abilityName);
    EXPECT_EQ(readJsInfo->moduleName, writeJsInfo.moduleName);
    EXPECT_EQ(readJsInfo->formData, writeJsInfo.formData);
    EXPECT_EQ(readJsInfo->formSrc, writeJsInfo.formSrc);
    EXPECT_EQ(readJsInfo->formWindow.designWidth, writeJsInfo.formWindow.designWidth);
    EXPECT_EQ(readJsInfo->formWindow.autoDesignWidth, writeJsInfo.formWindow.autoDesignWidth);
    EXPECT_EQ(readJsInfo->versionCode, writeJsInfo.versionCode);
    EXPECT_EQ(readJsInfo->versionName, writeJsInfo.versionName);
    EXPECT_EQ(readJsInfo->compatibleVersion, writeJsInfo.compatibleVersion);
    EXPECT_EQ(readJsInfo->isDynamic, writeJsInfo.isDynamic);
    EXPECT_EQ(readJsInfo->transparencyEnabled, writeJsInfo.transparencyEnabled);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end Marshalling_Unmarshalling_SmallData_001";
}

/**
 * @tc.name: Marshalling_Unmarshalling_BigData_001
 * @tc.desc: Verify Marshalling and Unmarshalling round-trip with big formData (>32KB).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, Marshalling_Unmarshalling_BigData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin Marshalling_Unmarshalling_BigData_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formId = 200;
    writeJsInfo.formName = "bigForm";
    writeJsInfo.bundleName = "com.bigtest";
    writeJsInfo.abilityName = "BigAbility";
    writeJsInfo.moduleName = "entry";
    writeJsInfo.formData = CreateBigFormData(BIG_DATA + 100);
    writeJsInfo.formSrc = "formSrc";
    writeJsInfo.formWindow.designWidth = 720;
    writeJsInfo.formWindow.autoDesignWidth = true;
    writeJsInfo.versionCode = 2;
    writeJsInfo.versionName = "2.0";
    writeJsInfo.compatibleVersion = 2;

    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.Marshalling(parcel));

    std::unique_ptr<FormJsInfo> readJsInfo(FormJsInfo::Unmarshalling(parcel));
    ASSERT_NE(readJsInfo, nullptr);
    EXPECT_EQ(readJsInfo->formId, writeJsInfo.formId);
    EXPECT_EQ(readJsInfo->formName, writeJsInfo.formName);
    EXPECT_EQ(readJsInfo->bundleName, writeJsInfo.bundleName);
    EXPECT_EQ(readJsInfo->abilityName, writeJsInfo.abilityName);
    EXPECT_EQ(readJsInfo->moduleName, writeJsInfo.moduleName);
    EXPECT_EQ(readJsInfo->formData, writeJsInfo.formData);
    EXPECT_EQ(readJsInfo->formSrc, writeJsInfo.formSrc);
    EXPECT_EQ(readJsInfo->formWindow.designWidth, writeJsInfo.formWindow.designWidth);
    EXPECT_EQ(readJsInfo->formWindow.autoDesignWidth, writeJsInfo.formWindow.autoDesignWidth);
    EXPECT_EQ(readJsInfo->versionCode, writeJsInfo.versionCode);
    EXPECT_EQ(readJsInfo->versionName, writeJsInfo.versionName);
    EXPECT_EQ(readJsInfo->compatibleVersion, writeJsInfo.compatibleVersion);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end Marshalling_Unmarshalling_BigData_001";
}

/**
 * @tc.name: Marshalling_Unmarshalling_MultipleBigData_001
 * @tc.desc: Verify multiple FormJsInfo objects with big formData can be marshalled/unmarshalled
 *           in the same MessageParcel (core bug scenario: WriteParcelableVector with ashmem).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, Marshalling_Unmarshalling_MultipleBigData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin Marshalling_Unmarshalling_MultipleBigData_001";
    std::vector<FormJsInfo> writeList;
    for (int i = 0; i < 3; i++) {
        FormJsInfo jsInfo;
        jsInfo.formId = 300 + i;
        jsInfo.formName = "multiForm_" + std::to_string(i);
        jsInfo.bundleName = "com.multitest";
        jsInfo.abilityName = "MultiAbility";
        jsInfo.moduleName = "entry";
        jsInfo.formData = CreateBigFormData(BIG_DATA + 1 + i * 100);
        jsInfo.formSrc = "formSrc";
        jsInfo.versionCode = 3;
        jsInfo.versionName = "3.0";
        jsInfo.compatibleVersion = 3;
        writeList.push_back(jsInfo);
    }

    MessageParcel parcel;
    int32_t count = static_cast<int32_t>(writeList.size());
    parcel.WriteInt32(count);
    for (const auto &jsInfo : writeList) {
        ASSERT_TRUE(parcel.WriteParcelable(&jsInfo));
    }

    int32_t readCount = parcel.ReadInt32();
    EXPECT_EQ(readCount, count);
    for (int i = 0; i < readCount; i++) {
        std::unique_ptr<FormJsInfo> readJsInfo(parcel.ReadParcelable<FormJsInfo>());
        ASSERT_NE(readJsInfo, nullptr);
        EXPECT_EQ(readJsInfo->formId, writeList[i].formId);
        EXPECT_EQ(readJsInfo->formName, writeList[i].formName);
        EXPECT_EQ(readJsInfo->formData, writeList[i].formData);
    }
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end Marshalling_Unmarshalling_MultipleBigData_001";
}

/**
 * @tc.name: WriteAshmemFormData_OverMaxSize_001
 * @tc.desc: Verify WriteAshmemFormData returns false when size > MAX_FORM_DATA_BUFFER_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteAshmemFormData_OverMaxSize_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteAshmemFormData_OverMaxSize_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    std::string data = "test";
    int32_t overMaxSize = 128 * 1024 * 1024 + 1;
    EXPECT_FALSE(formJsInfo.WriteAshmemFormData(parcel, overMaxSize, data.c_str()));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteAshmemFormData_OverMaxSize_001";
}

/**
 * @tc.name: WriteImageData_STATE_REMOVED_001
 * @tc.desc: Verify WriteImageData with IMAGE_DATA_STATE_REMOVED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteImageData_STATE_REMOVED_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteImageData_STATE_REMOVED_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formProviderData.SetImageDataState(FormProviderData::IMAGE_DATA_STATE_REMOVED);
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WriteImageData(parcel));
    FormJsInfo readJsInfo;
    readJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(readJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteImageData_STATE_REMOVED_001";
}

/**
 * @tc.name: WriteImageData_STATE_ADDED_OverThreshold_001
 * @tc.desc: Verify WriteImageData with IMAGE_DATA_STATE_ADDED and size > IMAGE_DATA_THRESHOLD.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteImageData_STATE_ADDED_OverThreshold_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteImageData_STATE_ADDED_OverThreshold_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formProviderData.SetImageDataState(FormProviderData::IMAGE_DATA_STATE_ADDED);
    MockGetImageDataMap(true);
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WriteImageData(parcel));
    FormJsInfo readJsInfo;
    readJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(readJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteImageData_STATE_ADDED_OverThreshold_001";
}

/**
 * @tc.name: WriteImageData_DefaultState_001
 * @tc.desc: Verify WriteImageData with unexpected imageDateState value.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WriteImageData_DefaultState_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WriteImageData_DefaultState_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formProviderData.SetImageDataState(99);
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WriteImageData(parcel));
    FormJsInfo readJsInfo;
    readJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(readJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WriteImageData_DefaultState_001";
}

/**
 * @tc.name: ReadImageData_STATE_REMOVED_001
 * @tc.desc: Verify ReadImageData with IMAGE_DATA_STATE_REMOVED keeps imageDataMap empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadImageData_STATE_REMOVED_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadImageData_STATE_REMOVED_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_REMOVED);
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadImageData_STATE_REMOVED_001";
}

/**
 * @tc.name: ReadImageData_STATE_ADDED_NullFormAshmem_001
 * @tc.desc: Verify ReadImageData returns early when FormAshmem is null in ADDED state.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadImageData_STATE_ADDED_NullFormAshmem_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadImageData_STATE_ADDED_NullFormAshmem_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(1);
    parcel.WriteInt32(0);
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadImageData_STATE_ADDED_NullFormAshmem_001";
}

/**
 * @tc.name: ReadImageData_STATE_ADDED_OverThreshold_001
 * @tc.desc: Verify ReadImageData with size > IMAGE_DATA_THRESHOLD keeps imageDataMap empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadImageData_STATE_ADDED_OverThreshold_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadImageData_STATE_ADDED_OverThreshold_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(FormJsInfo::IMAGE_DATA_THRESHOLD + 1);
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadImageData_STATE_ADDED_OverThreshold_001";
}

/**
 * @tc.name: ReadImageData_DefaultState_001
 * @tc.desc: Verify ReadImageData with unexpected state keeps imageDataMap empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadImageData_DefaultState_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadImageData_DefaultState_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    parcel.WriteInt32(99);
    formJsInfo.ReadImageData(parcel);
    EXPECT_TRUE(formJsInfo.imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadImageData_DefaultState_001";
}

/**
 * @tc.name: CheckAshmemSize_InvalidFd_001
 * @tc.desc: Verify CheckAshmemSize returns false when fd < 0.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, CheckAshmemSize_InvalidFd_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin CheckAshmemSize_InvalidFd_001";
    EXPECT_FALSE(FormJsInfo::CheckAshmemSize(-1, 100));
    EXPECT_FALSE(FormJsInfo::CheckAshmemSize(-2, 100));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end CheckAshmemSize_InvalidFd_001";
}

/**
 * @tc.name: CheckAshmemSize_SizeMismatch_001
 * @tc.desc: Verify CheckAshmemSize returns false when bufferSize != ashmemSize.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, CheckAshmemSize_SizeMismatch_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin CheckAshmemSize_SizeMismatch_001";
    int fd = AshmemCreate("CheckAshmemSize_Mismatch", 1024);
    ASSERT_GE(fd, 0);
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    EXPECT_TRUE(FormJsInfo::CheckAshmemSize(fd, 1024));
    EXPECT_FALSE(FormJsInfo::CheckAshmemSize(fd, 2048));
    EXPECT_FALSE(FormJsInfo::CheckAshmemSize(fd, 512));
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end CheckAshmemSize_SizeMismatch_001";
}

/**
 * @tc.name: ReadPkgNameMap_KeyValueMismatch_001
 * @tc.desc: Verify ReadPkgNameMap handles mismatched key/value vector sizes.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadPkgNameMap_KeyValueMismatch_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadPkgNameMap_KeyValueMismatch_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    std::vector<std::string> keys = {"key1", "key2"};
    std::vector<std::string> values = {"val1"};
    parcel.WriteStringVector(keys);
    parcel.WriteStringVector(values);
    formJsInfo.ReadPkgNameMap(parcel);
    EXPECT_TRUE(formJsInfo.modulePkgNameMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadPkgNameMap_KeyValueMismatch_001";
}

/**
 * @tc.name: CopyFormJsInfoWithoutFormData_FullVerification_001
 * @tc.desc: Verify all fields are correctly copied except formData and formSrc.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, CopyFormJsInfoWithoutFormData_FullVerification_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin CopyFormJsInfoWithoutFormData_FullVerification_001";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 100;
    formJsInfo.formName = "testForm";
    formJsInfo.bundleName = "com.test";
    formJsInfo.abilityName = "MainAbility";
    formJsInfo.moduleName = "entry";
    formJsInfo.modulePkgNameMap = {{ "module1", "pkg1" }};
    formJsInfo.formTempFlag = true;
    formJsInfo.jsFormCodePath = "/path/to/js";
    formJsInfo.formData = "form_data_content";
    formJsInfo.formSrc = "formSrcContent";
    formJsInfo.formWindow.designWidth = 720;
    formJsInfo.formWindow.autoDesignWidth = true;
    formJsInfo.versionCode = 1;
    formJsInfo.versionName = "1.0";
    formJsInfo.compatibleVersion = 1;
    formJsInfo.type = FormType::JS;
    formJsInfo.uiSyntax = FormType::ETS;
    formJsInfo.isDynamic = false;
    formJsInfo.transparencyEnabled = true;
    formJsInfo.templateFormImperativeFwk = "lite";

    FormJsInfo copy = formJsInfo.CopyFormJsInfoWithoutFormData();
    EXPECT_EQ(copy.formId, 100);
    EXPECT_EQ(copy.formName, "testForm");
    EXPECT_EQ(copy.bundleName, "com.test");
    EXPECT_EQ(copy.abilityName, "MainAbility");
    EXPECT_EQ(copy.moduleName, "entry");
    EXPECT_EQ(copy.modulePkgNameMap.size(), 1);
    EXPECT_EQ(copy.modulePkgNameMap["module1"], "pkg1");
    EXPECT_EQ(copy.formTempFlag, true);
    EXPECT_EQ(copy.jsFormCodePath, "/path/to/js");
    EXPECT_EQ(copy.formData, "");
    EXPECT_EQ(copy.formSrc, "");
    EXPECT_TRUE(copy.imageDataMap.empty());
    EXPECT_EQ(copy.formWindow.designWidth, 720);
    EXPECT_EQ(copy.formWindow.autoDesignWidth, true);
    EXPECT_EQ(copy.versionCode, 1);
    EXPECT_EQ(copy.versionName, "1.0");
    EXPECT_EQ(copy.compatibleVersion, 1);
    EXPECT_EQ(copy.type, FormType::JS);
    EXPECT_EQ(copy.uiSyntax, FormType::ETS);
    EXPECT_EQ(copy.isDynamic, false);
    EXPECT_EQ(copy.transparencyEnabled, true);
    EXPECT_EQ(copy.templateFormImperativeFwk, "lite");
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end CopyFormJsInfoWithoutFormData_FullVerification_001";
}

/**
 * @tc.name: Marshalling_Unmarshalling_CompleteFields_001
 * @tc.desc: Verify Marshalling and Unmarshalling round-trip preserves all fields.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, Marshalling_Unmarshalling_CompleteFields_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin Marshalling_Unmarshalling_CompleteFields_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formId = 100;
    writeJsInfo.formName = "testForm";
    writeJsInfo.bundleName = "com.test";
    writeJsInfo.abilityName = "MainAbility";
    writeJsInfo.moduleName = "entry";
    writeJsInfo.modulePkgNameMap = {{ "module1", "pkg1" }};
    writeJsInfo.formTempFlag = true;
    writeJsInfo.jsFormCodePath = "/path/to/js";
    writeJsInfo.formData = "small_form_data";
    writeJsInfo.formSrc = "formSrc";
    writeJsInfo.formWindow.designWidth = 720;
    writeJsInfo.formWindow.autoDesignWidth = true;
    writeJsInfo.versionCode = 1;
    writeJsInfo.versionName = "1.0";
    writeJsInfo.compatibleVersion = 1;
    writeJsInfo.type = FormType::JS;
    writeJsInfo.uiSyntax = FormType::ETS;
    writeJsInfo.isDynamic = false;
    writeJsInfo.transparencyEnabled = true;
    writeJsInfo.templateFormImperativeFwk = "lite";

    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.Marshalling(parcel));

    std::unique_ptr<FormJsInfo> readJsInfo(FormJsInfo::Unmarshalling(parcel));
    ASSERT_NE(readJsInfo, nullptr);
    EXPECT_EQ(readJsInfo->formId, writeJsInfo.formId);
    EXPECT_EQ(readJsInfo->formName, writeJsInfo.formName);
    EXPECT_EQ(readJsInfo->bundleName, writeJsInfo.bundleName);
    EXPECT_EQ(readJsInfo->abilityName, writeJsInfo.abilityName);
    EXPECT_EQ(readJsInfo->moduleName, writeJsInfo.moduleName);
    EXPECT_EQ(readJsInfo->modulePkgNameMap.size(), writeJsInfo.modulePkgNameMap.size());
    EXPECT_EQ(readJsInfo->modulePkgNameMap["module1"], "pkg1");
    EXPECT_EQ(readJsInfo->formTempFlag, writeJsInfo.formTempFlag);
    EXPECT_EQ(readJsInfo->jsFormCodePath, writeJsInfo.jsFormCodePath);
    EXPECT_EQ(readJsInfo->formData, writeJsInfo.formData);
    EXPECT_EQ(readJsInfo->formSrc, writeJsInfo.formSrc);
    EXPECT_EQ(readJsInfo->formWindow.designWidth, writeJsInfo.formWindow.designWidth);
    EXPECT_EQ(readJsInfo->formWindow.autoDesignWidth, writeJsInfo.formWindow.autoDesignWidth);
    EXPECT_EQ(readJsInfo->versionCode, writeJsInfo.versionCode);
    EXPECT_EQ(readJsInfo->versionName, writeJsInfo.versionName);
    EXPECT_EQ(readJsInfo->compatibleVersion, writeJsInfo.compatibleVersion);
    EXPECT_EQ(readJsInfo->type, writeJsInfo.type);
    EXPECT_EQ(readJsInfo->uiSyntax, writeJsInfo.uiSyntax);
    EXPECT_EQ(readJsInfo->isDynamic, writeJsInfo.isDynamic);
    EXPECT_EQ(readJsInfo->transparencyEnabled, writeJsInfo.transparencyEnabled);
    EXPECT_EQ(readJsInfo->templateFormImperativeFwk, writeJsInfo.templateFormImperativeFwk);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end Marshalling_Unmarshalling_CompleteFields_001";
}

/**
 * @tc.name: ReadFromParcel_BindingDataNull_001
 * @tc.desc: Verify ReadFromParcel returns false when FormProviderData parcelable is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadFromParcel_BindingDataNull_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadFromParcel_BindingDataNull_001";
    MessageParcel parcel;
    parcel.WriteInt64(100);
    parcel.WriteString16(Str8ToStr16("testForm"));
    parcel.WriteString16(Str8ToStr16("com.test"));
    parcel.WriteString16(Str8ToStr16("MainAbility"));
    parcel.WriteString16(Str8ToStr16("entry"));
    parcel.WriteBool(false);
    parcel.WriteString16(Str8ToStr16("jsPath"));
    parcel.WriteInt32(4);
    parcel.WriteString16(Str8ToStr16("test"));
    parcel.WriteString16(Str8ToStr16("formSrc"));
    parcel.WriteInt32(720);
    parcel.WriteBool(true);
    parcel.WriteUint32(1);
    parcel.WriteString16(Str8ToStr16("1.0"));
    parcel.WriteUint32(1);
    parcel.WriteInt32(static_cast<int32_t>(FormType::JS));
    parcel.WriteInt32(static_cast<int32_t>(FormType::JS));
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    parcel.WriteString16(Str8ToStr16("none"));
    parcel.WriteInt32(0);

    FormJsInfo formJsInfo;
    EXPECT_FALSE(formJsInfo.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadFromParcel_BindingDataNull_001";
}

/**
 * @tc.name: ReadPkgNameMap_ValidData_001
 * @tc.desc: Verify ReadPkgNameMap correctly populates modulePkgNameMap with matched keys/values.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadPkgNameMap_ValidData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadPkgNameMap_ValidData_001";
    FormJsInfo formJsInfo;
    MessageParcel parcel;
    std::vector<std::string> keys = {"module1", "module2"};
    std::vector<std::string> values = {"pkg1", "pkg2"};
    parcel.WriteStringVector(keys);
    parcel.WriteStringVector(values);
    formJsInfo.ReadPkgNameMap(parcel);
    EXPECT_EQ(formJsInfo.modulePkgNameMap.size(), 2);
    EXPECT_EQ(formJsInfo.modulePkgNameMap["module1"], "pkg1");
    EXPECT_EQ(formJsInfo.modulePkgNameMap["module2"], "pkg2");
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadPkgNameMap_ValidData_001";
}

/**
 * @tc.name: ReadPkgNameMap_ReadKeysFail_001
 * @tc.desc: Verify ReadPkgNameMap handles ReadStringVector failure for keys.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, ReadPkgNameMap_ReadKeysFail_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin ReadPkgNameMap_ReadKeysFail_001";
    FormJsInfo formJsInfo;
    Parcel parcel;
    formJsInfo.ReadPkgNameMap(parcel);
    EXPECT_TRUE(formJsInfo.modulePkgNameMap.empty());
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end ReadPkgNameMap_ReadKeysFail_001";
}

/**
 * @tc.name: WritePkgNameMap_WithPopulatedMap_001
 * @tc.desc: Verify WritePkgNameMap writes populated modulePkgNameMap correctly.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, WritePkgNameMap_WithPopulatedMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin WritePkgNameMap_WithPopulatedMap_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.modulePkgNameMap = {{ "module1", "pkg1" }, { "module2", "pkg2" }};
    MessageParcel parcel;
    EXPECT_TRUE(writeJsInfo.WritePkgNameMap(parcel));

    FormJsInfo readJsInfo;
    readJsInfo.ReadPkgNameMap(parcel);
    EXPECT_EQ(readJsInfo.modulePkgNameMap.size(), 2);
    EXPECT_EQ(readJsInfo.modulePkgNameMap["module1"], "pkg1");
    EXPECT_EQ(readJsInfo.modulePkgNameMap["module2"], "pkg2");
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end WritePkgNameMap_WithPopulatedMap_001";
}

/**
 * @tc.name: Unmarshalling_Success_001
 * @tc.desc: Verify Unmarshalling returns valid pointer when ReadFromParcel succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormJsInfoTest, Unmarshalling_Success_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-begin Unmarshalling_Success_001";
    FormJsInfo writeJsInfo;
    writeJsInfo.formId = 500;
    writeJsInfo.formName = "unmarshalTest";
    writeJsInfo.bundleName = "com.unmarshal";
    writeJsInfo.abilityName = "UnmarshalAbility";
    writeJsInfo.moduleName = "entry";
    writeJsInfo.formData = "data";
    writeJsInfo.formSrc = "formSrc";
    writeJsInfo.formWindow.designWidth = 720;
    writeJsInfo.formWindow.autoDesignWidth = true;
    writeJsInfo.versionCode = 1;
    writeJsInfo.versionName = "1.0";
    writeJsInfo.compatibleVersion = 1;
    writeJsInfo.type = FormType::JS;
    writeJsInfo.uiSyntax = FormType::ETS;
    writeJsInfo.isDynamic = false;
    writeJsInfo.transparencyEnabled = true;

    MessageParcel parcel;
    ASSERT_TRUE(writeJsInfo.Marshalling(parcel));

    std::unique_ptr<FormJsInfo> result(FormJsInfo::Unmarshalling(parcel));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->formId, 500);
    EXPECT_EQ(result->formName, "unmarshalTest");
    EXPECT_EQ(result->bundleName, "com.unmarshal");
    EXPECT_EQ(result->abilityName, "UnmarshalAbility");
    EXPECT_EQ(result->moduleName, "entry");
    EXPECT_EQ(result->formData, "data");
    EXPECT_EQ(result->formSrc, "formSrc");
    EXPECT_EQ(result->formWindow.designWidth, 720);
    EXPECT_EQ(result->formWindow.autoDesignWidth, true);
    EXPECT_EQ(result->versionCode, 1);
    EXPECT_EQ(result->versionName, "1.0");
    EXPECT_EQ(result->compatibleVersion, 1);
    EXPECT_EQ(result->type, FormType::JS);
    EXPECT_EQ(result->uiSyntax, FormType::ETS);
    EXPECT_EQ(result->isDynamic, false);
    EXPECT_EQ(result->transparencyEnabled, true);
    GTEST_LOG_(INFO) << "FmsFormJsInfoTest-end Unmarshalling_Success_001";
}

} // namespace AppExecFwk
} // namespace OHOS
