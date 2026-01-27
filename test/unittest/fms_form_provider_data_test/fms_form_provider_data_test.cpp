/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "string_ex.h"
#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string FORM_DB_DATA_BASE_FILE_DIR = "/data/formmgr";
const int32_t FOUR = 4;
const int32_t TEN = 10;
const int32_t ELEVEN = 11;
const int32_t DEFAULT_VALUE = 0;  // Used to adapt functional code.

class FmsFormProviderDataTest : public testing::Test {
public:
    void SetUp();
    void Test();
    bool InitJsonData();
    bool InitJsonData2();
    bool CreateJsonFileByJsonData1(const nlohmann::json &jsonData);
    bool CreateJsonFileByJsonData2(const nlohmann::json &jsonData);
    bool CreateMergeJsonFileByJsonData3(const nlohmann::json &jsonData);

    nlohmann::json jsonData_;
};
void FmsFormProviderDataTest::SetUp()
{
    DIR *dirptr = opendir(FORM_DB_DATA_BASE_FILE_DIR.c_str());
    if (dirptr == nullptr) {
        HILOG_WARN("%{public}s, opendir is fail", __func__);
        if (-1 == mkdir(FORM_DB_DATA_BASE_FILE_DIR.c_str(), S_IRWXU)) {
            HILOG_ERROR("%{public}s, dir create fail", __func__);
            return;
        }
    } else {
        closedir(dirptr);
    }
}

bool FmsFormProviderDataTest::InitJsonData()
{
    nlohmann::json tmpJson;
    tmpJson["name"] = "li";
    tmpJson["age"] = TEN;
    jsonData_["0"] = tmpJson;
    return true;
}

bool FmsFormProviderDataTest::InitJsonData2()
{
    nlohmann::json tmpJson;
    tmpJson["name"] = "wang";
    tmpJson["age"] = ELEVEN;
    jsonData_["1"] = tmpJson;
    return true;
}

bool FmsFormProviderDataTest::CreateJsonFileByJsonData1(const nlohmann::json &jsonData)
{
    std::ofstream o("/data/formmgr/ByJsonFile1.json");
    o.close();

    std::fstream f("/data/formmgr/ByJsonFile1.json");
    if (f.good() == false) {
        return false;
    }

    f << std::setw(FOUR) << jsonData << std::endl;

    f.close();
    return true;
}

bool FmsFormProviderDataTest::CreateJsonFileByJsonData2(const nlohmann::json &jsonData)
{
    std::ofstream o("/data/formmgr/ByJsonFile2.json");
    o.close();

    std::fstream f("/data/formmgr/ByJsonFile2.json");
    if (f.good() == false) {
        return false;
    }

    f << std::setw(FOUR) << jsonData << std::endl;

    f.close();
    return true;
}

bool FmsFormProviderDataTest::CreateMergeJsonFileByJsonData3(const nlohmann::json &jsonData)
{
    std::ofstream o("/data/formmgr/ByJsonFile3.json");
    o.close();

    std::fstream f("/data/formmgr/ByJsonFile3.json");
    if (f.good() == false) {
        return false;
    }

    f << std::setw(FOUR) << jsonData << std::endl;

    f.close();
    return true;
}

/**
 * @tc.name: FmsFormProviderDataTest_001
 * @tc.desc: Verify the CreateJsonFileByJsonData1 function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, CreateJsonFileByJsonData1(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_001 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_002
 * @tc.desc: Verify the CreateJsonFileByJsonData2 function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_002 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_.dump());
    EXPECT_EQ(true, CreateJsonFileByJsonData2(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_002 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_003
 * @tc.desc: Verify the GetDataString function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_003 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    GTEST_LOG_(INFO) << "print:" <<formProviderData.GetDataString();
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_003 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_004
 * @tc.desc: Verify the MergeData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_004 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, InitJsonData2());
    formProviderData.MergeData(jsonData_);
    EXPECT_EQ(true, CreateMergeJsonFileByJsonData3(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_004 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_005
 * @tc.desc: Verify the ConvertRawImageData function.
 * @tc.type: FUNC
 * @tc.require: issueI5KIZC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_005 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    std::shared_ptr<char> data = std::make_shared<char>('a');
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_TRUE(formProviderData.ConvertRawImageData());
    EXPECT_EQ(1, formProviderData.GetImageDataMap().size());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_005 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_006
 * @tc.desc: Verify the AddImageData and WriteImageDataToParcel function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_006 start";
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    formProviderData.AddImageData(picName, 1);
    Parcel parcel;
    std::shared_ptr<char> data = std::make_shared<char>('a');
    EXPECT_EQ(true, formProviderData.WriteImageDataToParcel(parcel, picName, data, 1));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_006 end";
}
/**
 * @tc.name: FmsFormProviderDataTest_007
 * @tc.desc: Verify the UpdateData and GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_007 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.UpdateData(jsonData_);
    auto result = formProviderData.GetData();

    EXPECT_EQ(jsonData_, result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_007 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_008
 * @tc.desc: Verify the RemoveImageData and AddImageData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_008 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "abc";
    int32_t size = 1;
    std::shared_ptr<char> data;
    formProviderData.AddImageData(picName, data, size);
    formProviderData.RemoveImageData(picName);

    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_008 end";

}

/**
 * @tc.name: FmsFormProviderDataTest_009
 * @tc.desc: Verify the SetDataString and GetDataString function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_009 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string jsonDataString = "abc";
    formProviderData.SetDataString(jsonDataString);
    auto result = formProviderData.GetDataString();

    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_009 end";

}

/**
 * @tc.name: FmsFormProviderDataTest_0010
 * @tc.desc: Verify the ReadFromParcel function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0010 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    auto result = formProviderData.ReadFromParcel(parcel);

    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0010 end";

}

/**
 * @tc.name: FmsFormProviderDataTest_0011
 * @tc.desc: Verify the Marshalling function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0011 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);

    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0011 end";

}

/**
 * @tc.name: FmsFormProviderDataTest_0012
 * @tc.desc: Verify the Unmarshalling function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0012 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    auto result = formProviderData.Unmarshalling(parcel);

    EXPECT_TRUE(result == nullptr);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0012 end";

}

/**
 * @tc.name: FmsFormProviderDataTest_0013
 * @tc.desc: Verify the ClearData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0013 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.UpdateData(jsonData_);
    formProviderData.ClearData();

    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0013 end";

}

/**
 * @tc.number: FmsFormProviderDataTest_0014
 * @tc.name: Verify the MergeData function.
 * @tc.desc: When sonFormProviderData_ is not nullptr, the interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0014 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, InitJsonData2());
    formProviderData.MergeData(jsonData_);
    EXPECT_FALSE(formProviderData.jsonFormProviderData_.empty());
    formProviderData.MergeData(jsonData_);
    EXPECT_EQ(true, CreateMergeJsonFileByJsonData3(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0014 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0015
 * @tc.name: Verify the AddImageData function.
 * @tc.desc: When data is nullptr, the interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0015 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "imageTest";
    std::shared_ptr<char> data = nullptr;
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0015 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0016
 * @tc.name: Verify the AddImageData function.
 * @tc.desc: When picName is "", the interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0016 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "";
    std::shared_ptr<char> data = nullptr;
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0016 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0017
 * @tc.name: Verify the AddImageData function.
 * @tc.desc: When fd is -1, the interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0017 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "imageTest";
    int fd = -1;
    formProviderData.AddImageData(picName, fd);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0017 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0018
 * @tc.name: Verify the SetDataString and GetDataString function.
 * @tc.desc: Verify the SetDataString and GetDataString interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0018 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string jsonDataString = "";
    formProviderData.SetDataString(jsonDataString);
    auto result = formProviderData.GetDataString();
    EXPECT_TRUE(result != jsonDataString);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0018 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0019
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_NO_OPERATION, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0019 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteInt32(DEFAULT_VALUE);
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0019 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0020
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_REMOVED, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0020 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteInt32(DEFAULT_VALUE);
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_REMOVED);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0020 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0021
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is 100, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0021 start";
    EXPECT_EQ(true, InitJsonData());
    constexpr int32_t defaultValue = 100;
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteInt32(DEFAULT_VALUE);
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(defaultValue);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0021 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0022
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_ADDED, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0022 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteInt32(DEFAULT_VALUE);
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0022 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0023
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_ADDED and imageDataNum is exception value, the
 *           interface return value is false.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0023 start";
    EXPECT_EQ(true, InitJsonData());
    constexpr int32_t imageDataNum = 1001;  // 1001: Eead parcel max image data num size.
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(imageDataNum);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0023 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0024
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_ADDED and imageDataNum is normal value, the
 *           interface return value is false.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0024 start";
    EXPECT_EQ(true, InitJsonData());
    constexpr int32_t imageDataNum = 1;
    constexpr int32_t len = 0;
    FormAshmem formAshmem;
    char data = 'A';
    constexpr int32_t size = 1;
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(imageDataNum);
    formAshmem.WriteToAshmem("ReadFromParcelTest", &data, size);
    parcel.WriteInt32(len);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0024 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0025
 * @tc.name: Verify the ReadFromParcel function.
 * @tc.desc: When the parameter parcel is IMAGE_DATA_STATE_ADDED and imageDataNum is normal value, the
 *           interface return value is false.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0025 start";
    EXPECT_EQ(true, InitJsonData());
    constexpr int32_t imageDataNum = 1;
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(jsonData_.dump()));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(imageDataNum);
    auto result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0025 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0026
 * @tc.name: Verify the Marshalling function.
 * @tc.desc: When the parameter imageDataState_ is IMAGE_DATA_STATE_NO_OPERATION, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0026 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_NO_OPERATION;
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0026 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0027
 * @tc.name: Verify the Marshalling function.
 * @tc.desc: When the parameter imageDataState_ is IMAGE_DATA_STATE_REMOVED, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0027 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_REMOVED;
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0027 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0028
 * @tc.name: Verify the Marshalling function.
 * @tc.desc: When the parameter imageDataState_ is IMAGE_DATA_STATE_ADDED, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0028 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0028 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0029
 * @tc.name: Verify the Marshalling function.
 * @tc.desc: When the parameter imageDataState_ is 100, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0029 start";
    EXPECT_EQ(true, InitJsonData());
    constexpr int32_t defaultValue = 100;
    FormProviderData formProviderData(jsonData_);
    formProviderData.imageDataState_ = defaultValue;
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0029 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0030
 * @tc.name: Verify the Marshalling function.
 * @tc.desc: When the parameter imageDataState_ is null, the interface return value is true.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0030 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    Parcel parcel;
    auto result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0030 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0031
 * @tc.name: Verify the ParseImagesData function.
 * @tc.desc: Verify whether the ParseImagesData interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0031 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.ParseImagesData();
    EXPECT_TRUE(formProviderData.jsonFormProviderData_ != nullptr);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0031 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0032
 * @tc.name: Verify the ParseImagesData function.
 * @tc.desc: When the jsonFormProviderData_ is nullptr, the ParseImagesData interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0032 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_ = nullptr;
    formProviderData.ParseImagesData();
    EXPECT_TRUE(formProviderData.jsonFormProviderData_ == nullptr);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0032 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0033
 * @tc.name: Verify the NeedCache function.
 * @tc.desc: When the jsonFormProviderData_ is nullptr, the NeedCache interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0033 start";
    FormProviderData formProviderData("{'a':'1','b':'2'}");
    formProviderData.jsonFormProviderData_.clear();
    EXPECT_FALSE(formProviderData.NeedCache());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0033 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0034
 * @tc.name: Verify the SetImageDataState function.
 * @tc.desc: Verify whether the NeedCache interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0034 start";
    FormProviderData formProviderData("");
    constexpr int32_t imageStage = 1000;
    EXPECT_NE(imageStage, formProviderData.imageDataState_);
    formProviderData.SetImageDataState(imageStage);
    EXPECT_EQ(imageStage, formProviderData.imageDataState_);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0034 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0035
 * @tc.name: Verify the GetImageDataState function.
 * @tc.desc: Verify whether the GetImageDataState interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0035 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    EXPECT_EQ(formProviderData.imageDataState_, formProviderData.GetImageDataState());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0035 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0036
 * @tc.name: Verify the WriteAshmemDataToParcel function.
 * @tc.desc: Verify whether the WriteAshmemDataToParcel interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0036 start";
    Parcel parcel;
    std::string name = "formAshmemData";
    size_t size = sizeof(name);
    const char* dataPtr = "formAshmemData";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    auto result = formProviderData.WriteAshmemDataToParcel(parcel, size, dataPtr);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0036 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0037
 * @tc.name: Verify the ReadAshmemDataFromParcel function.
 * @tc.desc: Verify whether the ReadAshmemDataFromParcel interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0037 start";
    Parcel parcel;
    size_t bufferSize = 0;
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    auto result = formProviderData.ReadAshmemDataFromParcel(parcel, bufferSize);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0037 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0038
 * @tc.name: Verify the WriteFileDescriptor function.
 * @tc.desc: Verify whether the WriteFileDescriptor interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0038 start";
    Parcel parcel;
    int fd = -1;
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    auto result = formProviderData.WriteFileDescriptor(parcel, fd);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0038 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0039
 * @tc.name: Verify the ReadFileDescriptor and ReleaseMemory function.
 * @tc.desc: Verify whether ReadFileDescriptor and ReleaseMemory interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0039 start";
    Parcel parcel;
    FormProviderData formProviderData;
    formProviderData.ReleaseMemory(2, nullptr, nullptr, 0);
    auto result = formProviderData.ReadFileDescriptor(parcel);
    EXPECT_EQ(result, -1);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0039 end";
}

/**
 * @tc.number: FmsFormProviderDataTest_0040
 * @tc.name: Verify the CheckAshmemSize function.
 * @tc.desc: Verify whether the CheckAshmemSize interface calls normally.
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_0040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0040 start";
    int fd = -1;
    int32_t bufferSize = 0;
    bool isAstc = false;
    auto result =  FormProviderData::CheckAshmemSize(fd, bufferSize, isAstc);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_0040 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_042
 * @tc.desc: Verify the CreateJsonFileByJsonData1 function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_042 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, CreateJsonFileByJsonData1(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_042 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_043
 * @tc.desc: Verify the CreateJsonFileByJsonData2 function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_043 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_.dump());
    EXPECT_EQ(true, CreateJsonFileByJsonData2(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_043 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_044
 * @tc.desc: Verify the GetDataString function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_044 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    GTEST_LOG_(INFO) << "print:" <<formProviderData.GetDataString();
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_044 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_045
 * @tc.desc: Verify the MergeData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_045 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, InitJsonData2());
    formProviderData.MergeData(jsonData_);
    EXPECT_EQ(true, CreateMergeJsonFileByJsonData3(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_045 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_046
 * @tc.desc: Verify the ConvertRawImageData function.
 * @tc.type: FUNC
 * @tc.require: issueI5KIZC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_046 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    std::shared_ptr<char> data = std::make_shared<char>('a');
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_TRUE(formProviderData.ConvertRawImageData());
    EXPECT_EQ(1, formProviderData.GetImageDataMap().size());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_046 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_047
 * @tc.desc: Verify the AddImageData and WriteImageDataToParcel function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_047 start";
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    formProviderData.AddImageData(picName, 1);
    Parcel parcel;
    std::shared_ptr<char> data = std::make_shared<char>('a');
    EXPECT_EQ(true, formProviderData.WriteImageDataToParcel(parcel, picName, data, 1));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_047 end";
}
/**
 * @tc.name: FmsFormProviderDataTest_048
 * @tc.desc: Verify the UpdateData and GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_048 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    formProviderData.UpdateData(jsonData_);
    auto result = formProviderData.GetData();

    EXPECT_EQ(jsonData_, result);
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_048 end";
}

/**
 * @tc.name: FmsFormProviderDataTest_049
 * @tc.desc: Verify the RemoveImageData and AddImageData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_049 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "abc";
    int32_t size = 1;
    std::shared_ptr<char> data;
    formProviderData.AddImageData(picName, data, size);
    formProviderData.RemoveImageData(picName);

    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_049 end";

}

/**
 0* @tc.name: FmsFormProviderDataTest_050
 * @tc.desc: Verify the SetDataString and GetDataString function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_050 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string jsonDataString = "abc";
    formProviderData.SetDataString(jsonDataString);
    auto result = formProviderData.GetDataString();

    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_050 end";

}

/**
 0* @tc.name: FmsFormProviderDataTest_051
 * @tc.desc: Verify the EnableDbCache and IsDbCacheEnabled function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_051 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);

    formProviderData.EnableDbCache(true);
    EXPECT_TRUE(formProviderData.IsDbCacheEnabled());
    EXPECT_TRUE(formProviderData.enableDbCache_);

    formProviderData.EnableDbCache(false);
    EXPECT_FALSE(formProviderData.IsDbCacheEnabled());
    EXPECT_FALSE(formProviderData.enableDbCache_);

    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_051 end";

}
}
