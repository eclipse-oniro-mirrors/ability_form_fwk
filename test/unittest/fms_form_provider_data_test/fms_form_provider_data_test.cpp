/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

#include "ipc_file_descriptor.h"
#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "fms_log_wrapper.h"
#define private public
#include "form_provider_data.h"
#undef private

using namespace testing::ext;

namespace OHOS::AppExecFwk {
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
 * @tc.name: AddImageData_FD_ValidFile_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData with fd, when file is a valid small image.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_FD_ValidFile_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_FD_ValidFile_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "validImage";
    std::string testData = "test image data content";
    std::string testFile = "/data/formmgr/test_valid_image.tmp";
    std::ofstream file(testFile);
    file << testData;
    file.close();
    int fd = open(testFile.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    formProviderData.AddImageData(picName, fd);
    close(fd);
    unlink(testFile.c_str());
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) != formProviderData.rawImageBytesMap_.end());
    EXPECT_EQ(formProviderData.rawImageBytesMap_[picName].second, static_cast<int32_t>(testData.length()));
    GTEST_LOG_(INFO) << "AddImageData_FD_ValidFile_001 end";
}

/**
 * @tc.name: ReadAshmem_BufferSizeExceed_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadAshmemDataFromParcel with bufferSize exceeds MAX_BUFFER_SIZE.
 */
HWTEST_F(FmsFormProviderDataTest, ReadAshmem_BufferSizeExceed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadAshmem_BufferSizeExceed_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    constexpr int32_t overSize = 32 * 1024 * 1024 + 1;
    char* result = formProviderData.ReadAshmemDataFromParcel(parcel, overSize);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "ReadAshmem_BufferSizeExceed_001 end";
}

/**
 * @tc.name: ReadAshmem_BufferSizeNegative_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadAshmemDataFromParcel with negative bufferSize.
 */
HWTEST_F(FmsFormProviderDataTest, ReadAshmem_BufferSizeNegative_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadAshmem_BufferSizeNegative_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    char* result = formProviderData.ReadAshmemDataFromParcel(parcel, -1);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "ReadAshmem_BufferSizeNegative_001 end";
}

/**
 * @tc.name: WriteFd_ValidFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteFileDescriptor with valid fd.
 */
HWTEST_F(FmsFormProviderDataTest, WriteFd_ValidFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteFd_ValidFd_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    std::string testFile = "/data/formmgr/test_fd_write.tmp";
    int fd = open(testFile.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);
    bool result = formProviderData.WriteFileDescriptor(parcel, fd);
    close(fd);
    unlink(testFile.c_str());
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteFd_ValidFd_001 end";
}

/**
 * @tc.name: WriteAshmemDataToParcel_ZeroSize_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteAshmemDataToParcel with zero size data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteAshmemDataToParcel_ZeroSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteAshmemDataToParcel_ZeroSize_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    const char* dataPtr = "test";
    bool result = formProviderData.WriteAshmemDataToParcel(parcel, 0, dataPtr);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "WriteAshmemDataToParcel_ZeroSize_001 end";
}

/**
 * @tc.name: WriteAshmem_LargeData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteAshmemDataToParcel with large data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteAshmem_LargeData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteAshmem_LargeData_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    std::string largeData(1024 * 100, 'a');
    const char* dataPtr = largeData.c_str();
    size_t size = largeData.length();
    bool result = formProviderData.WriteAshmemDataToParcel(parcel, size, dataPtr);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteAshmem_LargeData_001 end";
}

/**
 * @tc.name: ConvertRawImage_MultiImages_001
 * @tc.type: FUNC
 * @tc.desc: Verify ConvertRawImageData with multiple images.
 */
HWTEST_F(FmsFormProviderDataTest, ConvertRawImage_MultiImages_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConvertRawImage_MultiImages_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::shared_ptr<char> data1 = std::shared_ptr<char>(new char[10], std::default_delete<char[]>());
    std::shared_ptr<char> data2 = std::shared_ptr<char>(new char[20], std::default_delete<char[]>());
    formProviderData.AddImageData("image1", data1, 10);
    formProviderData.AddImageData("image2", data2, 20);
    EXPECT_TRUE(formProviderData.ConvertRawImageData());
    EXPECT_EQ(2, static_cast<int>(formProviderData.GetImageDataMap().size()));
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "ConvertRawImage_MultiImages_001 end";
}

/**
 * @tc.name: WriteImageData_EmptyData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteImageDataToParcel with empty data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteImageData_EmptyData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteImageData_EmptyData_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    std::string picName = "emptyImage";
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[1], std::default_delete<char[]>());
    data.get()[0] = '\0';
    bool result = formProviderData.WriteImageDataToParcel(parcel, picName, data, 1);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteImageData_EmptyData_001 end";
}

/**
 * @tc.name: WriteImageData_ValidData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteImageDataToParcel with valid data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteImageData_ValidData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteImageData_ValidData_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    std::string picName = "validDataImage";
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[100], std::default_delete<char[]>());
    memset(data.get(), 'A', 100);
    bool result = formProviderData.WriteImageDataToParcel(parcel, picName, data, 100);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteImageData_ValidData_001 end";
}

/**
 * @tc.name: IsValidSize_ValidSize_001
 * @tc.type: FUNC
 * @tc.desc: Verify isValidSize with valid size.
 */
HWTEST_F(FmsFormProviderDataTest, IsValidSize_ValidSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidSize_ValidSize_001 start";
    FormProviderData formProviderData("");
    EXPECT_TRUE(formProviderData.isValidSize(100));
    EXPECT_TRUE(formProviderData.isValidSize(INT32_MAX));
    GTEST_LOG_(INFO) << "IsValidSize_ValidSize_001 end";
}

/**
 * @tc.name: IsValidSize_NegativeSize_001
 * @tc.type: FUNC
 * @tc.desc: Verify isValidSize with invalid size (zero and negative).
 */
HWTEST_F(FmsFormProviderDataTest, IsValidSize_NegativeSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidSize_NegativeSize_001 start";
    FormProviderData formProviderData("");
    EXPECT_FALSE(formProviderData.isValidSize(0));
    EXPECT_FALSE(formProviderData.isValidSize(-1));
    EXPECT_FALSE(formProviderData.isValidSize(-100));
    GTEST_LOG_(INFO) << "IsValidSize_NegativeSize_001 end";
}

/**
 * @tc.name: IsValidSize_ExceedInt32Max_001
 * @tc.type: FUNC
 * @tc.desc: Verify isValidSize with size exceeds INT32_MAX.
 */
HWTEST_F(FmsFormProviderDataTest, IsValidSize_ExceedInt32Max_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidSize_ExceedInt32Max_001 start";
    FormProviderData formProviderData("");
    EXPECT_FALSE(formProviderData.isValidSize(static_cast<off_t>(INT32_MAX) + 1));
    EXPECT_FALSE(formProviderData.isValidSize(static_cast<off_t>(INT32_MAX) + 1000));
    GTEST_LOG_(INFO) << "IsValidSize_ExceedInt32Max_001 end";
}

/**
 * @tc.name: HandleImageAdded_ZeroCount_001
 * @tc.type: FUNC
 * @tc.desc: Verify HandleImageDataStateAdded with imageDataNum is zero.
 */
HWTEST_F(FmsFormProviderDataTest, HandleImageAdded_ZeroCount_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleImageAdded_ZeroCount_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    parcel.WriteInt32(0);
    bool result = formProviderData.HandleImageDataStateAdded(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "HandleImageAdded_ZeroCount_001 end";
}

/**
 * @tc.name: MarshallingUnmarshalling_WithImage_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling and Unmarshalling with image data and comprehensive state verification.
 */
HWTEST_F(FmsFormProviderDataTest, MarshallingUnmarshalling_WithImage_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MarshallingUnmarshalling_WithImage_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData writeProviderData(jsonData_);
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[10], std::default_delete<char[]>());
    memset(data.get(), 'B', 10);
    writeProviderData.AddImageData("marshTest", data, 10);
    writeProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    
    auto writeImageDataState = writeProviderData.GetImageDataState();
    auto writeRawImageBytesMapSize = writeProviderData.rawImageBytesMap_.size();
    
    Parcel parcel;
    EXPECT_TRUE(writeProviderData.Marshalling(parcel));
    
    FormProviderData* readProviderData = FormProviderData::Unmarshalling(parcel);
    ASSERT_NE(readProviderData, nullptr);
    EXPECT_FALSE(readProviderData->jsonFormProviderData_.empty());
    EXPECT_EQ(readProviderData->GetImageDataState(), writeImageDataState);
    EXPECT_EQ(readProviderData->GetImageDataMap().size(), writeRawImageBytesMapSize);
    EXPECT_TRUE(readProviderData->HasData());
    delete readProviderData;
    GTEST_LOG_(INFO) << "MarshallingUnmarshalling_WithImage_001 end";
}

/**
 * @tc.name: WriteFormData_EmptyJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteFormData with empty json data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteFormData_EmptyJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteFormData_EmptyJson_001 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    Parcel parcel;
    bool result = formProviderData.WriteFormData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteFormData_EmptyJson_001 end";
}

/**
 * @tc.name: WriteFormData_NormalJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteFormData with normal json data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteFormData_NormalJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteFormData_NormalJson_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    Parcel parcel;
    bool result = formProviderData.WriteFormData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteFormData_NormalJson_001 end";
}

/**
 * @tc.name: ParseImages_NonIntegerFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify ParseImagesData with invalid fd type in json.
 */
HWTEST_F(FmsFormProviderDataTest, ParseImages_NonIntegerFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseImages_NonIntegerFd_001 start";
    std::string jsonStr = R"({"formImages": {"image1": "not_an_integer"}})";
    FormProviderData formProviderData(jsonStr);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "ParseImages_NonIntegerFd_001 end";
}

/**
 * @tc.name: ParseImages_ValidFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify ParseImagesData with valid fd in json.
 */
HWTEST_F(FmsFormProviderDataTest, ParseImages_ValidFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseImages_ValidFd_001 start";
    std::string testFile = "/data/formmgr/test_parse_image.tmp";
    std::ofstream file(testFile);
    file << "test data";
    file.close();
    int fd = open(testFile.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    std::string jsonStr = R"({"formImages": {"parseTest": )" + std::to_string(fd) + R"(}})";
    FormProviderData formProviderData(jsonStr);
    close(fd);
    unlink(testFile.c_str());
    GTEST_LOG_(INFO) << "ParseImages_ValidFd_001 end";
}

/**
 * @tc.name: AddImageData_StateUpdate_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData with shared_ptr and size updates imageDataState.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_StateUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_StateUpdate_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[10], std::default_delete<char[]>());
    formProviderData.AddImageData("stateTest", data, 10);
    EXPECT_EQ(formProviderData.GetImageDataState(), FormProviderData::IMAGE_DATA_STATE_ADDED);
    GTEST_LOG_(INFO) << "AddImageData_StateUpdate_001 end";
}

/**
 * @tc.name: Marshalling_MultiImages_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling with IMAGE_DATA_STATE_ADDED and multiple images.
 */
HWTEST_F(FmsFormProviderDataTest, Marshalling_MultiImages_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_MultiImages_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::shared_ptr<char> data1 = std::shared_ptr<char>(new char[20], std::default_delete<char[]>());
    std::shared_ptr<char> data2 = std::shared_ptr<char>(new char[30], std::default_delete<char[]>());
    formProviderData.AddImageData("multi1", data1, 20);
    formProviderData.AddImageData("multi2", data2, 30);
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_ADDED;
    Parcel parcel;
    bool result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_MultiImages_001 end";
}

/**
 * @tc.name: ReadFromParcel_EmptyJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with empty json string.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_EmptyJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_EmptyJson_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString16(Str8ToStr16("{}"));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_EmptyJson_001 end";
}

/**
 * @tc.name: ReadFromParcel_NullJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with invalid json string and verify comprehensive state changes.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_NullJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_NullJson_001 start";
    FormProviderData formProviderData("");
    auto initialDataString = formProviderData.GetDataString();
    Parcel parcel;
    parcel.WriteInt32(11);
    parcel.WriteString16(Str8ToStr16("{invalid json}"));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    EXPECT_EQ(formProviderData.imageDataState_, FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    EXPECT_EQ(formProviderData.GetImageDataState(), FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    EXPECT_TRUE(formProviderData.GetImageDataMap().empty());
    EXPECT_EQ(formProviderData.GetDataString(), initialDataString);
    EXPECT_FALSE(formProviderData.HasData());
    GTEST_LOG_(INFO) << "ReadFromParcel_NullJson_001 end";
}

/**
 * @tc.name: HasData_OnlyImageMap_001
 * @tc.type: FUNC
 * @tc.desc: Verify HasData with only imageDataMap.
 */
HWTEST_F(FmsFormProviderDataTest, HasData_OnlyImageMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HasData_OnlyImageMap_001 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    imageDataMap["hasDataTest"] = std::make_pair(formAshmem, 10);
    formProviderData.SetImageDataMap(imageDataMap);
    EXPECT_TRUE(formProviderData.HasData());
    GTEST_LOG_(INFO) << "HasData_OnlyImageMap_001 end";
}

/**
 * @tc.name: Constructor_NonObjectJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify constructor with non-object json (array type).
 */
HWTEST_F(FmsFormProviderDataTest, Constructor_NonObjectJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Constructor_NonObjectJson_001 start";
    nlohmann::json jsonArray = nlohmann::json::array();
    jsonArray.push_back("test");
    FormProviderData formProviderData(jsonArray);
    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    GTEST_LOG_(INFO) << "Constructor_NonObjectJson_001 end";
}

/**
 * @tc.name: AddImageData_FileTooLarge_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData when file size exceeds MAX_IMAGE_BYTE_SIZE.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_FileTooLarge_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_FileTooLarge_001 start";
    FormProviderData formProviderData("");
    std::string picName = "largeImage";
    std::string testFile = "/data/formmgr/test_large_image.tmp";
    int fd = open(testFile.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);
    std::string largeData(51 * 1024 * 1024, 'A');
    write(fd, largeData.c_str(), largeData.size());
    close(fd);
    fd = open(testFile.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    formProviderData.AddImageData(picName, fd);
    close(fd);
    unlink(testFile.c_str());
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "AddImageData_FileTooLarge_001 end";
}

/**
 * @tc.name: ReadAshmemDataFromParcel_InvalidBufferSize_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadAshmemDataFromParcel with invalid buffer size (zero and negative).
 */
HWTEST_F(FmsFormProviderDataTest, ReadAshmemDataFromParcel_InvalidBufferSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadAshmemDataFromParcel_InvalidBufferSize_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    char* result1 = formProviderData.ReadAshmemDataFromParcel(parcel, 0);
    EXPECT_EQ(result1, nullptr);
    char* result2 = formProviderData.ReadAshmemDataFromParcel(parcel, -1);
    EXPECT_EQ(result2, nullptr);
    GTEST_LOG_(INFO) << "ReadAshmemDataFromParcel_InvalidBufferSize_001 end";
}

/**
 * @tc.name: WriteFileDescriptor_DupFailed_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteFileDescriptor when dup fails (invalid fd).
 */
HWTEST_F(FmsFormProviderDataTest, WriteFileDescriptor_DupFailed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteFileDescriptor_DupFailed_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    int invalidFd = -1;
    bool result = formProviderData.WriteFileDescriptor(parcel, invalidFd);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "WriteFileDescriptor_DupFailed_001 end";
}

/**
 * @tc.name: HandleImageDataStateAdded_NullAshmem_001
 * @tc.type: FUNC
 * @tc.desc: Verify HandleImageDataStateAdded when ReadParcelable returns nullptr.
 */
HWTEST_F(FmsFormProviderDataTest, HandleImageDataStateAdded_NullAshmem_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleImageDataStateAdded_NullAshmem_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(1);
    parcel.WriteParcelable(nullptr);
    bool result = formProviderData.HandleImageDataStateAdded(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "HandleImageDataStateAdded_NullAshmem_001 end";
}

/**
 * @tc.name: ConvertRawImageData_EmptyMap_001
 * @tc.type: FUNC
 * @tc.desc: Verify ConvertRawImageData with empty rawImageBytesMap_.
 */
HWTEST_F(FmsFormProviderDataTest, ConvertRawImageData_EmptyMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConvertRawImageData_EmptyMap_001 start";
    FormProviderData formProviderData("");
    bool result = formProviderData.ConvertRawImageData();
    EXPECT_TRUE(result);
    EXPECT_TRUE(formProviderData.GetImageDataMap().empty());
    GTEST_LOG_(INFO) << "ConvertRawImageData_EmptyMap_001 end";
}

/**
 * @tc.name: IsValidSize_ZeroSize_001
 * @tc.type: FUNC
 * @tc.desc: Verify isValidSize with zero size.
 */
HWTEST_F(FmsFormProviderDataTest, IsValidSize_ZeroSize_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidSize_ZeroSize_001 start";
    FormProviderData formProviderData("");
    EXPECT_FALSE(formProviderData.isValidSize(0));
    GTEST_LOG_(INFO) << "IsValidSize_ZeroSize_001 end";
}

/**
 * @tc.name: IsValidSize_NegativeSize_002
 * @tc.type: FUNC
 * @tc.desc: Verify isValidSize with negative size.
 */
HWTEST_F(FmsFormProviderDataTest, IsValidSize_NegativeSize_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidSize_NegativeSize_002 start";
    FormProviderData formProviderData("");
    EXPECT_FALSE(formProviderData.isValidSize(-1));
    EXPECT_FALSE(formProviderData.isValidSize(-100));
    GTEST_LOG_(INFO) << "IsValidSize_NegativeSize_002 end";
}

/**
 * @tc.name: ParseImagesData_NonIntegerFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify ParseImagesData when fd in json is not integer.
 */
HWTEST_F(FmsFormProviderDataTest, ParseImagesData_NonIntegerFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseImagesData_NonIntegerFd_001 start";
    std::string jsonStr = R"({"formImages": {"image1": "not_an_integer"}})";
    FormProviderData formProviderData(jsonStr);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "ParseImagesData_NonIntegerFd_001 end";
}

/**
 * @tc.name: ReadFromParcel_BigDataNullRawData_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel when ReadAshmemDataFromParcel returns nullptr for big data.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_BigDataNullRawData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_BigDataNullRawData_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(35000);
    parcel.WriteParcelable(nullptr);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_BigDataNullRawData_001 end";
}

/**
 * @tc.name: Marshalling_WriteImageDataFailed_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling with invalid image data state.
 */
HWTEST_F(FmsFormProviderDataTest, Marshalling_WriteImageDataFailed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_WriteImageDataFailed_001 start";
    FormProviderData formProviderData("");
    std::shared_ptr<char> validData = std::make_shared<char>('a');
    formProviderData.AddImageData("test", validData, 1);
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_NO_OPERATION;
    Parcel parcel;
    bool result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_WriteImageDataFailed_001 end";
}

/**
 * @tc.name: MergeData_EmptyAddData_002
 * @tc.type: FUNC
 * @tc.desc: Verify MergeData when addJsonData is empty.
 */
HWTEST_F(FmsFormProviderDataTest, MergeData_EmptyAddData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MergeData_EmptyAddData_002 start";
    FormProviderData formProviderData("{\"key\": \"value\"}");
    nlohmann::json emptyJson;
    formProviderData.MergeData(emptyJson);
    EXPECT_FALSE(formProviderData.jsonFormProviderData_.empty());
    EXPECT_EQ(formProviderData.jsonFormProviderData_["key"], "value");
    GTEST_LOG_(INFO) << "MergeData_EmptyAddData_002 end";
}

/**
 * @tc.name: ReadFileDescriptor_NullDescriptor_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFileDescriptor when ReadObject returns nullptr.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFileDescriptor_NullDescriptor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFileDescriptor_NullDescriptor_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteParcelable(nullptr);
    int fd = formProviderData.ReadFileDescriptor(parcel);
    EXPECT_EQ(fd, -1);
    GTEST_LOG_(INFO) << "ReadFileDescriptor_NullDescriptor_001 end";
}

/**
 * @tc.name: SetImageDataMap_EmptyMap_002
 * @tc.type: FUNC
 * @tc.desc: Verify SetImageDataMap with empty map sets imageDataState to NO_OPERATION.
 */
HWTEST_F(FmsFormProviderDataTest, SetImageDataMap_EmptyMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetImageDataMap_EmptyMap_002 start";
    FormProviderData formProviderData("");
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> emptyMap;
    formProviderData.SetImageDataMap(emptyMap);
    EXPECT_EQ(formProviderData.imageDataState_, FormProviderData::IMAGE_DATA_STATE_NO_OPERATION);
    GTEST_LOG_(INFO) << "SetImageDataMap_EmptyMap_002 end";
}

/**
 * @tc.name: SetImageDataMap_NonEmptyMap_002
 * @tc.type: FUNC
 * @tc.desc: Verify SetImageDataMap with non-empty map sets imageDataState to ADDED.
 */
HWTEST_F(FmsFormProviderDataTest, SetImageDataMap_NonEmptyMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetImageDataMap_NonEmptyMap_002 start";
    FormProviderData formProviderData("");
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> nonEmptyMap;
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    nonEmptyMap["test"] = std::make_pair(formAshmem, 10);
    formProviderData.SetImageDataMap(nonEmptyMap);
    EXPECT_EQ(formProviderData.imageDataState_, FormProviderData::IMAGE_DATA_STATE_ADDED);
    GTEST_LOG_(INFO) << "SetImageDataMap_NonEmptyMap_002 end";
}

/**
 * @tc.name: CheckAshmemSize_InvalidFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify CheckAshmemSize with invalid fd.
 */
HWTEST_F(FmsFormProviderDataTest, CheckAshmemSize_InvalidFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAshmemSize_InvalidFd_001 start";
    int fd = -1;
    int32_t bufferSize = 1024;
    bool isAstc = false;
    bool result = FormProviderData::CheckAshmemSize(fd, bufferSize, isAstc);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "CheckAshmemSize_InvalidFd_001 end";
}

/**
 * @tc.name: Constructor_WithIsUsedInFRS_002
 * @tc.type: FUNC
 * @tc.desc: Verify constructor with isUsedInFRS=true (should not call ParseImagesData).
 */
HWTEST_F(FmsFormProviderDataTest, Constructor_WithIsUsedInFRS_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Constructor_WithIsUsedInFRS_002 start";
    std::string jsonStr = R"({"formImages": {"image1": 1}})";
    FormProviderData formProviderData(jsonStr, true);
    EXPECT_FALSE(formProviderData.jsonFormProviderData_.empty());
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "Constructor_WithIsUsedInFRS_002 end";
}

/**
 * @tc.name: WriteAshmemDataToParcel_LargeData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteAshmemDataToParcel with large data (100KB).
 */
HWTEST_F(FmsFormProviderDataTest, WriteAshmemDataToParcel_LargeData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteAshmemDataToParcel_LargeData_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    std::string largeData(100 * 1024, 'B');
    const char* dataPtr = largeData.c_str();
    size_t size = largeData.length();
    bool result = formProviderData.WriteAshmemDataToParcel(parcel, size, dataPtr);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteAshmemDataToParcel_LargeData_001 end";
}

/**
 * @tc.name: AddImageData_ValidFd_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData with valid file descriptor and small file.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_ValidFd_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_ValidFd_001 start";
    FormProviderData formProviderData("");
    std::string picName = "validImage";
    std::string testData = "test image data content";
    std::string testFile = "/data/formmgr/test_valid_image_001.tmp";
    std::ofstream file(testFile);
    file << testData;
    file.close();
    int fd = open(testFile.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    formProviderData.AddImageData(picName, fd);
    close(fd);
    unlink(testFile.c_str());
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) != formProviderData.rawImageBytesMap_.end());
    EXPECT_EQ(formProviderData.rawImageBytesMap_[picName].second, static_cast<int32_t>(testData.length()));
    EXPECT_EQ(formProviderData.imageDataState_, FormProviderData::IMAGE_DATA_STATE_ADDED);
    GTEST_LOG_(INFO) << "AddImageData_ValidFd_001 end";
}

/**
 * @tc.name: ReadFromParcel_InvalidJsonString_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with invalid json string in parcel.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_InvalidJsonString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_InvalidJsonString_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(15);
    parcel.WriteString16(Str8ToStr16("{invalid json}"));
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_InvalidJsonString_001 end";
}

/**
 * @tc.name: ConvertRawImageData_MultiImages_001
 * @tc.type: FUNC
 * @tc.desc: Verify ConvertRawImageData with multiple images in rawImageBytesMap_.
 */
HWTEST_F(FmsFormProviderDataTest, ConvertRawImageData_MultiImages_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConvertRawImageData_MultiImages_001 start";
    FormProviderData formProviderData("");
    std::shared_ptr<char> data1 = std::shared_ptr<char>(new char[10], std::default_delete<char[]>());
    std::shared_ptr<char> data2 = std::shared_ptr<char>(new char[20], std::default_delete<char[]>());
    formProviderData.AddImageData("image1", data1, 10);
    formProviderData.AddImageData("image2", data2, 20);
    EXPECT_EQ(2, static_cast<int>(formProviderData.rawImageBytesMap_.size()));
    bool result = formProviderData.ConvertRawImageData();
    EXPECT_TRUE(result);
    EXPECT_EQ(2, static_cast<int>(formProviderData.GetImageDataMap().size()));
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "ConvertRawImageData_MultiImages_001 end";
}

/**
 * @tc.name: ClearData_WithJsonData_001
 * @tc.type: FUNC
 * @tc.desc: Verify ClearData clears jsonFormProviderData_.
 */
HWTEST_F(FmsFormProviderDataTest, ClearData_WithJsonData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClearData_WithJsonData_001 start";
    FormProviderData formProviderData("{\"key\": \"value\"}");
    EXPECT_FALSE(formProviderData.jsonFormProviderData_.empty());
    formProviderData.ClearData();
    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    GTEST_LOG_(INFO) << "ClearData_WithJsonData_001 end";
}

/**
 * @tc.name: GetDataString_EmptyJson_002
 * @tc.type: FUNC
 * @tc.desc: Verify GetDataString returns empty string when jsonFormProviderData_ is empty.
 */
HWTEST_F(FmsFormProviderDataTest, GetDataString_EmptyJson_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetDataString_EmptyJson_002 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    std::string result = formProviderData.GetDataString();
    EXPECT_TRUE(result.empty());
    GTEST_LOG_(INFO) << "GetDataString_EmptyJson_002 end";
}

/**
 * @tc.name: HasData_EmptyData_002
 * @tc.type: FUNC
 * @tc.desc: Verify HasData returns false when both jsonFormProviderData_ and imageDataMap_ are empty.
 */
HWTEST_F(FmsFormProviderDataTest, HasData_EmptyData_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HasData_EmptyData_002 start";
    FormProviderData formProviderData("");
    formProviderData.jsonFormProviderData_.clear();
    EXPECT_FALSE(formProviderData.HasData());
    GTEST_LOG_(INFO) << "HasData_EmptyData_002 end";
}

/**
 * @tc.name: UpdateData_WithNewJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify UpdateData replaces old json data with new json data.
 */
HWTEST_F(FmsFormProviderDataTest, UpdateData_WithNewJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateData_WithNewJson_001 start";
    nlohmann::json oldJson;
    oldJson["old"] = "value";
    FormProviderData formProviderData(oldJson);
    nlohmann::json newJson;
    newJson["new"] = "data";
    formProviderData.UpdateData(newJson);
    auto data = formProviderData.GetData();
    EXPECT_EQ(data["new"], "data");
    EXPECT_TRUE(data.find("old") == data.end());
    GTEST_LOG_(INFO) << "UpdateData_WithNewJson_001 end";
}

/**
 * @tc.name: RemoveImageData_ExistingImage_001
 * @tc.type: FUNC
 * @tc.desc: Verify RemoveImageData removes existing image from rawImageBytesMap_.
 */
HWTEST_F(FmsFormProviderDataTest, RemoveImageData_ExistingImage_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveImageData_ExistingImage_001 start";
    FormProviderData formProviderData("");
    std::shared_ptr<char> data = std::make_shared<char>('a');
    formProviderData.AddImageData("toRemove", data, 1);
    EXPECT_EQ(1, formProviderData.rawImageBytesMap_.size());
    formProviderData.RemoveImageData("toRemove");
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "RemoveImageData_ExistingImage_001 end";
}

/**
 * @tc.name: WriteImageDataToParcel_ValidData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteImageDataToParcel with valid image data.
 */
HWTEST_F(FmsFormProviderDataTest, WriteImageDataToParcel_ValidData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteImageDataToParcel_ValidData_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    std::string picName = "validImage";
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[100], std::default_delete<char[]>());
    memset(data.get(), 'A', 100);
    bool result = formProviderData.WriteImageDataToParcel(parcel, picName, data, 100);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteImageDataToParcel_ValidData_001 end";
}

/**
 * @tc.name: WriteImageDataToParcel_EmptyData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteImageDataToParcel with empty data (size=1).
 */
HWTEST_F(FmsFormProviderDataTest, WriteImageDataToParcel_EmptyData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteImageDataToParcel_EmptyData_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    std::string picName = "emptyImage";
    std::shared_ptr<char> data = std::shared_ptr<char>(new char[1], std::default_delete<char[]>());
    data.get()[0] = '\0';
    bool result = formProviderData.WriteImageDataToParcel(parcel, picName, data, 1);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteImageDataToParcel_EmptyData_001 end";
}

/**
 * @tc.name: ReadFromParcel_ImageDataStateAdded_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with IMAGE_DATA_STATE_ADDED and zero imageDataNum.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_ImageDataStateAdded_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataStateAdded_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString16(Str8ToStr16("{}"));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(0);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataStateAdded_001 end";
}

/**
 * @tc.name: Marshalling_WithDefaultState_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling with default imageDataState_ (NO_OPERATION).
 */
HWTEST_F(FmsFormProviderDataTest, Marshalling_WithDefaultState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_WithDefaultState_001 start";
    FormProviderData formProviderData("{\"key\": \"value\"}");
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_NO_OPERATION;
    Parcel parcel;
    bool result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_WithDefaultState_001 end";
}

/**
 * @tc.name: Marshalling_WithRemovedState_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling with IMAGE_DATA_STATE_REMOVED.
 */
HWTEST_F(FmsFormProviderDataTest, Marshalling_WithRemovedState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_WithRemovedState_001 start";
    FormProviderData formProviderData("{\"key\": \"value\"}");
    formProviderData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_REMOVED;
    Parcel parcel;
    bool result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_WithRemovedState_001 end";
}

/**
 * @tc.name: WriteFormData_BigData_001
 * @tc.type: FUNC
 * @tc.desc: Verify WriteFormData with big data (> BIG_DATA) uses ashmem.
 */
HWTEST_F(FmsFormProviderDataTest, WriteFormData_BigData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteFormData_BigData_001 start";
    std::string bigJsonStr = R"({"data": ")" + std::string(35000, 'C') + R"("})";
    FormProviderData formProviderData(bigJsonStr);
    Parcel parcel;
    bool result = formProviderData.WriteFormData(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "WriteFormData_BigData_001 end";
}

/**
 * @tc.name: AddImageData_NullData_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData with null shared_ptr data.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_NullData_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_NullData_001 start";
    FormProviderData formProviderData("");
    std::string picName = "nullDataImage";
    std::shared_ptr<char> nullData = nullptr;
    formProviderData.AddImageData(picName, nullData, 10);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(picName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "AddImageData_NullData_001 end";
}

/**
 * @tc.name: AddImageData_EmptyPicName_001
 * @tc.type: FUNC
 * @tc.desc: Verify AddImageData with empty picName.
 */
HWTEST_F(FmsFormProviderDataTest, AddImageData_EmptyPicName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddImageData_EmptyPicName_001 start";
    FormProviderData formProviderData("");
    std::string emptyPicName = "";
    std::shared_ptr<char> data = std::make_shared<char>('a');
    formProviderData.AddImageData(emptyPicName, data, 1);
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.find(emptyPicName) == formProviderData.rawImageBytesMap_.end());
    GTEST_LOG_(INFO) << "AddImageData_EmptyPicName_001 end";
}

/**
 * @tc.name: ParseImagesData_NoFormImages_001
 * @tc.type: FUNC
 * @tc.desc: Verify ParseImagesData when json does not contain formImages key.
 */
HWTEST_F(FmsFormProviderDataTest, ParseImagesData_NoFormImages_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseImagesData_NoFormImages_001 start";
    std::string jsonStr = R"({"key": "value"})";
    FormProviderData formProviderData(jsonStr);
    formProviderData.ParseImagesData();
    EXPECT_TRUE(formProviderData.rawImageBytesMap_.empty());
    GTEST_LOG_(INFO) << "ParseImagesData_NoFormImages_001 end";
}

/**
 * @tc.name: SetImageDataState_CustomValue_001
 * @tc.type: FUNC
 * @tc.desc: Verify SetImageDataState sets custom value.
 */
HWTEST_F(FmsFormProviderDataTest, SetImageDataState_CustomValue_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetImageDataState_CustomValue_001 start";
    FormProviderData formProviderData("");
    constexpr int32_t customValue = 999;
    formProviderData.SetImageDataState(customValue);
    EXPECT_EQ(customValue, formProviderData.GetImageDataState());
    GTEST_LOG_(INFO) << "SetImageDataState_CustomValue_001 end";
}

/**
 * @tc.name: GetImageDataMap_Empty_001
 * @tc.type: FUNC
 * @tc.desc: Verify GetImageDataMap returns empty map when no images.
 */
HWTEST_F(FmsFormProviderDataTest, GetImageDataMap_Empty_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetImageDataMap_Empty_001 start";
    FormProviderData formProviderData("");
    auto imageMap = formProviderData.GetImageDataMap();
    EXPECT_TRUE(imageMap.empty());
    GTEST_LOG_(INFO) << "GetImageDataMap_Empty_001 end";
}

/**
 * @tc.name: GetImageDataState_Default_001
 * @tc.type: FUNC
 * @tc.desc: Verify GetImageDataState returns default value (0).
 */
HWTEST_F(FmsFormProviderDataTest, GetImageDataState_Default_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetImageDataState_Default_001 start";
    FormProviderData formProviderData("");
    EXPECT_EQ(0, formProviderData.GetImageDataState());
    GTEST_LOG_(INFO) << "GetImageDataState_Default_001 end";
}

/**
 * @tc.name: Unmarshalling_ValidParcel_001
 * @tc.type: FUNC
 * @tc.desc: Verify Unmarshalling creates valid FormProviderData from parcel.
 */
HWTEST_F(FmsFormProviderDataTest, Unmarshalling_ValidParcel_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unmarshalling_ValidParcel_001 start";
    FormProviderData writeProviderData("{\"key\": \"value\"}");
    Parcel parcel;
    EXPECT_TRUE(writeProviderData.Marshalling(parcel));
    FormProviderData* readProviderData = FormProviderData::Unmarshalling(parcel);
    ASSERT_NE(readProviderData, nullptr);
    EXPECT_FALSE(readProviderData->GetData().empty());
    delete readProviderData;
    GTEST_LOG_(INFO) << "Unmarshalling_ValidParcel_001 end";
}

/**
 * @tc.name: Constructor_NullJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify constructor with nullptr json.
 */
HWTEST_F(FmsFormProviderDataTest, Constructor_NullJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Constructor_NullJson_001 start";
    nlohmann::json jsonNull = nullptr;
    FormProviderData formProviderData(jsonNull);
    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    GTEST_LOG_(INFO) << "Constructor_NullJson_001 end";
}

/**
 * @tc.name: Constructor_StringJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify constructor with string type json.
 */
HWTEST_F(FmsFormProviderDataTest, Constructor_StringJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Constructor_StringJson_001 start";
    nlohmann::json jsonString = "test string";
    FormProviderData formProviderData(jsonString);
    EXPECT_TRUE(formProviderData.jsonFormProviderData_.empty());
    GTEST_LOG_(INFO) << "Constructor_StringJson_001 end";
}

/**
 * @tc.name: ReadFromParcel_ImageDataStateRemoved_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with IMAGE_DATA_STATE_REMOVED.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_ImageDataStateRemoved_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataStateRemoved_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString16(Str8ToStr16("{}"));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_REMOVED);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataStateRemoved_001 end";
}

/**
 * @tc.name: ReadFromParcel_UnknownImageDataState_001
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel with unknown imageDataState value.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_UnknownImageDataState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_UnknownImageDataState_001 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString16(Str8ToStr16("{}"));
    parcel.WriteInt32(999);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_UnknownImageDataState_001 end";
}

/**
 * @tc.name: Marshalling_UnknownImageDataState_001
 * @tc.type: FUNC
 * @tc.desc: Verify Marshalling with unknown imageDataState value.
 */
HWTEST_F(FmsFormProviderDataTest, Marshalling_UnknownImageDataState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_UnknownImageDataState_001 start";
    FormProviderData formProviderData("{\"key\": \"value\"}");
    formProviderData.imageDataState_ = 999;
    Parcel parcel;
    bool result = formProviderData.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_UnknownImageDataState_001 end";
}

/**
 * @tc.name: ReadFromParcel_ImageDataNumExceed_002
 * @tc.type: FUNC
 * @tc.desc: Verify ReadFromParcel when imageDataNum exceeds READ_PARCEL_MAX_IMAGE_DATA_NUM_SIZE.
 */
HWTEST_F(FmsFormProviderDataTest, ReadFromParcel_ImageDataNumExceed_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataNumExceed_002 start";
    FormProviderData formProviderData("");
    Parcel parcel;
    parcel.WriteInt32(2);
    parcel.WriteString16(Str8ToStr16("{}"));
    parcel.WriteInt32(FormProviderData::IMAGE_DATA_STATE_ADDED);
    parcel.WriteInt32(1001);
    bool result = formProviderData.ReadFromParcel(parcel);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "ReadFromParcel_ImageDataNumExceed_002 end";
}

}  // namespace OHOS::AppExecFwk
