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
#include "hilog_wrapper.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string FORM_DB_DATA_BASE_FILE_DIR = "/data/formmgr";
const int32_t four = 4;
const int32_t ten = 10;
const int32_t eleven = 11;

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
    tmpJson["age"] = ten;
    jsonData_["0"] = tmpJson;
    return true;
}

bool FmsFormProviderDataTest::InitJsonData2()
{
    nlohmann::json tmpJson;
    tmpJson["name"] = "wang";
    tmpJson["age"] = eleven;
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

    f << std::setw(four) << jsonData << std::endl;

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

    f << std::setw(four) << jsonData << std::endl;

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

    f << std::setw(four) << jsonData << std::endl;

    f.close();
    return true;
}

HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_001, TestSize.Level0) // create
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_001 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    EXPECT_EQ(true, CreateJsonFileByJsonData1(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_001 end";
}

HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_002, TestSize.Level0) // test constructor with string
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_002 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_.dump());
    EXPECT_EQ(true, CreateJsonFileByJsonData2(formProviderData.jsonFormProviderData_));
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_002 end";
}

HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_003, TestSize.Level0) // test GetDataString
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_003 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    GTEST_LOG_(INFO) << "print:" <<formProviderData.GetDataString();
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_003 end";
}

HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_004, TestSize.Level0) // test MergeData
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
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_005, TestSize.Level0) // test MergeData
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_005 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
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
HWTEST_F(FmsFormProviderDataTest, FmsFormProviderDataTest_006, TestSize.Level0) // test MergeData
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataTest_006 start";
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    formProviderData.AddImageData(picName, 1);
    Parcel parcel;
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
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
}