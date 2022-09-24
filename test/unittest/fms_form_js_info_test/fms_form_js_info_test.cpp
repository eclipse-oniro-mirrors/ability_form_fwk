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

#include "form_js_info.h"
#include "hilog_wrapper.h"
#include "nlohmann/json.hpp"

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
    // mock GetImageDataMap size is 130
    MockGetImageDataMap(true);
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
} // namespace AppExecFwk
} // namespace OHOS
