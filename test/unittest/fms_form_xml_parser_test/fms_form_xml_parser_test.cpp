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

#include <gtest/gtest.h>
#include <string>

#include "form_mgr_errors.h"
#include "form_xml_parser.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
class FmsFormXMLParserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};


void FmsFormXMLParserTest::SetUpTestCase()
{}

void FmsFormXMLParserTest::TearDownTestCase()
{}

void FmsFormXMLParserTest::SetUp()
{}

void FmsFormXMLParserTest::TearDown()
{}

/**
 * @tc.number: FmsFormXMLParserTest_Parse_001
 * @tc.name: Parse
 * @tc.desc: Verify that the return value is true.(formId is invalid)
 */
HWTEST_F(FmsFormXMLParserTest, FmsFormXMLParserTest_Parse_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormXMLParserTest_Parse_001 start";
    FormXMLParser parser;
    int32_t ret = parser.Parse();
    EXPECT_EQ(ret, ERR_OK);
    const std::map<std::string, int32_t> &configMap = parser.GetConfigMap();
    EXPECT_FALSE(configMap.empty());
    EXPECT_TRUE(configMap.find("maxNormalFormSize") != configMap.end());
    EXPECT_TRUE(configMap.find("maxTempFormSize") != configMap.end());
    EXPECT_TRUE(configMap.find("hostMaxFormSize") != configMap.end());
    GTEST_LOG_(INFO) << "FmsFormXMLParserTest_Parse_001 end";
}
}
