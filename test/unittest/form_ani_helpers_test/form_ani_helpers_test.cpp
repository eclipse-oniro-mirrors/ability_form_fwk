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
 
#include <gtest/gtest.h>
#include "ani_helpers.h"
#include <string>
#include <climits>

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
namespace AniHelpersTest {

using namespace OHOS::AbilityRuntime::FormAniHelpers;

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test to handle empty string
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesEmptyString, TestSize.Level1)
{
    int64_t result;
    EXPECT_TRUE(ConvertStringToInt64("", result));
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test to handle zero value
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesZero, TestSize.Level1)
{
    int64_t result;
    EXPECT_TRUE(ConvertStringToInt64("0", result));
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test positive formID values
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesPositiveNumbers, TestSize.Level1)
{
    int64_t result;
    EXPECT_TRUE(ConvertStringToInt64("1", result));
    EXPECT_EQ(result, 1);
    
    EXPECT_TRUE(ConvertStringToInt64("123", result));
    EXPECT_EQ(result, 123);
    
    EXPECT_TRUE(ConvertStringToInt64("123456789", result));
    EXPECT_EQ(result, 123456789);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test negative formID values
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesNegativeNumbers, TestSize.Level1)
{
    int64_t result;
    EXPECT_TRUE(ConvertStringToInt64("-1", result));
    EXPECT_EQ(result, -1);
    
    EXPECT_TRUE(ConvertStringToInt64("-123", result));
    EXPECT_EQ(result, -123);
    
    EXPECT_TRUE(ConvertStringToInt64("-123456789", result));
    EXPECT_EQ(result, -123456789);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test maximum 64 bit integer formID value
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesMaxInt64, TestSize.Level1)
{
    int64_t result;
    std::string maxInt64Str = "9223372036854775807"; // INT64_MAX
    EXPECT_TRUE(ConvertStringToInt64(maxInt64Str, result));
    EXPECT_EQ(result, INT64_MAX);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test minimum 64 bit integer formID value
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, HandlesMinInt64, TestSize.Level1)
{
    int64_t result;
    std::string minInt64Str = "-9223372036854775808"; // INT64_MIN
    EXPECT_TRUE(ConvertStringToInt64(minInt64Str, result));
    EXPECT_EQ(result, INT64_MIN);
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test to hande too big values
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, RejectsNumbersAboveMaxInt64, TestSize.Level1)
{
    int64_t result;
    EXPECT_FALSE(ConvertStringToInt64("9223372036854775808", result)); // INT64_MAX + 1
    EXPECT_FALSE(ConvertStringToInt64("9999999999999999999", result));
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test to hande the values shorter than int64
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, RejectsNumbersBelowMinInt64, TestSize.Level1)
{
    int64_t result;
    EXPECT_FALSE(ConvertStringToInt64("-9223372036854775809", result)); // INT64_MIN - 1
    EXPECT_FALSE(ConvertStringToInt64("-9999999999999999999", result));
}

/**
 * @tc.name: ConvertStringToInt64Test_001
 * @tc.desc: Test to reject invalid values
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToInt64Test, RejectsInvalidFormats, TestSize.Level1)
{
    int64_t result;
    EXPECT_FALSE(ConvertStringToInt64("abc", result));
    EXPECT_FALSE(ConvertStringToInt64("123abc", result));
    EXPECT_FALSE(ConvertStringToInt64("12.34", result));
    EXPECT_FALSE(ConvertStringToInt64("123 ", result));
    EXPECT_FALSE(ConvertStringToInt64(" 123", result));
    EXPECT_FALSE(ConvertStringToInt64("+123", result)); // Note: function doesn't handle '+'
    EXPECT_FALSE(ConvertStringToInt64("--123", result));
    EXPECT_FALSE(ConvertStringToInt64("-", result));
    EXPECT_FALSE(ConvertStringToInt64("0123", result)); // Leading zeros not allowed
}

/**
 * @tc.name: ConvertStringToIntTest_001
 * @tc.desc: Test to check correct conversions
 * @tc.type: FUNC
 */
HWTEST(ConvertStringToIntTest, BasicConversion, TestSize.Level1)
{
    EXPECT_EQ(ConvertStringToInt("0"), 0);
    EXPECT_EQ(ConvertStringToInt("123"), 123);
    EXPECT_EQ(ConvertStringToInt("-456"), -456);
    EXPECT_EQ(ConvertStringToInt("999999"), 999999);
}
}
}
}