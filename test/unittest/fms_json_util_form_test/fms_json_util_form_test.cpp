/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <stack>
#include <string>

#include "gtest/gtest.h"
#include "json_util_form.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;

namespace OHOS::AppExecFwk {

class FmsJsonUtilFormTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp()
    {
    }
    void TearDown()
    {
    }
};

/**
 * @brief Build a deeply nested JSON object string of the form
 *        {"data":[[[...N layers...]]]} for depth-limit tests.
 * @param depth number of nested array layers (>= 1).
 * @return JSON string with specified nesting depth.
 */
static std::string GenerateDeepNestedJson(int depth)
{
    std::string result;
    constexpr int32_t bracketCharsPerLayer = 2;
    constexpr int32_t fixedJsonOverhead = 16;
    result.reserve(depth * bracketCharsPerLayer + fixedJsonOverhead);
    result.append(R"({"data":)");
    for (int i = 0; i < depth; ++i) {
        result.push_back('[');
    }
    result.append(R"("leaf")");
    for (int i = 0; i < depth; ++i) {
        result.push_back(']');
    }
    result.push_back('}');
    return result;
}

/**
 * @brief Measure the maximum nesting depth of a JSON value (iterative, no stack overflow risk).
 * @param val JSON value to measure.
 * @return Maximum nesting depth (0 for primitives, 1 for single-layer array/object, etc.).
 */
static int JsonNestingDepth(const nlohmann::json &val)
{
    int maxDepth = 0;
    std::stack<std::pair<const nlohmann::json *, int>> stk;
    stk.emplace(&val, 0);
    while (!stk.empty()) {
        auto [node, depth] = stk.top();
        stk.pop();
        if (!node->is_structured()) {
            maxDepth = std::max(maxDepth, depth);
            continue;
        }
        int childDepth = depth + 1;
        maxDepth = std::max(maxDepth, childDepth);
        if (node->is_array()) {
            for (auto &elem : *node) {
                stk.emplace(&elem, childDepth);
            }
        } else {
            for (auto &[key, elem] : node->items()) {
                stk.emplace(&elem, childDepth);
            }
        }
    }
    return maxDepth;
}

/**
 * @tc.name: SafeJsonParse_NormalDepth_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse succeeds for a normal-depth JSON (depth <= 5).
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_NormalDepth_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_NormalDepth_001 start";
    std::string jsonStr = GenerateDeepNestedJson(5);
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("data"));
    EXPECT_TRUE(parsed["data"].is_array());
    EXPECT_EQ(JsonNestingDepth(parsed), 6);
    GTEST_LOG_(INFO) << "SafeJsonParse_NormalDepth_001 end";
}

/**
 * @tc.name: SafeJsonParse_DepthExceed_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns discarded json when depth = MAX_JSON_PARSE_DEPTH + 1.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_DepthExceed_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_DepthExceed_001 start";
    std::string jsonStr = GenerateDeepNestedJson(MAX_JSON_PARSE_DEPTH + 1);
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_DepthExceed_001 end";
}

/**
 * @tc.name: SafeJsonParse_DeepStackOverflow_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns discarded json for an extreme-depth JSON (5000 layers).
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_DeepStackOverflow_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_DeepStackOverflow_001 start";
    constexpr int32_t extremeDepth = 5000;
    std::string jsonStr = GenerateDeepNestedJson(extremeDepth);
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_DeepStackOverflow_001 end";
}

/**
 * @tc.name: SafeJsonParse_EmptyString_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns a discarded value for an empty input string.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_EmptyString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_EmptyString_001 start";
    nlohmann::json parsed = SafeJsonParse(std::string());
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_EmptyString_001 end";
}

/**
 * @tc.name: SafeJsonParse_InvalidJson_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns a discarded value for an invalid JSON string.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_InvalidJson_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_InvalidJson_001 start";
    nlohmann::json parsed = SafeJsonParse(std::string("{invalid json}"));
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_InvalidJson_001 end";
}

/**
 * @tc.name: SafeJsonParse_BracketsInStringValue_001
 * @tc.type: FUNC
 * @tc.desc: Verify pre-scan does not count brackets inside JSON string values as nesting depth.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_BracketsInStringValue_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_BracketsInStringValue_001 start";
    std::string bracketsInside;
    for (int i = 0; i < 200; ++i) {
        bracketsInside.push_back('[');
    }
    bracketsInside.append("leaf");
    for (int i = 0; i < 200; ++i) {
        bracketsInside.push_back(']');
    }
    std::string jsonStr = "{\"text\": \"" + bracketsInside + "\"}";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("text"));
    EXPECT_TRUE(parsed["text"].is_string());
    EXPECT_EQ(JsonNestingDepth(parsed), 1);
    GTEST_LOG_(INFO) << "SafeJsonParse_BracketsInStringValue_001 end";
}

/**
 * @tc.name: SafeJsonParse_EscapedQuotesInString_001
 * @tc.type: FUNC
 * @tc.desc: Verify escaped quotes in string values do not affect bracket depth scanning.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_EscapedQuotesInString_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_EscapedQuotesInString_001 start";
    std::string jsonStr = R"({"key":"val\"ue[[[[[[[]]]]]]"})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("key"));
    EXPECT_TRUE(parsed["key"].is_string());
    EXPECT_EQ(JsonNestingDepth(parsed), 1);
    GTEST_LOG_(INFO) << "SafeJsonParse_EscapedQuotesInString_001 end";
}

/**
 * @tc.name: SafeJsonParse_AllowExceptionsTrue_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse with allowExceptions=true succeeds for shallow JSON
 *           and returns discarded for over-limit depth without throwing.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_AllowExceptionsTrue_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_AllowExceptionsTrue_001 start";
    std::string shallowJson = GenerateDeepNestedJson(5);
    nlohmann::json parsed = SafeJsonParse(shallowJson, true);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("data"));
    std::string overLimitJson = GenerateDeepNestedJson(MAX_JSON_PARSE_DEPTH + 1);
    nlohmann::json parsedOver = SafeJsonParse(overLimitJson, true);
    EXPECT_TRUE(parsedOver.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_AllowExceptionsTrue_001 end";
}

/**
 * @tc.name: SafeJsonParse_WhitespaceOnly_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns discarded for a whitespace-only input string.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_WhitespaceOnly_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_WhitespaceOnly_001 start";
    nlohmann::json parsed = SafeJsonParse(std::string("   \n\t  "));
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_WhitespaceOnly_001 end";
}

/**
 * @tc.name: SafeJsonParse_NullByteString_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse handles a string containing an embedded null byte gracefully.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_NullByteString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_NullByteString_001 start";
    nlohmann::json parsed = SafeJsonParse(std::string("abc\0def", 7));
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_NullByteString_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_UnmatchedOpenBrackets_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse with unmatched open brackets returns discarded because
 *           IsJsonDepthSafe returns false (unbalanced brackets).
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_UnmatchedOpenBrackets_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnmatchedOpenBrackets_001 start";
    std::string jsonStr = R"({{{"key":1}})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnmatchedOpenBrackets_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_UnmatchedCloseBrackets_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse with unmatched close brackets returns discarded because
 *           IsJsonDepthSafe returns false (currentDepth < 0).
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_UnmatchedCloseBrackets_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnmatchedCloseBrackets_001 start";
    std::string jsonStr = R"({"key":1}}})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnmatchedCloseBrackets_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_BackslashOutsideString_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse with a backslash outside a string does not trigger escape handling;
 *           nlohmann parse fails.
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_BackslashOutsideString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_BackslashOutsideString_001 start";
    std::string jsonStr = R"(\{"key":1})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_BackslashOutsideString_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_MixedArrayObjectNesting_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse succeeds with mixed array and object nesting.
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_MixedArrayObjectNesting_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_MixedArrayObjectNesting_001 start";
    std::string jsonStr = R"({"data": [{"key": [{"inner": 1}]}]})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("data"));
    // Depth: object(1) -> array(2) -> object(3) -> array(4) -> object(5) = 5
    int depth = JsonNestingDepth(parsed);
    EXPECT_EQ(depth, 5);
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_MixedArrayObjectNesting_001 end";
}

/**
 * @tc.name: SafeJsonParse_AllowExceptionsFalse_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse with allowExceptions=false (default) succeeds for shallow JSON.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_AllowExceptionsFalse_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_AllowExceptionsFalse_001 start";
    std::string shallowJson = GenerateDeepNestedJson(5);
    nlohmann::json parsed = SafeJsonParse(shallowJson, false);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.contains("data"));
    GTEST_LOG_(INFO) << "SafeJsonParse_AllowExceptionsFalse_001 end";
}

/**
 * @tc.name: SafeJsonParse_DeepValidButParseFails_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse returns discarded for JSON that passes depth scan but is invalid.
 *           [1,2,] has trailing comma (invalid JSON), depth=1.
 */
HWTEST_F(FmsJsonUtilFormTest, SafeJsonParse_DeepValidButParseFails_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SafeJsonParse_DeepValidButParseFails_001 start";
    std::string jsonStr = "[1,2,]";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "SafeJsonParse_DeepValidButParseFails_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_NegativeDepthRecovery_001
 * @tc.type: FUNC
 * @tc.desc: Verify close-brackets before open-brackets cause IsJsonDepthSafe to
 *           return false immediately, preventing negative-depth "recovery".
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_NegativeDepthRecovery_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_NegativeDepthRecovery_001 start";
    std::string jsonStr = R"(}}{"key":1})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_NegativeDepthRecovery_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_UnclosedBracket_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse rejects JSON with unclosed brackets;
 *           IsJsonDepthSafe returns false (currentDepth != 0 at end of scan).
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_UnclosedBracket_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnclosedBracket_001 start";
    std::string jsonStr = R"({"key":"value")";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnclosedBracket_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_EscapeNonQuoteChar_001
 * @tc.type: FUNC
 * @tc.desc: Verify escaped non-quote characters (\t, \n) inside a string
 *           are consumed by escapeNext and do not affect bracket depth.
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_EscapeNonQuoteChar_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_EscapeNonQuoteChar_001 start";
    std::string jsonStr = R"({"key":"val\tue"})";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_FALSE(parsed.is_discarded());
    EXPECT_TRUE(parsed.is_object());
    EXPECT_TRUE(parsed.contains("key"));
    EXPECT_TRUE(parsed["key"].is_string());
    EXPECT_EQ(JsonNestingDepth(parsed), 1);
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_EscapeNonQuoteChar_001 end";
}

/**
 * @tc.name: IsJsonDepthSafe_UnclosedString_001
 * @tc.type: FUNC
 * @tc.desc: Verify SafeJsonParse rejects JSON with an unclosed string
 *           (inString=true at end of scan).
 */
HWTEST_F(FmsJsonUtilFormTest, IsJsonDepthSafe_UnclosedString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnclosedString_001 start";
    std::string jsonStr = R"({"key":"value)";
    nlohmann::json parsed = SafeJsonParse(jsonStr);
    EXPECT_TRUE(parsed.is_discarded());
    GTEST_LOG_(INFO) << "IsJsonDepthSafe_UnclosedString_001 end";
}

}  // namespace OHOS::AppExecFwk
