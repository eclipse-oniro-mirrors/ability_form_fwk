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

#include "jsonutilform_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "json_util_form.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
// Input bounds for fuzzer data generation
constexpr int32_t FUZZ_MAX_LENGTH = 256;
constexpr int32_t FUZZ_MAX_NUM = 10000;
constexpr int32_t FUZZ_MIN_NUM = -10000;
constexpr int32_t FUZZ_KEY_MAX_LEN = 16;
constexpr int32_t FUZZ_SHORT_KEY_LEN = 8;
constexpr int32_t FUZZ_STR_VAL_MAX_LEN = 32;
constexpr int32_t FUZZ_ARRAY_LEN_MAX = 10;
constexpr int32_t FUZZ_DEEP_DEPTH_MAX = 200;
constexpr int32_t FUZZ_BRACKET_COUNT_MAX = 50;
constexpr int32_t FUZZ_MIXED_LEVELS_MAX = 30;
constexpr int32_t FUZZ_PATTERN_TYPE_MAX = 4;
constexpr int32_t FUZZ_ESCAPE_CHAR_MAX = 5;
// Reserve calculation constants
constexpr int32_t RESERVE_GROWTH_DIVISOR = 4;
constexpr int32_t BRACES_PER_LEVEL = 2;
constexpr int32_t MAX_ESCAPE_BYTES_PER_CHAR = 2;
constexpr int32_t JSON_KEYVAL_OVERHEAD = 4;
constexpr int32_t MAX_DIGITS_PER_NUM_ELEMENT = 8;
constexpr int32_t JSON_BRACKET_OVERHEAD = 2;
constexpr int32_t HEX_HIGH_NIBBLE_POS = 2;
constexpr int32_t HEX_LOW_NIBBLE_POS = 3;
constexpr int32_t HEX_NIBBLE_BITS = 4;

enum FuzzPatternType : int32_t {
    PATTERN_RANDOM = 0,
    PATTERN_DEEP_NESTED = 1,
    PATTERN_UNBALANCED = 2,
    PATTERN_ESCAPE_SEQ = 3,
    PATTERN_MIXED_NESTING = 4,
};

enum EscapeCharIndex : int32_t {
    ESC_QUOTE = 0,
    ESC_BACKSLASH = 1,
    ESC_NEWLINE = 2,
    ESC_TAB = 3,
    ESC_RETURN = 4,
    ESC_SLASH = 5,
};

// Append \uXXXX escape for C0 control chars (U+0000..U+001F)
static void AppendDefaultChar(std::string &escaped, unsigned char uc)
{
    if (uc < 0x20) {
        char buf[7] = {'\\', 'u', '0', '0', '0', '0', '\0'};
        buf[HEX_HIGH_NIBBLE_POS] = "0123456789abcdef"[uc >> HEX_NIBBLE_BITS];
        buf[HEX_LOW_NIBBLE_POS] = "0123456789abcdef"[uc & 0x0F];
        escaped.append(buf);
    } else {
        escaped += static_cast<char>(uc);
    }
}

// Escape characters per JSON RFC 8259 § 7
static std::string EscapeJsonString(const std::string &raw)
{
    std::string escaped;
    escaped.reserve(raw.size() + raw.size() / RESERVE_GROWTH_DIVISOR);
    for (unsigned char uc : raw) {
        switch (uc) {
            case '"': {
                escaped.append("\\\"");
                break;
            }
            case '\\': {
                escaped.append("\\\\");
                break;
            }
            case '\b': {
                escaped.append("\\b");
                break;
            }
            case '\f': {
                escaped.append("\\f");
                break;
            }
            case '\n': {
                escaped.append("\\n");
                break;
            }
            case '\r': {
                escaped.append("\\r");
                break;
            }
            case '\t': {
                escaped.append("\\t");
                break;
            }
            default: {
                AppendDefaultChar(escaped, uc);
                break;
            }
        }
    }
    return escaped;
}

static std::string GenRandomFuzzString(FuzzedDataProvider *fdp)
{
    return fdp->ConsumeRandomLengthString(FUZZ_MAX_LENGTH);
}

static std::string GenDeepNestedBrackets(FuzzedDataProvider *fdp)
{
    int32_t depth = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_DEEP_DEPTH_MAX);
    // 2 braces per level + key/val overhead: 2*depth + 2*keyMaxLen + 4
    std::string result;
    result.reserve(static_cast<size_t>(BRACES_PER_LEVEL * depth)
        + BRACES_PER_LEVEL * FUZZ_KEY_MAX_LEN + JSON_KEYVAL_OVERHEAD);
    for (int32_t i = 0; i < depth; i++) {
        result += '{';
    }
    std::string innerKey = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    std::string innerVal = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    result.append("\"")
        .append(EscapeJsonString(innerKey))
        .append("\":\"")
        .append(EscapeJsonString(innerVal))
        .append("\"");
    for (int32_t i = 0; i < depth; i++) {
        result += '}';
    }
    return result;
}

static std::string GenUnbalancedBrackets(FuzzedDataProvider *fdp)
{
    int32_t openCount = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_BRACKET_COUNT_MAX);
    int32_t closeCount = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_BRACKET_COUNT_MAX);
    std::string result;
    result.reserve(static_cast<size_t>(openCount + closeCount));
    for (int32_t i = 0; i < openCount; i++) {
        result += fdp->ConsumeBool() ? '{' : '[';
    }
    for (int32_t i = 0; i < closeCount; i++) {
        result += fdp->ConsumeBool() ? '}' : ']';
    }
    return result;
}

static void AppendEscapeChar(FuzzedDataProvider *fdp, std::string &val)
{
    val += '\\';
    int32_t escIdx = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_ESCAPE_CHAR_MAX);
    switch (escIdx) {
        case ESC_QUOTE: val += '"'; break;
        case ESC_BACKSLASH: val += '\\'; break;
        case ESC_NEWLINE: val += 'n'; break;
        case ESC_TAB: val += 't'; break;
        case ESC_RETURN: val += 'r'; break;
        case ESC_SLASH: val += '/'; break;
        default: val += '"'; break;
    }
}

static std::string GenEscapeSequenceString(FuzzedDataProvider *fdp)
{
    std::string key = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    std::string val;
    int32_t valLen = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_STR_VAL_MAX_LEN);
    // Each escape char is 2 bytes, plain char is 1 byte
    val.reserve(static_cast<size_t>(MAX_ESCAPE_BYTES_PER_CHAR * valLen));
    for (int32_t i = 0; i < valLen; i++) {
        if (fdp->ConsumeBool()) {
            AppendEscapeChar(fdp, val);
        } else {
            val += fdp->ConsumeIntegralInRange<char>('a', 'z');
        }
    }
    std::string json;
    json.append("{\"")
        .append(EscapeJsonString(key))
        .append("\":\"")
        .append(val)
        .append("\"}");
    return json;
}

static std::string GenMixedNestingString(FuzzedDataProvider *fdp)
{
    int32_t levels = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_MIXED_LEVELS_MAX);
    // Per level: 1 bracket + up to (shortKeyLen+3) overhead; closing = levels
    // + leaf value: 2*keyMaxLen + 2
    std::string result;
    result.reserve(static_cast<size_t>(levels) * (FUZZ_SHORT_KEY_LEN + JSON_KEYVAL_OVERHEAD)
        + levels + BRACES_PER_LEVEL * FUZZ_KEY_MAX_LEN + JSON_BRACKET_OVERHEAD);
    std::string openChars;
    for (int32_t i = 0; i < levels; i++) {
        if (fdp->ConsumeBool()) {
            result += '{';
            std::string k = fdp->ConsumeRandomLengthString(FUZZ_SHORT_KEY_LEN);
            result.append("\"")
                .append(EscapeJsonString(k))
                .append("\":");
            openChars += '{';
        } else {
            result += '[';
            openChars += '[';
        }
    }
    std::string leafVal = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    result.append("\"")
        .append(EscapeJsonString(leafVal))
        .append("\"");
    // Close brackets in reverse order to match opening type
    for (int32_t i = static_cast<int32_t>(openChars.size()) - 1; i >= 0; i--) {
        result += (openChars[i] == '{') ? '}' : ']';
    }
    return result;
}

std::string GenerateFuzzedJsonString(FuzzedDataProvider *fdp)
{
    int32_t patternType = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_PATTERN_TYPE_MAX);
    switch (patternType) {
        case PATTERN_RANDOM: return GenRandomFuzzString(fdp);
        case PATTERN_DEEP_NESTED: return GenDeepNestedBrackets(fdp);
        case PATTERN_UNBALANCED: return GenUnbalancedBrackets(fdp);
        case PATTERN_ESCAPE_SEQ: return GenEscapeSequenceString(fdp);
        case PATTERN_MIXED_NESTING: return GenMixedNestingString(fdp);
        default: return fdp->ConsumeRandomLengthString(FUZZ_MAX_LENGTH);
    }
}

static void FuzzSafeJsonParseBasic(FuzzedDataProvider *fdp)
{
    std::string jsonStr1 = GenerateFuzzedJsonString(fdp);
    bool allowExceptions1 = fdp->ConsumeBool();
    SafeJsonParse(jsonStr1, allowExceptions1);

    bool allowExceptions2 = fdp->ConsumeBool();
    SafeJsonParse(std::string(), allowExceptions2);
}

static void FuzzParseInfoFromJsonStr(FuzzedDataProvider *fdp)
{
    std::string parseData = fdp->ConsumeRandomLengthString(FUZZ_MAX_LENGTH);
    std::string parsedStr;
    ParseInfoFromJsonStr<std::string>(parseData.c_str(), parsedStr);
    ParseInfoFromJsonStr<std::string>(nullptr, parsedStr);
}

static std::string BuildJsonKeyValue(const std::string &key, const std::string &value)
{
    std::string json;
    json.append("{\"")
        .append(EscapeJsonString(key))
        .append("\":\"")
        .append(EscapeJsonString(value))
        .append("\"}");
    return json;
}

static std::string BuildJsonKeyBool(const std::string &key, bool value)
{
    std::string json;
    json.append("{\"")
        .append(EscapeJsonString(key))
        .append("\":")
        .append(value ? "true" : "false")
        .append("}");
    return json;
}

static std::string BuildJsonKeyNum(const std::string &key, int32_t value)
{
    std::string json;
    json.append("{\"")
        .append(EscapeJsonString(key))
        .append("\":")
        .append(std::to_string(value))
        .append("}");
    return json;
}

static void FuzzGetValueBool(FuzzedDataProvider *fdp)
{
    std::string key = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    bool boolValue = fdp->ConsumeBool();
    std::string boolKeyJson = BuildJsonKeyBool(key, boolValue);
    auto boolParsed = SafeJsonParse(boolKeyJson, false);
    if (!boolParsed.is_discarded() && boolParsed.is_object()) {
        int32_t parseResult = ERR_OK;
        bool resultBool = false;
        GetValueIfFindKey<bool, bool>(boolParsed, boolParsed.end(), key,
            resultBool, JsonType::BOOLEAN, fdp->ConsumeBool(), parseResult,
            ArrayType::NOT_ARRAY);
    }
}

static void FuzzGetValueNum(FuzzedDataProvider *fdp)
{
    std::string numKey = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    int32_t numValue = fdp->ConsumeIntegralInRange<int32_t>(FUZZ_MIN_NUM, FUZZ_MAX_NUM);
    std::string numKeyJson = BuildJsonKeyNum(numKey, numValue);
    auto numParsed = SafeJsonParse(numKeyJson, false);
    if (!numParsed.is_discarded() && numParsed.is_object()) {
        int32_t parseResult = ERR_OK;
        int32_t resultNum = 0;
        GetValueIfFindKey<int32_t, int32_t>(numParsed, numParsed.end(), numKey,
            resultNum, JsonType::NUMBER, fdp->ConsumeBool(), parseResult,
            ArrayType::NOT_ARRAY);
    }
}

static void FuzzGetValueStr(FuzzedDataProvider *fdp)
{
    std::string strKey = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    std::string strValue = fdp->ConsumeRandomLengthString(FUZZ_MAX_LENGTH);
    std::string strKeyJson = BuildJsonKeyValue(strKey, strValue);
    auto strParsed = SafeJsonParse(strKeyJson, false);
    if (!strParsed.is_discarded() && strParsed.is_object()) {
        int32_t parseResult = ERR_OK;
        std::string resultStr;
        GetValueIfFindKey<std::string, std::string>(strParsed, strParsed.end(), strKey,
            resultStr, JsonType::STRING, fdp->ConsumeBool(), parseResult,
            ArrayType::NOT_ARRAY);
    }
}

static std::string BuildJsonNumArray(FuzzedDataProvider *fdp, const std::string &key)
{
    int32_t arrLen = fdp->ConsumeIntegralInRange<int32_t>(0, FUZZ_ARRAY_LEN_MAX);
    // Per element: up to 7 digits (signed range -10000..10000) + comma
    // + brackets + key overhead
    std::string arrJson;
    arrJson.reserve(MAX_DIGITS_PER_NUM_ELEMENT * static_cast<size_t>(arrLen)
        + JSON_BRACKET_OVERHEAD + BRACES_PER_LEVEL * FUZZ_KEY_MAX_LEN + JSON_KEYVAL_OVERHEAD);
    arrJson += '[';
    for (int32_t i = 0; i < arrLen; i++) {
        arrJson += std::to_string(fdp->ConsumeIntegralInRange<int32_t>(FUZZ_MIN_NUM, FUZZ_MAX_NUM));
        if (i < arrLen - 1) {
            arrJson += ',';
        }
    }
    arrJson += ']';
    std::string json;
    json.append("{\"")
        .append(EscapeJsonString(key))
        .append("\":")
        .append(arrJson)
        .append("}");
    return json;
}

static void FuzzGetValueArr(FuzzedDataProvider *fdp)
{
    std::string arrKey = fdp->ConsumeRandomLengthString(FUZZ_KEY_MAX_LEN);
    std::string arrKeyJson = BuildJsonNumArray(fdp, arrKey);
    auto arrParsed = SafeJsonParse(arrKeyJson, false);
    if (!arrParsed.is_discarded() && arrParsed.is_object()) {
        int32_t parseResult = ERR_OK;
        std::vector<int32_t> resultArr;
        GetValueIfFindKey<std::vector<int32_t>, std::vector<int32_t>>(arrParsed,
            arrParsed.end(), arrKey, resultArr, JsonType::ARRAY,
            fdp->ConsumeBool(), parseResult, ArrayType::NUMBER);
    }
}

static void FuzzGetJsonStrFromInfo(FuzzedDataProvider *fdp)
{
    std::string infoStr = fdp->ConsumeRandomLengthString(FUZZ_MAX_LENGTH);
    GetJsonStrFromInfo<std::string>(infoStr);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FuzzSafeJsonParseBasic(fdp);
    FuzzParseInfoFromJsonStr(fdp);
    FuzzGetValueBool(fdp);
    FuzzGetValueNum(fdp);
    FuzzGetValueStr(fdp);
    FuzzGetValueArr(fdp);
    FuzzGetJsonStrFromInfo(fdp);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
