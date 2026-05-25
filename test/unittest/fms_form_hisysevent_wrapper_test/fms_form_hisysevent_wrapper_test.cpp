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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "errors.h"
#include "hisysevent_c.h"
#define private public
#include "form_hisysevent_wrapper.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *LONG_KEY_NAME = "very_long_key_name_that_exceeds_the_maximum_length_of_param_name_limit";

HiSysEventParam *FindParamByName(std::vector<HiSysEventParam> &params, const std::string &name)
{
    for (auto &param : params) {
        if (std::string(param.name) == name) {
            return &param;
        }
    }
    return nullptr;
}

void VerifyParamCommon(const HiSysEventParam &param, const std::string &key, HiSysEventParamType type)
{
    EXPECT_EQ(std::string(param.name), key);
    EXPECT_EQ(param.t, type);
    EXPECT_EQ(param.arraySize, 0);
}

void VerifyInt8Param(const HiSysEventParam &param, const std::string &key, int8_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_INT8);
    EXPECT_EQ(param.v.i8, expectedValue);
}

void VerifyUint8Param(const HiSysEventParam &param, const std::string &key, uint8_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_UINT8);
    EXPECT_EQ(param.v.ui8, expectedValue);
}

void VerifyInt64Param(const HiSysEventParam &param, const std::string &key, int64_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_INT64);
    EXPECT_EQ(param.v.i64, expectedValue);
}

void VerifyUint64Param(const HiSysEventParam &param, const std::string &key, uint64_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_UINT64);
    EXPECT_EQ(param.v.ui64, expectedValue);
}

void VerifyInt32Param(const HiSysEventParam &param, const std::string &key, int32_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_INT32);
    EXPECT_EQ(param.v.i32, expectedValue);
}

void VerifyUint32Param(const HiSysEventParam &param, const std::string &key, uint32_t expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_UINT32);
    EXPECT_EQ(param.v.ui32, expectedValue);
}

void VerifyBoolParam(const HiSysEventParam &param, const std::string &key, bool expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_BOOL);
    EXPECT_EQ(param.v.b, expectedValue);
}

void VerifyFloatParam(const HiSysEventParam &param, const std::string &key, float expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_FLOAT);
    EXPECT_FLOAT_EQ(param.v.f, expectedValue);
}

void VerifyDoubleParam(const HiSysEventParam &param, const std::string &key, double expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_DOUBLE);
    EXPECT_DOUBLE_EQ(param.v.d, expectedValue);
}

void VerifyStringParam(const HiSysEventParam &param, const std::string &key, const std::string &expectedValue)
{
    VerifyParamCommon(param, key, HISYSEVENT_STRING);
    ASSERT_NE(param.v.s, nullptr);
    EXPECT_EQ(std::string(param.v.s), expectedValue);
}

void VerifyArrayParamCommon(const HiSysEventParam &param, const std::string &key,
    HiSysEventParamType type, size_t expectedSize)
{
    EXPECT_EQ(std::string(param.name), key);
    EXPECT_EQ(param.t, type);
    EXPECT_EQ(static_cast<size_t>(param.arraySize), expectedSize);
    if (expectedSize == 0) {
        EXPECT_EQ(param.v.array, nullptr);
    } else {
        ASSERT_NE(param.v.array, nullptr);
    }
}

void VerifyInt64ArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<int64_t> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_INT64_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        int64_t* arr = static_cast<int64_t*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyUint64ArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<uint64_t> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_UINT64_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        uint64_t* arr = static_cast<uint64_t*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyInt32ArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<int32_t> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_INT32_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        int32_t* arr = static_cast<int32_t*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyUint32ArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<uint32_t> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_UINT32_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        uint32_t* arr = static_cast<uint32_t*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyUint8ArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<uint8_t> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_UINT8_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        uint8_t* arr = static_cast<uint8_t*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyBoolArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<bool> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_BOOL_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        bool* arr = static_cast<bool*>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(arr[i], expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void VerifyStringArrayParam(const HiSysEventParam &param, const std::string &key,
    const std::vector<std::string> &expectedValues)
{
    VerifyArrayParamCommon(param, key, HISYSEVENT_STRING_ARRAY, expectedValues.size());
    if (!expectedValues.empty()) {
        char** arr = static_cast<char**>(param.v.array);
        for (size_t i = 0; i < expectedValues.size(); ++i) {
            EXPECT_EQ(std::string(arr[i]), expectedValues[i]) << "Array element mismatch at index " << i;
        }
    }
}

void FindAndVerifyInt8Param(std::vector<HiSysEventParam> &params, const std::string &key, int8_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyInt8Param(*param, key, expectedValue);
}

void FindAndVerifyUint8Param(std::vector<HiSysEventParam> &params, const std::string &key, uint8_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint8Param(*param, key, expectedValue);
}

void FindAndVerifyInt64Param(std::vector<HiSysEventParam> &params, const std::string &key, int64_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyInt64Param(*param, key, expectedValue);
}

void FindAndVerifyUint64Param(std::vector<HiSysEventParam> &params, const std::string &key, uint64_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint64Param(*param, key, expectedValue);
}

void FindAndVerifyInt32Param(std::vector<HiSysEventParam> &params, const std::string &key, int32_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyInt32Param(*param, key, expectedValue);
}

void FindAndVerifyUint32Param(std::vector<HiSysEventParam> &params, const std::string &key, uint32_t expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint32Param(*param, key, expectedValue);
}

void FindAndVerifyBoolParam(std::vector<HiSysEventParam> &params, const std::string &key, bool expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyBoolParam(*param, key, expectedValue);
}

void FindAndVerifyFloatParam(std::vector<HiSysEventParam> &params, const std::string &key, float expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyFloatParam(*param, key, expectedValue);
}

void FindAndVerifyDoubleParam(std::vector<HiSysEventParam> &params, const std::string &key, double expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyDoubleParam(*param, key, expectedValue);
}

void FindAndVerifyStringParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::string &expectedValue)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyStringParam(*param, key, expectedValue);
}

void FindAndVerifyInt64ArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<int64_t> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyInt64ArrayParam(*param, key, expectedValues);
}

void FindAndVerifyUint64ArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<uint64_t> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint64ArrayParam(*param, key, expectedValues);
}

void FindAndVerifyInt32ArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<int32_t> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyInt32ArrayParam(*param, key, expectedValues);
}

void FindAndVerifyUint32ArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<uint32_t> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint32ArrayParam(*param, key, expectedValues);
}

void FindAndVerifyUint8ArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<uint8_t> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyUint8ArrayParam(*param, key, expectedValues);
}

void FindAndVerifyBoolArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<bool> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyBoolArrayParam(*param, key, expectedValues);
}

void FindAndVerifyStringArrayParam(std::vector<HiSysEventParam> &params, const std::string &key,
    const std::vector<std::string> &expectedValues)
{
    HiSysEventParam *param = FindParamByName(params, key);
    ASSERT_NE(param, nullptr);
    VerifyStringArrayParam(*param, key, expectedValues);
}

void VerifyAllBuffersEmpty(const FormHiSysEventBuilder &builder)
{
    EXPECT_EQ(builder.params_.size(), 0);
    EXPECT_EQ(builder.stringBuffers_.size(), 0);
    EXPECT_EQ(builder.stringArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.charPtrArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.int64ArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.uint64ArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.int32ArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.uint32ArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.uint8ArrayBuffers_.size(), 0);
    EXPECT_EQ(builder.boolArrayBuffers_.size(), 0);
}

void WriteAndVerify(FormHiSysEventBuilder &builder, const std::string &domain, const std::string &eventName)
{
    int ret = builder.Write(domain, eventName, HISYSEVENT_BEHAVIOR);
    EXPECT_EQ(ret, ERR_OK);
    VerifyAllBuffersEmpty(builder);
}
}

class FmsFormHiSysEventWrapperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormHiSysEventWrapperTest::SetUpTestCase() {}

void FmsFormHiSysEventWrapperTest::TearDownTestCase() {}

void FmsFormHiSysEventWrapperTest::SetUp() {}

void FmsFormHiSysEventWrapperTest::TearDown() {}

/**
 * @tc.name: WriteEvent_001
 * @tc.desc: test WriteEvent function without params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, WriteEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "WriteEvent_001 start";
    std::string domain = "FORM";
    std::string eventName = "FORM_ADD";
    HiSysEventEventType eventType = HISYSEVENT_BEHAVIOR;
    int ret = FormHiSysEventWrapper::WriteEvent(domain, eventName, eventType);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "WriteEvent_001 end ret=" << ret;
}

/**
 * @tc.name: Builder_Int64_001
 * @tc.desc: test InsertParam function with int64_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Int64_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Int64_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("formId", static_cast<int64_t>(12345678901234LL));
    builder.InsertParam("count", static_cast<int64_t>(-12345678901234LL));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyInt64Param(builder.params_, "formId", 12345678901234LL);
    FindAndVerifyInt64Param(builder.params_, "count", -12345678901234LL);

    WriteAndVerify(builder, "FORM", "TEST_INT64");
    GTEST_LOG_(INFO) << "Builder_Int64_001 end";
}

/**
 * @tc.name: Builder_Uint64_001
 * @tc.desc: test InsertParam function with uint64_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint64_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint64_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("userId", static_cast<uint64_t>(12345678901234ULL));
    builder.InsertParam("size", static_cast<uint64_t>(0ULL));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyUint64Param(builder.params_, "userId", 12345678901234ULL);
    FindAndVerifyUint64Param(builder.params_, "size", 0ULL);

    WriteAndVerify(builder, "FORM", "TEST_UINT64");
    GTEST_LOG_(INFO) << "Builder_Uint64_001 end";
}

/**
 * @tc.name: Builder_Int32_001
 * @tc.desc: test InsertParam function with int32_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Int32_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Int32_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("dimension", static_cast<int32_t>(2));
    builder.InsertParam("type", static_cast<int32_t>(-1));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyInt32Param(builder.params_, "dimension", 2);
    FindAndVerifyInt32Param(builder.params_, "type", -1);

    WriteAndVerify(builder, "FORM", "TEST_INT32");
    GTEST_LOG_(INFO) << "Builder_Int32_001 end";
}

/**
 * @tc.name: Builder_Uint32_001
 * @tc.desc: test InsertParam function with uint32_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint32_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint32_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("width", static_cast<uint32_t>(100));
    builder.InsertParam("height", static_cast<uint32_t>(200));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyUint32Param(builder.params_, "width", 100);
    FindAndVerifyUint32Param(builder.params_, "height", 200);

    WriteAndVerify(builder, "FORM", "TEST_UINT32");
    GTEST_LOG_(INFO) << "Builder_Uint32_001 end";
}

/**
 * @tc.name: Builder_Bool_001
 * @tc.desc: test InsertParam function with bool type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Bool_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Bool_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("isVisible", true);
    builder.InsertParam("isEnabled", false);
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyBoolParam(builder.params_, "isVisible", true);
    FindAndVerifyBoolParam(builder.params_, "isEnabled", false);

    WriteAndVerify(builder, "FORM", "TEST_BOOL");
    GTEST_LOG_(INFO) << "Builder_Bool_001 end";
}

/**
 * @tc.name: Builder_Float_001
 * @tc.desc: test InsertParam function with float type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Float_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Float_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("ratio", 0.5f);
    builder.InsertParam("rate", -1.0f);
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyFloatParam(builder.params_, "ratio", 0.5f);
    FindAndVerifyFloatParam(builder.params_, "rate", -1.0f);

    WriteAndVerify(builder, "FORM", "TEST_FLOAT");
    GTEST_LOG_(INFO) << "Builder_Float_001 end";
}

/**
 * @tc.name: Builder_Double_001
 * @tc.desc: test InsertParam function with double type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Double_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Double_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("value", 0.123456789);
    builder.InsertParam("score", -0.5);
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyDoubleParam(builder.params_, "value", 0.123456789);
    FindAndVerifyDoubleParam(builder.params_, "score", -0.5);

    WriteAndVerify(builder, "FORM", "TEST_DOUBLE");
    GTEST_LOG_(INFO) << "Builder_Double_001 end";
}

/**
 * @tc.name: Builder_Int8_001
 * @tc.desc: test InsertParam function with int8_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Int8_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Int8_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("int8Value", static_cast<int8_t>(-128));
    builder.InsertParam("int8Max", static_cast<int8_t>(127));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyInt8Param(builder.params_, "int8Value", static_cast<int8_t>(-128));
    FindAndVerifyInt8Param(builder.params_, "int8Max", static_cast<int8_t>(127));

    WriteAndVerify(builder, "FORM", "TEST_INT8");
    GTEST_LOG_(INFO) << "Builder_Int8_001 end";
}

/**
 * @tc.name: Builder_Uint8_001
 * @tc.desc: test InsertParam function with uint8_t type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint8_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint8_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("uint8Value", static_cast<uint8_t>(0));
    builder.InsertParam("uint8Max", static_cast<uint8_t>(255));
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyUint8Param(builder.params_, "uint8Value", static_cast<uint8_t>(0));
    FindAndVerifyUint8Param(builder.params_, "uint8Max", static_cast<uint8_t>(255));

    WriteAndVerify(builder, "FORM", "TEST_UINT8");
    GTEST_LOG_(INFO) << "Builder_Uint8_001 end";
}

/**
 * @tc.name: Builder_String_001
 * @tc.desc: test InsertParam function with std::string type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_String_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_String_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("bundleName", std::string("com.example.test"));
    builder.InsertParam("moduleName", std::string("entry"));
    builder.InsertParam("emptyString", std::string(""));
    EXPECT_EQ(builder.params_.size(), 3);

    FindAndVerifyStringParam(builder.params_, "bundleName", "com.example.test");
    FindAndVerifyStringParam(builder.params_, "moduleName", "entry");
    FindAndVerifyStringParam(builder.params_, "emptyString", "");

    WriteAndVerify(builder, "FORM", "TEST_STRING");
    GTEST_LOG_(INFO) << "Builder_String_001 end";
}

/**
 * @tc.name: Builder_Int64Array_001
 * @tc.desc: test InsertParam function with int64_t array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Int64Array_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Int64Array_001 start";
    FormHiSysEventBuilder builder;
    std::vector<int64_t> values = {12345LL, 67890LL, 11111LL};
    builder.InsertParam("formIds", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt64ArrayParam(builder.params_, "formIds", values);

    WriteAndVerify(builder, "FORM", "TEST_INT64ARRAY");
    GTEST_LOG_(INFO) << "Builder_Int64Array_001 end";
}

/**
 * @tc.name: Builder_Uint64Array_001
 * @tc.desc: test InsertParam function with uint64_t array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint64Array_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint64Array_001 start";
    FormHiSysEventBuilder builder;
    std::vector<uint64_t> values = {12345ULL, 67890ULL};
    builder.InsertParam("userIds", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyUint64ArrayParam(builder.params_, "userIds", values);

    WriteAndVerify(builder, "FORM", "TEST_UINT64ARRAY");
    GTEST_LOG_(INFO) << "Builder_Uint64Array_001 end";
}

/**
 * @tc.name: Builder_Int32Array_001
 * @tc.desc: test InsertParam function with int32_t array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Int32Array_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Int32Array_001 start";
    FormHiSysEventBuilder builder;
    std::vector<int32_t> values = {1, 2, 3};
    builder.InsertParam("dimensions", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt32ArrayParam(builder.params_, "dimensions", values);

    WriteAndVerify(builder, "FORM", "TEST_INT32ARRAY");
    GTEST_LOG_(INFO) << "Builder_Int32Array_001 end";
}

/**
 * @tc.name: Builder_Uint32Array_001
 * @tc.desc: test InsertParam function with uint32_t array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint32Array_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint32Array_001 start";
    FormHiSysEventBuilder builder;
    std::vector<uint32_t> values = {100, 200, 300};
    builder.InsertParam("sizes", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyUint32ArrayParam(builder.params_, "sizes", values);

    WriteAndVerify(builder, "FORM", "TEST_UINT32ARRAY");
    GTEST_LOG_(INFO) << "Builder_Uint32Array_001 end";
}

/**
 * @tc.name: Builder_Uint8Array_001
 * @tc.desc: test InsertParam function with uint8_t array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Uint8Array_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Uint8Array_001 start";
    FormHiSysEventBuilder builder;
    std::vector<uint8_t> values = {1, 2, 3, 4, 5};
    builder.InsertParam("data", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyUint8ArrayParam(builder.params_, "data", values);

    WriteAndVerify(builder, "FORM", "TEST_UINT8ARRAY");
    GTEST_LOG_(INFO) << "Builder_Uint8Array_001 end";
}

/**
 * @tc.name: Builder_BoolArray_001
 * @tc.desc: test InsertParam function with bool array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_BoolArray_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_BoolArray_001 start";
    FormHiSysEventBuilder builder;
    std::vector<bool> values = {true, false, true, false, true};
    builder.InsertParam("flags", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyBoolArrayParam(builder.params_, "flags", values);

    WriteAndVerify(builder, "FORM", "TEST_BOOLARRAY");
    GTEST_LOG_(INFO) << "Builder_BoolArray_001 end";
}

/**
 * @tc.name: Builder_BoolArray_002
 * @tc.desc: test InsertParam function with empty bool array.
 * @tc.type: FUNC
 * @tc.note: Uses Clear() instead of Write() because OH_HiSysEvent_Write
 *           may reject empty array params at the platform level.
 *           This test verifies the builder correctly creates an empty
 *           array param (arraySize=0, v.array=nullptr).
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_BoolArray_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_BoolArray_002 start";
    FormHiSysEventBuilder builder;
    std::vector<bool> values = {};
    builder.InsertParam("flags", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyBoolArrayParam(builder.params_, "flags", values);

    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    GTEST_LOG_(INFO) << "Builder_BoolArray_002 end";
}

/**
 * @tc.name: Builder_StringArray_001
 * @tc.desc: test InsertParam function with string array type params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_StringArray_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_StringArray_001 start";
    FormHiSysEventBuilder builder;
    std::vector<std::string> values = {"com.example.test", "com.example.entry"};
    builder.InsertParam("bundleNames", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyStringArrayParam(builder.params_, "bundleNames", values);

    WriteAndVerify(builder, "FORM", "TEST_STRINGARRAY");
    GTEST_LOG_(INFO) << "Builder_StringArray_001 end";
}

/**
 * @tc.name: Builder_MixedParams_001
 * @tc.desc: test InsertParam function with mixed type params in single builder.
 * @tc.type: FUNC
 * @tc.note: This test verifies that different param types (int64, string,
 *           int32, bool, float) coexist correctly in the same builder,
 *           which is the typical real-world usage pattern. Each type is
 *           already covered by its own dedicated test case; this test
 *           focuses on cross-type interaction within one Write call.
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_MixedParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_MixedParams_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("formId", static_cast<int64_t>(12345));
    builder.InsertParam("bundleName", std::string("com.example.test"));
    builder.InsertParam("moduleName", "entry");
    builder.InsertParam("dimension", static_cast<int32_t>(2));
    builder.InsertParam("isVisible", true);
    builder.InsertParam("ratio", 0.5f);
    EXPECT_EQ(builder.params_.size(), 6);

    FindAndVerifyInt64Param(builder.params_, "formId", 12345);
    FindAndVerifyStringParam(builder.params_, "bundleName", "com.example.test");
    FindAndVerifyStringParam(builder.params_, "moduleName", "entry");
    FindAndVerifyInt32Param(builder.params_, "dimension", 2);
    FindAndVerifyBoolParam(builder.params_, "isVisible", true);
    FindAndVerifyFloatParam(builder.params_, "ratio", 0.5f);

    WriteAndVerify(builder, "FORM", "TEST_MIXED");
    GTEST_LOG_(INFO) << "Builder_MixedParams_001 end";
}

/**
 * @tc.name: Builder_EmptyParams_001
 * @tc.desc: test InsertParam function with empty array params.
 * @tc.type: FUNC
 * @tc.note: Uses Clear() instead of Write() because OH_HiSysEvent_Write
 *           may reject empty array params at the platform level.
 *           This test verifies the builder correctly creates empty array
 *           params (arraySize=0, v.array=nullptr).
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_EmptyParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_EmptyParams_001 start";
    FormHiSysEventBuilder builder;
    std::vector<int64_t> emptyVec;
    builder.InsertParam("emptyVec", emptyVec);
    std::vector<std::string> emptyStrVec;
    builder.InsertParam("emptyStrVec", emptyStrVec);
    EXPECT_EQ(builder.params_.size(), 2);

    FindAndVerifyInt64ArrayParam(builder.params_, "emptyVec", emptyVec);
    FindAndVerifyStringArrayParam(builder.params_, "emptyStrVec", emptyStrVec);

    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    GTEST_LOG_(INFO) << "Builder_EmptyParams_001 end";
}

/**
 * @tc.name: Builder_EmptyNumericArrayTypes_001
 * @tc.desc: test InsertParam with empty arrays for uint64, int32, uint32, uint8.
 * @tc.type: FUNC
 * @tc.note: Uses Clear() instead of Write() because OH_HiSysEvent_Write
 *           may reject empty array params at the platform level.
 *           Empty int64 and string arrays are covered in Builder_EmptyParams_001,
 *           empty bool array in Builder_BoolArray_002. This test covers
 *           remaining numeric array types.
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_EmptyNumericArrayTypes_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_EmptyNumericArrayTypes_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("emptyUint64", std::vector<uint64_t>{});
    builder.InsertParam("emptyInt32", std::vector<int32_t>{});
    builder.InsertParam("emptyUint32", std::vector<uint32_t>{});
    builder.InsertParam("emptyUint8", std::vector<uint8_t>{});
    EXPECT_EQ(builder.params_.size(), 4);

    FindAndVerifyUint64ArrayParam(builder.params_, "emptyUint64", {});
    FindAndVerifyInt32ArrayParam(builder.params_, "emptyInt32", {});
    FindAndVerifyUint32ArrayParam(builder.params_, "emptyUint32", {});
    FindAndVerifyUint8ArrayParam(builder.params_, "emptyUint8", {});

    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    GTEST_LOG_(INFO) << "Builder_EmptyNumericArrayTypes_001 end";
}

/**
 * @tc.name: Builder_Clear_001
 * @tc.desc: test Clear function to clear all params and buffers, then reuse builder.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_Clear_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_Clear_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("formId", static_cast<int64_t>(12345));
    builder.InsertParam("bundleName", std::string("test"));
    std::vector<int64_t> arr = {1LL, 2LL, 3LL};
    builder.InsertParam("array", arr);
    EXPECT_EQ(builder.params_.size(), 3);
    EXPECT_GT(builder.stringBuffers_.size(), 0);
    EXPECT_GT(builder.int64ArrayBuffers_.size(), 0);
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    builder.InsertParam("newParam", static_cast<int64_t>(67890));
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt64Param(builder.params_, "newParam", 67890);

    WriteAndVerify(builder, "FORM", "TEST_CLEAR");
    GTEST_LOG_(INFO) << "Builder_Clear_001 end";
}

/**
 * @tc.name: Builder_MaxParams_001
 * @tc.desc: test InsertParam function when params count exceeds MAX_PARAM_COUNT.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_MaxParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_MaxParams_001 start";
    FormHiSysEventBuilder builder;
    for (int i = 0; i < static_cast<int>(MAX_PARAM_COUNT); ++i) {
        builder.InsertParam("param" + std::to_string(i), static_cast<int64_t>(i));
    }
    EXPECT_EQ(builder.params_.size(), MAX_PARAM_COUNT);

    builder.InsertParam("overflow", static_cast<int64_t>(999));
    EXPECT_EQ(builder.params_.size(), MAX_PARAM_COUNT);

    HiSysEventParam *overflowParam = FindParamByName(builder.params_, "overflow");
    EXPECT_EQ(overflowParam, nullptr);

    FindAndVerifyInt64Param(builder.params_, "param0", 0);
    FindAndVerifyInt64Param(builder.params_, "param63", 63);

    WriteAndVerify(builder, "FORM", "TEST_MAXPARAMS");
    GTEST_LOG_(INFO) << "Builder_MaxParams_001 end";
}

/**
 * @tc.name: Builder_LongKey_001
 * @tc.desc: test InsertParam function with key name exceeds MAX_LENGTH_OF_PARAM_NAME.
 * @tc.type: FUNC
 * @tc.note: Uses index access because same truncated key is inserted multiple times,
 *           FindParamByName would only find the first match.
 *           The builder does NOT enforce unique keys — it appends all params
 *           to params_ without deduplication. When a long key is truncated,
 *           multiple params may share the same truncated name. This is
 *           intentional: the builder's role is to collect params; duplicate
 *           key handling is deferred to OH_HiSysEvent_Write at the platform
 *           level. For explicit duplicate key testing, see
 *           Builder_RepeatedInsertSameKey_001.
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_LongKey_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_LongKey_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam(LONG_KEY_NAME, static_cast<int64_t>(12345));
    builder.InsertParam(LONG_KEY_NAME, std::string("test_value"));
    std::vector<int64_t> values = {12345LL, 67890LL};
    builder.InsertParam(LONG_KEY_NAME, values);
    EXPECT_EQ(builder.params_.size(), 3);
    std::string expectedKey(LONG_KEY_NAME);
    if (expectedKey.length() >= MAX_LENGTH_OF_PARAM_NAME) {
        expectedKey = expectedKey.substr(0, MAX_LENGTH_OF_PARAM_NAME - 1);
    }
    EXPECT_EQ(std::string(builder.params_[0].name), expectedKey);
    EXPECT_EQ(strlen(builder.params_[0].name), MAX_LENGTH_OF_PARAM_NAME - 1);
    EXPECT_EQ(builder.params_[0].t, HISYSEVENT_INT64);
    EXPECT_EQ(builder.params_[0].v.i64, 12345);
    EXPECT_EQ(std::string(builder.params_[1].name), expectedKey);
    EXPECT_EQ(strlen(builder.params_[1].name), MAX_LENGTH_OF_PARAM_NAME - 1);
    EXPECT_EQ(builder.params_[1].t, HISYSEVENT_STRING);
    EXPECT_EQ(std::string(builder.params_[1].v.s), "test_value");
    EXPECT_EQ(std::string(builder.params_[2].name), expectedKey);
    EXPECT_EQ(strlen(builder.params_[2].name), MAX_LENGTH_OF_PARAM_NAME - 1);
    VerifyInt64ArrayParam(builder.params_[2], expectedKey, values);
    WriteAndVerify(builder, "FORM", "TEST_LONGKEY");
    GTEST_LOG_(INFO) << "Builder_LongKey_001 end";
}

/**
 * @tc.name: Builder_WriteTwice_001
 * @tc.desc: test Write function called twice with same builder.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_WriteTwice_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_WriteTwice_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("param1", static_cast<int64_t>(12345));
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt64Param(builder.params_, "param1", 12345);

    WriteAndVerify(builder, "FORM", "TEST1");
    EXPECT_EQ(builder.params_.size(), 0);
    builder.InsertParam("param2", static_cast<int64_t>(67890));
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt64Param(builder.params_, "param2", 67890);

    WriteAndVerify(builder, "FORM", "TEST2");
    GTEST_LOG_(INFO) << "Builder_WriteTwice_001 end";
}

/**
 * @tc.name: Builder_NullCharPtr_001
 * @tc.desc: test InsertParam with nullptr char pointer should be rejected.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_NullCharPtr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_NullCharPtr_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("nullParam", static_cast<const char*>(nullptr));

    EXPECT_EQ(builder.params_.size(), 0);
    VerifyAllBuffersEmpty(builder);
    GTEST_LOG_(INFO) << "Builder_NullCharPtr_001 end";
}

/**
 * @tc.name: Builder_LongString_001
 * @tc.desc: test InsertParam with very long string value.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_LongString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_LongString_001 start";
    FormHiSysEventBuilder builder;
    std::string longString(1024, 'a');
    builder.InsertParam("longString", longString);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyStringParam(builder.params_, "longString", longString);
    EXPECT_EQ(builder.stringBuffers_.size(), 1);

    WriteAndVerify(builder, "FORM", "TEST_LONGSTRING");
    GTEST_LOG_(INFO) << "Builder_LongString_001 end";
}

/**
 * @tc.name: Builder_LargeArray_001
 * @tc.desc: test InsertParam with large array (100 elements).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_LargeArray_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_LargeArray_001 start";
    FormHiSysEventBuilder builder;
    std::vector<int64_t> largeArray;
    for (int i = 0; i < 100; ++i) {
        largeArray.push_back(static_cast<int64_t>(i));
    }
    builder.InsertParam("largeArray", largeArray);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyInt64ArrayParam(builder.params_, "largeArray", largeArray);
    EXPECT_EQ(builder.int64ArrayBuffers_.size(), 1);

    WriteAndVerify(builder, "FORM", "TEST_LARGEARRAY");
    GTEST_LOG_(INFO) << "Builder_LargeArray_001 end";
}

/**
 * @tc.name: Builder_MaxKeyLength_001
 * @tc.desc: test InsertParam with key length exactly MAX_LENGTH_OF_PARAM_NAME-1.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_MaxKeyLength_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_MaxKeyLength_001 start";
    FormHiSysEventBuilder builder;
    std::string maxKey(MAX_LENGTH_OF_PARAM_NAME - 1, 'k');
    builder.InsertParam(maxKey, static_cast<int64_t>(12345));
    EXPECT_EQ(builder.params_.size(), 1);

    HiSysEventParam *param = FindParamByName(builder.params_, maxKey);
    ASSERT_NE(param, nullptr);
    EXPECT_EQ(std::string(param->name), maxKey);
    EXPECT_EQ(strlen(param->name), MAX_LENGTH_OF_PARAM_NAME - 1);

    WriteAndVerify(builder, "FORM", "TEST_MAXKEY");
    GTEST_LOG_(INFO) << "Builder_MaxKeyLength_001 end";
}

/**
 * @tc.name: Builder_SingleElementArray_001
 * @tc.desc: test InsertParam with single element arrays (boundary case).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_SingleElementArray_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_SingleElementArray_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("singleInt64", std::vector<int64_t>{100LL});
    builder.InsertParam("singleUint64", std::vector<uint64_t>{200ULL});
    builder.InsertParam("singleInt32", std::vector<int32_t>{300});
    builder.InsertParam("singleUint32", std::vector<uint32_t>{400});
    builder.InsertParam("singleUint8", std::vector<uint8_t>{50});
    builder.InsertParam("singleString", std::vector<std::string>{"test"});
    EXPECT_EQ(builder.params_.size(), 6);

    FindAndVerifyInt64ArrayParam(builder.params_, "singleInt64", {100LL});
    FindAndVerifyUint64ArrayParam(builder.params_, "singleUint64", {200ULL});
    FindAndVerifyInt32ArrayParam(builder.params_, "singleInt32", {300});
    FindAndVerifyUint32ArrayParam(builder.params_, "singleUint32", {400U});
    FindAndVerifyUint8ArrayParam(builder.params_, "singleUint8", {static_cast<uint8_t>(50)});
    FindAndVerifyStringArrayParam(builder.params_, "singleString", {"test"});

    WriteAndVerify(builder, "FORM", "TEST_SINGLE");
    GTEST_LOG_(INFO) << "Builder_SingleElementArray_001 end";
}

/**
 * @tc.name: Builder_WriteWithNoParams_001
 * @tc.desc: test builder initial state and Clear on empty builder.
 * @tc.type: FUNC
 * @tc.note: Write() on an empty builder is not tested here because
 *           OH_HiSysEvent_Write behavior with zero params is
 *           platform-dependent. This test verifies the builder's
 *           empty initial state and that Clear() works on an
 *           already-empty builder.
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_WriteWithNoParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_WriteWithNoParams_001 start";
    FormHiSysEventBuilder builder;
    EXPECT_EQ(builder.params_.size(), 0);
    VerifyAllBuffersEmpty(builder);
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    GTEST_LOG_(INFO) << "Builder_WriteWithNoParams_001 end";
}

/**
 * @tc.name: Builder_ClearBeforeWrite_001
 * @tc.desc: test Clear function called before Write, then reuse builder with WriteAndVerify.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_ClearBeforeWrite_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_ClearBeforeWrite_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("param1", static_cast<int64_t>(12345));
    builder.InsertParam("param2", std::string("test"));
    builder.InsertParam("param3", std::vector<int64_t>{1LL, 2LL});
    EXPECT_GT(builder.stringBuffers_.size(), 0);
    EXPECT_GT(builder.int64ArrayBuffers_.size(), 0);
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    builder.InsertParam("reusedParam", static_cast<int64_t>(67890));
    WriteAndVerify(builder, "FORM", "TEST_CLEARBEFORE");
    GTEST_LOG_(INFO) << "Builder_ClearBeforeWrite_001 end";
}

/**
 * @tc.name: Builder_RepeatedInsertSameKey_001
 * @tc.desc: test InsertParam with same key inserted multiple times.
 * @tc.type: FUNC
 * @tc.note: Uses index access to verify all params with same key,
 *           FindParamByName would only find the first match.
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_RepeatedInsertSameKey_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_RepeatedInsertSameKey_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("sameKey", static_cast<int64_t>(1));
    builder.InsertParam("sameKey", static_cast<int64_t>(2));
    builder.InsertParam("sameKey", static_cast<int64_t>(3));
    EXPECT_EQ(builder.params_.size(), 3);

    std::vector<int64_t> expectedValues = {1, 2, 3};
    size_t matchCount = 0;
    for (const auto &param : builder.params_) {
        if (std::string(param.name) == "sameKey") {
            EXPECT_EQ(param.t, HISYSEVENT_INT64);
            EXPECT_LT(matchCount, expectedValues.size());
            EXPECT_EQ(param.v.i64, expectedValues[matchCount]);
            matchCount++;
        }
    }
    EXPECT_EQ(matchCount, 3);

    WriteAndVerify(builder, "FORM", "TEST_SAMEKEY");
    GTEST_LOG_(INFO) << "Builder_RepeatedInsertSameKey_001 end";
}

/**
 * @tc.name: Builder_MultipleClears_001
 * @tc.desc: test multiple Clear calls in sequence.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_MultipleClears_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_MultipleClears_001 start";
    FormHiSysEventBuilder builder;
    builder.InsertParam("param", static_cast<int64_t>(12345));
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    builder.Clear();
    VerifyAllBuffersEmpty(builder);
    builder.InsertParam("newParam", static_cast<int64_t>(67890));
    WriteAndVerify(builder, "FORM", "TEST_MULTICLEAR");
    GTEST_LOG_(INFO) << "Builder_MultipleClears_001 end";
}

/**
 * @tc.name: Builder_CharPtrEmptyString_001
 * @tc.desc: test InsertParam with char pointer pointing to empty string.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_CharPtrEmptyString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_CharPtrEmptyString_001 start";
    FormHiSysEventBuilder builder;
    const char* emptyStr = "";
    builder.InsertParam("emptyCharPtr", emptyStr);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyStringParam(builder.params_, "emptyCharPtr", "");
    EXPECT_EQ(builder.stringBuffers_.size(), 1);

    WriteAndVerify(builder, "FORM", "TEST_EMPTYCHARPTR");
    GTEST_LOG_(INFO) << "Builder_CharPtrEmptyString_001 end";
}

/**
 * @tc.name: Builder_StringArrayWithEmptyStrings_001
 * @tc.desc: test InsertParam with string array containing empty strings.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_StringArrayWithEmptyStrings_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_StringArrayWithEmptyStrings_001 start";
    FormHiSysEventBuilder builder;
    std::vector<std::string> values = {"first", "", "third", "", ""};
    builder.InsertParam("mixedArray", values);
    EXPECT_EQ(builder.params_.size(), 1);

    FindAndVerifyStringArrayParam(builder.params_, "mixedArray", values);

    WriteAndVerify(builder, "FORM", "TEST_EMPTYSTRARRAY");
    GTEST_LOG_(INFO) << "Builder_StringArrayWithEmptyStrings_001 end";
}

/**
 * @tc.name: Builder_MaxParamsMinusOne_001
 * @tc.desc: test InsertParam with MAX_PARAM_COUNT-1 params (just below limit).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHiSysEventWrapperTest, Builder_MaxParamsMinusOne_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Builder_MaxParamsMinusOne_001 start";
    FormHiSysEventBuilder builder;
    for (size_t i = 0; i < MAX_PARAM_COUNT - 1; ++i) {
        builder.InsertParam("param" + std::to_string(i), static_cast<int64_t>(i));
    }
    EXPECT_EQ(builder.params_.size(), MAX_PARAM_COUNT - 1);

    for (size_t i = 0; i < MAX_PARAM_COUNT - 1; ++i) {
        FindAndVerifyInt64Param(builder.params_, "param" + std::to_string(i), static_cast<int64_t>(i));
    }

    builder.InsertParam("lastParam", static_cast<int64_t>(999));
    EXPECT_EQ(builder.params_.size(), MAX_PARAM_COUNT);
    FindAndVerifyInt64Param(builder.params_, "lastParam", 999);
    WriteAndVerify(builder, "FORM", "TEST_MAXMINUS");
    GTEST_LOG_(INFO) << "Builder_MaxParamsMinusOne_001 end";
}
}
}