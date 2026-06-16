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

#include "util/form_status_print.h"
#include "util/form_status_common.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {

struct EventTestEntry {
    FormFsmEvent event;
    std::string expectedStr;
};

const EventTestEntry EVENT_TEST_TABLE[] = {
    {FormFsmEvent::RENDER_FORM, "[RENDER_FORM]"},
    {FormFsmEvent::RENDER_FORM_DONE, "[RENDER_FORM_DONE]"},
    {FormFsmEvent::RENDER_FORM_FAIL, "[RENDER_FORM_FAIL]"},
    {FormFsmEvent::RECYCLE_DATA, "[RECYCLE_DATA]"},
    {FormFsmEvent::RECYCLE_DATA_DONE, "[RECYCLE_DATA_DONE]"},
    {FormFsmEvent::RECYCLE_DATA_FAIL, "[RECYCLE_DATA_FAIL]"},
    {FormFsmEvent::RECYCLE_FORM, "[RECYCLE_FORM]"},
    {FormFsmEvent::RECYCLE_FORM_DONE, "[RECYCLE_FORM_DONE]"},
    {FormFsmEvent::RECYCLE_FORM_FAIL, "[RECYCLE_FORM_FAIL]"},
    {FormFsmEvent::RECOVER_FORM, "[RECOVER_FORM]"},
    {FormFsmEvent::RECOVER_FORM_DONE, "[RECOVER_FORM_DONE]"},
    {FormFsmEvent::RECOVER_FORM_FAIL, "[RECOVER_FORM_FAIL]"},
    {FormFsmEvent::DELETE_FORM, "[DELETE_FORM]"},
    {FormFsmEvent::DELETE_FORM_DONE, "[DELETE_FORM_DONE]"},
    {FormFsmEvent::DELETE_FORM_FAIL, "[DELETE_FORM_FAIL]"},
    {FormFsmEvent::DELETE_FORM_FINISH, "[DELETE_FORM_FINISH]"},
    {FormFsmEvent::EXECUTION_TIMEOUT, "[EXECUTION_TIMEOUT]"},
    {FormFsmEvent::RELOAD_FORM, "[RELOAD_FORM]"},
};

class FmsFormStatusPrintTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormStatusPrintTest::SetUpTestCase()
{}

void FmsFormStatusPrintTest::TearDownTestCase()
{}

void FmsFormStatusPrintTest::SetUp()
{}

void FmsFormStatusPrintTest::TearDown()
{}

class FmsFormEventToStringParamTest : public testing::TestWithParam<EventTestEntry> {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormEventToStringParamTest::SetUpTestCase()
{}

void FmsFormEventToStringParamTest::TearDownTestCase()
{}

void FmsFormEventToStringParamTest::SetUp()
{}

void FmsFormEventToStringParamTest::TearDown()
{}

INSTANTIATE_TEST_SUITE_P(FormEventToStringTests, FmsFormEventToStringParamTest,
    ValuesIn(EVENT_TEST_TABLE));

/**
 * @tc.name: FmsFormEventToStringParamTest_FormEventToString_001
 * @tc.desc: Verify FormFsmEvent enum value has correct string representation
 * @tc.type: FUNC
 */
HWTEST_P(FmsFormEventToStringParamTest, FmsFormEventToStringParamTest_FormEventToString_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEventToStringParamTest_FormEventToString_001 start";
    const EventTestEntry& entry = GetParam();
    std::string result = FormStatusPrint::FormEventToString(entry.event);
    EXPECT_EQ(result, entry.expectedStr) << "Event: " << static_cast<int>(entry.event) <<
        ", Actual: \"" << result << "\", Expected: \"" << entry.expectedStr << "\"";
    GTEST_LOG_(INFO) << "FmsFormEventToStringParamTest_FormEventToString_001 end";
}

/**
 * @tc.name: FmsFormStatusPrintTest_FormEventToString_Invalid_001
 * @tc.desc: Verify FormEventToString handles invalid event value gracefully
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormStatusPrintTest, FmsFormStatusPrintTest_FormEventToString_Invalid_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormStatusPrintTest_FormEventToString_Invalid_001 start";
    FormFsmEvent invalidEvent = static_cast<FormFsmEvent>(100);
    std::string result = FormStatusPrint::FormEventToString(invalidEvent);
    EXPECT_EQ(result, "100") << "Invalid event should return its numeric value as string";
    GTEST_LOG_(INFO) << "FmsFormStatusPrintTest_FormEventToString_Invalid_001 end";
}
}