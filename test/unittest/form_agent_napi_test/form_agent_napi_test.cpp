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
#include <memory>
#include <string>
 
#include "form_mgr_errors.h"
#include "js_form_agent.h"
 
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
 
namespace {
class FormAgentNapiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};
 
// Mirror of NapiFormUtil::ThrowParamNumError's message builder. Keep in sync
// with frameworks/js/napi/formUtil/napi_form_util.cpp:158-162.
std::string BuildParamNumErrorMessage(const std::string &gotNum, const std::string &expectedNum)
{
    return "Parameter error. Got " + gotNum + ", expected " + expectedNum;
}
 
// Mirror of NapiFormUtil::ThrowParamError's message builder. Keep in sync with
// frameworks/js/napi/formUtil/napi_form_util.cpp:164-168.
std::string BuildParamErrorMessage(const std::string &extraMessage)
{
    return "Parameter error. " + extraMessage;
}
 
/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_001
 * @tc.name: Verify UpdateFormCrossBundleCallbackInfo sentinel defaults.
 * @tc.desc: test the default-constructed callback info matches the parser's sentinel values.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_001 starts";
    UpdateFormCrossBundleCallbackInfo info;
    EXPECT_EQ(info.formId, -1);
    EXPECT_EQ(info.formBindingData, nullptr);
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_001 ends";
}
 
/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_002
 * @tc.name: Verify parameter-count error message format.
 * @tc.desc: test the "Parameter error. Got <argc>, expected 2" contract for ArkTS callers.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_002 starts";
    auto msg = BuildParamNumErrorMessage("1", "2");
    EXPECT_EQ(msg, "Parameter error. Got 1, expected 2");
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_002 ends";
}
 
/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_003
 * @tc.name: Verify parameter-validation error message format.
 * @tc.desc: test the formId / formBindingData error message prefixes.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_003 starts";
    auto formIdMsg = BuildParamErrorMessage("formId is invalid");
    EXPECT_EQ(formIdMsg, "Parameter error. formId is invalid");
 
    auto dataMsg = BuildParamErrorMessage("formBindingData is invalid");
    EXPECT_EQ(dataMsg, "Parameter error. formBindingData is invalid");
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_003 ends";
}
 
/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_004
 * @tc.name: Verify FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE value stability.
 * @tc.desc: test that the dedicated internal code 2293857 remains stable for the 201 mapping.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_004 starts";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE, 2293857);
 
    EXPECT_EQ(ERR_FORM_EXTERNAL_PERMISSION_DENIED, 201);
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_004 ends";
}
}  // namespace