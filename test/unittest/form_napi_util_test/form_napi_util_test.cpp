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
#include <gtest/gtest.h>
#define private public
#include "napi_form_util.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;

namespace {
class FormNapiUtilTest : public testing::Test {
public:
    // TestSuite setup has to be static
    static void SetUpTestCase()
    {}
};

/**
 * @tc.name: FormNapiUtilTest_0001
 * @tc.desc: Verify CreateParamTypeErrorMessage paramName empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FormNapiUtilTest, FormNapiUtilTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormNapiUtilTest_0001 starts";

    auto result = NapiFormUtil::CreateParamTypeErrorMessage("", "string");
    EXPECT_EQ(result, "Parameter error.");

    GTEST_LOG_(INFO) << "FormNapiUtilTest_0001 test ends";
}

/**
 * @tc.name: FormNapiUtilTest_0002
 * @tc.desc: Verify CreateParamTypeErrorMessage type empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FormNapiUtilTest, FormNapiUtilTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormNapiUtilTest_0002 starts";

    auto result = NapiFormUtil::CreateParamTypeErrorMessage("formId", "");
    EXPECT_EQ(result, "Parameter error. The type of \"formId\" is invalid.");

    GTEST_LOG_(INFO) << "FormNapiUtilTest_0002 test ends";
}

/**
 * @tc.name: FormNapiUtilTest_0003
 * @tc.desc: Verify CreateParamTypeErrorMessage paramName and type is not empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FormNapiUtilTest, FormNapiUtilTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormNapiUtilTest_0003 starts";

    auto result = NapiFormUtil::CreateParamTypeErrorMessage("formId", "string");
    EXPECT_EQ(result, "Parameter error. The type of \"formId\" must be string.");

    GTEST_LOG_(INFO) << "FormNapiUtilTest_0003 test ends";
}
} // namespace