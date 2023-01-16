/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "form_errors.h"
#undef private
#include "form_mgr_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormErrorsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormErrorsTest::SetUpTestCase() {}
void FormErrorsTest::TearDownTestCase() {}
void FormErrorsTest::SetUp() {}
void FormErrorsTest::TearDown() {}

/**
 * @tc.number: FormErrors_GetErrorMessage_001
 * @tc.name: GetErrorMessage
 * @tc.desc: Verify that the returned value of the interface is the error information corresponding to
 *           the passed error code
 */
HWTEST_F(FormErrorsTest, FormErrors_GetErrorMessage_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormErrors_GetErrorMessage_001 starts";
    FormErrors formErrors;
    std::string ret = formErrors.GetErrorMessage(ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(ret, "can't get form info by the formName.");
    GTEST_LOG_(INFO) << "FormErrors_GetErrorMessage_001 ends";
}

/**
 * @tc.number: FormErrors_GetErrorMessage_002
 * @tc.name: GetErrorMessage
 * @tc.desc: Verify that the interface return value is ERR_ APPEXECFWK_ FORM_ COMMON_ Error message
 *           corresponding to code
 */
HWTEST_F(FormErrorsTest, FormErrors_GetErrorMessage_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormErrors_GetErrorMessage_002 starts";
    FormErrors formErrors;
    int errCode = -1;
    std::string ret = formErrors.GetErrorMessage(errCode);
    EXPECT_EQ(ret, "some internal server error occurs.");
    GTEST_LOG_(INFO) << "FormErrors_GetErrorMessage_002 ends";
}
} // namespace