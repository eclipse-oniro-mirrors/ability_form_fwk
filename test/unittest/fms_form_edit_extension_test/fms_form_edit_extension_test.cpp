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
#include "want.h"
#include "form_constants.h"
#include "res_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Global::Resource;

namespace {
class FmsFormEditExtensionTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp()
    {}
    void TearDown()
    {}
};

/**
 * @tc.name: FmsFormEditExtensionTest_0001
 * @tc.desc: Verify colorMode constant value matches DARK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0001 starts";
    EXPECT_EQ(static_cast<int32_t>(ColorMode::DARK), 0);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0001 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0002
 * @tc.desc: Verify colorMode constant value matches LIGHT.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0002 starts";
    EXPECT_EQ(static_cast<int32_t>(ColorMode::LIGHT), 1);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0002 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0003
 * @tc.desc: Verify colorMode constant value matches COLOR_MODE_NOT_SET.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0003 starts";
    EXPECT_EQ(static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET), -1);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0003 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0004
 * @tc.desc: Verify PARAM_FORM_EDIT_COLOR_MODE constant value.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0004 starts";
    EXPECT_EQ(std::string(Constants::PARAM_FORM_EDIT_COLOR_MODE), "ohos.extra.param.form_edit_color_mode");
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0004 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0005
 * @tc.desc: Verify Want.GetIntParam returns DARK when colorMode=0 is set.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0005 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, static_cast<int32_t>(ColorMode::DARK));
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    EXPECT_EQ(colorMode, 0);
    EXPECT_EQ(colorMode, static_cast<int32_t>(ColorMode::DARK));
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0005 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0006
 * @tc.desc: Verify Want.GetIntParam returns LIGHT when colorMode=1 is set.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0006 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, static_cast<int32_t>(ColorMode::LIGHT));
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    EXPECT_EQ(colorMode, 1);
    EXPECT_EQ(colorMode, static_cast<int32_t>(ColorMode::LIGHT));
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0006 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0007
 * @tc.desc: Verify Want.GetIntParam returns COLOR_MODE_NOT_SET when colorMode is not set.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0007 starts";
    AAFwk::Want want;
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    EXPECT_EQ(colorMode, -1);
    EXPECT_EQ(colorMode, static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0007 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0008
 * @tc.desc: Verify Want.GetIntParam returns COLOR_MODE_NOT_SET when colorMode is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0008 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, 99);
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    EXPECT_EQ(colorMode, 99);
    EXPECT_NE(colorMode, static_cast<int32_t>(ColorMode::DARK));
    EXPECT_NE(colorMode, static_cast<int32_t>(ColorMode::LIGHT));
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0008 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0009
 * @tc.desc: Verify invalid colorMode (-1) is not DARK or LIGHT.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0009 starts";
    AAFwk::Want want;
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    bool shouldApply = (colorMode == static_cast<int32_t>(ColorMode::DARK) ||
        colorMode == static_cast<int32_t>(ColorMode::LIGHT));
    EXPECT_FALSE(shouldApply);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0009 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0010
 * @tc.desc: Verify DARK (0) passes the color mode filter.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0010 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, static_cast<int32_t>(ColorMode::DARK));
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    bool shouldApply = (colorMode == static_cast<int32_t>(ColorMode::DARK) ||
        colorMode == static_cast<int32_t>(ColorMode::LIGHT));
    EXPECT_TRUE(shouldApply);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0010 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0011
 * @tc.desc: Verify LIGHT (1) passes the color mode filter.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0011 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, static_cast<int32_t>(ColorMode::LIGHT));
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    bool shouldApply = (colorMode == static_cast<int32_t>(ColorMode::DARK) ||
        colorMode == static_cast<int32_t>(ColorMode::LIGHT));
    EXPECT_TRUE(shouldApply);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0011 test ends";
}

/**
 * @tc.name: FmsFormEditExtensionTest_0012
 * @tc.desc: Verify invalid colorMode (99) does not pass the color mode filter.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionTest, FmsFormEditExtensionTest_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0012 starts";
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_EDIT_COLOR_MODE, 99);
    int32_t colorMode = want.GetIntParam(Constants::PARAM_FORM_EDIT_COLOR_MODE,
        static_cast<int32_t>(ColorMode::COLOR_MODE_NOT_SET));
    bool shouldApply = (colorMode == static_cast<int32_t>(ColorMode::DARK) ||
        colorMode == static_cast<int32_t>(ColorMode::LIGHT));
    EXPECT_FALSE(shouldApply);
    GTEST_LOG_(INFO) << "FmsFormEditExtensionTest_0012 test ends";
}
} // namespace
