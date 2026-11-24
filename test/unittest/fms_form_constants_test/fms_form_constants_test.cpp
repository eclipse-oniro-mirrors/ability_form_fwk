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

#include "form_constants.h"
#include "form_constants_util.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
class FormConstantsTest : public testing::Test {};

/**
 * @tc.name: GetDimensionString_001
 * @tc.desc: Verify all supported form dimensions and invalid dimension boundaries.
 * @tc.type: FUNC
 */
HWTEST_F(FormConstantsTest, GetDimensionString_001, TestSize.Level1)
{
    const std::pair<Constants::Dimension, const char*> expectedDimensions[] = {
        {Constants::Dimension::DIMENSION_1_2, "1*2"},
        {Constants::Dimension::DIMENSION_2_2, "2*2"},
        {Constants::Dimension::DIMENSION_2_4, "2*4"},
        {Constants::Dimension::DIMENSION_4_4, "4*4"},
        {Constants::Dimension::DIMENSION_2_1_LEGACY, "2*1"},
        {Constants::Dimension::DIMENSION_1_1, "1*1"},
        {Constants::Dimension::DIMENSION_6_4, "6*4"},
        {Constants::Dimension::DIMENSION_2_3, "2*3"},
        {Constants::Dimension::DIMENSION_3_3, "3*3"},
        {Constants::Dimension::DIMENSION_2_1, "2*1"},
        {Constants::Dimension::DIMENSION_4_2, "4*2"},
    };
    for (const auto& item : expectedDimensions) {
        EXPECT_STREQ(FormConstantsUtil::GetDimensionString(item.first), item.second);
    }
    EXPECT_EQ(FormConstantsUtil::GetDimensionString(static_cast<Constants::Dimension>(0)), nullptr);
    EXPECT_EQ(FormConstantsUtil::GetDimensionString(static_cast<Constants::Dimension>(12)), nullptr);
}

/**
 * @tc.name: Dimension_Enum_001
 * @tc.desc: Verify Dimension enum values and DIMENSION_MAX bound.
 * @tc.type: FUNC
 */
HWTEST_F(FormConstantsTest, Dimension_Enum_001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_MIN), 1);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_1_2), 1);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_2_1_LEGACY), 5);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_1_1), 6);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_6_4), 7);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_2_3), 8);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_3_3), 9);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_2_1), 10);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_4_2), 11);
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_MAX),
        static_cast<int32_t>(Constants::Dimension::DIMENSION_4_2));
    EXPECT_EQ(static_cast<int32_t>(Constants::Dimension::DIMENSION_MAX), 11);
}

/**
 * @tc.name: GetLiveFormActiveState_001
 * @tc.desc: Verify all live form states and malformed status values.
 * @tc.type: FUNC
 */
HWTEST_F(FormConstantsTest, GetLiveFormActiveState_001, TestSize.Level1)
{
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("00"), "INACTIVE");
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("01"), "INACTIVE");
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("10"), "PAUSE");
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("11"), "PAUSE");
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("20"), "ACTIVE");
    EXPECT_STREQ(FormConstantsUtil::GetLiveFormActiveState("21"), "ACTIVE");
    EXPECT_EQ(FormConstantsUtil::GetLiveFormActiveState(""), nullptr);
    EXPECT_EQ(FormConstantsUtil::GetLiveFormActiveState("0"), nullptr);
    EXPECT_EQ(FormConstantsUtil::GetLiveFormActiveState("02"), nullptr);
    EXPECT_EQ(FormConstantsUtil::GetLiveFormActiveState("30"), nullptr);
    EXPECT_EQ(FormConstantsUtil::GetLiveFormActiveState("001"), nullptr);
}

/**
 * @tc.name: IsLiveFormSupportLauncher_001
 * @tc.desc: Verify launcher support for valid and invalid live form statuses.
 * @tc.type: FUNC
 */
HWTEST_F(FormConstantsTest, IsLiveFormSupportLauncher_001, TestSize.Level1)
{
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("00"));
    EXPECT_TRUE(FormConstantsUtil::IsLiveFormSupportLauncher("01"));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("10"));
    EXPECT_TRUE(FormConstantsUtil::IsLiveFormSupportLauncher("11"));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("20"));
    EXPECT_TRUE(FormConstantsUtil::IsLiveFormSupportLauncher("21"));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher(""));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("02"));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("31"));
    EXPECT_FALSE(FormConstantsUtil::IsLiveFormSupportLauncher("011"));
}

/**
 * @tc.name: IsConditionRefreshType_001
 * @tc.desc: Verify only network-change refresh uses the conditional refresh path.
 * @tc.type: FUNC
 */
HWTEST_F(FormConstantsTest, IsConditionRefreshType_001, TestSize.Level1)
{
    EXPECT_TRUE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_NETWORKCHANGED));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_DEFAULT));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_HOST));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_VISIABLE));
}
}  // namespace
