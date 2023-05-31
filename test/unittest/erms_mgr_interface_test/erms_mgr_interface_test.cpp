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
#include <gmock/gmock.h>

#include "erms_mgr_param.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class IEcologicalRuleManagerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};
void IEcologicalRuleManagerTest::SetUp()
{}

void IEcologicalRuleManagerTest::TearDown()
{}

using ExperienceRule = OHOS::AppExecFwk::ErmsParams::ExperienceRule;

/**
 * @tc.number: ExperienceRule_ReadFromParcel_0100
 * @tc.name: ReadFromParcel
 * @tc.desc: test ReadFromParcel function
 */
HWTEST_F(IEcologicalRuleManagerTest, ExperienceRule_ReadFromParcel_0100, TestSize.Level1)
{
    ExperienceRule rule;
    Parcel parcel;
    EXPECT_EQ(true, rule.ReadFromParcel(parcel));
}

/**
 * @tc.number: ExperienceRule_Marshalling_0100
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling function
 */
HWTEST_F(IEcologicalRuleManagerTest, ExperienceRule_Marshalling_0100, TestSize.Level1)
{
    ExperienceRule rule;
    Parcel parcel;
    EXPECT_EQ(true, rule.Marshalling(parcel));
}

/**
 * @tc.number: ExperienceRule_Unmarshalling_0100
 * @tc.name: Unmarshalling
 * @tc.desc: test Unmarshalling function
 */
HWTEST_F(IEcologicalRuleManagerTest, ExperienceRule_Unmarshalling_0100, TestSize.Level1)
{
    ExperienceRule rule;
    Parcel parcel;
    EXPECT_NE(nullptr, rule.Unmarshalling(parcel));
}

