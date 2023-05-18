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
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

class CallerInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void CallerInfoTest::SetUpTestCase(void)
{}

void CallerInfoTest::TearDownTestCase(void)
{}

void CallerInfoTest::SetUp(void)
{}

void CallerInfoTest::TearDown(void)
{}

/**
 * @tc.number: CallerInfoTest_ReadFromParcel_0100
 * @tc.name: ReadFromParcel
 * @tc.desc: test ReadFromParcel function
 */
HWTEST_F(CallerInfoTest, CallerInfoTest_ReadFromParcel_0100, TestSize.Level1)
{
    ErmsParams::CallerInfo callerInfo;
    Parcel parcel;
    EXPECT_EQ(true, callerInfo.ReadFromParcel(parcel));
}

/**
 * @tc.number: CallerInfo_Marshalling_0100
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling function
 */
HWTEST_F(CallerInfoTest, CallerInfo_Marshalling_0100, TestSize.Level1)
{
    ErmsParams::CallerInfo callerInfo;
    Parcel parcel;
    EXPECT_EQ(true, callerInfo.Marshalling(parcel));
}

/**
 * @tc.number: CallerInfo_Unmarshalling_0100
 * @tc.name: Unmarshalling
 * @tc.desc: test Unmarshalling function
 */
HWTEST_F(CallerInfoTest, CallerInfo_Unmarshalling_0100, TestSize.Level1)
{
    ErmsParams::CallerInfo callerInfo;
    Parcel parcel;
    EXPECT_NE(nullptr, callerInfo.Unmarshalling(parcel));
}

