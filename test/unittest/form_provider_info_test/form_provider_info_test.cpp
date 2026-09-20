/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "form_provider_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormProviderInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormProviderInfoTest::SetUpTestCase() {}
void FormProviderInfoTest::TearDownTestCase() {}
void FormProviderInfoTest::SetUp() {}
void FormProviderInfoTest::TearDown() {}

/**
 * @tc.number: FormProviderInfo_ReadFromParcel_001
 * @tc.name: ReadFromParcel
 * @tc.desc: Verify whether the ReadFromParcel interface is called normally
 */
HWTEST_F(FormProviderInfoTest, FormProviderInfo_ReadFromParcel_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderInfo_ReadFromParcel_001 starts";
    FormProviderInfo formProviderInfo;
    FormProviderData formProvicerData;
    formProvicerData.imageDataState_ = FormProviderData::IMAGE_DATA_STATE_REMOVED;
    Parcel parcel;
    parcel.WriteParcelable(&formProvicerData);
    auto result = formProviderInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormProviderInfo_ReadFromParcel_001 ends";
}

/**
 * @tc.number: FormProviderInfo_Marshalling_001
 * @tc.name: Marshalling
 * @tc.desc: Verify whether the Marshalling interface is called normally
 */
HWTEST_F(FormProviderInfoTest, FormProviderInfo_Marshalling_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderInfo_Marshalling_001 starts";
    FormProviderInfo formProviderInfo;
    Parcel parcel;
    auto relust = formProviderInfo.Marshalling(parcel);
    EXPECT_TRUE(relust);
    GTEST_LOG_(INFO) << "FormProviderInfo_Marshalling_001 ends";
}

/**
 * @tc.number: FormProviderInfo_NeedCache_001
 * @tc.name: NeedCache
 * @tc.desc: Verify whether the NeedCache interface is called normally
 */
HWTEST_F(FormProviderInfoTest, FormProviderInfo_NeedCache_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderInfo_NeedCache_001 starts";
    FormProviderInfo formProviderInfo;
    auto result = formProviderInfo.NeedCache();
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FormProviderInfo_NeedCache_001 ends";
}
} // namespace
