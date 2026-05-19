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

#define private public
#define protected public
#include "form_custom_config.h"
#undef private
#undef protected

#include "message_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class FormCustomConfigTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Marshalling_001
 * @tc.desc: Test Marshalling with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Marshalling_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_001 starts";
    FormCustomConfig config;
    config.bundleName = "com.example.test";
    config.moduleName = "entry";
    config.abilityName = "MainAbility";
    config.formName = "widget";
    config.relatedBundleName = "com.example.related";
    config.isShowInFormCenter = true;
    config.isRepeatAdditionSupported = false;

    Parcel parcel;
    EXPECT_TRUE(config.Marshalling(parcel));
    GTEST_LOG_(INFO) << "Marshalling_001 ends";
}

/**
 * @tc.name: ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel with valid parcel data.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, ReadFromParcel_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_001 starts";
    FormCustomConfig srcConfig;
    srcConfig.bundleName = "com.example.test";
    srcConfig.moduleName = "entry";
    srcConfig.abilityName = "MainAbility";
    srcConfig.formName = "widget";
    srcConfig.relatedBundleName = "com.example.related";
    srcConfig.isShowInFormCenter = true;
    srcConfig.isRepeatAdditionSupported = false;

    Parcel parcel;
    ASSERT_TRUE(srcConfig.Marshalling(parcel));

    FormCustomConfig destConfig;
    EXPECT_TRUE(destConfig.ReadFromParcel(parcel));
    EXPECT_EQ(destConfig.bundleName, "com.example.test");
    EXPECT_EQ(destConfig.moduleName, "entry");
    EXPECT_EQ(destConfig.abilityName, "MainAbility");
    EXPECT_EQ(destConfig.formName, "widget");
    EXPECT_EQ(destConfig.relatedBundleName, "com.example.related");
    EXPECT_TRUE(destConfig.isShowInFormCenter);
    EXPECT_FALSE(destConfig.isRepeatAdditionSupported);
    GTEST_LOG_(INFO) << "ReadFromParcel_001 ends";
}

/**
 * @tc.name: ReadFromParcel_002
 * @tc.desc: Test ReadFromParcel with empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, ReadFromParcel_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_002 starts";
    Parcel parcel;
    FormCustomConfig config;
    EXPECT_FALSE(config.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_002 ends";
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: Test Unmarshalling with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Unmarshalling_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unmarshalling_001 starts";
    FormCustomConfig srcConfig;
    srcConfig.bundleName = "com.test.bundle";
    srcConfig.moduleName = "module";
    srcConfig.abilityName = "Ability";
    srcConfig.formName = "Form";
    srcConfig.relatedBundleName = "com.test.related";
    srcConfig.isShowInFormCenter = false;
    srcConfig.isRepeatAdditionSupported = true;

    Parcel parcel;
    ASSERT_TRUE(srcConfig.Marshalling(parcel));

    FormCustomConfig *destConfig = FormCustomConfig::Unmarshalling(parcel);
    ASSERT_NE(destConfig, nullptr);
    EXPECT_EQ(destConfig->bundleName, "com.test.bundle");
    EXPECT_EQ(destConfig->moduleName, "module");
    EXPECT_EQ(destConfig->abilityName, "Ability");
    EXPECT_EQ(destConfig->formName, "Form");
    EXPECT_EQ(destConfig->relatedBundleName, "com.test.related");
    EXPECT_FALSE(destConfig->isShowInFormCenter);
    EXPECT_TRUE(destConfig->isRepeatAdditionSupported);
    delete destConfig;
    GTEST_LOG_(INFO) << "Unmarshalling_001 ends";
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: Test Unmarshalling with empty parcel returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Unmarshalling_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unmarshalling_002 starts";
    Parcel parcel;
    FormCustomConfig *config = FormCustomConfig::Unmarshalling(parcel);
    EXPECT_EQ(config, nullptr);
    GTEST_LOG_(INFO) << "Unmarshalling_002 ends";
}

/**
 * @tc.name: Marshalling_RoundTrip_001
 * @tc.desc: Test Marshalling/Unmarshalling round trip with default values.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Marshalling_RoundTrip_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_001 starts";
    FormCustomConfig srcConfig;
    Parcel parcel;
    ASSERT_TRUE(srcConfig.Marshalling(parcel));

    FormCustomConfig *destConfig = FormCustomConfig::Unmarshalling(parcel);
    ASSERT_NE(destConfig, nullptr);
    EXPECT_EQ(destConfig->bundleName, "");
    EXPECT_EQ(destConfig->moduleName, "");
    EXPECT_EQ(destConfig->abilityName, "");
    EXPECT_EQ(destConfig->formName, "");
    EXPECT_EQ(destConfig->relatedBundleName, "");
    EXPECT_TRUE(destConfig->isShowInFormCenter);
    EXPECT_TRUE(destConfig->isRepeatAdditionSupported);
    delete destConfig;
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_001 ends";
}

/**
 * @tc.name: Marshalling_RoundTrip_002
 * @tc.desc: Test round trip with all bool combinations.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Marshalling_RoundTrip_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_002 starts";
    FormCustomConfig srcConfig;
    srcConfig.bundleName = "bundle";
    srcConfig.isShowInFormCenter = false;
    srcConfig.isRepeatAdditionSupported = false;

    Parcel parcel;
    ASSERT_TRUE(srcConfig.Marshalling(parcel));

    FormCustomConfig *destConfig = FormCustomConfig::Unmarshalling(parcel);
    ASSERT_NE(destConfig, nullptr);
    EXPECT_FALSE(destConfig->isShowInFormCenter);
    EXPECT_FALSE(destConfig->isRepeatAdditionSupported);
    delete destConfig;
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_002 ends";
}

/**
 * @tc.name: Marshalling_002
 * @tc.desc: Verify Marshalling with all string fields populated and booleans set to false.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, Marshalling_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_002 start";
    FormCustomConfig config;
    config.bundleName = "com.example.longbundlename.test";
    config.moduleName = "entry_module";
    config.abilityName = "EntryFormAbility";
    config.formName = "test_form_widget";
    config.relatedBundleName = "com.related.bundle";
    config.isShowInFormCenter = false;
    config.isRepeatAdditionSupported = false;
    Parcel parcel;
    auto result = config.Marshalling(parcel);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "Marshalling_002 end";
}

/**
 * @tc.name: ReadFromParcel_003
 * @tc.desc: Verify ReadFromParcel round-trip with all fields including relatedBundleName.
 * @tc.type: FUNC
 */
HWTEST_F(FormCustomConfigTest, ReadFromParcel_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_003 start";
    FormCustomConfig src;
    src.bundleName = "com.test.full";
    src.moduleName = "module";
    src.abilityName = "Ability";
    src.formName = "Form";
    src.relatedBundleName = "com.related";
    src.isShowInFormCenter = false;
    src.isRepeatAdditionSupported = true;
    Parcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));
    FormCustomConfig dest;
    EXPECT_TRUE(dest.ReadFromParcel(parcel));
    EXPECT_EQ(dest.bundleName, src.bundleName);
    EXPECT_EQ(dest.moduleName, src.moduleName);
    EXPECT_EQ(dest.abilityName, src.abilityName);
    EXPECT_EQ(dest.formName, src.formName);
    EXPECT_EQ(dest.relatedBundleName, src.relatedBundleName);
    EXPECT_EQ(dest.isShowInFormCenter, src.isShowInFormCenter);
    EXPECT_EQ(dest.isRepeatAdditionSupported, src.isRepeatAdditionSupported);
    GTEST_LOG_(INFO) << "ReadFromParcel_003 end";
}
