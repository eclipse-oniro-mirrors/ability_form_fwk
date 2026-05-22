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
#include "form_record_filter.h"
#undef private
#undef protected

#include "message_parcel.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class FormRecordFilterTest : public testing::Test {
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
HWTEST_F(FormRecordFilterTest, Marshalling_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_001 starts";
    FormRecordFilter filter;
    filter.bundleName = "com.example.test";
    filter.moduleName = "entry";
    filter.abilityName = "MainAbility";
    filter.formName = "widget";

    Parcel parcel;
    EXPECT_TRUE(filter.Marshalling(parcel));
    GTEST_LOG_(INFO) << "Marshalling_001 ends";
}

/**
 * @tc.name: Marshalling_002
 * @tc.desc: Test Marshalling with all fields populated.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Marshalling_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_002 starts";
    FormRecordFilter filter;
    filter.bundleName = "com.example.longbundlename.test";
    filter.moduleName = "entry_module";
    filter.abilityName = "EntryFormAbility";
    filter.formName = "test_form_widget";
    
    Parcel parcel;
    EXPECT_TRUE(filter.Marshalling(parcel));
    GTEST_LOG_(INFO) << "Marshalling_002 ends";
}

/**
 * @tc.name: Marshalling_003
 * @tc.desc: Test Marshalling with empty strings.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Marshalling_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_003 starts";
    FormRecordFilter filter;
    filter.bundleName = "";
    filter.moduleName = "";
    filter.abilityName = "";
    filter.formName = "";
    
    Parcel parcel;
    EXPECT_TRUE(filter.Marshalling(parcel));
    GTEST_LOG_(INFO) << "Marshalling_003 ends";
}

/**
 * @tc.name: ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel with valid parcel data.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_001 starts";
    FormRecordFilter srcFilter;
    srcFilter.bundleName = "com.example.test";
    srcFilter.moduleName = "entry";
    srcFilter.abilityName = "MainAbility";
    srcFilter.formName = "widget";

    Parcel parcel;
    ASSERT_TRUE(srcFilter.Marshalling(parcel));

    FormRecordFilter destFilter;
    EXPECT_TRUE(destFilter.ReadFromParcel(parcel));
    EXPECT_EQ(destFilter.bundleName, "com.example.test");
    EXPECT_EQ(destFilter.moduleName, "entry");
    EXPECT_EQ(destFilter.abilityName, "MainAbility");
    EXPECT_EQ(destFilter.formName, "widget");
    GTEST_LOG_(INFO) << "ReadFromParcel_001 ends";
}

/**
 * @tc.name: ReadFromParcel_002
 * @tc.desc: Test ReadFromParcel with empty parcel.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_002 starts";
    Parcel parcel;
    FormRecordFilter filter;
    EXPECT_FALSE(filter.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_002 ends";
}

/**
 * @tc.name: ReadFromParcel_003
 * @tc.desc: Test ReadFromParcel with partial data.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_003 starts";
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("com.test.bundle"));
    // Missing other fields - should fail
    FormRecordFilter filter;
    EXPECT_FALSE(filter.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_003 ends";
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: Test Unmarshalling with valid data.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Unmarshalling_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unmarshalling_001 starts";
    FormRecordFilter srcFilter;
    srcFilter.bundleName = "com.test.bundle";
    srcFilter.moduleName = "module";
    srcFilter.abilityName = "Ability";
    srcFilter.formName = "Form";

    Parcel parcel;
    ASSERT_TRUE(srcFilter.Marshalling(parcel));

    FormRecordFilter *destFilter = FormRecordFilter::Unmarshalling(parcel);
    ASSERT_NE(destFilter, nullptr);
    EXPECT_EQ(destFilter->bundleName, "com.test.bundle");
    EXPECT_EQ(destFilter->moduleName, "module");
    EXPECT_EQ(destFilter->abilityName, "Ability");
    EXPECT_EQ(destFilter->formName, "Form");
    delete destFilter;
    GTEST_LOG_(INFO) << "Unmarshalling_001 ends";
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: Test Unmarshalling with empty parcel returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Unmarshalling_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unmarshalling_002 starts";
    Parcel parcel;
    FormRecordFilter *filter = FormRecordFilter::Unmarshalling(parcel);
    EXPECT_EQ(filter, nullptr);
    GTEST_LOG_(INFO) << "Unmarshalling_002 ends";
}

/**
 * @tc.name: Marshalling_RoundTrip_001
 * @tc.desc: Test Marshalling/Unmarshalling round trip with default values.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Marshalling_RoundTrip_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_001 starts";
    FormRecordFilter srcFilter;
    Parcel parcel;
    ASSERT_TRUE(srcFilter.Marshalling(parcel));

    FormRecordFilter *destFilter = FormRecordFilter::Unmarshalling(parcel);
    ASSERT_NE(destFilter, nullptr);
    EXPECT_EQ(destFilter->bundleName, "");
    EXPECT_EQ(destFilter->moduleName, "");
    EXPECT_EQ(destFilter->abilityName, "");
    EXPECT_EQ(destFilter->formName, "");
    delete destFilter;
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_001 ends";
}

/**
 * @tc.name: Marshalling_RoundTrip_002
 * @tc.desc: Test round trip with all fields populated.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Marshalling_RoundTrip_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_002 starts";
    FormRecordFilter srcFilter;
    srcFilter.bundleName = "bundle";
    srcFilter.moduleName = "module";
    srcFilter.abilityName = "ability";
    srcFilter.formName = "form";

    Parcel parcel;
    ASSERT_TRUE(srcFilter.Marshalling(parcel));

    FormRecordFilter *destFilter = FormRecordFilter::Unmarshalling(parcel);
    ASSERT_NE(destFilter, nullptr);
    EXPECT_EQ(destFilter->bundleName, "bundle");
    EXPECT_EQ(destFilter->moduleName, "module");
    EXPECT_EQ(destFilter->abilityName, "ability");
    EXPECT_EQ(destFilter->formName, "form");
    delete destFilter;
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_002 ends";
}

/**
 * @tc.name: Marshalling_RoundTrip_003
 * @tc.desc: Test round trip with Chinese characters.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, Marshalling_RoundTrip_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_003 starts";
    FormRecordFilter srcFilter;
    srcFilter.bundleName = "com.example.测试";
    srcFilter.moduleName = "模块";
    srcFilter.abilityName = "能力";
    srcFilter.formName = "卡片";

    Parcel parcel;
    ASSERT_TRUE(srcFilter.Marshalling(parcel));

    FormRecordFilter *destFilter = FormRecordFilter::Unmarshalling(parcel);
    ASSERT_NE(destFilter, nullptr);
    EXPECT_EQ(destFilter->bundleName, "com.example.测试");
    EXPECT_EQ(destFilter->moduleName, "模块");
    EXPECT_EQ(destFilter->abilityName, "能力");
    EXPECT_EQ(destFilter->formName, "卡片");
    delete destFilter;
    GTEST_LOG_(INFO) << "Marshalling_RoundTrip_003 ends";
}

/**
 * @tc.name: ReadFromParcel_004
 * @tc.desc: Test ReadFromParcel sequentially reads all four fields.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_004 starts";
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("bundle1"));
    parcel.WriteString16(Str8ToStr16("module1"));
    parcel.WriteString16(Str8ToStr16("ability1"));
    parcel.WriteString16(Str8ToStr16("form1"));
    
    FormRecordFilter filter;
    EXPECT_TRUE(filter.ReadFromParcel(parcel));
    EXPECT_EQ(filter.bundleName, "bundle1");
    EXPECT_EQ(filter.moduleName, "module1");
    EXPECT_EQ(filter.abilityName, "ability1");
    EXPECT_EQ(filter.formName, "form1");
    GTEST_LOG_(INFO) << "ReadFromParcel_004 ends";
}

/**
 * @tc.name: ReadFromParcel_005
 * @tc.desc: Test ReadFromParcel fails when moduleName read fails.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_005 starts";
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("bundle"));
    // moduleName missing - should fail
    
    FormRecordFilter filter;
    EXPECT_FALSE(filter.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_005 ends";
}

/**
 * @tc.name: ReadFromParcel_006
 * @tc.desc: Test ReadFromParcel fails when abilityName read fails.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_006 starts";
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("bundle"));
    parcel.WriteString16(Str8ToStr16("module"));
    // abilityName missing - should fail
    
    FormRecordFilter filter;
    EXPECT_FALSE(filter.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_006 ends";
}

/**
 * @tc.name: ReadFromParcel_007
 * @tc.desc: Test ReadFromParcel fails when formName read fails.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordFilterTest, ReadFromParcel_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_007 starts";
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("bundle"));
    parcel.WriteString16(Str8ToStr16("module"));
    parcel.WriteString16(Str8ToStr16("ability"));
    // formName missing - should fail
    
    FormRecordFilter filter;
    EXPECT_FALSE(filter.ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_007 ends";
}