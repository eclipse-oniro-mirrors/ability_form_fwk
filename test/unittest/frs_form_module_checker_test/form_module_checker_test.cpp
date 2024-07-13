/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#define private public
#include "form_module_checker.h"
#undef private
#include "utils/log.h"

class FormModuleCheckerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        GTEST_LOG_(INFO) << "FormModuleCheckerTest SetUpTestCase";
    }

    static void TearDownTestCase()
    {
        GTEST_LOG_(INFO) << "FormModuleCheckerTest TearDownTestCase";
    }

    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(FormModuleCheckerTest, Test001, testing::ext::TestSize.Level1)
{
    std::unique_ptr<ApiAllowListChecker> apiAllowListFilter = nullptr;
    std::shared_ptr<FormModuleChecker> formChecker = std::make_shared<FormModuleChecker>();
    bool ret = formChecker->CheckModuleLoadable("effectKit", apiAllowListFilter);
    ASSERT_TRUE(ret);
    ASSERT_TRUE((*apiAllowListFilter)("effectKit.a"));
    ASSERT_TRUE((*apiAllowListFilter)("effectKit.b"));
    ASSERT_TRUE((*apiAllowListFilter)("effectKit.xx"));
    ASSERT_FALSE((*apiAllowListFilter)("bad-effectKit.xx"));
}

HWTEST_F(FormModuleCheckerTest, Test002, testing::ext::TestSize.Level1)
{
    std::unique_ptr<ApiAllowListChecker> apiAllowListFilter = nullptr;
    std::shared_ptr<FormModuleChecker> formChecker = std::make_shared<FormModuleChecker>();
    bool ret = formChecker->CheckModuleLoadable("multimedia.image", apiAllowListFilter);
    ASSERT_TRUE(ret);
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.PixelMapFormat.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.Size.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.AlphaType.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.ScaleMode.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.Region.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.PositionArea.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.ImageInfo.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.InitializationOptions.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.SourceOptions.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.createImageSource"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.PixelMap.a"));
    ASSERT_TRUE((*apiAllowListFilter)("multimedia.image.ImageSource.a"));
    ASSERT_FALSE((*apiAllowListFilter)("multimedia.image.image.a"));
}

/**
 * @tc.name: Test003
 * @tc.desc: test CheckModuleLoadable function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test003, testing::ext::TestSize.Level1)
{
    std::unique_ptr<ApiAllowListChecker> apiAllowListFilter = nullptr;
    std::shared_ptr<FormModuleChecker> formChecker = std::make_shared<FormModuleChecker>();
    ASSERT_TRUE(formChecker != nullptr);
    bool ret = formChecker->CheckModuleLoadable("i18n", apiAllowListFilter);
    EXPECT_TRUE(ret);
    EXPECT_TRUE((*apiAllowListFilter)("i18n"));
    EXPECT_TRUE((*apiAllowListFilter)("i18n.System"));
    EXPECT_TRUE((*apiAllowListFilter)("i18n.System.getSystemLanguage"));
    EXPECT_TRUE((*apiAllowListFilter)("i18n.System.is24HourClock"));
    EXPECT_FALSE((*apiAllowListFilter)("i18n.System.xx"));
    EXPECT_FALSE((*apiAllowListFilter)("i18n.System.getSystemLanguage.sss"));
    EXPECT_FALSE((*apiAllowListFilter)("i18n.System.is24HourClock.sss"));
}

/**
 * @tc.name: Test004
 * @tc.desc: test CheckModuleLoadable function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test004, testing::ext::TestSize.Level1)
{
    std::unique_ptr<ApiAllowListChecker> apiAllowListFilter = nullptr;
    std::shared_ptr<FormModuleChecker> formChecker = std::make_shared<FormModuleChecker>();
    ASSERT_TRUE(formChecker != nullptr);
    bool ret = formChecker->CheckModuleLoadable("intl", apiAllowListFilter);
    EXPECT_TRUE(ret);
    EXPECT_TRUE((*apiAllowListFilter)("intl"));
    EXPECT_TRUE((*apiAllowListFilter)("intl.Locale"));
    EXPECT_TRUE((*apiAllowListFilter)("intl.Locale.sss"));
    EXPECT_TRUE((*apiAllowListFilter)("intl.Locale.."));
    EXPECT_TRUE((*apiAllowListFilter)("intl.DateTimeFormat"));
    EXPECT_TRUE((*apiAllowListFilter)("intl.DateTimeFormat.xx"));
    EXPECT_FALSE((*apiAllowListFilter)("intl.xxx"));
    EXPECT_FALSE((*apiAllowListFilter)("intl.System"));
}

/**
 * @tc.name: Test005
 * @tc.desc: test CheckModuleLoadable function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test005, testing::ext::TestSize.Level1)
{
    std::unique_ptr<ApiAllowListChecker> apiAllowListFilter = nullptr;
    std::shared_ptr<FormModuleChecker> formChecker = std::make_shared<FormModuleChecker>();
    ASSERT_TRUE(formChecker != nullptr);
    bool ret = formChecker->CheckModuleLoadable("font", apiAllowListFilter);
    EXPECT_TRUE(ret);
    EXPECT_TRUE((*apiAllowListFilter)("font"));
    EXPECT_TRUE((*apiAllowListFilter)("font.registerFont"));
    EXPECT_FALSE((*apiAllowListFilter)("font.registerFon.xx"));
    EXPECT_FALSE((*apiAllowListFilter)("font.xx"));
}

/**
 * @tc.name: Test006
 * @tc.desc: test IsModuelAllowToLoad function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test006, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::IsModuelAllowToLoad("i18n"));
    EXPECT_TRUE(FormModuleChecker::IsModuelAllowToLoad("intl"));
    EXPECT_TRUE(FormModuleChecker::IsModuelAllowToLoad("effectKit"));
    EXPECT_TRUE(FormModuleChecker::IsModuelAllowToLoad("font"));
    EXPECT_TRUE(FormModuleChecker::IsModuelAllowToLoad("multimedia.image"));
    EXPECT_FALSE(FormModuleChecker::IsModuelAllowToLoad("multimedia"));
    EXPECT_FALSE(FormModuleChecker::IsModuelAllowToLoad("abc"));
    EXPECT_FALSE(FormModuleChecker::IsModuelAllowToLoad("xyz"));
}

/**
 * @tc.name: Test007
 * @tc.desc: test CheckApiAllowList function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test007, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("i18n"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("i18n.System"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("i18n.System.getSystemLanguage"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("i18n.System.is24HourClock"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("i18n.System.xx"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("i18n.System.getSystemLanguage.sss"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("i18n.System.is24HourClock.sss"));
}

/**
 * @tc.name: Test008
 * @tc.desc: test CheckApiAllowList function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test008, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl.Locale"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl.Locale.sss"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl.Locale.."));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl.DateTimeFormat"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("intl.DateTimeFormat.xx"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("intl.xxx"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("intl.System"));
}

/**
 * @tc.name: Test009
 * @tc.desc: test CheckApiAllowList function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test009, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("effectKit.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("effectKit.b"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("effectKit.xx"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("bad-effectKit.xx"));
}

/**
 * @tc.name: Test010
 * @tc.desc: test CheckApiAllowList function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test010, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("font.registerFont"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("font.a"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("font.ac"));
}

/**
 * @tc.name: Test011
 * @tc.desc: test CheckApiAllowList function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test011, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.PixelMapFormat.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.Size.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.AlphaType.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.ScaleMode.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.Region.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.PositionArea.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.ImageInfo.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.InitializationOptions.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.SourceOptions.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.createImageSource"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.PixelMap.a"));
    EXPECT_TRUE(FormModuleChecker::CheckApiAllowList("multimedia.image.ImageSource.a"));
    EXPECT_FALSE(FormModuleChecker::CheckApiAllowList("multimedia.image.image.a"));
}

/**
 * @tc.name: Test012
 * @tc.desc: test CheckApiWithSuffix function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test012, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("i18n", "i18n.System.getSystemLanguage"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("i18n", "i18n.System.is24HourClock"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("i18n.System.is24HourClock", "i18n.System.is24HourClock"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("i18n.load", "i18n.System.is24HourClock"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("i18n.System.getSystemLanguage", "i18n.System.is24HourClock"));
}

/**
 * @tc.name: Test013
 * @tc.desc: test CheckApiWithSuffix function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test013, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("intl", "intl.Locale.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("intl", "intl.DateTimeFormat.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("intl.Locale", "intl.Locale.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("intl.DateTimeFormat", "intl.DateTimeFormat.*"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("intl.getSystemLanguage", "intl.DateTimeFormat.abc"));
}

/**
 * @tc.name: Test014
 * @tc.desc: test CheckApiWithSuffix function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test014, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("effectKit", "effectKit"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("effectKit", "effectKit.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("effectKit.abc", "effectKit.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("effectKit..*", "effectKit.*"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("intl.effectKit", "effectKit.*"));
}

/**
 * @tc.name: Test015
 * @tc.desc: test CheckApiWithSuffix function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test015, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("font", "font"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("font", "font.registerFont"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("font.", "font.registerFont"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("font..a", "font.registerFont"));
}

/**
 * @tc.name: Test016
 * @tc.desc: test CheckApiWithSuffix function.
 * @tc.type: FUNC
 */
HWTEST_F(FormModuleCheckerTest, Test016, testing::ext::TestSize.Level1)
{
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.PixelMapFormat.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.Size.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.AlphaType.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.ScaleMode.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.Region.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.PositionArea.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.ImageInfo.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.DecodingOptions.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.InitializationOptions.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.SourceOptions.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.createImageSource.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.PixelMap.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.image", "multimedia.image.ImageSource.*"));
    EXPECT_TRUE(FormModuleChecker::CheckApiWithSuffix("multimedia.", "multimedia.image"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("multimedia..", "multimedia.image.PixelMapFormat.*"));
    EXPECT_FALSE(FormModuleChecker::CheckApiWithSuffix("multimedia.abc", "multimedia.image.PixelMapFormat.*"));
}
