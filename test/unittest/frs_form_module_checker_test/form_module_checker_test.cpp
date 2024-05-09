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
#include "form_module_checker.h"
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

