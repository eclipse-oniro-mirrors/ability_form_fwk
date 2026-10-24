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
#include <string>

#include "configuration.h"
#include "global_configuration_key.h"
#include "form_constants.h"
#include "form_resource_param.h"
#include "refbase.h"

#define private public
#define protected public
#include "form_observer/form_resource_observer.h"
#undef private
#undef protected

#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormResourceObserverTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

AppExecFwk::Configuration BuildConfigWithLanguage(const std::string &language)
{
    AppExecFwk::Configuration config;
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, language);
    return config;
}

AppExecFwk::Configuration BuildConfigWithColorMode(const std::string &colorMode)
{
    AppExecFwk::Configuration config;
    config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, colorMode);
    return config;
}
}  // namespace

/**
 * @tc.name: FormFwkResourceObserver_Construct_001
 * @tc.desc: Verify constructor sets userId_ to the passed value.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, FormFwkResourceObserver_Construct_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormFwkResourceObserver_Construct_001 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    EXPECT_EQ(observer->userId_, 100);

    GTEST_LOG_(INFO) << "FormFwkResourceObserver_Construct_001 end";
}

/**
 * @tc.name: FormFwkResourceObserver_Construct_002
 * @tc.desc: Verify constructor initializes language_ and colorMode_ from system params.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, FormFwkResourceObserver_Construct_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormFwkResourceObserver_Construct_002 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(0);
    ASSERT_NE(observer, nullptr);
    EXPECT_EQ(observer->language_, FormResourceParam::GetSystemLanguage());
    EXPECT_EQ(observer->colorMode_, FormResourceParam::GetSystemColorMode());

    GTEST_LOG_(INFO) << "FormFwkResourceObserver_Construct_002 end";
}

/**
 * @tc.name: HandleLanguageUpdate_001
 * @tc.desc: Verify HandleLanguageUpdate updates language_ regardless of userId (guard moved to OnConfigurationUpdated).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleLanguageUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleLanguageUpdate_001 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    observer->language_ = "en-US";
    observer->HandleLanguageUpdate(BuildConfigWithLanguage("zh-CN"));
    EXPECT_EQ(observer->language_, "zh-CN");

    GTEST_LOG_(INFO) << "HandleLanguageUpdate_001 end";
}

/**
 * @tc.name: HandleLanguageUpdate_002
 * @tc.desc: Verify HandleLanguageUpdate does nothing when language is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleLanguageUpdate_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "HandleLanguageUpdate_002 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(Constants::DEFAULT_USER_ID);
    ASSERT_NE(observer, nullptr);
    observer->language_ = "en-US";
    observer->HandleLanguageUpdate(BuildConfigWithLanguage(""));
    EXPECT_EQ(observer->language_, "en-US");

    GTEST_LOG_(INFO) << "HandleLanguageUpdate_002 end";
}

/**
 * @tc.name: HandleLanguageUpdate_003
 * @tc.desc: Verify HandleLanguageUpdate does nothing when language unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleLanguageUpdate_003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "HandleLanguageUpdate_003 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(Constants::DEFAULT_USER_ID);
    ASSERT_NE(observer, nullptr);
    observer->language_ = "zh-CN";
    observer->HandleLanguageUpdate(BuildConfigWithLanguage("zh-CN"));
    EXPECT_EQ(observer->language_, "zh-CN");

    GTEST_LOG_(INFO) << "HandleLanguageUpdate_003 end";
}

/**
 * @tc.name: HandleColorModeUpdate_001
 * @tc.desc: Verify HandleColorModeUpdate updates colorMode_ regardless of userId
 * (guard moved to OnConfigurationUpdated).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleColorModeUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleColorModeUpdate_001 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(Constants::DEFAULT_USER_ID);
    ASSERT_NE(observer, nullptr);
    observer->colorMode_ = "light";
    observer->HandleColorModeUpdate(BuildConfigWithColorMode("dark"));
    EXPECT_EQ(observer->colorMode_, "dark");

    GTEST_LOG_(INFO) << "HandleColorModeUpdate_001 end";
}

/**
 * @tc.name: HandleColorModeUpdate_002
 * @tc.desc: Verify HandleColorModeUpdate does nothing when colorMode is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleColorModeUpdate_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "HandleColorModeUpdate_002 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    observer->colorMode_ = "light";
    observer->HandleColorModeUpdate(BuildConfigWithColorMode(""));
    EXPECT_EQ(observer->colorMode_, "light");

    GTEST_LOG_(INFO) << "HandleColorModeUpdate_002 end";
}

/**
 * @tc.name: HandleColorModeUpdate_003
 * @tc.desc: Verify HandleColorModeUpdate does nothing when colorMode unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, HandleColorModeUpdate_003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "HandleColorModeUpdate_003 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    observer->colorMode_ = "dark";
    observer->HandleColorModeUpdate(BuildConfigWithColorMode("dark"));
    EXPECT_EQ(observer->colorMode_, "dark");

    GTEST_LOG_(INFO) << "HandleColorModeUpdate_003 end";
}

/**
 * @tc.name: OnConfigurationUpdated_001
 * @tc.desc: Verify OnConfigurationUpdated triggers language update for default user.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, OnConfigurationUpdated_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnConfigurationUpdated_001 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(Constants::DEFAULT_USER_ID);
    ASSERT_NE(observer, nullptr);
    observer->language_ = "en-US";
    EXPECT_NO_FATAL_FAILURE(observer->OnConfigurationUpdated(BuildConfigWithLanguage("zh-CN")));
    EXPECT_EQ(observer->language_, "zh-CN");

    GTEST_LOG_(INFO) << "OnConfigurationUpdated_001 end";
}

/**
 * @tc.name: OnConfigurationUpdated_002
 * @tc.desc: Verify OnConfigurationUpdated triggers colorMode update for non-default user.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, OnConfigurationUpdated_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnConfigurationUpdated_002 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    observer->colorMode_ = "light";
    EXPECT_NO_FATAL_FAILURE(observer->OnConfigurationUpdated(BuildConfigWithColorMode("dark")));
    EXPECT_EQ(observer->colorMode_, "dark");

    GTEST_LOG_(INFO) << "OnConfigurationUpdated_002 end";
}

/**
 * @tc.name: OnConfigurationUpdated_003
 * @tc.desc: Verify OnConfigurationUpdated does NOT trigger colorMode update for default user.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, OnConfigurationUpdated_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnConfigurationUpdated_003 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(Constants::DEFAULT_USER_ID);
    ASSERT_NE(observer, nullptr);
    observer->colorMode_ = "light";
    EXPECT_NO_FATAL_FAILURE(observer->OnConfigurationUpdated(BuildConfigWithColorMode("dark")));
    EXPECT_EQ(observer->colorMode_, "light");

    GTEST_LOG_(INFO) << "OnConfigurationUpdated_003 end";
}

/**
 * @tc.name: OnConfigurationUpdated_004
 * @tc.desc: Verify OnConfigurationUpdated does NOT trigger language update for non-default user.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormResourceObserverTest, OnConfigurationUpdated_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnConfigurationUpdated_004 start";

    sptr<FormFwkResourceObserver> observer = new (std::nothrow) FormFwkResourceObserver(100);
    ASSERT_NE(observer, nullptr);
    observer->language_ = "en-US";
    EXPECT_NO_FATAL_FAILURE(observer->OnConfigurationUpdated(BuildConfigWithLanguage("zh-CN")));
    EXPECT_EQ(observer->language_, "en-US");

    GTEST_LOG_(INFO) << "OnConfigurationUpdated_004 end";
}
