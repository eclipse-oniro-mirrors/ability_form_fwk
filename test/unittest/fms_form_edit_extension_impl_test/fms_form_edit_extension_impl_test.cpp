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
#include <cstring>

#define private public
#define protected public
#include "js_form_edit_extension_impl.h"
#undef private
#undef protected

#include "form_edit_extension_context.h"
#include "form_constants.h"
#include "global_configuration_key.h"
#include "inner/mock_napi_common_want.h"
#include "res_common.h"
#include "runtime.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;

namespace {
constexpr int32_t COLOR_MODE_NOT_SET = static_cast<int32_t>(OHOS::Global::Resource::ColorMode::COLOR_MODE_NOT_SET);
constexpr int32_t COLOR_MODE_DARK = static_cast<int32_t>(OHOS::Global::Resource::ColorMode::DARK);
constexpr int32_t COLOR_MODE_LIGHT = static_cast<int32_t>(OHOS::Global::Resource::ColorMode::LIGHT);
}

class FmsFormEditExtensionImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    std::unique_ptr<Runtime> runtime;
    std::unique_ptr<JsFormEditExtensionImpl> impl;
    std::shared_ptr<FormEditExtensionContext> context;
    int32_t lastColorMode = COLOR_MODE_NOT_SET;
    bool callbackCalled = false;
};

void FmsFormEditExtensionImplTest::SetUpTestCase(void) {}

void FmsFormEditExtensionImplTest::TearDownTestCase(void) {}

void FmsFormEditExtensionImplTest::SetUp()
{
    ResetUnwrapWantMock();
    Runtime::Options options;
    options.loadAce = false;
    runtime = Runtime::Create(options);
    ASSERT_NE(runtime, nullptr);
    impl = std::make_unique<JsFormEditExtensionImpl>(runtime);
    ASSERT_NE(impl, nullptr);

    context = std::make_shared<FormEditExtensionContext>();
    ASSERT_NE(context, nullptr);
    impl->context_ = context;

    callbackCalled = false;
    lastColorMode = COLOR_MODE_NOT_SET;
    context->RegisterAbilityConfigUpdateCallback(
        [this](AppExecFwk::Configuration &config) {
            callbackCalled = true;
            std::string mode = config.GetItem(
                AppExecFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
            if (mode == "dark") {
                lastColorMode = COLOR_MODE_DARK;
            } else if (mode == "light") {
                lastColorMode = COLOR_MODE_LIGHT;
            }
        });
}

void FmsFormEditExtensionImplTest::TearDown()
{
    impl.reset();
    runtime.reset();
    ResetUnwrapWantMock();
}

/**
 * @tc.name: ProcessOnSessionCreate_ArgcZero_001
 * @tc.desc: Verify ProcessOnSessionCreate when argc is 0, should return early without crash.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ArgcZero_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ArgcZero_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 0;
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ArgcZero_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ArgvNull_001
 * @tc.desc: Verify ProcessOnSessionCreate when argv is nullptr, should return early without crash.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ArgvNull_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ArgvNull_001 start";
    napi_env env = nullptr;
    size_t argc = 1;
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, nullptr, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ArgvNull_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_UnwrapWantFail_001
 * @tc.desc: Verify ProcessOnSessionCreate when UnwrapWant returns false, should return early.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_UnwrapWantFail_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_UnwrapWantFail_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(false);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_UnwrapWantFail_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ColorModeNotSet_001
 * @tc.desc: Verify ProcessOnSessionCreate when colorMode is COLOR_MODE_NOT_SET, should return early
 *           without calling SetAbilityColorMode.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ColorModeNotSet_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeNotSet_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, COLOR_MODE_NOT_SET);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeNotSet_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ColorModeInvalidLow_001
 * @tc.desc: Verify ProcessOnSessionCreate when colorMode is less than DARK (e.g. -2),
 *           should return early with warning log.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ColorModeInvalidLow_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeInvalidLow_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, -2);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeInvalidLow_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ColorModeInvalidHigh_001
 * @tc.desc: Verify ProcessOnSessionCreate when colorMode is greater than LIGHT (e.g. 2),
 *           should return early with warning log.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ColorModeInvalidHigh_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeInvalidHigh_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, 2);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeInvalidHigh_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ContextNull_001
 * @tc.desc: Verify ProcessOnSessionCreate when context_ is nullptr, should return early with error log.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ContextNull_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ContextNull_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    impl->context_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_FALSE(callbackCalled);
    impl->context_ = context;
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ContextNull_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_DarkMode_001
 * @tc.desc: Verify ProcessOnSessionCreate with valid DARK colorMode, should call SetAbilityColorMode
 *           and trigger the config update callback with "dark".
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_DarkMode_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_DarkMode_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(lastColorMode, COLOR_MODE_DARK);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_DarkMode_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_LightMode_001
 * @tc.desc: Verify ProcessOnSessionCreate with valid LIGHT colorMode, should call SetAbilityColorMode
 *           and trigger the config update callback with "light".
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_LightMode_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_LightMode_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, COLOR_MODE_LIGHT);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(lastColorMode, COLOR_MODE_LIGHT);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_LightMode_001 end";
}

/**
 * @tc.name: CallObjectMethod_OnSessionCreate_001
 * @tc.desc: Verify CallObjectMethod with name "onSessionCreate" and jsObj_ is null,
 *           should call ProcessOnSessionCreate then delegate to base which returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, CallObjectMethod_OnSessionCreate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallObjectMethod_OnSessionCreate_001 start";
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    impl->jsObj_ = nullptr;
    auto result = impl->CallObjectMethod("onSessionCreate", &argv, argc, false);
    EXPECT_EQ(result, nullptr);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(lastColorMode, COLOR_MODE_DARK);
    GTEST_LOG_(INFO) << "CallObjectMethod_OnSessionCreate_001 end";
}

/**
 * @tc.name: CallObjectMethod_NonSessionCreate_001
 * @tc.desc: Verify CallObjectMethod with a non-onSessionCreate method name and jsObj_ is null,
 *           should NOT call ProcessOnSessionCreate, base returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, CallObjectMethod_NonSessionCreate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallObjectMethod_NonSessionCreate_001 start";
    napi_value argv = nullptr;
    size_t argc = 0;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    impl->jsObj_ = nullptr;
    auto result = impl->CallObjectMethod("onCreate", &argv, argc, false);
    EXPECT_EQ(result, nullptr);
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "CallObjectMethod_NonSessionCreate_001 end";
}

/**
 * @tc.name: CallObjectMethod_NullName_001
 * @tc.desc: Verify CallObjectMethod with null name, should not trigger ProcessOnSessionCreate,
 *           base returns nullptr when jsObj_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, CallObjectMethod_NullName_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "CallObjectMethod_NullName_001 start";
    napi_value argv = nullptr;
    size_t argc = 0;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    impl->jsObj_ = nullptr;
    auto result = impl->CallObjectMethod(nullptr, &argv, argc, false);
    EXPECT_EQ(result, nullptr);
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "CallObjectMethod_NullName_001 end";
}

/**
 * @tc.name: CallObjectMethod_OnSessionCreate_ArgcZero_001
 * @tc.desc: Verify CallObjectMethod with "onSessionCreate" but argc=0,
 *           ProcessOnSessionCreate returns early due to argc check, base returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, CallObjectMethod_OnSessionCreate_ArgcZero_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallObjectMethod_OnSessionCreate_ArgcZero_001 start";
    napi_value argv = nullptr;
    size_t argc = 0;
    MockUnwrapWant(true, COLOR_MODE_DARK);
    impl->jsObj_ = nullptr;
    auto result = impl->CallObjectMethod("onSessionCreate", &argv, argc, false);
    EXPECT_EQ(result, nullptr);
    EXPECT_FALSE(callbackCalled);
    GTEST_LOG_(INFO) << "CallObjectMethod_OnSessionCreate_ArgcZero_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ColorModeBoundaryDark_001
 * @tc.desc: Verify ProcessOnSessionCreate with colorMode exactly 0 (DARK boundary),
 *           should call SetAbilityColorMode successfully.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ColorModeBoundaryDark_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeBoundaryDark_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, 0);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(lastColorMode, COLOR_MODE_DARK);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeBoundaryDark_001 end";
}

/**
 * @tc.name: ProcessOnSessionCreate_ColorModeBoundaryLight_001
 * @tc.desc: Verify ProcessOnSessionCreate with colorMode exactly 1 (LIGHT boundary),
 *           should call SetAbilityColorMode successfully.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionImplTest, ProcessOnSessionCreate_ColorModeBoundaryLight_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeBoundaryLight_001 start";
    napi_env env = nullptr;
    napi_value argv = nullptr;
    size_t argc = 1;
    MockUnwrapWant(true, 1);
    EXPECT_NO_FATAL_FAILURE(impl->ProcessOnSessionCreate(env, &argv, argc));
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(lastColorMode, COLOR_MODE_LIGHT);
    GTEST_LOG_(INFO) << "ProcessOnSessionCreate_ColorModeBoundaryLight_001 end";
}
