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

#include "form_edit_extension_context.h"
#include "inner/mock_ui_extension_context.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;

namespace {
constexpr const char *VALID_COLOR_RRGGBB = "#FF0000";
constexpr const char *VALID_COLOR_AARRGGBB = "#80FF0000";
constexpr const char *COLOR_WHITE_OPAQUE = "#FFFFFFFF";
constexpr const char *COLOR_TRANSPARENT = "#00FFFFFF";
}

class FmsFormEditExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void FmsFormEditExtensionContextTest::SetUpTestCase(void) {}

void FmsFormEditExtensionContextTest::TearDownTestCase(void) {}

void FmsFormEditExtensionContextTest::SetUp()
{
    ResetWindowBackgroundColorMocks();
}

void FmsFormEditExtensionContextTest::TearDown()
{
    ResetWindowBackgroundColorMocks();
}

/**
 * @tc.name: SetWindowBackgroundColor_001
 * @tc.desc: Verify SetWindowBackgroundColor with valid #RRGGBB color when window is available and
 *           SetBackgroundColor returns WM_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_001 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);
    bool result = context.SetWindowBackgroundColor(VALID_COLOR_RRGGBB);
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_001 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_002
 * @tc.desc: Verify SetWindowBackgroundColor with valid #AARRGGBB color when window is available and
 *           SetBackgroundColor returns WM_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_002 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);
    bool result = context.SetWindowBackgroundColor(VALID_COLOR_AARRGGBB);
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_002 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_003
 * @tc.desc: Verify SetWindowBackgroundColor returns false when GetWindow returns nullptr
 *           (window not attached yet).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_003 start";
    FormEditExtensionContext context;
    MockGetWindow(true);
    bool result = context.SetWindowBackgroundColor(COLOR_WHITE_OPAQUE);
#ifdef SUPPORT_SCREEN
    EXPECT_FALSE(result);
#else
    // Without SUPPORT_SCREEN, function returns true unconditionally
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_003 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_004
 * @tc.desc: Verify SetWindowBackgroundColor returns false when SetBackgroundColor returns
 *           WM_ERROR_DESTROYED_OBJECT (non-OK error).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_004 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_ERROR_DESTROYED_OBJECT);
    bool result = context.SetWindowBackgroundColor(COLOR_WHITE_OPAQUE);
#ifdef SUPPORT_SCREEN
    EXPECT_FALSE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_004 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_005
 * @tc.desc: Verify SetWindowBackgroundColor returns false when SetBackgroundColor returns
 *           WM_ERROR_INVALID_WINDOW (non-OK error).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_005 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_ERROR_INVALID_WINDOW);
    bool result = context.SetWindowBackgroundColor(COLOR_TRANSPARENT);
#ifdef SUPPORT_SCREEN
    EXPECT_FALSE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_005 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_006
 * @tc.desc: Verify SetWindowBackgroundColor returns true with transparent color string when
 *           window is available and SetBackgroundColor succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_006 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);
    bool result = context.SetWindowBackgroundColor(COLOR_TRANSPARENT);
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_006 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_007
 * @tc.desc: Verify SetWindowBackgroundColor with empty color string. The function does not
 *           validate color format — it passes the string to SetBackgroundColor. Verify behavior
 *           is consistent (returns true when SetBackgroundColor returns WM_OK).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_007 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);
    bool result = context.SetWindowBackgroundColor("");
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_007 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_008
 * @tc.desc: Verify SetWindowBackgroundColor with empty color string when SetBackgroundColor
 *           fails. Should return false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_008 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_ERROR_INVALID_PARAM);
    bool result = context.SetWindowBackgroundColor("");
#ifdef SUPPORT_SCREEN
    EXPECT_FALSE(result);
#else
    EXPECT_TRUE(result);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_008 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_009
 * @tc.desc: Verify multiple sequential calls to SetWindowBackgroundColor with different colors.
 *           Each call should return true when window and SetBackgroundColor are healthy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_009 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);

    bool result1 = context.SetWindowBackgroundColor("#FF0000");
    bool result2 = context.SetWindowBackgroundColor("#00FF00");
    bool result3 = context.SetWindowBackgroundColor("#0000FF");
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    EXPECT_TRUE(result3);
#else
    EXPECT_TRUE(result1);
    EXPECT_TRUE(result2);
    EXPECT_TRUE(result3);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_009 end";
}

/**
 * @tc.name: SetWindowBackgroundColor_010
 * @tc.desc: Verify SetWindowBackgroundColor after window becomes unavailable (nullptr) on
 *           second call. First call succeeds, second call returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWindowBackgroundColor_010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_010 start";
    FormEditExtensionContext context;
    MockGetWindow(false);
    MockSetBackgroundColor(Rosen::WMError::WM_OK);
    bool result1 = context.SetWindowBackgroundColor("#FF0000");
#ifdef SUPPORT_SCREEN
    EXPECT_TRUE(result1);
#else
    EXPECT_TRUE(result1);
#endif

    // Window becomes unavailable
    MockGetWindow(true);
    bool result2 = context.SetWindowBackgroundColor("#00FF00");
#ifdef SUPPORT_SCREEN
    EXPECT_FALSE(result2);
#else
    EXPECT_TRUE(result2);
#endif
    GTEST_LOG_(INFO) << "SetWindowBackgroundColor_010 end";
}

/**
 * @tc.name: FormEditErrorCode_001
 * @tc.desc: Verify FormEditErrorCode enum values match expected constants.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, FormEditErrorCode_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEditErrorCode_001 start";
    EXPECT_EQ(static_cast<int32_t>(FormEditErrorCode::ERROR_OK), 0);
    EXPECT_EQ(static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_PARAM_ERROR), 401);
    EXPECT_EQ(static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_IPC_ERROR), 16500050);
    EXPECT_EQ(static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), 16501000);
    GTEST_LOG_(INFO) << "FormEditErrorCode_001 end";
}

/**
 * @tc.name: SetWant_001
 * @tc.desc: Verify SetWant sets the want member correctly. Access want_ via private=public.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWant_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetWant_001 start";
    FormEditExtensionContext context;
    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("test.action");
    context.SetWant(want);
    EXPECT_NE(context.want_, nullptr);
    EXPECT_EQ(context.want_->GetAction(), "test.action");
    GTEST_LOG_(INFO) << "SetWant_001 end";
}

/**
 * @tc.name: SetWant_002
 * @tc.desc: Verify SetWant with nullptr. want_ should be set to nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEditExtensionContextTest, SetWant_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SetWant_002 start";
    FormEditExtensionContext context;
    context.SetWant(nullptr);
    EXPECT_EQ(context.want_, nullptr);
    GTEST_LOG_(INFO) << "SetWant_002 end";
}
