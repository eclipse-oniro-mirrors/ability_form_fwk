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

#include "inner/mock_ui_extension_context.h"

#include <gtest/gtest.h>
#include "fms_log_wrapper.h"
#include "ui_extension_context.h"

namespace {
    bool g_mockGetWindowReturnNullptr = false;
    OHOS::Rosen::WMError g_mockSetBackgroundColorRet = OHOS::Rosen::WMError::WM_OK;
}

void MockGetWindow(bool returnNullptr)
{
    g_mockGetWindowReturnNullptr = returnNullptr;
}

void MockSetBackgroundColor(OHOS::Rosen::WMError mockRet)
{
    g_mockSetBackgroundColorRet = mockRet;
}

void ResetWindowBackgroundColorMocks()
{
    g_mockGetWindowReturnNullptr = false;
    g_mockSetBackgroundColorRet = OHOS::Rosen::WMError::WM_OK;
}

namespace OHOS {
namespace AbilityRuntime {

#ifdef SUPPORT_SCREEN
sptr<Rosen::Window> UIExtensionContext::GetWindow()
{
    GTEST_LOG_(INFO) << "Mock UIExtensionContext::GetWindow called, returnNullptr=" << g_mockGetWindowReturnNullptr;
    if (g_mockGetWindowReturnNullptr) {
        return nullptr;
    }
    // Return a mock Window subclass whose SetBackgroundColor returns the mocked value.
    class MockWindow : public Rosen::Window {
    public:
        MockWindow() = default;
        ~MockWindow() override = default;
        Rosen::WMError SetBackgroundColor(const std::string& color) override
        {
            GTEST_LOG_(INFO) << "MockWindow::SetBackgroundColor color=" << color;
            return g_mockSetBackgroundColorRet;
        }
    };
    return sptr<Rosen::Window>(new MockWindow());
}
#endif // SUPPORT_SCREEN

} // namespace AbilityRuntime
} // namespace OHOS
