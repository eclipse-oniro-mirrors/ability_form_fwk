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

#ifndef INNER_MOCK_UI_EXTENSION_CONTEXT_H
#define INNER_MOCK_UI_EXTENSION_CONTEXT_H

#include <cstdint>
#include "window.h"

// Set mock return for UIExtensionContext::GetWindow()
// If returnNullptr is true, GetWindow returns nullptr.
// Otherwise returns a mock window that uses mockSetBackgroundColorRet.
void MockGetWindow(bool returnNullptr);

// Set mock return for Rosen::Window::SetBackgroundColor
void MockSetBackgroundColor(OHOS::Rosen::WMError mockRet);

// Reset all mocks to default values
void ResetWindowBackgroundColorMocks();

#endif // INNER_MOCK_UI_EXTENSION_CONTEXT_H
