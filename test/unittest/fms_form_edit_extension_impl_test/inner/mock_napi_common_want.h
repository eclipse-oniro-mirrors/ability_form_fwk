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

#ifndef INNER_MOCK_NAPI_COMMON_WANT_H
#define INNER_MOCK_NAPI_COMMON_WANT_H

#include <string>
#include "want.h"

// Set mock return for AppExecFwk::UnwrapWant
// If shouldSucceed is true, UnwrapWant returns true and sets want with mockColorMode.
// If shouldSucceed is false, UnwrapWant returns false.
void MockUnwrapWant(bool shouldSucceed, int32_t mockColorMode = -1);

// Reset mock to default (fail)
void ResetUnwrapWantMock();

#endif // INNER_MOCK_NAPI_COMMON_WANT_H
