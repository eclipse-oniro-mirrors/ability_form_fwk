/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_JS_FORM_INFO_UTIL_H
#define OHOS_FORM_FWK_JS_FORM_INFO_UTIL_H

#include "form_info.h"
#include "form_info_filter.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace AbilityRuntime {
EXTERN_C_START

bool ConvertFormInfoFilter(NativeEngine &engine, NativeValue *jsValue, AppExecFwk::FormInfoFilter &formInfoFilter);
NativeValue* CreateJsFormInfoArray(NativeEngine &engine, const std::vector<AppExecFwk::FormInfo> &formInfos);

EXTERN_C_END
} // namespace AppExecFwk
} // namespace OHOS
#endif /* OHOS_FORM_FWK_JS_FORM_INFO_UTIL_H */
