/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_JS_FORM_RUNTIME_H
#define OHOS_FORM_FWK_JS_FORM_RUNTIME_H

#include <unordered_set>

#include "js_runtime.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
class JsFormRuntime : public AbilityRuntime::JsRuntime {
public:
    ~JsFormRuntime();
    bool InsertHapPath(
        const std::string bundleName, const std::string moduleName, const std::string hapPath);
    void DestoryHapPath();
private:
    std::string bundleName_;
    std::unordered_set<std::string> moduleNameSet_;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_JS_FORM_RUNTIME_H