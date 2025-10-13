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

#include "js_form_runtime.h"

#include "rosen_text/font_collection_mgr.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {

bool JsFormRuntime::InsertHapPath(
    const std::string& bundleName, const std::string& moduleName, const std::string& hapPath)
{
    bundleName_ = bundleName;
    moduleNameSet_.insert(moduleName);
    return Rosen::FontCollectionMgr::GetInstance().InsertHapPath(bundleName, moduleName, hapPath);
}

void JsFormRuntime::DestroyHapPath()
{
    for (std::string moduleName : moduleNameSet_) {
        Rosen::FontCollectionMgr::GetInstance().DestroyHapPath(bundleName_, moduleName);
    }
}

JsFormRuntime::~JsFormRuntime()
{
    auto env = GetNapiEnv();
    if (!env) {
        HILOG_ERROR("Failed to GetNapiEnv");
        return;
    }

    DestroyHapPath();

    HILOG_WARN("DestroyLocalInstance.");
    auto envId = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(env));
    Rosen::FontCollectionMgr::GetInstance().DestroyLocalInstance(envId);
}
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS