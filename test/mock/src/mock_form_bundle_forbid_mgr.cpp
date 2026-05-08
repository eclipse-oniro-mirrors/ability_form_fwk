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

#include "mock_form_bundle_forbid_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormBundleForbidMgr> MockFormBundleForbidMgr::obj = nullptr;

FormBundleForbidMgr::FormBundleForbidMgr() {}
FormBundleForbidMgr::~FormBundleForbidMgr() {}

bool FormBundleForbidMgr::IsBundleForbidden(const std::string &bundleName)
{
    GTEST_LOG_(INFO) << "IsBundleForbidden called";
    if (AppExecFwk::MockFormBundleForbidMgr::obj) {
        return AppExecFwk::MockFormBundleForbidMgr::obj->IsBundleForbidden(bundleName);
    }
    return false;
}

void FormBundleForbidMgr::SetBundleForbiddenStatus(const std::string &bundleName, bool isForbidden)
{
    GTEST_LOG_(INFO) << "SetBundleForbiddenStatus called";
    if (AppExecFwk::MockFormBundleForbidMgr::obj) {
        AppExecFwk::MockFormBundleForbidMgr::obj->SetBundleForbiddenStatus(bundleName, isForbidden);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
