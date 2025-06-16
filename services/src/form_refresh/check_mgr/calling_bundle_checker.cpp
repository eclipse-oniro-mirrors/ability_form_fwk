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

#include "form_refresh/check_mgr/calling_bundle_checker.h"

#include "bms_mgr/form_bms_helper.h"

namespace OHOS {
namespace AppExecFwk {

CallingBundleChecker::CallingBundleChecker() {}
CallingBundleChecker::~CallingBundleChecker() {}

int CallingBundleChecker::CheckValid(const CheckValidFactor &factor)
{
    std::string bundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get bundleName failed, formId:%{public}" PRId64, factor.record.formId);
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleName != factor.record.bundleName) {
        HILOG_ERROR("not match caller bundleName:%{public}s, formId:%{public}" PRId64,
            bundleName.c_str(), factor.record.formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS