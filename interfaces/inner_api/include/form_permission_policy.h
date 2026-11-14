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

#ifndef OHOS_FORM_FWK_FORM_PERMISSION_POLICY_H
#define OHOS_FORM_FWK_FORM_PERMISSION_POLICY_H

#include <cstdint>
#include <string_view>

#include "bundle_constants.h"
#include "form_constants.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief Check type for permission evaluation.
 */
enum class CheckType : uint8_t {
    SaBypass,       // SA caller skips the entire chain; no deny code.
    SaOnly,         // Caller must be a system ability; deny: ERR_APPEXECFWK_FORM_PERMISSION_DENY.
    SystemApp,      // Caller is system app (not SA); deny: ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
    SystemCaller,   // Caller is system app or SA; deny: ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
    Permission,     // Caller holds the named permission; deny: the baked permDenyCode.
    CrossAccount,   // Caller is on current active account; deny: ERR_APPEXECFWK_FORM_PERMISSION_DENY.
};

/**
 * @brief Carrier of the deny result when the pre-check rejects an IPC request.
 *
 * Deny shape is part of each command's client-visible IPC contract and cannot be
 * derived from the reply protocol automatically (two commands may share the same
 * reply format yet differ in the deny channel). It exists solely to keep legacy
 * client compatibility; new commands must stay on the default CARRIER_STATUS.
 */
enum class DenyShape : uint8_t {
    CARRIER_STATUS,      // Deny code rides the binder status channel (SendRequest return value).
    CARRIER_REPLY_INT32, // Legacy: deny code is the reply's leading int32; status stays ERR_OK.
    CARRIER_REPLY_BOOL,  // Legacy: deny surfaces as the reply's plain false bool; status stays ERR_OK.
};

/**
 * @brief Access policy of one IPC message: an ordered check list.
 * Checks run in order; the first failing check returns its deny code.
 * An empty list means no check (pass-through, B-1/B-2 rows).
 */
struct FormPermissionPolicy {
    static constexpr uint8_t MAX_CHECK_COUNT = 4;
    // SaBypass, when present, occupies checks[0] only; later steps start here.
    static constexpr uint8_t SA_BYPASS_STEP_COUNT = 1;
    CheckType checks[MAX_CHECK_COUNT] = {};
    uint8_t checkCount = 0;
    std::string_view permName;
    // Final deny code for the Permission step: explicit override, else GetDefaultDenyCode(permName).
    ErrCode permDenyCode = 0;
    // Carrier of the deny result for legacy client compatibility; see DenyShape.
    DenyShape denyShape = DenyShape::CARRIER_STATUS;
};

/**
 * @brief Map a permission name to its default deny code.
 * @param permName Permission name string.
 * @return Default deny code for the given permission.
 */
constexpr ErrCode GetDefaultDenyCode(std::string_view permName)
{
    if (permName == Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    if (permName == Constants::PERMISSION_FORM_CUSTOM_CONFIG) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_CUSTOM_CONFIG;
    }
    if (permName == Constants::PERMISSION_UPDATE_FORM_CROSS_BUNDLE) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE;
    }
    return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
}

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_PERMISSION_POLICY_H
