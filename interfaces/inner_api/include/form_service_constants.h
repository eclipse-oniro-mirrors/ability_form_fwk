/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_SERVICE_CONSTANTS_H
#define OHOS_FORM_FWK_FORM_SERVICE_CONSTANTS_H

#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>

namespace OHOS {
namespace AppExecFwk {
constexpr const char *FORM_SERVICE_OWNER_PKG = "form_fwk";

constexpr const char *FORM_SERVICE_PARAM_KEY_LOCAL_USER_ID = "localUserId";
constexpr const char *FORM_SERVICE_PARAM_KEY_IS_PROXY_QUERY = "isProxyQuery";

constexpr int32_t FORM_SERVICE_MAX_PER_OWNER = 1;
constexpr int32_t FORM_SERVICE_QUERY_MAX_NUM = 512;

// Mirror unexported DM validation bounds; keep in sync.
constexpr int32_t FORM_SERVICE_DM_MAX_SERVICE_TYPE = 15;
constexpr int32_t FORM_SERVICE_MAX_SERVICE_NAME = 64;
constexpr int32_t FORM_SERVICE_MIN_DISPLAYNAME = 7;
constexpr int32_t FORM_SERVICE_MAX_DISPLAYNAME = 128;
constexpr int32_t FORM_SERVICE_MAX_CUSTOMDATA = 1024;
constexpr int32_t FORM_SERVICE_MIN_DESCRIPTION = 1;
constexpr int32_t FORM_SERVICE_MAX_DESCRIPTION = 256;
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SERVICE_CONSTANTS_H
