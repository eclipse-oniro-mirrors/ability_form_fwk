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

#ifndef OHOS_FORM_FWK_FORM_IPC_CONTEXT_H
#define OHOS_FORM_FWK_FORM_IPC_CONTEXT_H

#include <cstdint>

namespace OHOS {
namespace AppExecFwk {

/**
 * @struct FormIpcContext
 * @brief Caller identity snapshot for one IPC message.
 */
struct FormIpcContext {
    int32_t callingUid;
    uint64_t callingTokenId;
    int32_t callingPid;
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_IPC_CONTEXT_H
