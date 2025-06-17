/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_STATUS_COMMON_H
#define OHOS_FORM_FWK_FORM_STATUS_COMMON_H

namespace OHOS {
namespace AppExecFwk {
enum class FormFsmStatus {
    INIT = 0,
    RENDERED,
    RECYCLED,
    RENDERING,
    RECYCLING_DATA,
    RECYCLING,
    RECOVERING,
    DELETING,
    UNPROCESSABLE,
};

enum class FormFsmEvent {
    RENDER_FORM = 0,
    RENDER_FORM_DONE,
    RENDER_FORM_FAIL,
    RECYCLE_DATA,
    RECYCLE_DATA_DONE,
    RECYCLE_DATA_FAIL,
    RECYCLE_FORM,
    RECYCLE_FORM_DONE,
    RECYCLE_FORM_FAIL,
    RECOVER_FORM,
    RECOVER_FORM_DONE,
    RECOVER_FORM_FAIL,
    DELETE_FORM,
    DELETE_FORM_DONE,
    DELETE_FORM_FAIL,
    DELETE_FORM_FINISH,
    EXECUTION_TIMEOUT,
    RELOAD_FORM,
};

enum class FormFsmProcessType {
    PROCESS_TASK_DIRECT = 0,
    PROCESS_TASK_DELETE,
};

enum class FormEventTimeout {
    TIMEOUT_NO_NEED = 0,
    TIMEOUT_3_S = 3000,
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_COMMON_H
