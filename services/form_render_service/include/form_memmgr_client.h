/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_MEMMGR_CLIENT_H
#define OHOS_FORM_FWK_FORM_MEMMGR_CLIENT_H

#include <singleton.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormMemmgrClient
 * FormMemmgrClient is used to call memmgr service.
 */
class FormMemmgrClient final : public DelayedRefSingleton<FormMemmgrClient> {
    DECLARE_DELAYED_REF_SINGLETON(FormMemmgrClient)
public:
    DISALLOW_COPY_AND_MOVE(FormMemmgrClient);

    /**
     * @brief Setting the process status.
     * @param critical Indicates whether it is a critical process.
     */
    void SetCritical(bool critical);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_MEMMGR_CLIENT_H
