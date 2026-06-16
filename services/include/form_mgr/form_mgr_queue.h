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

#ifndef OHOS_FORM_FWK_FORM_MGR_QUEUE_H
#define OHOS_FORM_FWK_FORM_MGR_QUEUE_H

#include <functional>
#include <singleton.h>
#include "common/util/form_task_common.h"
#include "queue/form_singleton_queue_base.h"
#include "queue/task_wrapper_strategy.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t QUEUE_TASK_TIME_OUT = 5;
}

class FormMgrQueue final : public DelayedRefSingleton<FormMgrQueue>, public Common::FormSingletonQueueBase {
public:
    DISALLOW_COPY_AND_MOVE(FormMgrQueue);

    FormMgrQueue(): Common::FormSingletonQueueBase("FormMgrQueue",
        std::make_shared<Common::XCollieTimeoutStrategy>(QUEUE_TASK_TIME_OUT, "FMS_QueueTask")) {}
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_MGR_QUEUE_H