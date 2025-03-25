/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_COMMAND_PROCESS_STRATEGY_H
#define OHOS_FORM_FWK_FORM_COMMAND_PROCESS_STRATEGY_H

#include <queue>

#include "status_mgr_center/form_command_queue.h"
#include "status_mgr_center/form_status_mgr.h"

namespace OHOS {
namespace AppExecFwk {

// Base class for form command processing strategies
class FormCommandProcessStrategy {
public:
    virtual ~FormCommandProcessStrategy() = default;
    virtual void ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId) = 0;

private:
};

// Strategy class for RenderForm
class RenderFormStrategy : public FormCommandProcessStrategy {
public:
    void ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId) override;
};

// Strategy class for SimilarStatus
class SimilarStatusStrategy : public FormCommandProcessStrategy {
public:
    void ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId) override;
};

// Strategy class for DifferentStatus
class DifferentStatusStrategy : public FormCommandProcessStrategy {
public:
    void ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId) override;
};

// Factory class for creating form command process strategies
class CommandProcessStrategyFactory {
public:
    static std::unique_ptr<FormCommandProcessStrategy> CreateStrategy(
        TaskCommandType taskCommandType, FormStatus currentFormStatus);
};
}
}
#endif // OHOS_FORM_FWK_FORM_COMMAND_PROCESS_STRATEGY_H
