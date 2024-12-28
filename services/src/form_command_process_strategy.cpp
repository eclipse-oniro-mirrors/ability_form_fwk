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

#include "form_command_process_strategy.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
void RenderFormStrategy::ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId)
{
    if (commandQueue.empty()) {
        HILOG_ERROR("empty commandQueue, formId :%{public}" PRId64 ". ", formId);
        return;
    }
    size_t commandNums = commandQueue.size();
    for (size_t i = 0; i < commandNums - 1; ++i) {
        commandQueue.pop();
    }
    HILOG_DEBUG("HandleRenderCommand End, formId :%{public}" PRId64 ". ", formId);
}

void SimilarStatusStrategy::ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId)
{
    if (commandQueue.empty()) {
        HILOG_ERROR("empty commandQueue, formId :%{public}" PRId64 ". ", formId);
        return;
    }

    std::queue<FormCommand> tempCommandQueue;
    while (!commandQueue.empty()) {
        auto frontCommand = commandQueue.front();
        commandQueue.pop();
        if (frontCommand.getEventMsg().first == TaskCommandType::RENDER_FORM) {
            tempCommandQueue.push(frontCommand);
        }
    }

    while (!tempCommandQueue.empty()) {
        auto frontCommand = tempCommandQueue.front();
        tempCommandQueue.pop();
        commandQueue.push(frontCommand);
    }
    HILOG_DEBUG("HandleSimilarCommand End, formId :%{public}" PRId64 ". ", formId);
}

void DifferentStatusStrategy::ProcessCommandQueue(std::queue<FormCommand> &commandQueue, const int64_t formId)
{
    if (commandQueue.empty()) {
        HILOG_ERROR("empty CommandQueue, formId :%{public}" PRId64 ". ", formId);
        return;
    }

    auto backCommand = commandQueue.back();
    std::queue<FormCommand> tempCommandQueue;
    while (!commandQueue.empty()) {
        auto frontCommand = commandQueue.front();
        commandQueue.pop();
        if (frontCommand.getEventMsg().first == TaskCommandType::RENDER_FORM) {
            tempCommandQueue.push(frontCommand);
        }
    }

    while (!tempCommandQueue.empty()) {
        auto frontCommand = tempCommandQueue.front();
        tempCommandQueue.pop();
        commandQueue.push(frontCommand);
    }
    commandQueue.push(backCommand);
    HILOG_DEBUG("HandleDifferentCommand End, formId :%{public}" PRId64 ". ", formId);
}

std::unique_ptr<FormCommandProcessStrategy> CommandProcessStrategyFactory::CreateStrategy(
    TaskCommandType taskCommandType, FormStatus currentFormStatus)
{
    if (taskCommandType == TaskCommandType::RENDER_FORM) {
        return std::make_unique<RenderFormStrategy>();
    } else if (taskCommandType == TaskCommandType::RECOVER_FORM) {
        switch (currentFormStatus) {
            case FormStatus::UNPROCESSABLE:
                return std::make_unique<SimilarStatusStrategy>();
            case FormStatus::RECOVERED:
                return std::make_unique<SimilarStatusStrategy>();
            case FormStatus::RECOVERING:
                return std::make_unique<SimilarStatusStrategy>();
            case FormStatus::RECYCLED:
                return std::make_unique<DifferentStatusStrategy>();
            case FormStatus::RECYCLING:
                return std::make_unique<DifferentStatusStrategy>();
            default:
                return nullptr;
        }
    } else if (taskCommandType == TaskCommandType::RECYCLE_FORM) {
        switch (currentFormStatus) {
            case FormStatus::UNPROCESSABLE:
                return std::make_unique<DifferentStatusStrategy>();
            case FormStatus::RECOVERED:
                return std::make_unique<DifferentStatusStrategy>();
            case FormStatus::RECOVERING:
                return std::make_unique<DifferentStatusStrategy>();
            case FormStatus::RECYCLED:
                return std::make_unique<SimilarStatusStrategy>();
            case FormStatus::RECYCLING:
                return std::make_unique<SimilarStatusStrategy>();
            default:
                return nullptr;
        }
    }
        return nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS
