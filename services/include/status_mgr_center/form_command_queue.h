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

#ifndef OHOS_FORM_FWK_FORM_COMMAND_QUEUE_H
#define OHOS_FORM_FWK_FORM_COMMAND_QUEUE_H

#include <string>
#include <mutex>
#include <queue>

namespace OHOS {
namespace AppExecFwk {
enum class TaskCommandType : int64_t {
    RENDER_FORM,
    RECOVER_FORM,
    RECYCLE_FORM,
    DELETE_FORM,
    READDFORM_FORM,
};

// FormCommand Interface
class FormCommand {
public:
    FormCommand() = default;
    FormCommand(
        int64_t formId,
        const std::pair<TaskCommandType,
        int64_t>& eventMsg,
        uint32_t ms,
        std::function<void()> func)
        : formId_(formId), eventMsg_(eventMsg), ms_(ms), func_(func) {}
        
    void PostFormCommandTask();
 
    inline int64_t getFormId() const { return formId_; }
    inline void setFormId(int64_t formId) { formId_ = formId; }
 
    inline std::pair<TaskCommandType, int64_t> getEventMsg() const { return eventMsg_; }
    inline void setEventMsg(const std::pair<TaskCommandType, int64_t>& eventMsg) { eventMsg_ = eventMsg; }
 
    inline uint32_t getMs() const { return ms_; }
    inline void setMs(uint32_t ms) { ms_ = ms; }
 
    inline std::function<void()> getFunc() const { return func_; }
    inline void setFunc(const std::function<void()>& func) { func_ = func; }
 
protected:
    int64_t formId_;
    std::pair<TaskCommandType, int64_t> eventMsg_; // <TaskCommandType, formId>
    uint32_t ms_; // delay time
    std::function<void()> func_; // formCommand funtion
};

/**
 * @brief This class processes the commands in the queue based on the current form state.
 * @class FormCommandQueue
 * @param formId The form ID associated with this command queue.
 */
class FormCommandQueue final {
public:
    explicit FormCommandQueue(const int64_t &formId);
    ~FormCommandQueue();

    /**
     * @brief Push a task command to the command queue.
     * @param taskType TaskCommandType
     * @param taskCommand TaskCommand
     * @return none.
     */
    void PushFormCommand(FormCommand formCommand);

    /**
     * @brief Pop a task command form the command queue.
     * @param taskType TaskCommandType
     * @param taskCommand TaskCommand
     * @return none.
     */
    bool PopFormCommand(FormCommand &formCommand);

    /**
     * @brief check command queue is empty.
     * @return bool.
     */
    bool IsCommondQueueEmpty();

private:
    /**
     * @brief Processes the tasks in the command queue based on the current card state.
     * @return none.
     */
    void ProcessCommandQueue();

    //FormCommand queue
    std::mutex formCommandQueueMutex_;
    std::queue<FormCommand> CommandQueue;
    int64_t formId_;
};
}
}
#endif // OHOS_FORM_FWK_FORM_COMMAND_QUEUE_H
