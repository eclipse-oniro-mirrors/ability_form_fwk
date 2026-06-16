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

#include "formrenderstatusmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <functional>

#include "status_mgr_center/form_render_status.h"
#include "status_mgr_center/form_render_status_table.h"
#define private public
#define protected public
#include "status_mgr_center/form_render_status_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t MAX_FORM_ID = 100000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t BYTE_INDEX_FIRST = 0;
constexpr int32_t BYTE_INDEX_SECOND = 1;
constexpr int32_t BYTE_INDEX_THIRD = 2;
constexpr int32_t BYTE_INDEX_FOURTH = 3;
constexpr int32_t FIRST_BYTE_SHIFT = 24;
constexpr int32_t SECOND_BYTE_SHIFT = 16;
constexpr int32_t THIRD_BYTE_SHIFT = 8;
constexpr int32_t FSM_EVENT_COUNT = 18;
constexpr int32_t FSM_STATUS_COUNT = 9;
constexpr int32_t FSM_PROCESS_TYPE_COUNT = 7;

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[BYTE_INDEX_FIRST] << FIRST_BYTE_SHIFT) |
           (ptr[BYTE_INDEX_SECOND] << SECOND_BYTE_SHIFT) |
           (ptr[BYTE_INDEX_THIRD] << THIRD_BYTE_SHIFT) |
           ptr[BYTE_INDEX_FOURTH];
}

FormFsmEvent GetRandomFormFsmEvent(const char* data, size_t size)
{
    uint32_t eventIndex = static_cast<uint32_t>(GetU32Data(data)) % FSM_EVENT_COUNT;
    return static_cast<FormFsmEvent>(eventIndex);
}

FormFsmStatus GetRandomFormFsmStatus(const char* data, size_t size)
{
    uint32_t statusIndex = static_cast<uint32_t>(GetU32Data(data)) % FSM_STATUS_COUNT;
    return static_cast<FormFsmStatus>(statusIndex);
}

FormFsmProcessType GetRandomFormFsmProcessType(const char* data, size_t size)
{
    uint32_t processIndex = static_cast<uint32_t>(GetU32Data(data)) % FSM_PROCESS_TYPE_COUNT;
    return static_cast<FormFsmProcessType>(processIndex);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormRenderStatusMgr& formRenderStatusMgr = FormRenderStatusMgr::GetInstance();

    int64_t formId = static_cast<int64_t>(GetU32Data(data)) % MAX_FORM_ID + MIN_FORM_ID;

    FormFsmEvent event = GetRandomFormFsmEvent(data, size);

    std::function<int32_t()> func = []() { return 0; };

    formRenderStatusMgr.PostFormEvent(formId, event, func);
    formRenderStatusMgr.PostFormEvent(formId, event, nullptr);

    formRenderStatusMgr.ProcessTaskDirect(func);
    formRenderStatusMgr.ProcessTaskDirect(nullptr);

    formRenderStatusMgr.ProcessTaskDelete(formId);

    FormFsmStatus status = GetRandomFormFsmStatus(data, size);
    FormFsmProcessType processType = GetRandomFormFsmProcessType(data, size);

    formRenderStatusMgr.ExecFormTask(processType, formId, event, status, func);
    formRenderStatusMgr.ExecFormTask(processType, formId, event, status, nullptr);

    formRenderStatusMgr.PrintTaskInfo(formId, event, status);

    FormRenderStatus::GetInstance().HasFormStatus(formId);
    FormRenderStatus::GetInstance().GetFormStatus(formId);
    FormRenderStatus::GetInstance().SetFormStatus(formId, status);
    FormRenderStatus::GetInstance().DeleteFormStatus(formId);

    FormRenderStatusMachineInfo info;
    FormRenderStatusTable::GetInstance().GetFormStatusInfo(status, event, info);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size));
    if (ch == nullptr) {
        return 0;
    }

    errno_t ret = memset_s(ch, size, 0x00, size);
    if (ret != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}