/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormSerialQueue used in unit testing.
 */

#include "common/util/form_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {

FormSerialQueue::FormSerialQueue(const std::string &queueName) {}
FormSerialQueue::~FormSerialQueue() {}

bool FormSerialQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    return true;
}

bool FormSerialQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    return true;
}

bool FormSerialQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
