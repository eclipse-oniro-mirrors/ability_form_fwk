/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormSingletonQueueBase used in unit testing.
 */

#include <string>
#include <memory>
#include <functional>
#include "queue/form_singleton_queue_base.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {

FormSingletonQueueBase::FormSingletonQueueBase(const std::string &queueName,
    std::shared_ptr<ITaskWrapperStrategy> strategy)
    : queueName_(queueName), serialQueue_(nullptr), strategy_(nullptr) {}

FormSingletonQueueBase::~FormSingletonQueueBase() {}

bool FormSingletonQueueBase::ScheduleTask(uint64_t ms, std::function<void()> func, TaskQos qos)
{
    return false;
}

bool FormSingletonQueueBase::ScheduleDelayTask(
    const TaskKey &taskKey, uint64_t ms, std::function<void()> func, TaskQos qos)
{
    return false;
}

bool FormSingletonQueueBase::CancelDelayTask(const TaskKey &taskKey)
{
    return false;
}

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS
