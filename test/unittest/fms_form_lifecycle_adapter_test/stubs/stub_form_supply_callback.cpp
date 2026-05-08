/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormSupplyCallback additional methods used in unit testing.
 */

#include "form_provider/form_supply_callback.h"

namespace OHOS {
namespace AppExecFwk {

void FormSupplyCallback::AddConnection(sptr<FormAbilityConnection> connection) {}

void FormSupplyCallback::RemoveConnection(int32_t connectId) {}

void FormSupplyCallback::RemoveConnection(int64_t formId, const sptr<IRemoteObject> &hostToken) {}

void FormSupplyCallback::HandleHostDied(const sptr<IRemoteObject> &hostToken) {}

void FormSupplyCallback::ProcessFormAcquisition(int64_t formId) {}
}  // namespace AppExecFwk
}  // namespace OHOS
