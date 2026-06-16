/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormAbilityConnection used in unit testing.
 */

#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {

void FormAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) {}

void FormAbilityConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int resultCode) {}

void FormAbilityConnection::SetFormId(int64_t formId)
{
    formId_ = formId;
}

void FormAbilityConnection::SetProviderKey(const std::string &bundleName,
    const std::string &abilityName, const int32_t userId)
{
    bundleName_ = bundleName;
    abilityName_ = abilityName;
    userId_ = userId;
}
}  // namespace AppExecFwk
}  // namespace OHOS
