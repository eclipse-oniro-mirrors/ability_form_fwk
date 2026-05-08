/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormCastTempConnection used in unit testing.
 */

#include "form_provider/connection/form_cast_temp_connection.h"

namespace OHOS {
namespace AppExecFwk {

FormCastTempConnection::FormCastTempConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName, const int32_t userId)
{
    SetFormId(formId);
    SetProviderKey(bundleName, abilityName, userId);
}

void FormCastTempConnection::OnExecuteConnectTask(
    const Want &want, const sptr<IRemoteObject> &remoteObject) {}
}  // namespace AppExecFwk
}  // namespace OHOS
