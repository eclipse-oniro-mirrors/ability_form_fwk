/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormProviderMgr additional methods used in unit testing.
 */

#include "form_provider/form_provider_mgr.h"

namespace OHOS {
namespace AppExecFwk {

int FormProviderMgr::NotifyProviderFormDelete(const int64_t formId, const FormRecord &formRecord)
{
    return ERR_OK;
}

ErrCode FormProviderMgr::ConnectForConfigUpdate(const AppExecFwk::Configuration &configuration,
    const FormRecord &formRecord, const Want &want)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
