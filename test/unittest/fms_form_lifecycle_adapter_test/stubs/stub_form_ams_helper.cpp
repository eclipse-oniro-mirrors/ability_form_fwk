/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormAmsHelper used in unit testing.
 */

#include "ams_mgr/form_ams_helper.h"

namespace OHOS {
namespace AppExecFwk {

FormAmsHelper::FormAmsHelper() {}
FormAmsHelper::~FormAmsHelper() {}

ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    return ERR_OK;
}

ErrCode FormAmsHelper::ConnectServiceAbilityWithUserId(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId)
{
    return ERR_OK;
}

ErrCode FormAmsHelper::DisconnectServiceAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    return ERR_OK;
}

ErrCode FormAmsHelper::DisconnectServiceAbilityDelay(
    const sptr<AAFwk::IAbilityConnection> &connect, int delayTime)
{
    return ERR_OK;
}

ErrCode FormAmsHelper::StartAbility(const Want &want, int32_t userId)
{
    return ERR_OK;
}

sptr<AAFwk::IAbilityManager> FormAmsHelper::GetAbilityManager()
{
    return nullptr;
}

void FormAmsHelper::SetAbilityManager(const sptr<AAFwk::IAbilityManager> &abilityManager) {}

ErrCode FormAmsHelper::StopExtensionAbility(const Want &want)
{
    return ERR_OK;
}

void FormAmsHelper::RegisterConfigurationObserver() {}

void FormAmsHelper::UnRegisterConfigurationObserver() {}

ErrCode FormAmsHelper::StartAbilityOnlyUIAbility(Want &want, const sptr<IRemoteObject> &callerToken,
    uint32_t specifyTokenId, const int32_t userId)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
