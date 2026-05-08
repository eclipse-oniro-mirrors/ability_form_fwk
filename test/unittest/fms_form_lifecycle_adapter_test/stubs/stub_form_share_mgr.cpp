/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormShareMgr used in unit testing.
 */

#include "feature/form_share/form_share_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormShareMgr::FormShareMgr() {}
FormShareMgr::~FormShareMgr() {}

bool FormShareMgr::IsShareForm(const Want &want)
{
    return false;
}

void FormShareMgr::AddProviderData(const Want &want, WantParams &wantParams) {}

int32_t FormShareMgr::ShareForm(int64_t formId, const std::string &deviceId,
    const sptr<IRemoteObject> &callerToken, int64_t requestCode)
{
    return ERR_OK;
}

int32_t FormShareMgr::RecvFormShareInfoFromRemote(const FormShareInfo &info, const int32_t userId)
{
    return ERR_OK;
}

void FormShareMgr::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const Want &want, const sptr<IRemoteObject> &remoteObject) {}

void FormShareMgr::HandleProviderShareData(int64_t formId, const std::string &remoteDeviceId,
    const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) {}

void FormShareMgr::HandleFormShareInfoTimeout(int64_t eventId) {}

void FormShareMgr::HandleFreeInstallTimeout(int64_t eventId) {}

void FormShareMgr::OnInstallFinished(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator,
    int32_t resultCode, const std::string &formShareInfoKey, const int32_t userId) {}

void FormShareMgr::SendResponse(int64_t requestCode, int32_t result) {}

void FormShareMgr::OnEventTimeoutResponse(int64_t msg, int64_t eventId) {}
}  // namespace AppExecFwk
}  // namespace OHOS
