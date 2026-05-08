/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormRenderMgr additional methods used in unit testing.
 * The base mock (mock_form_render_mgr.cpp) provides UpdateRenderingForm.
 */

#include "form_render/form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {

bool FormRenderMgr::IsRerenderForRenderServiceDied(int64_t formId)
{
    return false;
}

ErrCode FormRenderMgr::RenderForm(const FormRecord &formRecord,
    const WantParams &wantParams, const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

int32_t FormRenderMgr::StopRenderingForm(int64_t formId, const FormRecord &formRecord,
    const std::string &compId, const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

void FormRenderMgr::DeleteAcquireForbiddenTaskByFormId(int64_t formId) {}

void FormRenderMgr::ExecAcquireProviderForbiddenTaskByFormId(int64_t formId) {}

void FormRenderMgr::ExecAcquireProviderForbiddenTask(const std::string &bundleName) {}

int32_t FormRenderMgr::RecoverForms(const std::vector<int64_t> &formIds,
    const AAFwk::WantParams &wantParams)
{
    return ERR_OK;
}

int32_t FormRenderMgr::ReleaseRenderer(int64_t formId, const FormRecord &formRecord,
    const std::string &compId)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
