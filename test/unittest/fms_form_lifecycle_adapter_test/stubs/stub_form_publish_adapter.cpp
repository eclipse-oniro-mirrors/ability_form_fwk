/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormPublishAdapter used in unit testing.
 */

#include "form_mgr/form_publish_adapter.h"

namespace OHOS {
namespace AppExecFwk {

FormPublishAdapter::FormPublishAdapter() {}
FormPublishAdapter::~FormPublishAdapter() {}

ErrCode FormPublishAdapter::CheckAddFormTaskTimeoutOrFailed(
    const int64_t formId, AddFormResultErrorCodes &formStates)
{
    return ERR_OK;
}

void FormPublishAdapter::RemoveFormIdMapElement(const int64_t formId) {}

void FormPublishAdapter::CancelAddFormRequestTimeOutTask(const int64_t formId, const int result) {}

ErrCode FormPublishAdapter::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::QueryPublishFormToHost(Want &wantToHost)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::QueryPublishFormToHost(Want &wantToHost, int32_t userId)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::CheckPublishForm(Want &want, bool needCheckFormPermission)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::AcquireAddFormResult(const int64_t formId)
{
    return ERR_OK;
}

bool FormPublishAdapter::IsRequestPublishFormSupported()
{
    return false;
}

ErrCode FormPublishAdapter::RequestPublishFormCommon(Want &want, int32_t userId, int64_t &formId)
{
    return ERR_OK;
}

ErrCode FormPublishAdapter::RequestPublishFormCrossUser(Want &want, int32_t userId, int64_t &formId)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
