/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormDataAdapter used in unit testing.
 */

#include "form_mgr/form_data_adapter.h"

namespace OHOS {
namespace AppExecFwk {

FormDataAdapter::FormDataAdapter() {}
FormDataAdapter::~FormDataAdapter() {}

int FormDataAdapter::UpdateForm(const int64_t formId, const int32_t callingUid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    return ERR_OK;
}

int FormDataAdapter::RequestForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const Want &want)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::UpdateFormSize(const int64_t &formId,
    float width, float height, float borderWidth, float formViewScale)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::UpdateFormSize(const int64_t formId,
    const int32_t newDimension, const Rect &newRect)
{
    return ERR_OK;
}

int FormDataAdapter::EnableUpdateForm(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

int FormDataAdapter::DisableUpdateForm(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::BatchRefreshForms(const int32_t formRefreshType)
{
    return ERR_OK;
}

int FormDataAdapter::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    return ERR_OK;
}

void FormDataAdapter::UpdateFormRenderParam(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const Want &want) {}

ErrCode FormDataAdapter::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::AcquireProviderFormInfoAsync(const int64_t formId,
    const FormItemInfo &info, const WantParams &wantParams)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::ReAcquireProviderFormInfoAsync(
    const FormItemInfo &info, const WantParams &wantParams)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms)
{
    return ERR_OK;
}

int32_t FormDataAdapter::OnNotifyRefreshForm(const int64_t &formId)
{
    return ERR_OK;
}

ErrCode FormDataAdapter::UpdateFormByCondition(int32_t type)
{
    return ERR_OK;
}

void FormDataAdapter::DelayRefreshFormsOnAppUpgrade(
    const std::vector<FormRecord> &updatedForms, const Want &want) {}

ErrCode FormDataAdapter::AcquireProviderFormInfoByFormRecord(
    const FormRecord &formRecord, const WantParams &wantParams)
{
    return ERR_OK;
}

void FormDataAdapter::ClearReconnectNum(int64_t formId) {}

bool FormDataAdapter::IsDeleteCacheInUpgradeScene(const FormRecord &record)
{
    return false;
}

void FormDataAdapter::DeleteInvalidFormCacheIfNeed() {}

ErrCode FormDataAdapter::UpdateTimer(const int64_t formId, const FormRecord &record)
{
    return ERR_OK;
}

void FormDataAdapter::UpdateReUpdateFormMap(const int64_t formId) {}

void FormDataAdapter::SetReUpdateFormMap(const int64_t formId) {}
}  // namespace AppExecFwk
}  // namespace OHOS
