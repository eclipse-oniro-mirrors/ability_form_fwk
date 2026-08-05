/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormCallbackAdapter used in unit testing.
 */

#include "form_mgr/form_callback_adapter.h"

namespace OHOS {
namespace AppExecFwk {

FormCallbackAdapter::FormCallbackAdapter() {}
FormCallbackAdapter::~FormCallbackAdapter() {}

ErrCode FormCallbackAdapter::RegisterFormRouterProxy(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterOverflowProxy()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterChangeSceneAnimationStateProxy()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterGetFormRectProxy()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterGetLiveFormStatusProxy()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::StartAbilityByFms(const Want &want)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterPublishFormCrossBundleControl(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterPublishFormCrossBundleControl()
{
    return ERR_OK;
}

bool FormCallbackAdapter::PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo)
{
    return false;
}

ErrCode FormCallbackAdapter::RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterTemplateFormDetailInfoChange()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterUpdateFormsConfigCallback(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterUpdateFormsConfigCallback()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UpdateFormsConfig(const std::vector<FormCustomConfig> &configs)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterDeleteFormsCallback(const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterDeleteFormsCallback()
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::DeleteForms(const std::vector<FormRecordFilter> &filters)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RegisterFormWantCallback(int32_t callingUid, const sptr<IRemoteObject> &callerToken)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterFormWantCallback(int32_t callingUid)
{
    return ERR_OK;
}

ErrCode FormCallbackAdapter::GetWantCallbackProxy(int32_t callingUid, sptr<IRemoteObject> &proxy)
{
    return ERR_OK;
}

void FormCallbackAdapter::SetFormPublishInterceptor(const sptr<IFormPublishInterceptor> &interceptor) {}

sptr<IFormPublishInterceptor> FormCallbackAdapter::GetFormPublishInterceptor()
{
    return nullptr;
}

ErrCode FormCallbackAdapter::CancelOverflow(const int64_t formId)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
