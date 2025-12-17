/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "form_render_impl.h"
#include "form_render_service_mgr.h"
#include "form_render_service_extension.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "status_mgr_center/form_render_status_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using namespace AbilityRuntime;
using namespace OHOS::AAFwk::GlobalConfigurationKey;

static OHOS::AbilityRuntime::ServiceExtension *FormRenderServiceCreator(const std::unique_ptr<Runtime> &runtime)
{
    HILOG_DEBUG("Create FormRenderServiceExtension");
    return FormRenderServiceExtension::Create(runtime);
}

__attribute__((constructor)) void RegisterServiceExtensionCreator()
{
    HILOG_DEBUG("Set FormRenderServiceExtension creator");
    OHOS::AbilityRuntime::ServiceExtension::SetCreator(FormRenderServiceCreator);
}

FormRenderImpl::FormRenderImpl()
{}

FormRenderImpl::~FormRenderImpl() = default;

int32_t FormRenderImpl::RenderForm(const FormJsInfo &formJsInfo, const Want &want, sptr<IRemoteObject> callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formJsInfo.formId);
    auto renderForm = [formJsInfo, want, callerToken] {
        return FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    };

    return FormRenderStatusMgr::GetInstance().PostFormEvent(formJsInfo.formId, FormFsmEvent::RENDER_FORM, renderForm);
}

int32_t FormRenderImpl::StopRenderingForm(
    const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formJsInfo.formId);
    auto deleteForm = [formJsInfo, want, callerToken] {
        return FormRenderServiceMgr::GetInstance().StopRenderingForm(formJsInfo, want, callerToken);
    };

    return FormRenderStatusMgr::GetInstance().PostFormEvent(formJsInfo.formId, FormFsmEvent::DELETE_FORM, deleteForm);
}

int32_t FormRenderImpl::ReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const Want &want)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    auto releaseForm = [formId, compId, uid, want] {
        return FormRenderServiceMgr::GetInstance().ReleaseRenderer(formId, compId, uid, want);
    };

    return FormRenderStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_FORM, releaseForm);
}

int32_t FormRenderImpl::CleanFormHost(const sptr<IRemoteObject> &hostToken)
{
    return FormRenderServiceMgr::GetInstance().CleanFormHost(hostToken);
}

int32_t FormRenderImpl::ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
{
    return FormRenderServiceMgr::GetInstance().ReloadForm(std::move(formJsInfos), want);
}

int32_t FormRenderImpl::OnUnlock()
{
    return FormRenderServiceMgr::GetInstance().OnUnlock();
}

int32_t FormRenderImpl::SetRenderGroupEnableFlag(const int64_t formId, bool isEnable, const Want &want)
{
    return FormRenderServiceMgr::GetInstance().SetRenderGroupEnableFlag(formId, isEnable, want);
}

int32_t FormRenderImpl::SetVisibleChange(const int64_t &formId, bool isVisible, const Want &want)
{
    return FormRenderServiceMgr::GetInstance().SetVisibleChange(formId, isVisible, want);
}

void FormRenderImpl::RunCachedConfigurationUpdated()
{
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();
}

int32_t FormRenderImpl::RecycleForm(const int64_t &formId, const Want &want)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    auto recoverForm = [formId, want] { return FormRenderServiceMgr::GetInstance().RecycleForm(formId, want); };

    return FormRenderStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_DATA, recoverForm);
}

int32_t FormRenderImpl::RecoverForm(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("formId:%{public}" PRId64, formJsInfo.formId);
    auto recoverForm = [formJsInfo, want] { return FormRenderServiceMgr::GetInstance().RecoverForm(formJsInfo, want); };

    return FormRenderStatusMgr::GetInstance().PostFormEvent(formJsInfo.formId, FormFsmEvent::RECOVER_FORM, recoverForm);
}

int32_t FormRenderImpl::UpdateFormSize(
    const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo, const std::string &uid)
{
    return FormRenderServiceMgr::GetInstance().UpdateFormSize(formId, formSurfaceInfo, uid);
}

bool FormRenderImpl::CheckIsFoundationCall()
{
    return IPCSkeleton::GetCallingUid() == FormConstants::FOUNDATION_UID;
}

int32_t FormRenderImpl::CheckPermission()
{
    if (!CheckIsFoundationCall()) {
        HILOG_ERROR("Caller not foundation");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return ERR_OK;
}
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
