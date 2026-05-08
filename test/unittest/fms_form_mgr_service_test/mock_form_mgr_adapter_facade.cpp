/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "form_mgr/form_mgr_adapter_facade.h"
#include "form_mgr/form_edit_service.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "form_instance.h"

namespace {
    int g_enableUpdateForm = OHOS::ERR_OK;
    int g_disableUpdateForm = OHOS::ERR_OK;
    int g_addForm = OHOS::ERR_OK;
    int g_deleteForm = OHOS::ERR_OK;
    int g_releaseForm = OHOS::ERR_OK;
    int g_requestForm = OHOS::ERR_OK;
    int g_notifyWhetherVisibleForms = OHOS::ERR_OK;
    int g_castTempForm = OHOS::ERR_OK;
    int g_messageEvent = OHOS::ERR_OK;
    int g_routerEvent = OHOS::ERR_OK;
    int g_deleteInvalidForms = OHOS::ERR_OK;
    int g_acquireFormState = OHOS::ERR_OK;
    int g_notifyFormsVisible = OHOS::ERR_OK;
    int g_notifyFormsEnableUpdate = OHOS::ERR_OK;
    int g_getFormsInfoByApp = OHOS::ERR_OK;
    int g_getFormsInfoByModule = OHOS::ERR_OK;
    int g_updateForm = OHOS::ERR_OK;
    int g_updateFormLocation = OHOS::ERR_OK;
    int g_setPublishFormResult = OHOS::ERR_OK;
    int g_acquireAddFormResult = OHOS::ERR_OK;
    bool g_isRequestPublishFormSupported = true;
    int32_t g_requestPublishForm = OHOS::ERR_OK;
    int g_stopRenderingForm = OHOS::ERR_OK;
    int g_releaseRenderer = OHOS::ERR_OK;
    int g_dumpStorageFormInfos = OHOS::ERR_OK;
    int g_dumpFormInfoByBundleName = OHOS::ERR_OK;
    int g_dumpFormInfoByFormId = OHOS::ERR_OK;
    int g_dumpFormTimerByFormId = OHOS::ERR_OK;
    int g_backgroundEvent = OHOS::ERR_OK;
    int g_registerFormRouterProxy = OHOS::ERR_OK;
    int g_unregisterFormRouterProxy = OHOS::ERR_OK;
    int g_getFormsCount = OHOS::ERR_OK;
    int g_getHostFormsCount = OHOS::ERR_OK;
    int g_getRunningFormInfos = OHOS::ERR_OK;
    int g_getRunningFormInfosByBundleName = OHOS::ERR_OK;
    int g_getFormInstanceById = OHOS::ERR_OK;
    int g_handleFormAddObserver = OHOS::ERR_OK;
    int g_registerAddObserver = OHOS::ERR_OK;
    int g_registerRemoveObserver = OHOS::ERR_OK;
    int g_registerClickFormEventObserver = OHOS::ERR_OK;
    int g_registerClickEventObserver = OHOS::ERR_OK;
    int g_unregisterClickEventObserver = OHOS::ERR_OK;
    int g_requestoverflow = OHOS::ERR_OK;
    int g_changesceneanimationstate = OHOS::ERR_OK;
    int g_getformrect = OHOS::ERR_OK;
    int g_startAbilityByFms = OHOS::ERR_OK;
    int g_registerChangeSceneAnimationStateProxy = OHOS::ERR_OK;
    int g_registerOverflowProxy = OHOS::ERR_OK;
    int g_registerGetFormRectProxy = OHOS::ERR_OK;
    int g_registerGetLiveFormStatusProxy = OHOS::ERR_OK;
    int g_unregisterGetLiveFormStatusProxy = OHOS::ERR_OK;
    int g_updateFormSizeFloat = OHOS::ERR_OK;
    int g_registerTemplateFormDetailInfoChange = OHOS::ERR_OK;
    int g_unregisterTemplateFormDetailInfoChange = OHOS::ERR_OK;
    int g_updateTemplateFormDetailInfo = OHOS::ERR_OK;
    int g_unregisterPublishFormCrossBundleControl = OHOS::ERR_OK;
    bool g_publishFormCrossBundleControl = true;
    bool g_hasFormVisible = true;
    int g_enableForms = OHOS::ERR_OK;
    int g_registerFormWantCallback = OHOS::ERR_OK;
    int g_unregisterFormWantCallback = OHOS::ERR_OK;
    int g_getWantCallbackProxy = OHOS::ERR_OK;
}

void MockEnableUpdateForm(int mockRet)
{
    g_enableUpdateForm = mockRet;
}

void MockDisableUpdateForm(int mockRet)
{
    g_disableUpdateForm = mockRet;
}

void MockAddForm(int mockRet)
{
    g_addForm = mockRet;
}

void MockDeleteForm(int mockRet)
{
    g_deleteForm = mockRet;
}

void MockReleaseForm(int mockRet)
{
    g_releaseForm = mockRet;
}

void MockRequestForm(int mockRet)
{
    g_requestForm = mockRet;
}

void MockNotifyWhetherVisibleForms(int mockRet)
{
    g_notifyWhetherVisibleForms = mockRet;
}

void MockCastTempForm(int mockRet)
{
    g_castTempForm = mockRet;
}

void MockMessageEvent(int mockRet)
{
    g_messageEvent = mockRet;
}

void MockRouterEvent(int mockRet)
{
    g_routerEvent = mockRet;
}

void MockAcquireFormState(int mockRet)
{
    g_acquireFormState = mockRet;
}

void MockNotifyFormsVisible(int mockRet)
{
    g_notifyFormsVisible = mockRet;
}

void MockNotifyFormsEnableUpdate(int mockRet)
{
    g_notifyFormsEnableUpdate = mockRet;
}

void MockGetFormsInfoByApp(int mockRet)
{
    g_getFormsInfoByApp = mockRet;
}

void MockGetFormsInfoByModule(int mockRet)
{
    g_getFormsInfoByModule = mockRet;
}

void MockIsRequestPublishFormSupported(bool mockRet)
{
    g_isRequestPublishFormSupported = mockRet;
}

void MockRrequestPublishForm(int32_t mockRet)
{
    g_requestPublishForm = mockRet;
}

void MockStopRenderingForm(int mockRet)
{
    g_stopRenderingForm = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
void MockFormMgrAdapterFacadeStartAbilityByFms(int mockRet)
{
    g_startAbilityByFms = mockRet;
}

void MockFormMgrAdapterFacadeRegisterChangeSceneAnimationStateProxy(int mockRet)
{
    g_registerChangeSceneAnimationStateProxy = mockRet;
}

void MockFormMgrAdapterFacadeRegisterOverflowProxy(int mockRet)
{
    g_registerOverflowProxy = mockRet;
}

void MockFormMgrAdapterFacadeRegisterGetFormRectProxy(int mockRet)
{
    g_registerGetFormRectProxy = mockRet;
}

void MockFormMgrAdapterFacadeRegisterGetLiveFormStatusProxy(int mockRet)
{
    g_registerGetLiveFormStatusProxy = mockRet;
}

void MockFormMgrAdapterFacadeUnregisterGetLiveFormStatusProxy(int mockRet)
{
    g_unregisterGetLiveFormStatusProxy = mockRet;
}

void MockFormMgrAdapterFacadeUpdateFormSizeFloat(int mockRet)
{
    g_updateFormSizeFloat = mockRet;
}

void MockFormMgrAdapterFacadeRegisterTemplateFormDetailInfoChange(int mockRet)
{
    g_registerTemplateFormDetailInfoChange = mockRet;
}

void MockFormMgrAdapterFacadeUnregisterTemplateFormDetailInfoChange(int mockRet)
{
    g_unregisterTemplateFormDetailInfoChange = mockRet;
}

void MockFormMgrAdapterFacadeUpdateTemplateFormDetailInfo(int mockRet)
{
    g_updateTemplateFormDetailInfo = mockRet;
}

void MockFormMgrAdapterFacadeUnregisterPublishFormCrossBundleControl(int mockRet)
{
    g_unregisterPublishFormCrossBundleControl = mockRet;
}

void MockFormMgrAdapterFacadePublishFormCrossBundleControl(bool mockRet)
{
    g_publishFormCrossBundleControl = mockRet;
}

void MockHasFormVisible(bool mockRet)
{
    g_hasFormVisible = mockRet;
}

void MockEnableForms(int mockRet)
{
    g_enableForms = mockRet;
}

void MockRegisterFormWantCallback(int mockRet)
{
    g_registerFormWantCallback = mockRet;
}

void MockUnregisterFormWantCallback(int mockRet)
{
    g_unregisterFormWantCallback = mockRet;
}

int FormMgrAdapterFacade::EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "EnableUpdateForm called " << g_enableUpdateForm;
    return g_enableUpdateForm;
}

int FormMgrAdapterFacade::DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DisableUpdateForm called " << g_disableUpdateForm;
    return g_disableUpdateForm;
}

int FormMgrAdapterFacade::AddForm(
    const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo)
{
    GTEST_LOG_(INFO) << "AddForm called " << g_addForm;
    return g_addForm;
}

int FormMgrAdapterFacade::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "DeleteForm called " << g_deleteForm;
    return g_deleteForm;
}

int FormMgrAdapterFacade::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    GTEST_LOG_(INFO) << "ReleaseForm called " << g_releaseForm;
    return g_releaseForm;
}

int FormMgrAdapterFacade::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    GTEST_LOG_(INFO) << "RequestForm called " << g_requestForm;
    return g_requestForm;
}

ErrCode FormMgrAdapterFacade::NotifyWhetherVisibleForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms called " << g_notifyWhetherVisibleForms;
    return g_notifyWhetherVisibleForms;
}

int FormMgrAdapterFacade::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "CastTempForm called " << g_castTempForm;
    return g_castTempForm;
}

int FormMgrAdapterFacade::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "MessageEvent called " << g_messageEvent;
    return g_messageEvent;
}

int FormMgrAdapterFacade::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "RouterEvent called " << g_routerEvent;
    return g_routerEvent;
}

int FormMgrAdapterFacade::DeleteInvalidForms(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms called " << g_deleteInvalidForms;
    return g_deleteInvalidForms;
}

int FormMgrAdapterFacade::AcquireFormState(
    const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
{
    GTEST_LOG_(INFO) << "AcquireFormState called " << g_acquireFormState;
    return g_acquireFormState;
}

int FormMgrAdapterFacade::NotifyFormsVisible(
    const std::vector<int64_t> &formIds, bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible called " << g_notifyFormsVisible;
    return g_notifyFormsVisible;
}

int FormMgrAdapterFacade::NotifyFormsEnableUpdate(
    const std::vector<int64_t> &formIds, bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    GTEST_LOG_(INFO) << "NotifyFormsEnableUpdate called " << g_notifyFormsEnableUpdate;
    return g_notifyFormsEnableUpdate;
}

int FormMgrAdapterFacade::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByApp called " << g_getFormsInfoByApp;
    return g_getFormsInfoByApp;
}

int FormMgrAdapterFacade::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    GTEST_LOG_(INFO) << "GetFormsInfoByModule called " << g_getFormsInfoByModule;
    return g_getFormsInfoByModule;
}

bool FormMgrAdapterFacade::IsRequestPublishFormSupported()
{
    return g_isRequestPublishFormSupported;
}

ErrCode FormMgrAdapterFacade::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    return g_requestPublishForm;
}

int FormMgrAdapterFacade::UpdateForm(const int64_t formId, const int32_t uid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    return g_updateForm;
}

int FormMgrAdapterFacade::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    return g_updateFormLocation;
}

int FormMgrAdapterFacade::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    return g_setPublishFormResult;
}

int FormMgrAdapterFacade::AcquireAddFormResult(const int64_t formId)
{
    return g_acquireAddFormResult;
}

int FormMgrAdapterFacade::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    return g_stopRenderingForm;
}

int FormMgrAdapterFacade::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    return g_releaseRenderer;
}

int FormMgrAdapterFacade::DumpStorageFormInfos(std::string &formInfos) const
{
    return g_dumpStorageFormInfos;
}

int FormMgrAdapterFacade::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const
{
    return g_dumpFormInfoByBundleName;
}

int FormMgrAdapterFacade::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const
{
    return g_dumpFormInfoByFormId;
}

int FormMgrAdapterFacade::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const
{
    return g_dumpFormTimerByFormId;
}

int FormMgrAdapterFacade::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    return g_backgroundEvent;
}

ErrCode FormMgrAdapterFacade::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return g_registerFormRouterProxy;
}

ErrCode FormMgrAdapterFacade::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    return g_unregisterFormRouterProxy;
}

int32_t FormMgrAdapterFacade::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    return g_getFormsCount;
}

int32_t FormMgrAdapterFacade::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    return g_getHostFormsCount;
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos,
    const int32_t userId)
{
    return g_getRunningFormInfos;
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    return g_getRunningFormInfosByBundleName;
}

ErrCode FormMgrAdapterFacade::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
    FormInstance &formInstance)
{
    return g_getFormInstanceById;
}

ErrCode FormMgrAdapterFacade::RegisterAddObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return g_registerAddObserver;
}

ErrCode FormMgrAdapterFacade::RegisterRemoveObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return g_registerRemoveObserver;
}

ErrCode FormMgrAdapterFacade::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return g_registerClickEventObserver;
}

ErrCode FormMgrAdapterFacade::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return g_unregisterClickEventObserver;
}

ErrCode FormMgrAdapterFacade::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    return g_requestoverflow;
}

ErrCode FormMgrAdapterFacade::ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state)
{
    return g_changesceneanimationstate;
}

ErrCode FormMgrAdapterFacade::GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect)
{
    return g_getformrect;
}

ErrCode FormMgrAdapterFacade::StartAbilityByFms(const Want &want)
{
    return g_startAbilityByFms;
}

ErrCode FormMgrAdapterFacade::RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
{
    return g_registerChangeSceneAnimationStateProxy;
}

ErrCode FormMgrAdapterFacade::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    return g_registerOverflowProxy;
}

ErrCode FormMgrAdapterFacade::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    return g_registerGetFormRectProxy;
}

ErrCode FormMgrAdapterFacade::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    return g_registerGetLiveFormStatusProxy;
}

ErrCode FormMgrAdapterFacade::UnregisterGetLiveFormStatusProxy()
{
    return g_unregisterGetLiveFormStatusProxy;
}

ErrCode FormMgrAdapterFacade::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
    float formViewScale)
{
    return g_updateFormSizeFloat;
}

ErrCode FormMgrAdapterFacade::RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken)
{
    return g_registerTemplateFormDetailInfoChange;
}

ErrCode FormMgrAdapterFacade::UnregisterTemplateFormDetailInfoChange()
{
    return g_unregisterTemplateFormDetailInfoChange;
}

ErrCode FormMgrAdapterFacade::UpdateTemplateFormDetailInfo(const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    return g_updateTemplateFormDetailInfo;
}

ErrCode FormMgrAdapterFacade::UnregisterPublishFormCrossBundleControl()
{
    return g_unregisterPublishFormCrossBundleControl;
}

bool FormMgrAdapterFacade::PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo)
{
    return g_publishFormCrossBundleControl;
}

bool FormMgrAdapterFacade::HasFormVisible(const uint32_t tokenId)
{
    return g_hasFormVisible;
}

int32_t FormMgrAdapterFacade::EnableForms(const std::string &bundleName, const int32_t userId, const bool enable)
{
    return g_enableForms;
}

ErrCode FormMgrAdapterFacade::RegisterFormWantCallback(int32_t callingUid, const sptr<IRemoteObject> &callerToken)
{
    return g_registerFormWantCallback;
}

ErrCode FormMgrAdapterFacade::UnregisterFormWantCallback(int32_t callingUid)
{
    return g_unregisterFormWantCallback;
}

ErrCode FormMgrAdapterFacade::GetWantCallbackProxy(int32_t callingUid, sptr<IRemoteObject> &proxy)
{
    return g_getWantCallbackProxy;
}
} // namespace AppExecFwk
} // namespace OHOS