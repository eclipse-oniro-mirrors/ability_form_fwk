/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_IPC_HANDLERS_H
#define OHOS_FORM_FWK_FORM_IPC_HANDLERS_H

#include "form_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
// Reads a FormDataProxy list from a parcel; shared by the proxy-form handlers.
bool ReadFormDataProxies(MessageParcel &data, std::vector<FormDataProxy> &formDataProxies);

namespace FormIpcHandlers {
int32_t HandleAddForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleCreateForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDeleteForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleStopRenderingForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleReleaseForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateFormProviderInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateFormCrossBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleSetNextRefreshTime(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleReleaseRenderer(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestPublishFormCrossUser(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestPublishForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleSetPublishFormResult(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleAcquireAddFormResult(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleLifecycleUpdate(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyWhetherVisibleForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleHasFormVisible(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleCastTempForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDumpStorageFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDumpFormInfoByBundleName(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDumpFormInfoByFormId(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDumpFormTimerByFormId(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleMessageEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRouterEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleBackgroundEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleInsightIntentEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDeleteInvalidForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleAcquireFormState(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyFormsVisible(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyFormsPrivacyProtected(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyFormsEnableUpdate(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetAllFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetAllTemplateFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormsInfoByApp(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetTemplateFormsInfoByApp(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormsInfoByModule(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetTemplateFormsInfoByModule(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormsInfoByFilter(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetPublishedFormInfoById(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetPublishedFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleShareForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleAcquireFormData(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRecvFormShareInfoFromRemote(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsRequestPublishFormSupported(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleStartAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleStartAbilityByFms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleStartUIAbilityByFms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleStartAbilityByCrossBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleCheckFMSReady(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsSystemAppForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterFormAddObserverByBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterFormRemoveObserverByBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormsCount(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormInstancesByFilter(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormInstanceById(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetHostFormsCount(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetRunningFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetRunningFormInfosByBundleName(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterPublishFormInterceptor(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterPublishFormInterceptor(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterClickCallbackEventObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterClickCallbackEventObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterAddObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterRemoveObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterFormRouterProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterFormRouterProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateProxyForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestPublishProxyForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleSetFormsRecyclable(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRecycleForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRecoverForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateFormLocation(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestPublishFormWithSnapshot(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleBatchRefreshForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleEnableForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsFormBundleForbidden(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleLockForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsFormProtected(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsFormDebugSignature(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsFormExempt(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyFormLocked(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateFormSize(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleOpenFormEditAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleCloseFormEditAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterOverflowProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterOverflowProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestOverflow(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterChangeSceneAnimationStateProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterChangeSceneAnimationStateProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleChangeSceneAnimationState(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterGetFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterGetFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormRect(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleNotifyUpdateFormSize(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterGetLiveFormStatusProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterGetLiveFormStatusProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleIsFormDueControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleReloadForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleReloadAllForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleSendNonTransparencyRatio(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterTemplateFormDetailInfoChange(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterTemplateFormDetailInfoChange(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateTemplateFormDetailInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterPublishFormCrossBundleControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterPublishFormCrossBundleControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetFormIdsByFormLocation(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterFormWantCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterFormWantCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterUpdateFormsConfigCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterUpdateFormsConfigCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUpdateFormsConfig(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterDeleteFormsCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterDeleteFormsCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleDeleteForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterFormHostService(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterFormHostService(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetAvailableFormHostServices(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRequestPublishFormCrossDevice(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleRegisterGetVisibleFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleUnregisterGetVisibleFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleGetVisibleFormRect(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleOpenFormManagePage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleOpenFormEditPage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
int32_t HandleOpenLiveFormPage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply);
} // namespace FormIpcHandlers
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_IPC_HANDLERS_H
