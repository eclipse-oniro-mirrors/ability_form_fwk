/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "../include/form_host_parallelize_fuzz.h"

using namespace OHOS::FuzzerConstants;

namespace OHOS {
namespace AppExecFwk {
void FormHostParallelizeFuzz::Execute(FuzzedDataProvider &provider)
{
    if (formMgrService_ == nullptr || formParallelizeUtil_ == nullptr) {
        return;
    }

    int code = provider.PickValueInArray(HOST_IPC_DODES);

    switch (code) {
        case IpcCode::CREATE_FORM: {
            Want want;
            RunningFormInfo runningFormInfo;
            formParallelizeUtil_->FillRunningFormInfo(provider, runningFormInfo);
            formMgrService_->CreateForm(want, runningFormInfo);
            break;
        }
        case IpcCode::DELETE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->DeleteForm(formId, callerToken);
            break;
        }
        case IpcCode::RELEASE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            bool delCache = provider.ConsumeBool();
            formMgrService_->ReleaseForm(formId, callerToken, delCache);
            break;
        }
        case IpcCode::REQUEST_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            Want want;
            formMgrService_->RequestForm(formId, callerToken, want);
            break;
        }
        case IpcCode::CAST_TEMP_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->CastTempForm(formId, callerToken);
            break;
        }
        case IpcCode::NOTIFY_FORM_WHETHER_VISIBLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            int32_t formVisibleType = provider.ConsumeIntegralInRange<int32_t>(0, 1);
            formMgrService_->NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
            break;
        }
        case IpcCode::LIFECYCLE_UPDATE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            bool updateType = provider.ConsumeBool();
            formMgrService_->LifecycleUpdate(formIds, callerToken, updateType);
            break;
        }
        case IpcCode::CHECK_FMS_READY: {
            formMgrService_->CheckFMSReady();
            break;
        }
        case IpcCode::DELETE_INVALID_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            int32_t numFormsDeleted = 0;
            formMgrService_->DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
            break;
        }
        case IpcCode::ACQUIRE_FORM_STATE: {
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            FormStateInfo stateInfo;
            formParallelizeUtil_->FillFormStateInfo(provider, stateInfo);
            formMgrService_->AcquireFormState(want, callerToken, stateInfo);
            break;
        }
        case IpcCode::REGISTER_FORM_ROUTER_PROXY: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterFormRouterProxy(formIds, callerToken);
            break;
        }
        case IpcCode::UNREGISTER_FORM_ROUTER_PROXY: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            formMgrService_->UnregisterFormRouterProxy(formIds);
            break;
        }
        case IpcCode::NOTIFY_FORMS_VISIBLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isVisible = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->NotifyFormsVisible(formIds, isVisible, callerToken);
            break;
        }
        case IpcCode::NOTIFY_FORMS_ENABLE_UPDATE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isEnableUpdate = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
            break;
        }
        case IpcCode::GET_ALL_FORMS_INFO: {
            std::vector<FormInfo> formInfos;
            formMgrService_->GetAllFormsInfo(formInfos);
            break;
        }
        case IpcCode::GET_ALL_TEMPLATE_FORMS_INFO: {
            std::vector<FormInfo> infos;
            formMgrService_->GetAllTemplateFormsInfo(infos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_FILTER: {
            FormInfoFilter filter;
            formParallelizeUtil_->FillFormInfoFilter(provider, filter);
            std::vector<FormInfo> formInfos;
            formMgrService_->GetFormsInfoByFilter(filter, formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_APP: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> formInfos;
            formMgrService_->GetFormsInfoByApp(bundleName, formInfos);
            break;
        }
        case IpcCode::GET_FORMS_INFO_BY_MODULE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string moduleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> formInfos;
            formMgrService_->GetFormsInfoByModule(bundleName, moduleName, formInfos);
            break;
        }
        case IpcCode::GET_TEMPLATE_FORMS_INFO_BY_APP: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> infos;
            formMgrService_->GetTemplateFormsInfoByApp(bundleName, infos);
            break;
        }
        case IpcCode::GET_TEMPLATE_FORMS_INFO_BY_MODULE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            std::string moduleName = provider.ConsumeRandomLengthString(64);
            std::vector<FormInfo> infos;
            formMgrService_->GetTemplateFormsInfoByModule(bundleName, moduleName, infos);
            break;
        }
        case IpcCode::SHARE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string deviceId = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            int64_t requestCode = provider.ConsumeIntegral<int64_t>();
            formMgrService_->ShareForm(formId, deviceId, callerToken, requestCode);
            break;
        }
        case IpcCode::ACQUIRE_DATA: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int64_t requestCode = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            AAFwk::WantParams formData;
            formMgrService_->AcquireFormData(formId, requestCode, callerToken, formData);
            break;
        }
        case IpcCode::NOTIFY_FORMS_PRIVACY_PROTECTED: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            bool isProtected = provider.ConsumeBool();
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
            break;
        }
        case IpcCode::SET_FORMS_RECYCLABLE: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            formMgrService_->SetFormsRecyclable(formIds);
            break;
        }
        case IpcCode::RECOVER_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            Want want;
            formMgrService_->RecoverForms(formIds, want);
            break;
        }
        case IpcCode::RECYCLE_FORMS: {
            size_t formIdsCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
            std::vector<int64_t> formIds;
            for (size_t i = 0; i < formIdsCount; ++i) {
                formIds.push_back(provider.ConsumeIntegral<int64_t>());
            }
            Want want;
            formMgrService_->RecycleForms(formIds, want);
            break;
        }
        case IpcCode::NOTIFY_FORM_LOCKED: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            bool isLocked = provider.ConsumeBool();
            formMgrService_->NotifyFormLocked(formId, isLocked);
            break;
        }
        case IpcCode::UPDATE_FORM_LOCATION: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t formLocation = provider.ConsumeIntegralInRange<int32_t>(0, 3);
            formMgrService_->UpdateFormLocation(formId, formLocation);
            break;
        }
        case IpcCode::SET_PUBLISH_FORM_RESULT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Constants::PublishFormResult errorCodeInfo;
            errorCodeInfo.message = provider.ConsumeRandomLengthString(128);
            errorCodeInfo.code = static_cast<Constants::PublishFormErrorCode>(
                provider.ConsumeIntegralInRange<int32_t>(0, 10));
            formMgrService_->SetPublishFormResult(formId, errorCodeInfo);
            break;
        }
        case IpcCode::UNREGISTER_OVERFLOW_PROXY: {
            formMgrService_->UnregisterOverflowProxy();
            break;
        }
        case IpcCode::REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY: {
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterChangeSceneAnimationStateProxy(callerToken);
            break;
        }
        case IpcCode::REGISTER_GET_FORM_RECT: {
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterGetFormRectProxy(callerToken);
            break;
        }
        case IpcCode::REGISTER_GET_LIVE_FORM_STATUS: {
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterGetLiveFormStatusProxy(callerToken);
            break;
        }
        case IpcCode::UPDATE_FORM_SIZE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            float width = provider.ConsumeFloatingPoint<float>();
            float height = provider.ConsumeFloatingPoint<float>();
            float borderWidth = provider.ConsumeFloatingPoint<float>();
            float formViewScale = provider.ConsumeFloatingPoint<float>();
            formMgrService_->UpdateFormSize(formId, width, height, borderWidth, formViewScale);
            break;
        }
        case IpcCode::UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY: {
            formMgrService_->UnregisterChangeSceneAnimationStateProxy();
            break;
        }
        case IpcCode::UNREGISTER_GET_FORM_RECT: {
            formMgrService_->UnregisterGetFormRectProxy();
            break;
        }
        case IpcCode::REGISTER_OVERFLOW_PROXY: {
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterOverflowProxy(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_GET_LIVE_FORM_STATUS: {
            formMgrService_->UnregisterGetLiveFormStatusProxy();
            break;
        }
        case IpcCode::NOTIFY_UPDATE_FORM_SIZE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t newDimension = provider.ConsumeIntegral<int32_t>();
            Rect newRect;
            formParallelizeUtil_->FillRectInfo(provider, newRect);
            formMgrService_->UpdateFormSize(formId, newDimension, newRect);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_FORBIDDEN: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            formMgrService_->IsFormBundleForbidden(bundleName);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_PROTECTED: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            formMgrService_->IsFormBundleProtected(bundleName, formId);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_EXEMPT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            formMgrService_->IsFormBundleExempt(formId);
            break;
        }
        case IpcCode::STOP_RENDERING_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string compId = provider.ConsumeRandomLengthString(64);
            formMgrService_->StopRenderingForm(formId, compId);
            break;
        }
        case IpcCode::RELEASE_RENDERER: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string compId = provider.ConsumeRandomLengthString(64);
            formMgrService_->ReleaseRenderer(formId, compId);
            break;
        }
        case IpcCode::ADD_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            FormJsInfo formInfo;
            formParallelizeUtil_->FillFormJsInfo(provider, formInfo);
            formMgrService_->AddForm(formId, want, callerToken, formInfo);
            break;
        }
        case IpcCode::IS_FORM_DUE_CONTROL: {
            FormMajorInfo formMajorInfo;
            formParallelizeUtil_->FillFormMajorInfo(provider, formMajorInfo);
            bool isDisablePolicy = provider.ConsumeBool();
            formMgrService_->IsFormDueControl(formMajorInfo, isDisablePolicy);
            break;
        }
        case IpcCode::SEND_NON_TRANSPARENT_RATIO: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t ratio = provider.ConsumeIntegralInRange<int32_t>(0, 100);
            formMgrService_->SendNonTransparencyRatio(formId, ratio);
            break;
        }
        case IpcCode::MESSAGE_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->MessageEvent(formId, want, callerToken);
            break;
        }
        default: {
            break;
        }
    }
}

} // namespace AppExecFwk
} // namespace OHOS