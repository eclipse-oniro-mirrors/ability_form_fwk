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
#include "../include/form_provider_parallelize_fuzz.h"

using namespace OHOS::FuzzerConstants;

namespace OHOS {
namespace AppExecFwk {
void FormProviderParallelizeFuzz::Execute(FuzzedDataProvider &provider)
{
    if (formMgrService_ == nullptr || formParallelizeUtil_ == nullptr) {
        return;
    }

    int code = provider.PickValueInArray(PROVIDER_IPC_DODES);

    switch (code) {
        case IpcCode::GET_FORMS_INFO: {
            FormInfoFilter filter;
            formParallelizeUtil_->FillFormInfoFilter(provider, filter);
            std::vector<FormInfo> formInfos;
            formMgrService_->GetFormsInfo(filter, formInfos);
            break;
        }
        case IpcCode::GET_PUBLISHED_FORM_INFO_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            RunningFormInfo formInfo;
            formMgrService_->GetPublishedFormInfoById(formId, formInfo);
            break;
        }
        case IpcCode::GET_PUBLISHED_FORM_INFOS: {
            std::vector<RunningFormInfo> formInfos;
            formMgrService_->GetPublishedFormInfos(formInfos);
            break;
        }
        case IpcCode::START_ABILITY_BY_FMS: {
            Want want;
            formMgrService_->StartAbilityByFms(want);
            break;
        }
        case IpcCode::START_ABILITY_BY_CROSS_BUNDLE: {
            Want want;
            formMgrService_->StartAbilityByCrossBundle(want);
            break;
        }
        case IpcCode::SET_NEXT_REFRESH_TIME: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int64_t nextTime = provider.ConsumeIntegral<int64_t>();
            formMgrService_->SetNextRefreshTime(formId, nextTime);
            break;
        }
        case IpcCode::UPDATE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormProviderData formProviderData;
            formParallelizeUtil_->FillFormProviderData(provider, formProviderData);
            formMgrService_->UpdateForm(formId, formProviderData);
            break;
        }
        case IpcCode::IS_REQUEST_PUBLISH_FORM_SUPPORTED: {
            formMgrService_->IsRequestPublishFormSupported();
            break;
        }
        case IpcCode::REQUEST_PUBLISH_FORM: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                formParallelizeUtil_->FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            formMgrService_->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
            break;
        }
        case IpcCode::OPEN_FORM_EDIT_ABILITY: {
            std::string abilityName = provider.ConsumeRandomLengthString(64);
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            bool isMainPage = provider.ConsumeBool();
            formMgrService_->OpenFormEditAbility(abilityName, formId, isMainPage);
            break;
        }
        case IpcCode::REQUEST_OVERFLOW: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            OverflowInfo overflowInfo;
            formParallelizeUtil_->FillOverflowInfo(provider, overflowInfo);
            bool isOverflow = provider.ConsumeBool();
            formMgrService_->RequestOverflow(formId, overflowInfo, isOverflow);
            break;
        }
        case IpcCode::CHANGE_SCENE_ANIMATION_STATE: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            int32_t state = provider.ConsumeIntegralInRange<int32_t>(0, 1);
            formMgrService_->ChangeSceneAnimationState(formId, state);
            break;
        }
        case IpcCode::GET_FORM_RECT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Rect rect;
            formMgrService_->GetFormRect(formId, rect);
            break;
        }
        case IpcCode::RELOAD_FORMS: {
            int32_t reloadNum = 0;
            std::string moduleName = provider.ConsumeRandomLengthString(64);
            std::string abilityName = provider.ConsumeRandomLengthString(64);
            std::string formName = provider.ConsumeRandomLengthString(64);
            formMgrService_->ReloadForms(reloadNum, moduleName, abilityName, formName);
            break;
        }
        case IpcCode::RELOAD_ALL_FORMS: {
            int32_t reloadNum = 0;
            formMgrService_->ReloadAllForms(reloadNum);
            break;
        }
        case IpcCode::UPDATE_TEMPLATE_FORM_DETAIL_INFO: {
            std::vector<TemplateFormDetailInfo> templateFormInfo;
            TemplateFormDetailInfo templateFormDetailInfo;
            formParallelizeUtil_->FillTemplateFormDetailInfo(provider, templateFormDetailInfo);
            templateFormInfo.push_back(templateFormDetailInfo);
            formMgrService_->UpdateTemplateFormDetailInfo(templateFormInfo);
            break;
        }
        case IpcCode::REGISTER_PUBLISH_FORM_CROSS_BUNDLE_CONTROL: {
            const sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterPublishFormCrossBundleControl(callerToken);
            break;
        }
        case IpcCode::UNREGISTER_PUBLISH_FORM_CROSS_BUNDLE_CONTROL: {
            formMgrService_->UnregisterPublishFormCrossBundleControl();
            break;
        }
        case IpcCode::CLOSE_FORM_EDIT_ABILITY: {
            bool isMainPage = provider.ConsumeBool();
            formMgrService_->CloseFormEditAbility(isMainPage);
            break;
        }
        default: {
            break;
        }
    }
}

} // namespace AppExecFwk
} // namespace OHOS