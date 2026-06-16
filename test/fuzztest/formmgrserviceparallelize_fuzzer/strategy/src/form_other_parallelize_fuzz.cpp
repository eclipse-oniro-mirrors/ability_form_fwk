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
#include "../include/form_other_parallelize_fuzz.h"

using namespace OHOS::FuzzerConstants;

namespace OHOS {
namespace AppExecFwk {
void FormOtherParallelizeFuzz::Execute(FuzzedDataProvider &provider)
{
    if (formMgrService_ == nullptr || formParallelizeUtil_ == nullptr) {
        return;
    }

    int code = provider.PickValueInArray(OTHER_IPC_DODES);

    switch (code) {
        case IpcCode::ACQUIRE_ADD_FORM_RESULT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            formMgrService_->AcquireAddFormResult(formId);
            break;
        }
        case IpcCode::HAS_FORM_VISIBLE_WITH_TOKENID: {
            uint32_t tokenId = provider.ConsumeIntegral<uint32_t>();
            formMgrService_->HasFormVisible(tokenId);
            break;
        }
        case IpcCode::STORAGE_FORM_INFOS: {
            std::string formInfos;
            formMgrService_->DumpStorageFormInfos(formInfos);
            break;
        }
        case IpcCode::FORM_INFOS_BY_NAME: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            std::string formInfos;
            formMgrService_->DumpFormInfoByBundleName(bundleName, formInfos);
            break;
        }
        case IpcCode::FORM_INFOS_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string formInfo;
            formMgrService_->DumpFormInfoByFormId(formId, formInfo);
            break;
        }
        case IpcCode::FORM_TIMER_INFO_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::string isTimingService;
            formMgrService_->DumpFormTimerByFormId(formId, isTimingService);
            break;
        }
        case IpcCode::ROUTER_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RouterEvent(formId, want, callerToken);
            break;
        }
        case IpcCode::BACKGROUND_EVENT: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->BackgroundEvent(formId, want, callerToken);
            break;
        }
        case IpcCode::START_ABILITY: {
            Want want;
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->StartAbility(want, callerToken);
            break;
        }
        case IpcCode::RECV_FORM_SHARE_INFO_FROM_REMOTE: {
            FormShareInfo info;
            formParallelizeUtil_->FillFormShareInfo(provider, info);
            formMgrService_->RecvFormShareInfoFromRemote(info);
            break;
        }
        case IpcCode::IS_SYSTEM_APP_FORM: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            formMgrService_->IsSystemAppForm(bundleName);
            break;
        }
        case IpcCode::GET_FORMS_COUNT: {
            bool isTempFormFlag = provider.ConsumeBool();
            int32_t formCount = 0;
            formMgrService_->GetFormsCount(isTempFormFlag, formCount);
            break;
        }
        case IpcCode::GET_HOST_FORMS_COUNT: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            int32_t formCount = 0;
            formMgrService_->GetHostFormsCount(bundleName, formCount);
            break;
        }
        case IpcCode::REGISTER_ADD_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterAddObserver(bundleName, callerToken);
            break;
        }
        case IpcCode::REGISTER_REMOVE_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterRemoveObserver(bundleName, callerToken);
            break;
        }
        case IpcCode::UPDATE_PROXY_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormProviderData formProviderData;
            formParallelizeUtil_->FillFormProviderData(provider, formProviderData);
            std::vector<FormDataProxy> formDataProxies;
            size_t proxyCount = provider.ConsumeIntegralInRange<size_t>(0, 4);
            for (size_t i = 0; i < proxyCount; ++i) {
                std::string key = provider.ConsumeRandomLengthString(NUMBER_32);
                std::string subscribeId = provider.ConsumeRandomLengthString(NUMBER_32);
                formDataProxies.emplace_back(key, subscribeId);
            }
            formMgrService_->UpdateProxyForm(formId, formProviderData, formDataProxies);
            break;
        }
        case IpcCode::REQUEST_PUBLISH_PROXY_FORM: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                formParallelizeUtil_->FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            std::vector<FormDataProxy> formDataProxies;
            size_t proxyCount = provider.ConsumeIntegralInRange<size_t>(0, 4);
            for (size_t i = 0; i < proxyCount; ++i) {
                std::string key = provider.ConsumeRandomLengthString(NUMBER_32);
                std::string subscribeId = provider.ConsumeRandomLengthString(NUMBER_32);
                formDataProxies.emplace_back(key, subscribeId);
            }
            formMgrService_->RequestPublishProxyForm(want, withFormBindingData, formBindingData, formId,
                formDataProxies);
            break;
        }
        case IpcCode::REGISTER_PUBLISH_FORM_INTERCEPTOR: {
            sptr<IRemoteObject> interceptorCallback = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterPublishFormInterceptor(interceptorCallback);
            break;
        }
        case IpcCode::UNREGISTER_PUBLISH_FORM_INTERCEPTOR: {
            sptr<IRemoteObject> interceptorCallback = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->UnregisterPublishFormInterceptor(interceptorCallback);
            break;
        }
        case IpcCode::REGISTER_CLICK_EVENT_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            std::string formEventType = provider.ConsumeRandomLengthString(NUMBER_32);
            sptr<IRemoteObject> observer = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterClickEventObserver(bundleName, formEventType, observer);
            break;
        }
        case IpcCode::UNREGISTER_CLICK_EVENT_OBSERVER: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            std::string formEventType = provider.ConsumeRandomLengthString(NUMBER_32);
            sptr<IRemoteObject> observer = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->UnregisterClickEventObserver(bundleName, formEventType, observer);
            break;
        }
        case IpcCode::REQUEST_PUBLISH_FORM_WITH_SNAPSHOT: {
            Want want;
            bool withFormBindingData = provider.ConsumeBool();
            std::unique_ptr<FormProviderData> formBindingData = nullptr;
            if (withFormBindingData) {
                formBindingData = std::make_unique<FormProviderData>();
                formParallelizeUtil_->FillFormProviderData(provider, *formBindingData);
            }
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            formMgrService_->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
            break;
        }
        case IpcCode::BATCH_REFRESH_FORMS: {
            int32_t formRefreshType = provider.ConsumeIntegralInRange<int32_t>(0, 2);
            formMgrService_->BatchRefreshForms(formRefreshType);
            break;
        }
        case IpcCode::ENABLE_FORMS: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            int32_t userId = provider.ConsumeIntegral<int32_t>();
            bool enable = provider.ConsumeBool();
            formMgrService_->EnableForms(bundleName, userId, enable);
            break;
        }
        case IpcCode::LOCK_FORMS: {
            size_t formLockInfosCount = provider.ConsumeIntegralInRange<size_t>(0, NUMBER_8);
            std::vector<FormLockInfo> formLockInfos;
            for (size_t i = 0; i < formLockInfosCount; ++i) {
                FormLockInfo info;
                formParallelizeUtil_->FillFormLockInfo(provider, info);
                formLockInfos.push_back(info);
            }
            LockChangeType type = static_cast<LockChangeType>(provider.ConsumeIntegralInRange<int32_t>(0, 1));
            formMgrService_->LockForms(formLockInfos, type);
            break;
        }
        case IpcCode::IS_FORM_BUNDLE_DEBUG_SIGNATURE: {
            std::string bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
            formMgrService_->IsFormBundleDebugSignature(bundleName);
            break;
        }
        default: {
            break;
        }
    }
}

} // namespace AppExecFwk
} // namespace OHOS