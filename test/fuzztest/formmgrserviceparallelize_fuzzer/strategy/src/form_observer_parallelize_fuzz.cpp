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
#include "../include/form_observer_parallelize_fuzz.h"

using namespace OHOS::FuzzerConstants;

namespace OHOS {
namespace AppExecFwk {
void FormObserverParallelizeFuzz::Execute(FuzzedDataProvider &provider)
{
    if (formMgrService_ == nullptr || formParallelizeUtil_ == nullptr) {
        return;
    }

    int code = provider.PickValueInArray(OBSERVER_IPC_DODES);

    switch (code) {
        case IpcCode::REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterFormAddObserverByBundle(bundleName, callerToken);
            break;
        }
        case IpcCode::REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            sptr<IRemoteObject> callerToken = formParallelizeUtil_->GetMockRemoteObject();
            formMgrService_->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
            break;
        }
        case IpcCode::GET_RUNNING_FORM_INFOS_BY_BUNDLE: {
            std::string bundleName = provider.ConsumeRandomLengthString(64);
            bool isUnusedIncluded = provider.ConsumeBool();
            std::vector<RunningFormInfo> runningFormInfos;
            formMgrService_->GetRunningFormInfosByBundleName(bundleName, isUnusedIncluded, runningFormInfos);
            break;
        }
        case IpcCode::GET_RUNNING_FORM_INFOS: {
            bool isUnusedIncluded = provider.ConsumeBool();
            std::vector<RunningFormInfo> runningFormInfos;
            formMgrService_->GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
            break;
        }
        case IpcCode::GET_FORM_INSTANCES_BY_FILTER: {
            FormInstancesFilter filter;
            formParallelizeUtil_->FillFormInstancesFilter(provider, filter);
            std::vector<FormInstance> formInstances;
            formMgrService_->GetFormInstancesByFilter(filter, formInstances);
            break;
        }
        case IpcCode::GET_FORM_INSTANCES_BY_ID: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            FormInstance formInstance;
            formMgrService_->GetFormInstanceById(formId, formInstance);
            break;
        }
        default: {
            break;
        }
    }
}

} // namespace AppExecFwk
} // namespace OHOS