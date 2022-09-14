/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_CALLER_MGR_H
#define OHOS_FORM_FWK_FORM_CALLER_MGR_H

#include <singleton.h>

#include "event_handler.h"
#include "form_host_caller.h"
#include "form_provider_interface.h"
#include "form_provider_caller.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormCallerMgr
 * FormCallerMgr is used to manager form host caller and form provider caller.
 */
class FormCallerMgr final : public DelayedRefSingleton<FormCallerMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormCallerMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormCallerMgr);
    // for host
    void AddFormHostCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken);

    std::shared_ptr<FormHostCaller> GetFormHostCaller(int64_t formId);

    void RemoveFormHostCaller(int64_t formId);

    // for provider
    void AddFormProviderCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken);

    void GetFormProviderCaller(int64_t formId, std::vector<std::shared_ptr<FormProviderCaller>> &formProviderCallers);

    void RemoveFormProviderCaller(int64_t formId, const sptr<IRemoteObject> &callerToken);
private:
    std::shared_ptr<EventHandler> GetEventHandler();

    // for host
    void OnHostCallBackDied(const wptr<IRemoteObject> &remote);
    void HandleHostCallBackDiedTask(const sptr<IRemoteObject> &remote);
    void RemoveFormHostCaller(const sptr<IRemoteObject> &callerToken);

    // for provider
    void OnProviderCallBackDied(const wptr<IRemoteObject> &remote);
    void HandleProviderCallBackDiedTask(const sptr<IRemoteObject> &remote);
    void RemoveFormProviderCaller(const sptr<IRemoteObject> &callerToken);

    std::shared_ptr<EventHandler> eventHandler_ = nullptr;
    // for host
    mutable std::recursive_mutex formHostCallerMutex_;
    std::map<int64_t, std::shared_ptr<FormHostCaller>> formHostCallers_;

    // for provider
    mutable std::recursive_mutex formProviderCallerMutex_;
    std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CALLER_MGR_H
