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

#ifndef OHOS_FORM_FWK_FORM_OBSERVER_ADAPTER_H
#define OHOS_FORM_FWK_FORM_OBSERVER_ADAPTER_H

#include <map>
#include <mutex>
#include <vector>

#include "iremote_object.h"
#include "running_form_info.h"
#include "singleton.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "form_observer/form_observer_record.h"

namespace OHOS {
namespace AppExecFwk {

class FormObserverAdapter final : public DelayedRefSingleton<FormObserverAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormObserverAdapter)

public:

    int RegisterFormAddObserverByBundle(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken);

    int RegisterFormRemoveObserverByBundle(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken);

    int RegisterAddObserver(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken);

    int RegisterRemoveObserver(const std::string &bundleName,
        const sptr<IRemoteObject> &callerToken);

    void CleanResource(const wptr<IRemoteObject> &remote);

    ErrCode RegisterClickEventObserver(const std::string &bundleName,
        const std::string &formEventType, const sptr<IRemoteObject> &observer);

    ErrCode UnregisterClickEventObserver(const std::string &bundleName,
        const std::string &formEventType, const sptr<IRemoteObject> &observer);
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_OBSERVER_ADAPTER_H