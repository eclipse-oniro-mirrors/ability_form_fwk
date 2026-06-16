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

#include "form_mgr/form_observer_adapter.h"

#include "hitrace_meter.h"
#include "ipc_skeleton.h"

#include "form_mgr/form_common_adapter.h"

#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {

FormObserverAdapter::FormObserverAdapter()
{
    HILOG_DEBUG("FormObserverAdapter created");
}

FormObserverAdapter::~FormObserverAdapter()
{
}

int FormObserverAdapter::RegisterFormAddObserverByBundle(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    return FormObserverRecord::GetInstance().SetFormAddObserver(bundleName, callerToken);
}

int FormObserverAdapter::RegisterFormRemoveObserverByBundle(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    return FormObserverRecord::GetInstance().SetFormRemoveObserver(bundleName, callerToken);
}

int FormObserverAdapter::RegisterAddObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    return FormCommonAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
}

int FormObserverAdapter::RegisterRemoveObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    return FormCommonAdapter::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
}

void FormObserverAdapter::CleanResource(const wptr<IRemoteObject> &remote)
{
    FormCommonAdapter::GetInstance().CleanResource(remote);
}

ErrCode FormObserverAdapter::RegisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("null CallerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormObserverRecord::GetInstance().SetFormEventObserver(bundleName, formEventType, observer);
}

ErrCode FormObserverAdapter::UnregisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("null CallerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormObserverRecord::GetInstance().RemoveFormEventObserver(bundleName, formEventType, observer);
}

} // namespace AppExecFwk
} // namespace OHOS