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

#ifndef OHOS_FORM_FWK_FORM_OBSERVER_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_OBSERVER_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {
class FormObserverTaskMgr final : public DelayedRefSingleton<FormObserverTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormObserverTaskMgr)

public:
    /**
    * @brief Post form add event.
    * @param bundleName BundleName of the form host
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void PostAddTaskToHost(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
    * @brief Post form remove event.
    * @param bundleName BundleName of the form host
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void PostRemoveTaskToHost(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
    * @brief Post form click event.
    * @param bundleName BundleName of the form host
    * @param formEventType form event type.
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void PostFormClickEventToHost(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
    * @brief Post BatchRefresh forms.
    * @param formRefreshType batch refresh forms type.
    */
    void PostBatchRefreshForms(const int32_t formRefreshType);

        /**
     * @brief notify configuration update to form provider(task).
     * @param configuration system configuration.
     */
    void PostBatchConfigurationUpdateForms(const AppExecFwk::Configuration& configuration);

private:
    /**
    * @brief Notify remote observer form click event.
    * @param bundleName BundleName of the form host
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void FormAdd(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
    * @brief Notify remote observer form click event.
    * @param bundleName BundleName of the form host
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void FormRemove(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
    * @brief Notify remote observer form click event.
    * @param bundleName BundleName of the form host
    * @param formEventType  form event type.
    * @param remoteObject the remote observer.
    * @param runningFormInfo Current form data.
    */
    void FormClickEvent(const std::string &bundleName, const std::string &formEventType,
        const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_OBSERVER_TASK_MGR_H