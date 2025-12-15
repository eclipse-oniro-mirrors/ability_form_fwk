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

#include "form_observer/form_observer_task_mgr.h"
#include "fms_log_wrapper.h"
#include "js_form_state_observer_interface.h"
#include "form_mgr/form_mgr_queue.h"
#include "form_mgr/form_mgr_adapter.h"
 
namespace OHOS {
namespace AppExecFwk {
FormObserverTaskMgr::FormObserverTaskMgr() {}

FormObserverTaskMgr::~FormObserverTaskMgr() {}

/**
 * @brief Post form add event.
 * @param bundleName BundleName of the form host
 * @param remoteObject thr remote observer.
 * @param runningFormInfo Current form data.
 */
void FormObserverTaskMgr::PostAddTaskToHost(const std::string bundleName,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");

    auto addFunc = [bundleName, remoteObject, runningFormInfo]() {
        FormObserverTaskMgr::GetInstance().FormAdd(bundleName, remoteObject, runningFormInfo);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, addFunc);
}

/**
 * @brief Post form remove event.
 * @param bundleName BundleName of the form host
 * @param remoteObject thr remote observer.
 * @param runningFormInfo Current form data.
 */
void FormObserverTaskMgr::PostRemoveTaskToHost(const std::string bundleName,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");

    auto removeFunc = [bundleName, remoteObject, runningFormInfo]() {
        FormObserverTaskMgr::GetInstance().FormRemove(bundleName, remoteObject, runningFormInfo);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, removeFunc);
}

/**
 * @brief Post form click event.
 * @param bundleName BundleName of the form host
 * @param formEventType form event type.
 * @param remoteObject thr remote observer.
 * @param runningFormInfo Current form data.
 */
void FormObserverTaskMgr::PostFormClickEventToHost(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");

    auto task = [bundleName, formEventType, remoteObject, runningFormInfo]() {
        if (remoteObject == nullptr) {
            HILOG_ERROR("null remoteObject");
            return;
        }
        FormObserverTaskMgr::GetInstance().FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, task);
}
 
/**
* @brief Post BatchRefresh forms.
* @param formRefreshType batch refresh forms type.
*/
void FormObserverTaskMgr::PostBatchRefreshForms(const int32_t formRefreshType)
{
    HILOG_DEBUG("call");
 
    auto batchRefreshForms = [formRefreshType]() {
        return FormMgrAdapter::GetInstance().BatchRefreshForms(formRefreshType);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, batchRefreshForms);
}

/**
* @brief notify configuration update to form provider(task).
* @param configuration system configuration.
*/
void FormObserverTaskMgr::PostBatchConfigurationUpdateForms(const AppExecFwk::Configuration& configuration)
{
    HILOG_INFO("Call.");
 
    auto batchConfigurationUpdate = [configuration]() {
        return FormMgrAdapter::GetInstance().BatchNotifyFormsConfigurationUpdate(configuration);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, batchConfigurationUpdate);
    HILOG_INFO("end");
}
 
void FormObserverTaskMgr::FormAdd(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");

    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("get jsFormStateObserverProxy failed");
        return;
    }
    remoteJsFormStateObserver->OnAddForm(bundleName, runningFormInfo);
    HILOG_DEBUG("end");
}

void FormObserverTaskMgr::FormRemove(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");

    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("get jsFormStateObserverProxy failed");
        return;
    }
    remoteJsFormStateObserver->OnRemoveForm(bundleName, runningFormInfo);
    HILOG_DEBUG("end");
}

void FormObserverTaskMgr::FormClickEvent(const std::string &bundleName, const std::string &formEventType,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");

    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("fail get js form state observer proxy");
        return;
    }

    remoteJsFormStateObserver->OnFormClickEvent(bundleName, formEventType, runningFormInfo);
    HILOG_DEBUG("end");
}

} // namespace AppExecFwk
} // namespace OHOS