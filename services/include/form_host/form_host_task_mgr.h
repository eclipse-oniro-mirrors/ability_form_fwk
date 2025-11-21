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

#ifndef OHOS_FORM_FWK_FORM_HOST_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_HOST_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "form_state_info.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class FormHostTaskMgr final : public DelayedRefSingleton<FormHostTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormHostTaskMgr)

public:
    DISALLOW_COPY_AND_MOVE(FormHostTaskMgr);

    /**
     * @brief Post form data to form host(task) when acquire form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void PostAcquireTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post form data to form host(task) when update form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void PostUpdateTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post uninstall message to form host(task).
     * @param formIds The Id list of the forms.
     * @param remoteObject Form provider proxy object.
     */
    void PostUninstallTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire form state message to form host(task).
    * @param state The form state.
    * @param want The want of onAcquireFormState.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireStateTaskToHost(AppExecFwk::FormState state, const AAFwk::Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire form data message to form host(task).
    * @param wantParams Indicates the data information acquired by the form.
    * @param requestCode Indicates the requested id.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireDataTaskToHost(const AAFwk::WantParams &wantParams, int64_t requestCode,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post enable form task.
     * @param formIds formIds The Id list of the forms.
     * @param enable True or false.
     * @param remoteObject Form host proxy object.
     */
    void PostEnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post lock form task.
     * @param formIds formIds The Id list of the forms.
     * @param lock True or false.
     * @param remoteObject Form host proxy object.
     */
    void PostLockFormsTaskToHost(const std::vector<int64_t> &formIds, const bool lock,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post re-add form task to form host when FormRenderService is died.
     * @param remoteObject Form host proxy object.
     */
    void PostFrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post connect FRS failed task to form host when FormRenderService is died.
     * @param formId The Id of the form.
     * @param errorCode Indicates error-code of the form.
     */
    void PostConnectFRSFailedTaskToHost(int64_t formId, int32_t errorCode);

    /**
     * @brief Handle form host died(task).
     * @param remoteHost Form host proxy object.
     */
    void PostHostDiedTask(const sptr<IRemoteObject> &remoteHost);

    /**
     * @brief Post due control form task.
     * @param formIds formIds The Id list of the forms.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @param isControl True is control form, false is not control form.
     * @param remoteObject Form host proxy object.
     */
    void PostDueControlFormsTaskToHost(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
        const bool isControl, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post check form task.
     * @param formIds formIds The Id list of the forms.
     * @param remoteObject Form host proxy object.
     */
    void PostCheckFormsTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);

private:
    /**
     * @brief Post form data to form host when acquire form..
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireTaskToHost(const int64_t formId, const FormRecord &record,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post form data to form host when update form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void UpdateTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle uninstall message.
     * @param formIds The Id list of the forms.
     * @param remoteObject Form provider proxy object.
     */
    void FormUninstall(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle acquire state.
     * @param state the form state.
     * @param want The want of onAcquireFormState.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireStateBack(AppExecFwk::FormState state, const AAFwk::Want &want,
        const sptr <IRemoteObject> &remoteObject);

    /**
     * @brief Handle acquire data.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireFormDataBack(const AAFwk::WantParams &wantParams, int64_t requestCode,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Enable form or disable form.
     * @param formIds formIds The Id list of the forms.
     * @param enable True or false.
     * @param remoteObject Form host proxy object.
     */
    void EnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Lock form or unlock form.
     * @param formIds formIds The Id list of the forms.
     * @param lock True or false.
     * @param remoteObject Form host proxy object.
     */
    void LockFormsTaskToHost(const std::vector<int64_t> &formIds, const bool lock,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post re-add form task to form host when FormRenderService is died.
     * @param remoteObject Form host proxy object.
     */
    void FrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post connect FRS failed task to form host when FormRenderService is died.
     * @param formId The Id of the form.
     * @param errorCode Indicates error-code of the form.
     */
    void ConnectFRSFailedTaskToHost(int64_t formId, int32_t errorCode);

    /**
     * @brief Handle form host died.
     * @param remoteHost Form host proxy object.
     */
    void HostDied(const sptr<IRemoteObject> &remoteHost);

    /**
     * @brief Exec due control form task.
     * @param formIds formIds The Id list of the forms.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @param isControl True is control form, false is not control form.
     * @param remoteObject Form host proxy object.
     */
    void DueControlFormsTaskToHost(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
        const bool isControl, const sptr<IRemoteObject> &remoteObject);
    
    /**
     * @brief Exec check form task.
     * @param formIds formIds The Id list of the forms.
     * @param remoteObject Form host proxy object.
     */
    void CheckFormsTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HOST_TASK_MGR_H