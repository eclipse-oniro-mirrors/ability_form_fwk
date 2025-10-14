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

#ifndef OHOS_FORM_FWK_FORM_PROVIDER_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_PROVIDER_TASK_MGR_H

#include <singleton.h>
#include "configuration.h"
#include "iremote_object.h"
#include "want.h"
#include "form_instance.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class FormProviderTaskMgr final : public DelayedRefSingleton<FormProviderTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormProviderTaskMgr)

public:
    DISALLOW_COPY_AND_MOVE(FormProviderTaskMgr);

    /**
     * @brief Acquire form data from form provider(task).
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostAcquireTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Refresh form data from form provider(task).
     *
     * @param formId The Id of the form.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostRefreshTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Delete form data from form provider(task).
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostDeleteTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

   /**
     * @brief Notify provider batch delete.
     * @param formIds The Id list.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Cast temp form data from form provider(task).
     *
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostCastTempTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire state to form provider.
    * @param wantArg The want of onAcquireFormState.
    * @param provider The provider info.
    * @param want The want of the request.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireStateTask(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr <IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire data to form provider.
    * @param formId The Id of the form.
    * @param want The want of the request.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireDataTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post message event to form provider.
     * @param formId The Id of the form.
     * @param message Event message.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostFormEventTask(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post event notify to form provider.
     * @param formEvent The vector of form ids.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param want The want of the form.
     * @param remoteObject The form provider proxy object.
     */
    void PostEventNotifyTask(const std::vector<int64_t> &formEvent, const int32_t formVisibleType, const Want &want,
        const sptr<IRemoteObject> &remoteObject);
    /**
     * @brief notify forms ability when configuration update.
     * @param configuration system configuration.
     * @param want The want of the request.
     */
    void NotifyConfigurationUpdate(const AppExecFwk::Configuration& configuration,
        const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief notify configuration update to form provider(task).
     *
     * @param formId The Id of the form.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostBatchConfigurationUpdateForms(const AppExecFwk::Configuration& configuration);
    
    /**
    * @brief Refresh form location data from form provider(task).
    *
    * @param formId The Id of the form.
    * @param want The want of the form.
    * @param remoteObject Form provider proxy object.
    * @return none.
    */
    void PostRefreshLocationTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post size changed to form provider.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostSizeChangedTask(const int64_t formId, const int32_t newDimension, const Rect &newRect,
        const Want &want, const sptr<IRemoteObject> &remoteObject);

private:
    /**
    * @brief Acquire provider formInfo.
    * @param formId The Id of the form.
    * @param want The want of the form.
    * @param remoteObject Form provider proxy object.
    */
    void AcquireProviderFormInfo(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for updating form.
     * @param formId The Id of the form.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     */
    void NotifyFormUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post provider delete.
     * @param formIds The Id list.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post provider batch delete.
     * @param formIds The Id list.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void ProviderBatchDelete(std::set<int64_t> formIds, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for cast temp form.
     *
     * @param formId The Id of the form.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void NotifyCastTemp(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Acquire form state to form provider.
     * @param wantArg The want of onAcquireFormState.
     * @param provider The provider info.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr <IRemoteObject> &remoteObject);

    /**
     * @brief Acquire form data to form provider.
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireFormData(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Fire message event to form provider.
     * @param formId The Id of the form.
     * @param message Event message.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Event notify to form provider.
    * @param formEvents The vector of form ids.
    * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
    * @param want The want of the form.
    * @param remoteObject The form provider proxy object.
    */
    void EventNotify(const std::vector<int64_t> &formEvents, const int32_t formVisibleType,
        const Want &want, const sptr<IRemoteObject> &remoteObject);

    void RemoveConnection(int32_t connectId);

    /**
    * @brief Notify form provider for updating form location.
    *
    * @param formId The Id of the from.
    * @param location The location of the form.
    * @param remoteObject Form provider proxy object.
    * @return none.
    */
    void NotifyFormLocationUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for size changed.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void NotifySizeChanged(const int64_t formId, const int32_t newDimension, const Rect &newRect,
        const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Delay detection of whether the form process exits normally.
     * @param connectId The ability connection id generated when save.
     */
    void DelayedFormExitDetect(int32_t connectId);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_PROVIDER_TASK_MGR_H