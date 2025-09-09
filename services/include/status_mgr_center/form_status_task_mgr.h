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

#ifndef OHOS_FORM_FWK_FORM_STATUS_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_STATUS_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "want.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class FormStatusTaskMgr final : public DelayedRefSingleton<FormStatusTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatusTaskMgr)

public:
    /**
     * @brief Post recycle forms.
     * @param formIds the Ids of forms to be recycled.
     * @param want The want of the request.
     * @param remoteObjectOfHost Form host proxy object.
     * @param remoteObjectOfRender Form render proxy object.
     */
    void PostRecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost, const sptr<IRemoteObject> &remoteObjectOfRender);

    /**
     * @brief Post recover form.
     * @param record The form record.
     * @param want The want of the request.
     * @param remoteObject Form render proxy object.
     */
    void PostRecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post release form.
     * @param formIds The Id of form to be recovered.
     * @param compId The compId of the forms.
     * @param uid calling user id.
     * @param remoteObject Form render proxy object.
     * @param isDynamic isDynamic flag.
     */
    void PostReleaseRenderer(int64_t formId, const std::string &compId, const std::string &uid,
        const sptr<IRemoteObject> &remoteObject, bool isDynamic = true);

    /**
     * @brief Post render form.
     * @param formRecord The form record.
     * @param want The want of the request.
     * @param remoteObject Form render proxy object.
     */
    void PostRenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post stop rendering form.
     * @param formRecord The form record.
     * @param want The want of the request.
     * @param remoteObject Form render proxy object.
     */
    void PostStopRenderingForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Schedules form recycle timeout task
     * @param formId Form ID
     * @return bool Returns true if the timeout was successfully scheduled, false otherwise
     */
    bool ScheduleRecycleTimeout(const int64_t formId);

    /**
     * @brief Cancel form recycle timeout task
     * @param formId Form ID
     * @return bool Returns true if the timeout was successfully canceled, false otherwise
     */
    bool CancelRecycleTimeout(const int64_t formId);

private:
    void RecycleForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost,
        const sptr<IRemoteObject> &remoteObjectOfRender);

    void RecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void ReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    bool PostDelayReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    void StopRenderingForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void RenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void RemoveConnection(int32_t connectId);

    void RestoreFormRecycledStatus(const FormRecord &formRecord, const sptr<IRemoteObject> &remoteObject);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_TASK_MGR_H