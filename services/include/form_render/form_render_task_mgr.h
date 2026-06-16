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

#ifndef OHOS_FORM_FWK_FORM_RENDER_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "want.h"
#include "data_center/form_record/form_record.h"
#include "form_surface_info.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class FormRenderTaskMgr final : public DelayedRefSingleton<FormRenderTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderTaskMgr)

public:
    void PostUpdateFormSize(const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo,
        const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    void PostOnUnlock(const sptr<IRemoteObject> &remoteObject);

    void PostSetRenderGroupEnableFlag(int64_t formId, bool isEnable, const sptr<IRemoteObject> &remoteObject);

    void PostSetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject);

    void PostReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    void PostSetRenderGroupParams(int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

private:
    void UpdateFormSize(const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo, const std::string &uid,
        const sptr<IRemoteObject> &remoteObject);

    void OnUnlock(const sptr<IRemoteObject> &remoteObject);

    void SetRenderGroupEnableFlag(int64_t formId, bool isEnable, const sptr<IRemoteObject> &remoteObject);

    void SetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject);

    void ReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
        const sptr<IRemoteObject> &remoteObject);
    void RestoreFormsRecycledStatus(const std::vector<FormRecord> &&formRecords);

    void SetRenderGroupParams(int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_TASK_MGR_H