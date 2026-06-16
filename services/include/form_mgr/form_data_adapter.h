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

#ifndef OHOS_FORM_FWK_FORM_DATA_ADAPTER_H
#define OHOS_FORM_FWK_FORM_DATA_ADAPTER_H

#include <unordered_map>

#include "singleton.h"
#include "app_mgr_interface.h"
#include "bundle_info.h"
#include "form_info.h"
#include "form_major_info.h"
#include "ipc_skeleton.h"
#include "want.h"
#include "want_params.h"

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "feature/param_update/param_control.h"
#include "form_host/form_host_record.h"
#include "form_provider/form_provider_mgr.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_render/form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {

class FormCommonAdapter;

class FormDataAdapter final : public DelayedRefSingleton<FormDataAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormDataAdapter)
public:

    int UpdateForm(const int64_t formId, const int32_t callingUid,
        const FormProviderData &formProviderData,
        const std::vector<FormDataProxy> &formDataProxies);

    int RequestForm(const int64_t formId,
        const sptr<IRemoteObject> &callerToken, const Want &want);

    ErrCode UpdateFormSize(const int64_t &formId,
        float width, float height, float borderWidth, float formViewScale);

    ErrCode UpdateFormSize(const int64_t formId,
        const int32_t newDimension, const Rect &newRect);

    int EnableUpdateForm(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken);

    int DisableUpdateForm(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken);

    ErrCode BatchRefreshForms(const int32_t formRefreshType);

    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime);

    void UpdateFormRenderParam(const int64_t formId, const sptr<IRemoteObject> &callerToken,
        const Want &want);

    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
        const bool isRequestPublishFormWithSnapshot = false);

    ErrCode AcquireProviderFormInfoAsync(const int64_t formId,
        const FormItemInfo &info, const WantParams &wantParams);

    ErrCode ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams);

    ErrCode ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms);

    int32_t OnNotifyRefreshForm(const int64_t &formId);

    ErrCode UpdateFormByCondition(int32_t type);

    void DelayRefreshFormsOnAppUpgrade(const std::vector<FormRecord> &updatedForms, const Want &want);

    ErrCode AcquireProviderFormInfoByFormRecord(const FormRecord &formRecord, const WantParams &wantParams);
    void ClearReconnectNum(int64_t formId);
    bool IsDeleteCacheInUpgradeScene(const FormRecord &record);
    void DeleteInvalidFormCacheIfNeed();

    ErrCode UpdateTimer(const int64_t formId, const FormRecord &record);
    void UpdateReUpdateFormMap(const int64_t formId);
    void SetReUpdateFormMap(const int64_t formId);

private:
    ErrCode InnerAcquireProviderFormInfoAsync(const int64_t formId,
        const FormItemInfo &info, const WantParams &wantParams);

    ErrCode HandleUpdateFormFlag(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate);
    void UpdateFormRenderParamsAfterReload(const int64_t formId);
    int64_t GetUpdateDurationFromAdditionalInfo(const std::string &additionalInfo);
    bool CheckUIAbilityContext(const pid_t pid);
    void PostEnterpriseAppInstallFailedRetryTask(const FormRecord &record, const Want &want);

    std::mutex reUpdateFormMapMutex_;
    std::map<int64_t, std::pair<int64_t, bool>> reUpdateFormMap_;
    std::mutex reconnectMutex_;
    std::unordered_map<int64_t, int32_t> formReconnectMap_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DATA_ADAPTER_H