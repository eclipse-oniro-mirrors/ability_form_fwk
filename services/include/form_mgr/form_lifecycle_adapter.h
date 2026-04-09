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

#ifndef OHOS_FORM_FWK_FORM_LIFECYCLE_ADAPTER_H
#define OHOS_FORM_FWK_FORM_LIFECYCLE_ADAPTER_H

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>

#include "form_major_info.h"
#include "form_mgr_errors.h"
#include "form_provider_data.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "want.h"


#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_js_info.h"
#include "form_mgr/form_mgr_adapter.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/event/form_event_notify_connection.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_report.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "form_host/form_host_record.h"
#include "form_provider/form_provider_mgr.h"
#include "form_provider/form_supply_callback.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_render/form_render_mgr.h"
#include "form_event_report.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_constants.h"
#include "common/util/form_task_common.h"
#include "form_provider/connection/form_cast_temp_connection.h"
#include "bundle_mgr_interface.h"
#include "bundle_info.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "configuration.h"
#ifdef THEME_MGR_ENABLE
#include "feature/theme_form/form_theme_form_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {

class FormCommonAdapter;
class FormPublishAdapter;

class FormLifecycleAdapter {
public:
    FormLifecycleAdapter(
        FormDataMgr* formDataMgr,
        FormInfoMgr* formInfoMgr,
        FormProviderMgr* formProviderMgr,
        FormRenderMgr* formRenderMgr,
        FormCommonAdapter* commonAdapter,
        FormPublishAdapter* publishAdapter);

    virtual ~FormLifecycleAdapter() = default;

    int AddForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo);

    int DeleteForm(const int64_t formId,
        const sptr<IRemoteObject> &callerToken);

    int ReleaseForm(const int64_t formId,
        const sptr<IRemoteObject> &callerToken, const bool delCache);

    int CastTempForm(const int64_t formId,
        const sptr<IRemoteObject> &callerToken);

    int CreateForm(const Want &want, RunningFormInfo &runningFormInfo);

    int StopRenderingForm(const int64_t formId, const std::string &compId);

    int ReleaseRenderer(const int64_t formId, const std::string &compId);

    int DeleteInvalidForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted);

    // Additional public methods per design document
    ErrCode EnableForms(const std::string &bundleName, const int32_t userId, const bool enable);
    ErrCode ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect);
    ErrCode RecoverForms(const std::vector<int64_t> &formIds, const Want &want);
    ErrCode SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock);
    ErrCode BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration);

#ifdef RES_SCHEDULE_ENABLE
    /**
     * @brief Set the value which indicate whether Refresh Timer task should be triggered.
     * @param isTimerTaskNeeded The value of whether Refresh Timer task should be triggered.
     */
    void SetTimerTaskNeeded(bool isTimerTaskNeeded);
#endif // RES_SCHEDULE_ENABLE

private:
    // Private helper methods
    ErrCode CheckFormCountLimit(const int64_t formId, const Want &want);
    ErrCode AddRequestPublishForm(const FormItemInfo &formItemInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo);
    ErrCode AllotForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo, const FormItemInfo &formItemInfo);
    ErrCode AllotFormById(const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo);
    ErrCode AllotFormBySpecificId(const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo);
    ErrCode AllotFormByInfo(const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo);
    ErrCode AddExistFormRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const FormRecord &record, const int64_t formId, const WantParams &wantParams, FormJsInfo &formInfo);
    ErrCode AddNewFormRecord(const FormItemInfo &info, const int64_t formId,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formJsInfo);
    void HandleFormRemoveObserver(const RunningFormInfo runningFormInfo);
    ErrCode HandleDeleteTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);
    ErrCode HandleDeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);
    ErrCode HandleDeleteFormCache(FormRecord &dbRecord, const int uid, const int64_t formId);
    ErrCode HandleReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);
    ErrCode HandleCastTempForm(const int64_t formId, const FormRecord &formRecord);
    void CheckIsAddFormByHost(const FormRecord &formRecord, Want &allotFormWant);
    int DeleteCommonForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const int32_t userId);
    bool IsFormRenderServiceCall(int callingUid);

#ifdef THEME_MGR_ENABLE
    int DeleteThemeForm(const int64_t formId);
    int AddThemeDBRecord(const Want &want, int64_t formId);
    FormRecord AllotThemeRecord(const Want &want, int64_t formId);
#endif

    FormDataMgr* formDataMgr_;
    FormInfoMgr* formInfoMgr_;
    FormProviderMgr* formProviderMgr_;
    FormRenderMgr* formRenderMgr_;
    FormCommonAdapter* commonAdapter_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_LIFECYCLE_ADAPTER_H
