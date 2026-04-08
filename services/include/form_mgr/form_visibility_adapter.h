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

#ifndef OHOS_FORM_FWK_FORM_VISIBILITY_ADAPTER_H
#define OHOS_FORM_FWK_FORM_VISIBILITY_ADAPTER_H

#include <map>
#include <mutex>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/event/form_event_notify_connection.h"
#include "common/util/form_util.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "form_host/form_host_record.h"
#include "form_mgr/form_mgr_queue.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_render/form_render_mgr.h"
#include "js_form_state_observer_interface.h"
#include "status_mgr_center/form_status.h"
#include "bms_mgr/form_bms_helper.h"

namespace OHOS {
namespace AppExecFwk {

class FormCommonAdapter;

class FormVisibilityAdapter {
public:
    FormVisibilityAdapter(
        FormDataMgr* formDataMgr,
        FormCacheMgr* formCacheMgr,
        RefreshCacheMgr* refreshCacheMgr,
        FormInfoMgr* formInfoMgr,
        FormRenderMgr* formRenderMgr,
        FormMgrQueue* formMgrQueue,
        FormCommonAdapter* commonAdapter);

    virtual ~FormVisibilityAdapter() = default;

    ErrCode NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType);

    bool HasFormVisible(const uint32_t tokenId);

    int NotifyFormsVisible(const std::vector<int64_t> &formIds,
        bool isVisible, const sptr<IRemoteObject> &callerToken);

    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds,
        bool isEnableUpdate, const sptr<IRemoteObject> &callerToken);

    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds);

    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want, bool isCheckCallingUid);

    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked);

    void PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps);

    void HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
        const sptr<IRemoteObject> &callerToken);

private:
    void SetVisibleChange(const int64_t formId, const int32_t formVisibleType, const int32_t userId);

    void PostVisibleNotify(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> &eventMaps,
        const int32_t formVisibleType, int32_t visibleNotifyDelay,
        const sptr<IRemoteObject> &callerToken);

    void NotifyWhetherFormsVisible(const std::string &bundleName,
        const std::vector<sptr<IRemoteObject>> &remoteObjects,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps, const int32_t formVisibleType);

    void FilterDataByVisibleType(std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> &eventMaps, const int32_t formVisibleType);

    void FilterFormInstanceMapsByVisibleType(
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords);

    void FilterEventMapsByVisibleType(std::map<std::string, std::vector<int64_t>> &eventMaps,
        const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords);

    bool isFormShouldUpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
        const sptr<IRemoteObject> &callerToken, FormRecord &formRecord);

    bool UpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
        const sptr<IRemoteObject> &callerToken, const int32_t &formVisibleType, FormRecord &formRecord);

    bool CreateHandleEventMap(const int64_t matchedFormId, const FormRecord &formRecord,
        std::map<std::string, std::vector<int64_t>> &eventMaps);

    ErrCode HandleEventNotify(const std::string &providerKey, const std::vector<int64_t> &formIdsByProvider,
        const int32_t formVisibleType);

    ErrCode HandleUpdateFormFlag(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate);

    FormDataMgr* formDataMgr_;
    FormCacheMgr* formCacheMgr_;
    RefreshCacheMgr* refreshCacheMgr_;
    FormInfoMgr* formInfoMgr_;
    FormRenderMgr* formRenderMgr_;
    FormMgrQueue* formMgrQueue_;
    FormCommonAdapter* commonAdapter_;
    int32_t visibleNotifyDelay_;
    mutable std::mutex formObserversMutex_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formObservers_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_VISIBILITY_ADAPTER_H