/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "form_provider/form_supply_callback.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "form_constants.h"
#include "data_center/form_data_proxy_mgr.h"
#include "form_mgr_errors.h"
#include "form_provider/form_provider_mgr.h"
#include "form_provider/form_provider_task_mgr.h"
#include "form_provider/form_provider_queue.h"
#include "form_render/form_render_mgr.h"
#include "feature/form_share/form_share_mgr.h"
#include "common/util/form_util.h"
#include "hitrace_meter.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "data_center/form_data_mgr.h"
#include "form_host_interface.h"
#include "common/util/form_report.h"
#include "data_center/form_record/form_record_report.h"
#include "form_mgr/form_mgr_adapter.h"
#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_event_retry_mgr.h"
#include "status_mgr_center/form_status_task_mgr.h"
#include "common/util/form_task_common.h"

namespace OHOS {
namespace AppExecFwk {
sptr<FormSupplyCallback> FormSupplyCallback::instance_ = nullptr;
std::mutex FormSupplyCallback::mutex_;
const std::string EMPTY_STATUS_DATA = "empty_status_data";

sptr<FormSupplyCallback> FormSupplyCallback::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) FormSupplyCallback();
            if (instance_ == nullptr) {
                HILOG_ERROR("create FormSupplyCallback failed");
            }
        }
    }
    return instance_;
}

void FormSupplyCallback::ProcessFormAcquisition(int64_t formId)
{
    FormRecord record;
    bool hasRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (hasRecord) {
        int64_t endTime;
        FormReport::GetInstance().GetEndAquireTime(formId, endTime);
        if (!endTime) {
            FormReport::GetInstance().SetEndAquireTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
            FormReport::GetInstance().HandleAddFormStatistic(formId);
        }
    }
}
/**
 * @brief Accept form binding data from form provider.
 * @param providerFormInfo Form binding data.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnAcquire(const FormProviderInfo &formProviderInfo, const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    int errCode = want.GetIntParam(Constants::PROVIDER_FLAG, ERR_OK);
    if (errCode != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }

    std::string strFormId = want.GetStringParam(Constants::PARAM_FORM_IDENTITY_KEY);
    if (strFormId.empty()) {
        HILOG_ERROR("empty formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    int64_t formId = std::stoll(strFormId);
    FormReport::GetInstance().SetAddFormFinish(formId);
    FormReport::GetInstance().SetStartAquireTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    FormRecordReport::GetInstance().SetFormRecordRecordInfo(formId, want);
    FormReport::GetInstance().SetFormRecordInfo(formId, want);
    ProcessFormAcquisition(formId);
    if (IsRemoveConnection(formId, want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN))) {
        RemoveConnection(connectId);
    }

    if (FormRenderMgr::GetInstance().IsNeedRender(formId)) {
        errCode = FormRenderMgr::GetInstance().UpdateRenderingForm(formId, formProviderInfo.GetFormData(),
            want.GetParams(), false);
        FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formProviderInfo.GetFormProxies(), want);
        return errCode;
    }

    int32_t ret = ERR_APPEXECFWK_FORM_INVALID_PARAM;
    int type = want.GetIntParam(Constants::ACQUIRE_TYPE, 0);
    HILOG_DEBUG("%{public}" PRId64 ",%{public}d,%{public}d",
        formId, connectId, type);
    switch (type) {
        case Constants::ACQUIRE_TYPE_CREATE_FORM:
            ret = FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
            break;
        case Constants::ACQUIRE_TYPE_RECREATE_FORM:
            ret = FormProviderMgr::GetInstance().UpdateForm(formId, formProviderInfo);
            break;
        default:
            HILOG_WARN("onAcquired type:%{public}d", type);
    }

    FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formProviderInfo.GetFormProxies(), want);
    HILOG_INFO("end");
    return ret;
}

/**
 * @brief Accept other event.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnEventHandle(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    std::string supplyInfo = want.GetStringParam(Constants::FORM_SUPPLY_INFO);
    HILOG_INFO("connectId:%{public}d, supplyInfo:%{public}s", connectId, supplyInfo.c_str());
    FormProviderQueue::GetInstance().CancelDelayTask(
        { Constants::DETECT_FORM_EXIT_DELAY_TASK, static_cast<int64_t>(connectId) });
    RemoveConnection(connectId);
    HILOG_INFO("end");
    return ERR_OK;
}

/**
 * @brief Accept form state from form provider.
 * @param state Form state.
 * @param provider provider info.
 * @param wantArg The want of onAcquireFormState.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnAcquireStateResult(FormState state,
    const std::string &provider, const Want &wantArg, const Want &want)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    RemoveConnection(connectId);

    ErrCode errCode = FormProviderMgr::GetInstance().AcquireFormStateBack(state, provider, wantArg);
    HILOG_INFO("errCode:%{public}d", errCode);
    return errCode;
}

int FormSupplyCallback::OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    HILOG_DEBUG("call");
    ErrCode errCode = FormProviderMgr::GetInstance().AcquireFormDataBack(wantParams, requestCode);
    HILOG_INFO("errCode:%{public}d", errCode);
    return errCode;
}

/**
 * @brief Save ability Connection for the callback.
 * @param connection ability connection.
 */
void FormSupplyCallback::AddConnection(sptr<FormAbilityConnection> connection)
{
    HILOG_DEBUG("call");
    if (connection == nullptr) {
        return;
    }
    int32_t connectKey = static_cast<int32_t>(FormUtil::GetCurrentSteadyClockMillseconds());
    std::lock_guard<std::mutex> lock(conMutex_);
    while (connections_.find(connectKey) != connections_.end()) {
        connectKey++;
    }
    connection->SetConnectId(connectKey);
    connections_.emplace(connectKey, connection);
    HILOG_DEBUG("end");
}

/**
 * @brief Delete ability connection after the callback come.
 * @param connectId The ability connection id generated when save.
 */
void FormSupplyCallback::RemoveConnection(int32_t connectId)
{
    HILOG_DEBUG("call");
    sptr<FormAbilityConnection> connection = nullptr;
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = connections_.find(connectId);
        if (conIterator != connections_.end()) {
            connection = conIterator->second;
            connections_.erase(connectId);
        }
    }

    if (connection != nullptr) {
        if (CanDisconnect(connection)) {
            FormAmsHelper::GetInstance().DisconnectServiceAbility(connection);
            HILOG_INFO("disconnect service ability, connectId:%{public}d", connectId);
        } else {
            FormAmsHelper::GetInstance().DisconnectServiceAbilityDelay(connection);
            HILOG_INFO("disconnect service ability delay, connectId:%{public}d", connectId);
        }
    }
    HILOG_DEBUG("end");
}
/**
 * @brief check if disconnect ability or not.
 * @param connection The ability connection.
 */
bool FormSupplyCallback::CanDisconnect(sptr<FormAbilityConnection> &connection)
{
    if (connection == nullptr) {
        HILOG_ERROR("null connection");
        return false;
    }
    HILOG_INFO("call");
    int count = 0;
    std::lock_guard<std::mutex> lock(conMutex_);
    for (auto &conn : connections_) {
        if (connection->GetProviderKey() == conn.second->GetProviderKey()) {
            HILOG_INFO("key:%{public}s", conn.second->GetProviderKey().c_str());
            count++;
            if (count >= 1) {
                HILOG_INFO("true count:%{public}d", count);
                return true;
            }
        }
    }
    HILOG_INFO("false count:%{public}d", count);
    return false;
}

void FormSupplyCallback::OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
    const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result)
{
    HILOG_DEBUG("formId %{public}" PRId64 " call", formId);
    DelayedSingleton<FormShareMgr>::GetInstance()->HandleProviderShareData(
        formId, remoteDeviceId, wantParams, requestCode, result);
}

bool FormSupplyCallback::IsRemoveConnection(int64_t formId, const sptr<IRemoteObject> &hostToken)
{
    HILOG_DEBUG("formId is %{public}" PRId64, formId);
    if (hostToken == nullptr) {
        return true;
    }

    std::lock_guard<std::mutex> lock(conMutex_);
    // keep one connection for each in application form in the same host
    int32_t count = 0;
    for (const auto &conn : connections_) {
        if (hostToken == conn.second->GetHostToken() && formId == conn.second->GetFormId()) {
            count++;
            if (count > 1) {
                break;
            }
        }
    }
    HILOG_DEBUG("count is %{public}d", count);
    if (count == 1) {
        HILOG_DEBUG("keep the connection");
        return false;
    }
    return true;
}

void FormSupplyCallback::RemoveConnection(int64_t formId, const sptr<IRemoteObject> &hostToken)
{
    HILOG_DEBUG("formId is %{public}" PRId64, formId);
    if (hostToken == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(conMutex_);
    for (const auto &conn : connections_) {
        if (hostToken == conn.second->GetHostToken() && formId == conn.second->GetFormId()) {
            Want want;
            want.SetParam(Constants::FORM_CONNECT_ID, conn.first);
            want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, hostToken);
            FormProviderTaskMgr::GetInstance().PostDeleteTask(formId, want, conn.second->GetProviderToken());
            HILOG_DEBUG("remove the connection, connect id is %{public}d", conn.first);
        }
    }
}

void FormSupplyCallback::HandleHostDied(const sptr<IRemoteObject> &hostToken)
{
    HILOG_DEBUG("call");
    if (hostToken == nullptr) {
        HILOG_ERROR("null hostToken");
        return;
    }

    std::vector<int32_t> connectIds;
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        for (const auto &conn : connections_) {
            if (hostToken == conn.second->GetHostToken()) {
                connectIds.push_back(conn.first);
                HILOG_DEBUG("remove the connection, connect id is %{public}d", conn.first);
            }
        }
    }

    for (const auto &connectId : connectIds) {
        RemoveConnection(connectId);
    }
}

int32_t FormSupplyCallback::OnRenderTaskDone(int64_t formId, const Want &want)
{
    HILOG_DEBUG("call");
    FormRenderMgr::GetInstance().RenderFormCallback(formId, want);
    return ERR_OK;
}

int32_t FormSupplyCallback::OnStopRenderingTaskDone(int64_t formId, const Want &want)
{
    HILOG_INFO("call");
    FormRenderMgr::GetInstance().StopRenderingFormCallback(formId, want);
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRenderingBlock(const std::string &bundleName)
{
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRecycleForm(const int64_t formId, const Want &want)
{
    std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
    if (statusData.empty()) {
        HILOG_DEBUG("status data of %{public}" PRId64 " is empty", formId);
        statusData = EMPTY_STATUS_DATA;
    }
    if (FormInfoRdbStorageMgr::GetInstance().UpdateStatusData(std::to_string(formId), statusData) != ERR_OK) {
        HILOG_ERROR("update status data of %{public}" PRId64 " failed", formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    std::string curTid = FormStatusMgr::GetInstance().GetFormEventId(formId);
    int32_t event =
        want.GetIntParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_DATA_FAIL));
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s, curTid:%{public}s, event:%{public}d.",
        formId,
        eventId.c_str(),
        curTid.c_str(),
        event);
    if (event != static_cast<int32_t>(FormFsmEvent::RECYCLE_DATA_FAIL)) {
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    }
    if (!eventId.empty() && eventId == curTid) {
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);

        auto reCycleForm = [formId, want]() {
            sptr<IRemoteObject> remoteObjectOfHost = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
            if (remoteObjectOfHost == nullptr) {
                HILOG_ERROR("null remoteObjectOfHost");
                return;
            }
            sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObjectOfHost);
            if (remoteFormHost == nullptr) {
                HILOG_ERROR("null remoteFormHost");
                return;
            }
            remoteFormHost->OnRecycleForm(formId);
            FormStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId);
        };
        FormStatusMgr::GetInstance().PostFormEvent(formId, (FormFsmEvent)event, reCycleForm);
    }
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRecoverFormsByConfigUpdate(std::vector<int64_t> &formIds)
{
    HILOG_INFO("recover forms by config update");
    Want want;
    return FormMgrAdapter::GetInstance().RecoverForms(formIds, want);
}

int32_t FormSupplyCallback::OnNotifyRefreshForm(const int64_t formId)
{
    FormMgrAdapter::GetInstance().OnNotifyRefreshForm(formId);
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRenderFormDone(const int64_t formId, const Want &want)
{
    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    std::string curTid = FormStatusMgr::GetInstance().GetFormEventId(formId);
    int32_t event =
        want.GetIntParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RENDER_FORM_FAIL));
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s, curTid:%{public}s, event:%{public}d.",
        formId,
        eventId.c_str(),
        curTid.c_str(),
        event);
    if (event != static_cast<int32_t>(FormFsmEvent::RENDER_FORM_FAIL)) {
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    }
    if (!eventId.empty() && eventId == curTid) {
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, (FormFsmEvent)event);
    }
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRecoverFormDone(const int64_t formId, const Want &want)
{
    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    std::string curTid = FormStatusMgr::GetInstance().GetFormEventId(formId);
    int32_t event =
        want.GetIntParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECOVER_FORM_FAIL));
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s, curTid:%{public}s, event:%{public}d.",
        formId,
        eventId.c_str(),
        curTid.c_str(),
        event);
    if (event != static_cast<int32_t>(FormFsmEvent::RECOVER_FORM_FAIL)) {
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    }
    if (!eventId.empty() && eventId == curTid) {
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, (FormFsmEvent)event);
    }
    return ERR_OK;
}

int32_t FormSupplyCallback::OnRecycleFormDone(const int64_t formId, const Want &want)
{
    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    std::string curTid = FormStatusMgr::GetInstance().GetFormEventId(formId);
    int32_t event =
        want.GetIntParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_FORM_FAIL));
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s, curTid:%{public}s, event:%{public}d.",
        formId,
        eventId.c_str(),
        curTid.c_str(),
        event);
    if (event != static_cast<int32_t>(FormFsmEvent::RECYCLE_FORM_FAIL)) {
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    }
    if (!eventId.empty() && eventId == curTid) {
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, (FormFsmEvent)event);
    }
    return ERR_OK;
}

int32_t FormSupplyCallback::OnDeleteFormDone(const int64_t formId, const Want &want)
{
    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    std::string curTid = FormStatusMgr::GetInstance().GetFormEventId(formId);
    int32_t event =
        want.GetIntParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::DELETE_FORM_FAIL));
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s, curTid:%{public}s, event:%{public}d.",
        formId,
        eventId.c_str(),
        curTid.c_str(),
        event);
    if (event != static_cast<int32_t>(FormFsmEvent::DELETE_FORM_FAIL)) {
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    }
    if (!eventId.empty() && eventId == curTid) {
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, (FormFsmEvent)event);
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
