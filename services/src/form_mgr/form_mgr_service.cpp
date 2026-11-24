/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "form_mgr/form_mgr_service.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "bundle_common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_ipc_dispatch_table.h"
#include "form_mgr_errors.h"
#include "form_stub_access_checker.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "data_center/form_cache_mgr.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "common/event/form_event_handler.h"
#include "data_center/form_info/form_info_mgr.h"
#include "form_mgr/form_ams_adapter.h"
#include "form_mgr/form_edit_service.h"
#include "form_mgr/form_mgr_adapter_facade.h"
#include "form_mgr/form_mgr_dump_handler.h"
#include "form_instance.h"
#include "common/util/form_serial_queue.h"
#include "feature/form_share/form_share_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_util.h"
#include "form_xml_parser.h"
#include "form_resource_param.h"
#include "running_form_info.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "common/util/mem_status_listener.h"
#include "os_account_manager.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#include "hisysevent.h"
#include "hitrace_meter.h"
#include "xcollie/watchdog.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "feature/form_check/form_abnormal_reporter.h"
#include "feature/param_update/param_common_event.h"
#include "feature/param_update/param_manager.h"
#include "string_wrapper.h"
#include "int_wrapper.h"
#include "want_params_wrapper.h"
#ifdef MEM_MGR_ENABLE
#include "mem_mgr_client.h"
#endif
#include "common/util/form_report.h"
#include "iform_host_delegate.h"

#ifdef RES_SCHEDULE_ENABLE
#include "common/event/system_event/form_systemload_listener.h"
#include "res_sched_client.h"
#include "res_type.h"
#endif // RES_SCHEDULE_ENABLE
#include "form_mgr/form_mgr_queue.h"
#include "common/event/system_event/form_os_account_subscriber.h"
#include "common/util/form_task_common.h"
#include "scene_board_judgement.h"
#include "form_host/form_mgr_host_adapter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAIN_USER_ID = 100;
constexpr int MILLISECOND_WIDTH = 3;
constexpr char MILLISECOND_FILLCHAR = '0';
const int32_t API_TIME_OUT = 5;
const int32_t API_TIME_OUT_30S = 30;
const long FORM_DISCON_NETWORK_CHECK_TIME = 600000; // ms
constexpr int32_t FORM_VISIBLE_RECT_QUERY_TIMEOUT_SEC = 5;
constexpr const char *APP_PROVISION_TYPE_DEBUG = "debug";
constexpr const char *FORM_MGR_SERVICE_QUEUE = "FormMgrServiceQueue";
#ifdef RES_SCHEDULE_ENABLE
constexpr int32_t SYSTEMLOADLEVEL_TIMERSTOP_THRESHOLD =
    static_cast<int32_t>(ResourceSchedule::ResType::SystemloadLevel::OVERHEATED);
#endif // RES_SCHEDULE_ENABLE
}
using namespace std::chrono;

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<FormMgrService>::GetInstance().get());

constexpr int32_t FORM_CON_NET_MAX = 100;

FormMgrService::FormMgrService()
    : SystemAbility(FORM_MGR_SERVICE_ID, true),
      state_(ServiceRunningState::STATE_NOT_START),
      serialQueue_(nullptr)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
}

FormMgrService::~FormMgrService()
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    // Safety net: OnStop normally tears down subscriptions first; guards make this idempotent.
    UnsubscribeSystemEvents();
#ifdef MEM_MGR_ENABLE
    if (memStatusListener_ != nullptr) {
        Memory::MemMgrClient::GetInstance().UnsubscribeAppState(*memStatusListener_);
    }
#endif
}

/**
* @brief Check form manager service ready.
* @return Returns ERR_OK if form manager service Ready, other values otherwise.
*/
int32_t FormMgrService::CheckFMSReady()
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        HILOG_ERROR("fms is not running");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // SA uid carries no user semantics; use the active account for SA callers.
    int32_t userId = FormUtil::IsSACall()
        ? FormUtil::GetCurrentAccountId()
        : FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    if (userId == Constants::ANY_USERID) {
        HILOG_ERROR("empty account");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_CheckFMSReady",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    bool result = FormInfoMgr::GetInstance().HasReloadedFormInfos(userId);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);

    if (!result) {
        HILOG_ERROR("form info not yet loaded");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}

bool FormMgrService::IsSystemAppForm(const std::string &bundleName)
{
    HILOG_DEBUG("check %{public}s is system form.", bundleName.c_str());
    if (!FormUtil::CheckIsFRSCall()) {
        HILOG_ERROR("caller is not FRS, deny system-form query");
        return false;
    }

    std::vector<FormRecord> formRecords;
    FormDataMgr::GetInstance().GetFormRecord(bundleName, formRecords);
    if (formRecords.empty()) {
        return false;
    }
    return formRecords.front().isSystemApp;
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param formId The Id of the forms to add.
 * @param want The want of the form to add.
 * @param callerToken Caller ability token.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::AddForm(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());

    ReportAddFormEvent(formId, want);
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_AddForm",
        API_TIME_OUT_30S, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    int ret = FormMgrAdapterFacade::GetInstance().AddForm(formId, want, callerToken, formInfo);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    const auto callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    int64_t newFormId = formId;
    if (newFormId == 0) {
        newFormId = formInfo.formId;
    }
    HILOG_WARN("add form result:%{public}d,userId:%{public}d,formId:%{public}" PRId64, ret, userId, newFormId);
    return ret;
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param want The want of the form to add.
 * @param runningFormInfo Running form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());

    ReportAddFormEvent(0, want);
    return FormMgrAdapterFacade::GetInstance().CreateForm(want, runningFormInfo);
}

void FormMgrService::ReportAddFormEvent(const int64_t formId, const Want &want)
{
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    eventInfo.formDimension = static_cast<int64_t>(want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0));
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    eventInfo.isDistributedForm = FormDistributedMgr::GetInstance().IsBundleDistributed(eventInfo.bundleName, userId);
    int ret = FormBmsHelper::GetInstance().GetCallerBundleName(eventInfo.hostBundleName);
    if (ret != ERR_OK || eventInfo.hostBundleName.empty()) {
        HILOG_ERROR("cannot get host bundle name by uid");
    }
    FormEventReport::SendFormEvent(FormEventName::ADD_FORM, HiSysEventType::BEHAVIOR, eventInfo);
}

/**
 * @brief Delete forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to delete.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());

    FormRecord record;
    FormDataMgr::GetInstance().GetFormRecord(formId, record);
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    if (formHostRecords.size() != 0) {
        eventInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    }
    eventInfo.bundleName = record.bundleName;
    eventInfo.moduleName = record.moduleName;
    eventInfo.formDimension = record.specification;
    eventInfo.isDistributedForm = record.isDistributedForm;
    FormEventReport::SendSecondFormEvent(FormEventName::DELETE_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_DeleteForm",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode ret = FormMgrAdapterFacade::GetInstance().DeleteForm(formId, callerToken);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    HILOG_WARN("delete form result:%{public}d,formId:%{public}" PRId64, ret, formId);
    return ret;
}

/**
 * @brief Stop rendering form.
 * @param formId The Id of the forms to delete.
 * @param compId The compId of the forms to delete.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }
    return FormMgrAdapterFacade::GetInstance().StopRenderingForm(formId, compId);
}

/**
 * @brief Release forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to release.
 * @param callerToken Caller ability token.
 * @param delCache Delete Cache or not.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());

    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(FormEventName::RELEASE_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapterFacade::GetInstance().ReleaseForm(formId, callerToken, delCache);
}

/**
 * @brief Update form with formId, send formId to form manager service.
 * @param formId The Id of the form to update.
 * @param formBindingData Form binding data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::UpdateForm(const int64_t formId, const FormProviderData &formBindingData)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().UpdateForm(formId, callingUid, formBindingData);
}

int FormMgrService::UpdateForm(const int64_t formId, const FormProviderInfo &formProviderInfo)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().UpdateForm(formId, callingUid, formProviderInfo);
}

/**
 * @brief Update form by cross bundle, restricted to system apps with UPDATE_FORM_CROSS_BUNDLE permission.
 * @param formId The Id of the form to update.
 * @param formBindingData Form binding data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::UpdateFormCrossBundle(const int64_t formId, const FormProviderData &formBindingData)
{
    HILOG_INFO("call, formId:%{public}" PRId64, formId);
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().UpdateFormCrossBundle(formId, callingUid, formBindingData);
}

/**
 * @brief Update forms with reminder agent, restricted to system callers with REQUIRE_FORM permission.
 * @param bundleName The bundle name of the target form provider.
 * @param userId The id of the target user.
 * @param want The want of the reminder agent.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrService::UpdateFormsWithReminderAgent(
    const std::string &bundleName, const int32_t userId, const Want &want)
{
    HILOG_INFO("call, bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
    return FormMgrAdapterFacade::GetInstance().UpdateFormsWithReminderAgent(bundleName, userId, want);
}

/**
 * @brief Request form with formId and want, send formId and want to form manager service.
 * @param formId The Id of the form to update.
 * @param callerToken Caller ability token.
 * @param want The want of the form to add.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendSecondFormEvent(FormEventName::REQUEST_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapterFacade::GetInstance().RequestForm(formId, callerToken, want);
}

/**
 * @brief set next refresh time.
 * @param formId The id of the form.
 * @param nextTime next refresh time.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(
        FormEventName::SET_NEXT_REFRESH_TIME_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapterFacade::GetInstance().SetNextRefreshTime(formId, nextTime);
}

int FormMgrService::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    return FormMgrAdapterFacade::GetInstance().ReleaseRenderer(formId, compId);
}

ErrCode FormMgrService::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    bool isFormAgent = want.GetBoolParam(Constants::IS_FORM_AGENT, false);
    HILOG_INFO("isFormAgent:%{public}d", isFormAgent);
    if (isFormAgent) {
        ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_AGENT_REQUIRE_FORM);
        if (ret != ERR_OK) {
            HILOG_ERROR("[%{public}s]request form permission denied", __FUNCTION__);
            return ret;
        }
    } else {
        if (!CheckCallerIsSystemApp()) {
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
        }

        if (!CheckAcrossLocalAccountsPermission()) {
            HILOG_ERROR("[%{public}s]Across local accounts permission failed", __FUNCTION__);
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
        }
    }
    std::string bundleName;
    FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    FormEventReport::SendRequestPublicFormEvent(bundleName, formName, RequestFormType::REQUEST_PUBLISH_FORM);
    return FormMgrAdapterFacade::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId);
}

ErrCode FormMgrService::RequestPublishFormCrossUser(Want &want, int32_t userId, int64_t &formId)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    if (userId == Constants::INVALID_USER_ID) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().RequestPublishFormCrossUser(want, userId, formId);
}

ErrCode FormMgrService::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    return FormMgrAdapterFacade::GetInstance().SetPublishFormResult(formId, errorCodeInfo);
}

ErrCode FormMgrService::AcquireAddFormResult(const int64_t formId)
{
    return FormMgrAdapterFacade::GetInstance().AcquireAddFormResult(formId);
}

/**
 * @brief Form visible/invisible notify, send formIds to form manager service.
 * @param formIds The Id list of the forms to notify.
 * @param callerToken Caller ability token.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);

    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_NotifyWhetherVisibleForms",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode ret = FormMgrAdapterFacade::GetInstance().NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return ret;
}

/**
 * @brief Query whether has visible form by tokenId.
 * @param tokenId Unique identification of application.
 * @return Returns true if has visible form, false otherwise.
 */
bool FormMgrService::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);

    return FormMgrAdapterFacade::GetInstance().HasFormVisible(tokenId);
}

/**
 * @brief temp form to normal form.
 * @param formId The Id of the form.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(FormEventName::CASTTEMP_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapterFacade::GetInstance().CastTempForm(formId, callerToken);
}

/**
 * @brief lifecycle update.
 * @param formIds formIds of host client.
 * @param callerToken Caller ability token.
 * @param updateType update type,enable or disable.
 * @return Returns true on success, false on failure.
 */
int FormMgrService::LifecycleUpdate(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, bool updateType)
{
    HILOG_INFO("updateType:%{public}d", updateType);

    if (updateType) {
        return FormMgrAdapterFacade::GetInstance().EnableUpdateForm(formIds, callerToken);
    } else {
        return FormMgrAdapterFacade::GetInstance().DisableUpdateForm(formIds, callerToken);
    }
}
/**
 * @brief Dump all of form storage infos.
 * @param formInfos All of form storage infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpStorageFormInfos(std::string &formInfos)
{
    return FormMgrDumpHandler::DumpStorageFormInfos(formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param bundleName The bundle name of form provider.
 * @param formInfos Form infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos)
{
    return FormMgrDumpHandler::DumpFormInfoByBundleName(bundleName, formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo)
{
    return FormMgrDumpHandler::DumpFormInfoByFormId(formId, formInfo);
}
/**
 * @brief Dump form timer by form id.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService)
{
    return FormMgrDumpHandler::DumpFormTimerByFormId(formId, isTimingService);
}

/**
 * @brief Process js message event.
 * @param formId Indicates the unique id of form.
 * @param want information passed to supplier.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }
    ret = FormMgrAdapterFacade::GetInstance().MessageEvent(formId, want, callerToken);
    if (ret != ERR_OK) {
        HILOG_ERROR("MessageEvent failed,formId:%{public}" PRId64 ", ret:%{public}d", formId, ret);
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    if (formHostRecords.size() != 0) {
        eventInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    }
    FormReport::GetInstance().SetDurationStartTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    FormEventReport::SendFormEvent(FormEventName::MESSAGE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return ret;
}

/**
 * @brief Process js router event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    eventInfo.uri = want.GetUriString();
    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    if (formHostRecords.size() != 0) {
        eventInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    }
    FormRecord formRecord;
    if (FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        eventInfo.formLocation = static_cast<int32_t>(formRecord.formLocation);
    }
    FormEventReport::SendFormEvent(FormEventName::ROUTE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapterFacade::GetInstance().RouterEvent(formId, want, callerToken);
}

/**
 * @brief Process js insight intent event, launch the target ability by insight intent.
 * @param formId Indicates the unique id of form.
 * @param want the want which carries the insight intent execute param.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::InsightIntentEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }
    return FormMgrAdapterFacade::GetInstance().InsightIntentEvent(formId, want, callerToken);
}

/**
 * @brief Process Background event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("the formId is not under currentActiveUser or invalid");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendSecondFormEvent(FormEventName::BACKGROUND_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapterFacade::GetInstance().BackgroundEvent(formId, want, callerToken);
}

void FormMgrService::RegisterSystemAbilityListener()
{
    auto addListener = [this](int32_t systemAbilityId) {
        if (!AddSystemAbilityListener(systemAbilityId)) {
            HILOG_WARN("AddSystemAbilityListener failed,saId:%{public}d", systemAbilityId);
        }
    };
    // listener for FormDataProxyMgr
    addListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    // CES/OsAccount may start later than subfoundation at boot, retry subscription on their ready callback.
    addListener(COMMON_EVENT_SERVICE_ID);
    addListener(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);

#ifdef MEM_MGR_ENABLE
    addListener(MEMORY_MANAGER_SA_ID);
#endif // MEM_MGR_ENABLE

#ifdef RES_SCHEDULE_ENABLE
    addListener(RES_SCHED_SYS_ABILITY_ID);
#endif // RES_SCHEDULE_ENABLE
}

/**
 * @brief Start event for the form manager service.
 */
void FormMgrService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOG_WARN("start service failed since it's running");
        return;
    }

    onStartBeginTime_ = GetCurrentDateTime();

    if (FormResourceParam::IsBopdMode()) {
        HILOG_ERROR("is bopd mode");
        // bopd mode need publish sa
        if (!Publish(DelayedSingleton<FormMgrService>::GetInstance().get())) {
            HILOG_ERROR("FormMgrService::Onstart Publish failed");
        }
        return;
    }
    HILOG_INFO("start,time:%{public}s", onStartBeginTime_.c_str());
    ErrCode errCode = Init();
    if (errCode != ERR_OK) {
        HILOG_ERROR("init failed,errCode:%{public}08x", errCode);
        return;
    }

    state_ = ServiceRunningState::STATE_RUNNING;
    RegisterSystemAbilityListener();
    onStartEndTime_ = GetCurrentDateTime();
    HILOG_INFO("success,time:%{public}s,onKvDataServiceAddTime:%{public}s",
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    FormEventReport::SendDiskUseEvent();
    FormTimerMgr::GetInstance().StartDiskUseInfoReportTimer();
}
/**
 * @brief Stop event for the form manager service.
 */
void FormMgrService::OnStop()
{
    HILOG_INFO("stop");

    state_ = ServiceRunningState::STATE_NOT_START;

    UnsubscribeSystemEvents();

    DelayedSingleton<FormShareMgr>::GetInstance()->UnregisterObserver();

    // Reset under instanceMutex_ so a concurrent binder-thread read in
    // InitFormShareMgrSerialQueue cannot copy a torn shared_ptr.
    {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        serialQueue_.reset();
        handler_.reset();
    }
    FormAmsHelper::GetInstance().UnRegisterAllConfigurationObservers();
    ParamCommonEvent::GetInstance().UnSubscriberEvent();
}

ErrCode FormMgrService::ReadFormConfigXML()
{
    FormXMLParser parser;
    int32_t ret = parser.Parse();
    if (ret != ERR_OK) {
        HILOG_WARN("[%{public}s]parse form config failed,use the default vaule", __FUNCTION__);
        return ret;
    }
    const std::map<std::string, int32_t> &configMap = parser.GetConfigMap();
    FormDataMgr::GetInstance().SetConfigMap(configMap);
    return ERR_OK;
}


void FormMgrService::SubscribeSystemEvents()
{
    std::lock_guard<std::mutex> lock(sysEventSubscribeMutex_);
    if (!isCesSubscribed_) {
        if (formSysEventReceiver_ == nullptr) {
            EventFwk::MatchingSkills matchingSkills;
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SECOND_MOUNTED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED);
            matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTED);
            // init TimerReceiver
            EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
            subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
            formSysEventReceiver_ = std::make_shared<FormSysEventReceiver>(subscribeInfo);
        }
        if (EventFwk::CommonEventManager::SubscribeCommonEvent(formSysEventReceiver_)) {
            isCesSubscribed_ = true;
        } else {
            HILOG_ERROR("SubscribeCommonEvent failed,retry on common event service ready");
        }
    }

    if (!isOsAccountSubscribed_) {
        if (osAccountSubscriber_ == nullptr) {
            AccountSA::OsAccountSubscribeInfo osAccountSubscribeInfo(
                std::set<AccountSA::OsAccountState>{ AccountSA::OsAccountState::CREATED });
            osAccountSubscriber_ = std::make_shared<FormOsAccountSubscriber>(osAccountSubscribeInfo);
        }
        ErrCode subscribeRet = AccountSA::OsAccountManager::SubscribeOsAccount(osAccountSubscriber_);
        if (subscribeRet == ERR_OK) {
            isOsAccountSubscribed_ = true;
        } else {
            HILOG_ERROR("SubscribeOsAccount failed,err:%{public}d,retry on account service ready", subscribeRet);
        }
    }
}

void FormMgrService::UnsubscribeSystemEvents()
{
    std::lock_guard<std::mutex> lock(sysEventSubscribeMutex_);
    if (formSysEventReceiver_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(formSysEventReceiver_);
        formSysEventReceiver_ = nullptr;
        FormBmsHelper::GetInstance().UnregisterBundleEventCallback();
    }
    if (osAccountSubscriber_ != nullptr) {
        AccountSA::OsAccountManager::UnsubscribeOsAccount(osAccountSubscriber_);
        osAccountSubscriber_ = nullptr;
    }
    // Reset so a later OnStart re-subscribes instead of trusting stale process-lifetime state.
    isCesSubscribed_ = false;
    isOsAccountSubscribed_ = false;
}

/**
 * @brief initialization of form manager service.
 */
ErrCode FormMgrService::Init()
{
    HILOG_INFO("call");
    // Assign under instanceMutex_ so a concurrent binder-thread read in
    // InitFormShareMgrSerialQueue cannot copy a torn shared_ptr.
    {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        serialQueue_ = std::make_shared<FormSerialQueue>(FORM_MGR_SERVICE_QUEUE);
        if (serialQueue_ == nullptr) {
            HILOG_ERROR("Init failed,null serialQueue_");
            return ERR_INVALID_OPERATION;
        }

        handler_ = std::make_shared<FormEventHandler>(serialQueue_);
        if (handler_ == nullptr) {
            HILOG_ERROR("init failed.null handler_");
            return ERR_INVALID_OPERATION;
        }
    }
    // Assemble the real access checker before Publish, since remote IPC may arrive right after publish.
    FormIpcDispatchTable::GetInstance().SetAccessChecker(std::make_shared<FormStubAccessChecker>());
    /* Publish service maybe failed, so we need call this function at the last,
     * so it can't affect the TDD test program */
    if (!Publish(DelayedSingleton<FormMgrService>::GetInstance().get())) {
        FormEventReport::SendFormFailedEvent(FormEventName::INIT_FMS_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(InitFmsFailedErrorType::PUBLISH_SER_FAILED));
        HILOG_ERROR("FormMgrService::Init Publish failed");
        return ERR_INVALID_OPERATION;
    }
    onStartPublishTime_ = GetCurrentDateTime();
    HILOG_INFO("FMS onStart publish done,time:%{public}s", onStartPublishTime_.c_str());

    SubscribeSystemEvents();

#ifdef MEM_MGR_ENABLE
    memStatusListener_ = std::make_shared<MemStatusListener>();
    Memory::MemMgrClient::GetInstance().SubscribeAppState(*memStatusListener_);
#endif

    FormDistributedMgr::GetInstance().Start();
    FormInfoMgr::GetInstance().Start();
    FormDbCache::GetInstance().Start();
    FormTimerMgr::GetInstance(); // Init FormTimerMgr
    FormCacheMgr::GetInstance().Start();

    formSysEventReceiver_->InitFormInfosAndRegister();

    // read param form form_config.xml.
    if (ReadFormConfigXML() != ERR_OK) {
        HILOG_WARN("[%{public}s]parse form config failed,use the default vaule", __FUNCTION__);
    }
    FormMgrAdapterFacade::GetInstance().Init();
    FormAmsHelper::GetInstance().RegisterConfigurationObserver(Constants::DEFAULT_USER_ID);
    ParamManager::GetInstance().InitParam();
    ParamCommonEvent::GetInstance().SubscriberEvent();
    return ERR_OK;
}

ErrCode FormMgrService::CheckFormPermission(std::string_view permission, bool checkSA)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);

    if (!checkSA && FormUtil::IsSACall()) {
        return ERR_OK;
    }

    // check if system app
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }

    auto isCallingPerm = FormUtil::VerifyCallingPermission(permission);
    if (!isCallingPerm) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    // checks whether the current user is inactive
    if (!CheckAcrossLocalAccountsPermission()) {
        HILOG_ERROR("[%{public}s]Across local accounts permission failed", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    HILOG_DEBUG("Permission verification ok");
    return ERR_OK;
}

/**
 * @brief Delete the invalid forms.
 * @param formIds Indicates the ID of the valid forms.
 * @param callerToken Caller ability token.
 * @param numFormsDeleted Returns the number of the deleted forms.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DeleteInvalidForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    HILOG_DEBUG("call");
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(FormEventName::DELETE_INVALID_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_DeleteInvalidForms",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    int ret = FormMgrAdapterFacade::GetInstance().DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return ret;
}

/**
  * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
  * @param want Indicates a set of parameters to be transparently passed to the form provider.
  * @param callerToken Caller ability token.
  * @param stateInfo Returns the form's state info of the specify.
  * @return Returns ERR_OK on success, others on failure.
  */
int FormMgrService::AcquireFormState(const Want &want,
    const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
{
    HILOG_DEBUG("call");
    FormEventInfo eventInfo;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendFormEvent(FormEventName::ACQUIREFORMSTATE_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapterFacade::GetInstance().AcquireFormState(want, callerToken, stateInfo);
}

/**
 * @brief Register form router event proxy.
 * @param formIds Indicates the ID of the forms.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
}

/**
* @brief Unregister form router event proxy.
* @param formIds Indicates the ID of the forms.
* @return Returns ERR_OK on success, others on failure.
*/
int FormMgrService::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    return FormMgrAdapterFacade::GetInstance().UnregisterFormRouterProxy(formIds);
}

/**
 * @brief Notify the form is visible or not.
 * @param formIds Indicates the ID of the forms.
 * @param isVisible Visible or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::NotifyFormsVisible(const std::vector<int64_t> &formIds,
    bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    return FormMgrAdapterFacade::GetInstance().NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrService::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

/**
 * @brief Notify the form is enable to be updated or not.
 * @param formIds Indicates the ID of the forms.
 * @param isEnableUpdate enable update or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds,
    bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
}

/**
 * @brief Get All FormsInfo.
 * @param formInfos Return the form information of all forms provided.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetAllFormsInfo(formInfos);
}

/**
 * @brief Get All TemplateFormsInfo.
 * @param formInfos Return the form information of all forms provided.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetAllTemplateFormsInfo(formInfos);
}

/**
 * @brief Get forms info by bundle name.
 * @param bundleName Application name.
 * @param formInfos Return the form information of the specify application name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_GetFormsInfoByApp",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode ret = FormMgrAdapterFacade::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return ret;
}

/**
 * @brief Get template form info by bundle name.
 * @param bundleName Application name.
 * @param formInfos Return the form information of the specify application name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetTemplateFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_GetTemplateFormsInfoByApp",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode ret = FormMgrAdapterFacade::GetInstance().GetTemplateFormsInfoByApp(bundleName, formInfos);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return ret;
}

/**
 * @brief Get forms info by bundle name and module name.
 * @param bundleName bundle name.
 * @param moduleName Module name of hap.
 * @param formInfos Return the forms information of the specify bundle name and module name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                                         std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

/**
 * @brief Get template form info by bundle name and module name.
 * @param bundleName bundle name.
 * @param moduleName Module name of hap.
 * @param formInfos Return the form information of the specify bundle name and module name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetTemplateFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
                                                 std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos);
}

int FormMgrService::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetFormsInfoByFilter(filter, formInfos);
}

int32_t FormMgrService::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    std::string callerBundleName;
    ErrCode ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get host bundle name failed", __FUNCTION__);
        return ret;
    }
    // retrieve moduleName from filter.
    std::string moduleName = filter.moduleName;
    if (moduleName.empty()) {
        // fulfill formInfos, the process should be the same as GetFormsInfoByApp.
        HILOG_INFO("flows to GetFormsInfoByAPP");
        return FormMgrAdapterFacade::GetInstance().GetFormsInfoByApp(callerBundleName, formInfos);
    }
    HILOG_INFO("flows to GetFormsInfoByModule");
    return FormMgrAdapterFacade::GetInstance().GetFormsInfoByModule(callerBundleName, moduleName, formInfos);
}

int32_t FormMgrService::GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    std::string callerBundleName;
    ErrCode ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get host bundle name failed", __FUNCTION__);
        return ret;
    }
    HILOG_INFO("flows to GetPublishedFormInfoById");
    return FormDataMgr::GetInstance().GetPublishedFormInfoById(callerBundleName, formInfo, formId);
}

int32_t FormMgrService::GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    std::string callerBundleName;
    ErrCode ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get host bundle name failed", __FUNCTION__);
        return ret;
    }
    HILOG_INFO("flows to GetPublishedFormInfos");
    return FormDataMgr::GetInstance().GetPublishedFormInfos(callerBundleName, formInfos);
}

int32_t FormMgrService::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    if (formId <= 0) {
        HILOG_ERROR("[%{public}s]invalid formId", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("[%{public}s]null callerToken", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (requestCode <= 0) {
        HILOG_ERROR("[%{public}s]invalid requestCode", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return FormMgrAdapterFacade::GetInstance().AcquireFormData(formId, requestCode, callerToken, formData);
}

bool FormMgrService::IsRequestPublishFormSupported()
{
    return FormMgrAdapterFacade::GetInstance().IsRequestPublishFormSupported();
}

int32_t FormMgrService::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    // check abilityName and uri to void implicit want.
    if (want.GetElement().GetAbilityName().empty() && want.GetUriString().empty()) {
        HILOG_ERROR("empty AbilityName and uri");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }
    return FormAmsHelper::GetInstance().StartAbilityByCallerToken(want, callerToken);
}

int32_t FormMgrService::StartAbilityByFms(const Want &want)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    std::string dstBundleName = want.GetElement().GetBundleName();
    std::string bundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get BundleName failed", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    if (dstBundleName != bundleName) {
        HILOG_ERROR("dstBundleName not self");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }
    return FormMgrAdapterFacade::GetInstance().StartAbilityByFms(want);
}

ErrCode FormMgrService::StartUIAbilityByFms(const Want &want)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormAmsAdapter::GetInstance().StartUIAbilityByFms(callingUid, want);
}

int32_t FormMgrService::StartAbilityByCrossBundle(const Want &want)
{
    HILOG_INFO("call");
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        HILOG_ERROR("capability not support");
        return ERR_APPEXECFWK_SYSTEMCAP_ERROR;
    }
    if (!PublishFormCrossBundleControl(want)) {
        HILOG_ERROR("PublishFormCrossBundleControl failed");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }
    if (!FormMgrAdapterFacade::GetInstance().IsForegroundApp()) {
        HILOG_ERROR("This application is not a foreground program");
        return ERR_APPEXECFWK_FORM_NOT_TRUST;
    }
    return FormMgrAdapterFacade::GetInstance().StartFormHostPage(want,
        Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE, Constants::OPEN_FORM_MANAGE_VIEW);
}

int32_t FormMgrService::OpenFormManagePage(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormMgrAdapterFacade::GetInstance().OpenFormManagePage(want);
}

int32_t FormMgrService::OpenFormEditSecondPage(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormMgrAdapterFacade::GetInstance().OpenFormEditSecondPage(want);
}

int32_t FormMgrService::OpenLiveFormPage(const Want &want, const std::string &formId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormMgrAdapterFacade::GetInstance().OpenLiveFormPage(want, formId);
}

void FormMgrService::InitFormShareMgrSerialQueue()
{
    // Copy the shared_ptrs under instanceMutex_ so OnStop cannot reset them
    // mid-copy (torn shared_ptr). Initialize is called outside the lock: its
    // RegisterEventTimeoutObserver virtual callback may re-enter the service.
    std::shared_ptr<FormEventHandler> handler;
    std::shared_ptr<FormSerialQueue> serialQueue;
    {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        handler = handler_;
        serialQueue = serialQueue_;
    }
    DelayedSingleton<FormShareMgr>::GetInstance()->Initialize(handler, serialQueue);
}

int32_t FormMgrService::ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
    int64_t requestCode)
{
    HILOG_DEBUG("FormMgrService ShareForm call deviceId :%{public}s,formId:%{public}" PRId64 "",
        deviceId.c_str(), formId);
    if (formId <= 0) {
        HILOG_ERROR("[%{public}s]invalid formId", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (deviceId.empty()) {
        HILOG_ERROR("empty deviceId");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("[%{public}s]null callerToken", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (requestCode <= 0) {
        HILOG_ERROR("[%{public}s]invalid requestCode", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    ErrCode ret = FormDataMgr::GetInstance().CheckInvalidForm(formId, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]invalid formId or not under currentActiveUser", __FUNCTION__);
        return ret;
    }

    InitFormShareMgrSerialQueue();

    return DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(formId, deviceId, callerToken, requestCode);
}

int32_t FormMgrService::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    HILOG_DEBUG("call");

    InitFormShareMgrSerialQueue();

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    return DelayedSingleton<FormShareMgr>::GetInstance()->RecvFormShareInfoFromRemote(info, userId);
}

int FormMgrService::Dump(int fd, const std::vector<std::u16string> &args)
{
    return FormMgrDumpHandler::Dump(fd, args);
}

int32_t FormMgrService::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();

    {
        if (!FormBmsHelper::GetInstance().IsBundleMgrValid()) {
            HILOG_ERROR("[%{public}s]get bundleMgr failed", __FUNCTION__);
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
    }

    if (!FormBmsHelper::GetInstance().CheckIsSystemAppByUid(callingUid)) {
        HILOG_ERROR("no permission");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapterFacade::GetInstance().RegisterPublishFormInterceptor(interceptorCallback);
}

int32_t FormMgrService::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();

    {
        if (!FormBmsHelper::GetInstance().IsBundleMgrValid()) {
            HILOG_ERROR("[%{public}s]get bundleMgr failed", __FUNCTION__);
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
    }

    if (!FormBmsHelper::GetInstance().CheckIsSystemAppByUid(callingUid)) {
        HILOG_ERROR("permission denied");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapterFacade::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
}

void FormMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID ||
        systemAbilityId == SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
        HILOG_INFO("SA:%{public}d ready,retry system event subscription", systemAbilityId);
        SubscribeSystemEvents();
        return;
    }
#ifdef RES_SCHEDULE_ENABLE
    if (systemAbilityId == RES_SCHED_SYS_ABILITY_ID) {
        auto formSystemloadLevelCb = [weakThis = weak_from_this()](int32_t level) {
            auto fmservice = weakThis.lock();
            if (fmservice == nullptr) {
                HILOG_ERROR("FormMgrService has been destroyed in system load callback");
                return;
            }
            fmservice->OnSystemloadLevel(level);
        };
        sptr<FormSystemloadListener> formSystemloadListener
            = new (std::nothrow) FormSystemloadListener(formSystemloadLevelCb);
        if (formSystemloadListener == nullptr) {
            HILOG_ERROR("Failed to create FormSystemloadListener");
            return;
        }
        ResourceSchedule::ResSchedClient::GetInstance().RegisterSystemloadNotifier(formSystemloadListener);
        HILOG_INFO("RegisterSystemloadNotifier for Systemloadlevel change");
        return;
    }
#endif // RES_SCHEDULE_ENABLE

#ifdef MEM_MGR_ENABLE
    if (systemAbilityId == MEMORY_MANAGER_SA_ID) {
        HILOG_INFO("MEMORY_MANAGER_SA start,SubscribeAppState");
        Memory::MemMgrClient::GetInstance().SubscribeAppState(*memStatusListener_);
        return;
    }
#endif // MEM_MGR_ENABLE

    if (systemAbilityId != DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        return;
    }
    SetOnKvDataServiceAddTime(GetCurrentDateTime());
    FormDataProxyMgr::GetInstance().RetryFailureSubscribes();
    HILOG_INFO("FMS KV data service add time:%{public}s", GetOnKvDataServiceAddTime().c_str());
}

bool FormMgrService::CheckCallerIsSystemApp() const
{
    if (!FormUtil::IsSACall() && !FormUtil::IsSystemAppCall()) {
        HILOG_ERROR("The caller not system-app,can't use system-api");
        return false;
    }
    return true;
}

std::string FormMgrService::GetCurrentDateTime()
{
    auto cTimeNow = std::chrono::system_clock::now();
    auto microPart = std::chrono::duration_cast<std::chrono::milliseconds>(
        cTimeNow.time_since_epoch()).count() % 1000;
    std::time_t t1 = std::chrono::system_clock::to_time_t(cTimeNow);
    char buf[32];
    std::tm t2;
    localtime_r(&t1, &t2);
    (void)strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S.", &t2);
    std::stringstream ss;
    ss << buf << std::setw(MILLISECOND_WIDTH) << std::setfill(MILLISECOND_FILLCHAR) << microPart;
    return ss.str();
}

bool FormMgrService::CheckAcrossLocalAccountsPermission() const
{
    // Non-foreground callers require INTERACT_ACROSS_LOCAL_ACCOUNTS.
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    std::vector<int32_t> foregroundUsers;
    FormUtil::GetForegroundUsers(foregroundUsers);
    if (std::find(foregroundUsers.begin(), foregroundUsers.end(), userId) == foregroundUsers.end()) {
        HILOG_INFO("userId:%{public}d not in %{public}zu foreground users", userId, foregroundUsers.size());
        bool isCallingPermAccount =
            FormUtil::VerifyCallingPermission(AppExecFwk::Constants::PERMISSION_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        if (!isCallingPermAccount) {
            HILOG_ERROR("[%{public}s]Across local accounts permission failed", __FUNCTION__);
            return false;
        }
    }
    return true;
}

ErrCode FormMgrService::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("[%{public}s]callerToken is null", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrService::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("[%{public}s]callerToken is null", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);
}

int32_t FormMgrService::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    return FormMgrAdapterFacade::GetInstance().GetFormsCount(isTempFormFlag, formCount);
}

int32_t FormMgrService::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    return FormMgrAdapterFacade::GetInstance().GetHostFormsCount(bundleName, formCount);
}

ErrCode FormMgrService::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("call");
    auto callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    return FormMgrAdapterFacade::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos, userId);
}

ErrCode FormMgrService::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().GetRunningFormInfosByBundleName(
        bundleName, isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrService::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    return FormMgrAdapterFacade::GetInstance().GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgrService::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    return FormMgrAdapterFacade::GetInstance().GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgrService::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    return FormMgrAdapterFacade::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgrService::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterAddObserver(bundleName, callerToken);
}

ErrCode FormMgrService::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
}

ErrCode FormMgrService::UpdateProxyForm(int64_t formId, const FormProviderData &formBindingData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().UpdateForm(formId, callingUid, formBindingData, formDataProxies);
}

ErrCode FormMgrService::RequestPublishProxyForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("call");
    return FormMgrAdapterFacade::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId,
        formDataProxies);
}

ErrCode FormMgrService::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    if (observer == nullptr) {
        HILOG_ERROR("[%{public}s]empty callerTokenParameter", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().RegisterClickEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgrService::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    if (observer == nullptr) {
        HILOG_ERROR("[%{public}s]empty callerTokenParameter", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, observer);
}

int32_t FormMgrService::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    return FormMgrAdapterFacade::GetInstance().SetFormsRecyclable(formIds);
}

int32_t FormMgrService::RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
{
    return FormMgrAdapterFacade::GetInstance().RecycleForms(formIds, want);
}

int32_t FormMgrService::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    return FormMgrAdapterFacade::GetInstance().RecoverForms(formIds, want);
}

ErrCode FormMgrService::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    std::lock_guard<std::mutex> lock(snapshotSetMutex_);
    HILOG_DEBUG("call");
    if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
        formLocation >= static_cast<int32_t>(Constants::FormLocation::FORM_LOCATION_END)) {
        HILOG_ERROR("invalid formLocation:%{public}d", formLocation);
        return ERR_APPEXECFWK_FORM_LOCATION_INVALID;
    }
    bool isRequestPublishFormWithSnapshot =
        requestPublishFormWithSnapshotSet_.find(formId) != requestPublishFormWithSnapshotSet_.end();
    return FormMgrAdapterFacade::GetInstance().UpdateFormLocation(
        formId, formLocation, isRequestPublishFormWithSnapshot);
}

ErrCode FormMgrService::BatchRefreshForms(const int32_t formRefreshType)
{
    return FormMgrAdapterFacade::GetInstance().BatchRefreshForms(formRefreshType);
}

ErrCode FormMgrService::RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    HILOG_INFO("[%{public}s]begin:%{public}s,publish:%{public}s,end:%{public}s,onKvDataServiceAddTime:%{public}s",
        __FUNCTION__,
        onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), GetOnKvDataServiceAddTime().c_str());
    std::string bundleName;
    FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    FormEventReport::SendRequestPublicFormEvent(bundleName, formName,
        RequestFormType::REQUEST_PUBLISH_FORM_WITH_SNAPSHOT);
    auto ret = FormMgrAdapterFacade::GetInstance().RequestPublishFormWithSnapshot(want, withFormBindingData,
        formBindingData, formId);
    if (ret == ERR_OK) {
        std::lock_guard<std::mutex> lock(snapshotSetMutex_);
        requestPublishFormWithSnapshotSet_.insert(formId);
        // Key by formId: same-key rescheduling replaces the pending task, so concurrent
        // publishes of one formId keep a single reset at the latest deadline.
        auto taskId = std::make_pair(static_cast<int64_t>(
            TaskType::UPDATE_IS_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT), formId);
        FormMgrQueue::GetInstance().ScheduleDelayTask(
            taskId, IS_FORM_REQUEST_PUBLISH_FORM_TASK_DELAY_TIME,
            [weakThis = weak_from_this(), taskId, formId]() {
                auto fmservice = weakThis.lock();
                if (fmservice == nullptr) {
                    HILOG_ERROR("FormMgrService has been destroyed in delay task");
                    return;
                }
                std::lock_guard<std::mutex> lock(fmservice->snapshotSetMutex_);
                fmservice->requestPublishFormWithSnapshotSet_.erase(formId);
                FormMgrQueue::GetInstance().CancelDelayTask(taskId);
            });
    }
    // Public API (FormMenuItem) only expects COMMON_CODE for failure cases.
    // Map specific error codes to COMMON_CODE for API compatibility.
    if (ret == ERR_APPEXECFWK_FORM_PUBLISH_NO_SPACE ||
        ret == ERR_APPEXECFWK_FORM_PUBLISH_NOT_SUPPORT) {
        HILOG_INFO("map %{public}d to COMMON_CODE for public API compatibility", ret);
        ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ret;
}

#ifdef RES_SCHEDULE_ENABLE
void FormMgrService::OnSystemloadLevel(int32_t level)
{
    if (level >= SYSTEMLOADLEVEL_TIMERSTOP_THRESHOLD) {
        FormMgrAdapterFacade::GetInstance().SetTimerTaskNeeded(false);
    } else {
        FormMgrAdapterFacade::GetInstance().SetTimerTaskNeeded(true);
    }
}
#endif // RES_SCHEDULE_ENABLE

int32_t FormMgrService::EnableForms(const std::string bundleName, const int32_t userId, const bool enable)
{
    if (userId < 0) {
        HILOG_ERROR("invalid userId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormMgrAdapterFacade::GetInstance().EnableForms(bundleName, userId, enable);
}

bool FormMgrService::IsFormBundleForbidden(const std::string &bundleName)
{
    HILOG_DEBUG("call");
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_IsFormBundleForbidden",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    bool result = FormBundleForbidMgr::GetInstance().IsBundleForbidden(bundleName);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return result;
}

int32_t FormMgrService::LockForms(const std::vector<FormLockInfo> &formLockInfos, LockChangeType type)
{
    int32_t retErrCode = ERR_OK;
    for (const auto &info : formLockInfos) {
        if (type == LockChangeType::SWITCH_CHANGE) {
            ErrCode ret = FormMgrAdapterFacade::GetInstance().SwitchLockForms(info.bundleName, info.userId, info.lock);
            if (ret != ERR_OK) {
                HILOG_ERROR("SwitchLockForms failed,bundleName:%{public}s,userId:%{public}d,"
                    "lock: %{public}d, ret: %{public}d", info.bundleName.c_str(), info.userId, info.lock, ret);
                retErrCode = ret;
            }
        } else {
            ErrCode ret = FormMgrAdapterFacade::GetInstance().ProtectLockForms(info.bundleName, info.userId, info.lock);
            if (ret != ERR_OK) {
                HILOG_ERROR("ProtectLockForms failed,bundleName:%{public}s,userId:%{public}d,"
                    "protect: %{public}d, ret: %{public}d", info.bundleName.c_str(), info.userId, info.lock, ret);
                retErrCode = ret;
            }
        }
    }
    FormBundleLockMgr::GetInstance().InitLockService();
    return retErrCode;
}

bool FormMgrService::IsFormBundleProtected(const std::string &bundleName, int64_t formId)
{
    HILOG_DEBUG("call");
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_IsFormBundleProtected",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    bool result = FormBundleLockMgr::GetInstance().IsBundleProtect(bundleName, userId, formId);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return result;
}

bool FormMgrService::IsFormBundleDebugSignature(const std::string &bundleName)
{
    HILOG_DEBUG("call");
    BundleInfo bundleInfo;
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);
    bool ret = FormBmsHelper::GetInstance().GetBundleInfoByFlags(bundleName, flags, userId, bundleInfo);
    if (!ret) {
        HILOG_ERROR("Get GetBundleInfoByFlags failed");
        return false;
    }
    return bundleInfo.applicationInfo.appProvisionType == APP_PROVISION_TYPE_DEBUG;
}

bool FormMgrService::IsFormBundleExempt(int64_t formId)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    if (!CheckCallerIsSystemApp()) {
        return true;
    }
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_IsFormBundleExempt",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    bool result = FormExemptLockMgr::GetInstance().IsExemptLock(formId);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return result;
}

int32_t FormMgrService::NotifyFormLocked(const int64_t &formId, bool isLocked)
{
    return FormMgrAdapterFacade::GetInstance().NotifyFormLocked(formId, isLocked);
}

ErrCode FormMgrService::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
    float formViewScale)
{
    HILOG_DEBUG("call");
    FormMgrAdapterFacade::GetInstance().UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    return ERR_OK;
}

ErrCode FormMgrService::OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int uid = IPCSkeleton::GetCallingUid();
    std::string callerName;
    ErrCode ret = FormBmsHelper::GetInstance().GetBundleNameByUid(uid, callerName);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get bundleName by uid failed");
        return ret;
    }

    RunningFormInfo runningFormInfo;
    int32_t userId = FormUtil::GetCallerUserId(uid);
    ret = FormDataMgr::GetInstance().GetRunningFormInfosByFormId(formId, runningFormInfo, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get running form info by id failed");
        return ret;
    }

    if (runningFormInfo.bundleName != callerName) {
        HILOG_ERROR("check bundleName fialed");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    if (runningFormInfo.formVisiblity != FormVisibilityType::VISIBLE) {
        HILOG_ERROR("check form visibility fialed");
        return ERR_APPEXECFWK_FORM_NOT_TRUST;
    }

    WantParams wantarams;
    if (isMainPage) {
        WantParams formInfoParam;
        formInfoParam.SetParam("bundleName", String::Box(runningFormInfo.bundleName));
        formInfoParam.SetParam("abilityName", String::Box(runningFormInfo.abilityName));
        formInfoParam.SetParam("moduleName", String::Box(runningFormInfo.moduleName));
        formInfoParam.SetParam("cardDimension", Integer::Box(runningFormInfo.dimension));
        formInfoParam.SetParam("cardName", String::Box(runningFormInfo.formName));
        formInfoParam.SetParam("cardId", String::Box(std::to_string(formId)));
        formInfoParam.SetParam("formConfigAbility", String::Box(abilityName));
        wantarams.SetParam("formInfo", WantParamWrapper::Box(formInfoParam));
    } else {
        wantarams.SetParam(Constants::PARAM_SEC_PAGE_ABILITY_NAME, String::Box(abilityName));
    }

    Want want;
    want.SetElementName(callerName, abilityName);
    want.SetParams(wantarams);
    return FormMgrAdapterFacade::GetInstance().StartFormHostPage(want, Constants::PAGE_ROUTER_SERVICE_CODE_FORM_EDIT,
        isMainPage ? Constants::PARAM_OPEN_FORM_EDIT_VIEW : Constants::PARAM_OPEN_FORM_EDIT_SEC_PAGE_VIEW);
}

ErrCode FormMgrService::CloseFormEditAbility(bool isMainPage)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    int uid = IPCSkeleton::GetCallingUid();
    return FormEditService::GetInstance().CloseFormEditAbility(uid, isMainPage);
}

ErrCode FormMgrService::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterOverflowProxy(callerToken);
}

ErrCode FormMgrService::UnregisterOverflowProxy()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterOverflowProxy();
}

ErrCode FormMgrService::RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().RequestOverflow(formId, callingUid, overflowInfo, isOverflow);
}

ErrCode FormMgrService::RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterChangeSceneAnimationStateProxy(callerToken);
}

ErrCode FormMgrService::UnregisterChangeSceneAnimationStateProxy()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterChangeSceneAnimationStateProxy();
}

ErrCode FormMgrService::ChangeSceneAnimationState(const int64_t formId, int32_t state)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().ChangeSceneAnimationState(formId, callingUid, state);
}

ErrCode FormMgrService::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterGetFormRectProxy(callerToken);
}

ErrCode FormMgrService::UnregisterGetFormRectProxy()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterGetFormRectProxy();
}

ErrCode FormMgrService::GetFormRect(const int64_t formId, Rect &rect)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().GetFormRect(formId, callingUid, rect);
}

ErrCode FormMgrService::RegisterGetVisibleFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterGetVisibleFormRectProxy(callerToken);
}

ErrCode FormMgrService::UnregisterGetVisibleFormRectProxy()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterGetVisibleFormRectProxy();
}

ErrCode FormMgrService::GetVisibleFormRect(const int64_t formId, Rect &rect)
{
#ifndef WATCH_API_DISABLE
    HILOG_INFO("call, formId:%{public}" PRId64, formId);
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS:GetVisibleFormRect",
        FORM_VISIBLE_RECT_QUERY_TIMEOUT_SEC, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    ErrCode result = FormMgrAdapterFacade::GetInstance().GetVisibleFormRect(
        formId, IPCSkeleton::GetCallingUid(), rect);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return result;
#else
    return ERR_APPEXECFWK_SYSTEMCAP_ERROR;
#endif
}

ErrCode FormMgrService::UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
{
    return FormMgrAdapterFacade::GetInstance().UpdateFormSize(formId, newDimension, newRect);
}

ErrCode FormMgrService::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
}

ErrCode FormMgrService::UnregisterGetLiveFormStatusProxy()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterGetLiveFormStatusProxy();
}

ErrCode FormMgrService::ReloadForms(int32_t &reloadNum, const std::string &moduleName, const std::string &abilityName,
    const std::string &formName)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    std::string callerBundleName;
    // the caller's own index comes from its uid, not from enable state
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleNameAndAppIndex(callerBundleName, appIndex);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get BundleName failed", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    std::vector<FormRecord> callerBundleForms;
    FormDataMgr::GetInstance().GetFormRecord(callerBundleName, callerBundleForms);
    std::vector<FormRecord> refreshForms;
    std::copy_if(callerBundleForms.begin(), callerBundleForms.end(), std::back_inserter(refreshForms),
        [&moduleName, &abilityName, &formName, appIndex] (const FormRecord &formRecord) {
            return formRecord.moduleName == moduleName &&
                   formRecord.abilityName == abilityName &&
                   formRecord.formName == formName &&
                   formRecord.appIndex == appIndex;
        });
    return FormMgrAdapterFacade::GetInstance().ReloadForms(reloadNum, refreshForms);
}

ErrCode FormMgrService::ReloadAllForms(int32_t &reloadNum)
{
    HILOG_INFO("[%{public}s]call", __FUNCTION__);
    std::string callerBundleName;
    // the caller's own index comes from its uid, not from enable state
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleNameAndAppIndex(callerBundleName, appIndex);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get BundleName failed", __FUNCTION__);
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    std::vector<FormRecord> allForms;
    FormDataMgr::GetInstance().GetFormRecord(callerBundleName, allForms);
    std::vector<FormRecord> refreshForms;
    std::copy_if(allForms.begin(), allForms.end(), std::back_inserter(refreshForms),
        [appIndex] (const FormRecord &formRecord) {
            return formRecord.appIndex == appIndex;
        });
    return FormMgrAdapterFacade::GetInstance().ReloadForms(reloadNum, refreshForms);
}

bool FormMgrService::IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
{
    HILOG_DEBUG("call");
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_IsFormDueControl",
        API_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
    bool result = FormMgrAdapterFacade::GetInstance().CheckFormDueControl(formMajorInfo, isDisablePolicy);
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    return result;
}

ErrCode FormMgrService::SendNonTransparencyRatio(int64_t formId, int32_t ratio)
{
    HILOG_DEBUG("call");
    FormAbnormalReporter::GetInstance().AddRecord(formId, ratio);
    return ERR_OK;
}

ErrCode FormMgrService::RegisterPublishFormCrossBundleControl(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterPublishFormCrossBundleControl(callerToken);
}

ErrCode FormMgrService::UnregisterPublishFormCrossBundleControl()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterPublishFormCrossBundleControl();
}

ErrCode FormMgrService::GetFormIdsByFormLocation(int32_t formLocation, std::vector<std::string> &formIds)
{
    HILOG_DEBUG("[%{public}s]call", __FUNCTION__);
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    if (!FormUtil::VerifyCallingPermission(AppExecFwk::Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
 
    if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
        formLocation >= static_cast<int32_t>(Constants::FormLocation::FORM_LOCATION_END)) {
        HILOG_ERROR("formLocation not FormLocation enum,formLocation = %{public}d", formLocation);
        return ERR_APPEXECFWK_FORM_LOCATION_INVALID;
    }
 
    const auto callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    FormMgrHostAdapter::GetInstance().GetFormIdsByFormLocation(
        userId, static_cast<Constants::FormLocation>(formLocation), formIds);
 
    return ERR_OK;
}

bool FormMgrService::PublishFormCrossBundleControl(const Want &want)
{
    bool isShowSingleForm = want.GetBoolParam(Constants::FORM_MANAGER_SHOW_SINGLE_FORM_KEY, false);
    if (!isShowSingleForm) {
        return true;
    }
    std::string callerBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("[%{public}s]get BundleName failed", __FUNCTION__);
        return false;
    }
    PublishFormCrossBundleInfo bundleInfo;
    bundleInfo.callerBundleName = callerBundleName;
    bundleInfo.targetBundleName = want.GetBundle();
    bundleInfo.targetTemplateFormDetailId = want.GetStringParam(Constants::TEMPLATE_FORM_DETAIL_ID_KEY);
    return FormMgrAdapterFacade::GetInstance().PublishFormCrossBundleControl(bundleInfo);
}

ErrCode FormMgrService::RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    return FormMgrAdapterFacade::GetInstance().RegisterTemplateFormDetailInfoChange(callerToken);
}

ErrCode FormMgrService::UnregisterTemplateFormDetailInfoChange()
{
    HILOG_INFO("call");
    return FormMgrAdapterFacade::GetInstance().UnregisterTemplateFormDetailInfoChange();
}

ErrCode FormMgrService::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    return FormMgrAdapterFacade::GetInstance().UpdateTemplateFormDetailInfo(templateFormInfo);
}

ErrCode FormMgrService::RegisterUpdateFormsConfigCallback(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterUpdateFormsConfigCallback(callerToken);
}

ErrCode FormMgrService::UnregisterUpdateFormsConfigCallback()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterUpdateFormsConfigCallback();
}

ErrCode FormMgrService::UpdateFormsConfig(const std::vector<FormCustomConfig> &configs)
{
    return FormMgrAdapterFacade::GetInstance().UpdateFormsConfig(configs);
}

ErrCode FormMgrService::RegisterDeleteFormsCallback(const sptr<IRemoteObject> &callerToken)
{
    return FormMgrAdapterFacade::GetInstance().RegisterDeleteFormsCallback(callerToken);
}

ErrCode FormMgrService::UnregisterDeleteFormsCallback()
{
    return FormMgrAdapterFacade::GetInstance().UnregisterDeleteFormsCallback();
}

ErrCode FormMgrService::DeleteForms(const std::vector<FormRecordFilter> &filters)
{
    return FormMgrAdapterFacade::GetInstance().DeleteForms(filters);
}

ErrCode FormMgrService::RegisterFormWantCallback(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().RegisterFormWantCallback(callingUid, callerToken);
}

ErrCode FormMgrService::UnregisterFormWantCallback()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapterFacade::GetInstance().UnregisterFormWantCallback(callingUid);
}

void FormMgrService::SetOnKvDataServiceAddTime(const std::string &time)
{
    std::lock_guard<std::mutex> lock(onKvDataServiceAddTimeMutex_);
    onKvDataServiceAddTime_ = time;
}

std::string FormMgrService::GetOnKvDataServiceAddTime() const
{
    std::lock_guard<std::mutex> lock(onKvDataServiceAddTimeMutex_);
    return onKvDataServiceAddTime_;
}

ErrCode FormMgrService::RegisterFormHostService(const FormHostServiceInfo &serviceInfo, int64_t &serviceId)
{
    HILOG_INFO("call");
#ifdef DISTRIBUTED_FORM_SUPPORTED
    return FormMgrAdapterFacade::GetInstance().RegisterFormHostService(serviceInfo, serviceId);
#else
    HILOG_WARN("[%{public}s]cross-device not supported on this build", __FUNCTION__);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
#endif
}

ErrCode FormMgrService::UnregisterFormHostService(int64_t serviceId)
{
    HILOG_INFO("call");
#ifdef DISTRIBUTED_FORM_SUPPORTED
    return FormMgrAdapterFacade::GetInstance().UnregisterFormHostService(serviceId);
#else
    HILOG_WARN("[%{public}s]cross-device not supported on this build", __FUNCTION__);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
#endif
}

ErrCode FormMgrService::GetAvailableFormHostServices(std::vector<PeerFormHostServiceInfo> &services)
{
    HILOG_INFO("call");
#ifdef DISTRIBUTED_FORM_SUPPORTED
    return FormMgrAdapterFacade::GetInstance().GetAvailableFormHostServices(services);
#else
    HILOG_WARN("[%{public}s]cross-device not supported on this build", __FUNCTION__);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
#endif
}

ErrCode FormMgrService::RequestPublishFormCrossDevice(const FormCrossDeviceRequest &request,
    const sptr<IRemoteObject> &callerToken, const sptr<IRemoteObject> &callback)
{
    HILOG_INFO("call");
    if (callerToken == nullptr || callback == nullptr) {
        HILOG_ERROR("callerToken or callback null");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
#ifdef DISTRIBUTED_FORM_SUPPORTED
    return FormMgrAdapterFacade::GetInstance().RequestPublishFormCrossDevice(request, callerToken, callback);
#else
    HILOG_WARN("[%{public}s]cross-device not supported on this build", __FUNCTION__);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS
