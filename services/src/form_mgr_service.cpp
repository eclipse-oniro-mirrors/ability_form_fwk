/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "form_mgr_service.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "bundle_common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "fms_log_wrapper.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_cache_mgr.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_data_proxy_mgr.h"
#include "form_db_cache.h"
#include "form_event_handler.h"
#include "form_event_report.h"
#include "form_info_mgr.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_serial_queue.h"
#include "form_share_mgr.h"
#include "form_task_mgr.h"
#include "form_timer_mgr.h"
#include "form_trust_mgr.h"
#include "form_util.h"
#include "form_xml_parser.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mem_status_listener.h"
#include "os_account_manager.h"
#include "permission_constants.h"
#include "permission_verification.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#include "hisysevent.h"
#include "xcollie/watchdog.h"
#include "mem_mgr_client.h"

#ifdef RES_SCHEDULE_ENABLE
#include "form_systemload_listener.h"
#include "res_sched_client.h"
#include "res_type.h"
#endif // RES_SCHEDULE_ENABLE

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAIN_USER_ID = 100;
constexpr int32_t GET_CALLING_UID_TRANSFORM_DIVISOR = 200000;
constexpr int MILLISECOND_WIDTH = 3;
constexpr char MILLISECOND_FILLCHAR = '0';
#ifdef RES_SCHEDULE_ENABLE
constexpr uint64_t SYSTEMLOADLEVEL_TIMERSTOP_THRESHOLD = ResourceSchedule::ResType::SystemloadLevel::HIGH;
#endif // RES_SCHEDULE_ENABLE
}
using namespace std::chrono;

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<FormMgrService>::GetInstance().get());

const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

const std::string FORM_MGR_SERVICE_QUEUE = "FormMgrServiceQueue";

constexpr int32_t FORM_DUMP_ARGC_MAX = 2;

const std::string FORM_DUMP_HELP = "options list:\n"
    "  -h, --help                           list available commands\n"
    "  -b, --bundle-form-info               query all form infos from bundle, Un-added form info will also be dumped\n"
    "  -v, --visible                        query form visible infos from args like bundleName_userId_instIndex\n"
    "  -s, --storage                        query form storage info\n"
    "  -t, --temp                           query temporary form info\n"
    "  -n  <bundle-name>                    query form info by a bundle name\n"
    "  -i  <form-id>                        query form info by a form ID\n"
    "  -r  --running                        query running form info\n"
    "  -a  --apps-blocked                   query blocked app name list\n";

const std::map<std::string, FormMgrService::DumpKey> FormMgrService::dumpKeyMap_ = {
    {"-h", FormMgrService::DumpKey::KEY_DUMP_HELP},
    {"--help", FormMgrService::DumpKey::KEY_DUMP_HELP},
    {"-b", FormMgrService::DumpKey::KEY_DUMP_STATIC},   // *****
    {"--bundle-form-info", FormMgrService::DumpKey::KEY_DUMP_STATIC},
    {"-v", FormMgrService::DumpKey::KEY_DUMP_VISIBLE},
    {"--visible", FormMgrService::DumpKey::KEY_DUMP_VISIBLE},
    {"-s", FormMgrService::DumpKey::KEY_DUMP_STORAGE},
    {"--storage", FormMgrService::DumpKey::KEY_DUMP_STORAGE},
    {"-t", FormMgrService::DumpKey::KEY_DUMP_TEMPORARY},
    {"--temp", FormMgrService::DumpKey::KEY_DUMP_TEMPORARY},
    {"-n", FormMgrService::DumpKey::KEY_DUMP_BY_BUNDLE_NAME},
    {"-i", FormMgrService::DumpKey::KEY_DUMP_BY_FORM_ID},
    {"-r", FormMgrService::DumpKey::KEY_DUMP_RUNNING},
    {"--running", FormMgrService::DumpKey::KEY_DUMP_RUNNING},
    {"-a", FormMgrService::DumpKey::KEY_DUMP_BLOCKED_APPS},
    {"--apps-blocked", FormMgrService::DumpKey::KEY_DUMP_BLOCKED_APPS},
};

FormMgrService::FormMgrService()
    : SystemAbility(FORM_MGR_SERVICE_ID, true),
      state_(ServiceRunningState::STATE_NOT_START),
      serialQueue_(nullptr)
{
    HILOG_INFO("called");
    DumpInit();
}

FormMgrService::~FormMgrService()
{
    HILOG_INFO("called");
    if (formSysEventReceiver_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(formSysEventReceiver_);
        formSysEventReceiver_ = nullptr;
        FormBmsHelper::GetInstance().UnregisterBundleEventCallback();
    }
    if (memStatusListener_ != nullptr) {
        Memory::MemMgrClient::GetInstance().UnsubscribeAppState(*memStatusListener_);
    }
}

/**
* @brief Check form manager service ready.
* @return Return true if form manager service Ready; return false otherwise.
*/

bool FormMgrService::CheckFMSReady()
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return false;
    }

    int32_t userId = FormUtil::GetCurrentAccountId();
    if (userId == Constants::ANY_USERID) {
        HILOG_ERROR("fail, account is empty");
        return false;
    }
    return FormInfoMgr::GetInstance().HasReloadedFormInfos();
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
    HILOG_INFO("FMS AddForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, add form permission denied");
        return ret;
    }
    ReportAddFormEvent(formId, want);
    return FormMgrAdapter::GetInstance().AddForm(formId, want, callerToken, formInfo);
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param want The want of the form to add.
 * @param runningFormInfo Running form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    HILOG_INFO("CreateForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("create form permission denied");
        return ret;
    }
    ReportAddFormEvent(0, want);
    return FormMgrAdapter::GetInstance().CreateForm(want, runningFormInfo);
}

void FormMgrService::ReportAddFormEvent(const int64_t formId, const Want &want)
{
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    int ret = FormBmsHelper::GetInstance().GetCallerBundleName(eventInfo.hostBundleName);
    if (ret != ERR_OK || eventInfo.hostBundleName.empty()) {
        HILOG_ERROR("fail, cannot get host bundle name by uid");
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
    HILOG_INFO("FMS DeleteForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, delete form permission denied");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    if (formHostRecords.size() != 0) {
        eventInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    }
    FormEventReport::SendSecondFormEvent(FormEventName::DELETE_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().DeleteForm(formId, callerToken);
}

/**
 * @brief Stop rendering form.
 * @param formId The Id of the forms to delete.
 * @param compId The compId of the forms to delete.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, delete form permission denied");
        return ret;
    }

    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, the form id is invalid or not under the current active user.");
        return ret;
    }
    return FormMgrAdapter::GetInstance().StopRenderingForm(formId, compId);
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
    HILOG_INFO("FMS ReleaseForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, release form permission denied");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(FormEventName::RELEASE_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().ReleaseForm(formId, callerToken, delCache);
}

/**
 * @brief Update form with formId, send formId to form manager service.
 * @param formId The Id of the form to update.
 * @param formBindingData Form binding data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::UpdateForm(const int64_t formId, const FormProviderData &formBindingData)
{
    HILOG_DEBUG("called.");
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapter::GetInstance().UpdateForm(formId, callingUid, formBindingData);
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
    HILOG_INFO("FMS RequestForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, request form permission denied");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendSecondFormEvent(FormEventName::REQUEST_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().RequestForm(formId, callerToken, want);
}

/**
 * @brief set next refresh time.
 * @param formId The id of the form.
 * @param nextTime next refresh time.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_DEBUG("called.");
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(
        FormEventName::SET_NEXT_REFRESH_TIME_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().SetNextRefreshTime(formId, nextTime);
}

int FormMgrService::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, request form permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().ReleaseRenderer(formId, compId);
}

ErrCode FormMgrService::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    HILOG_INFO("FMS RequestPublishForm called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    bool isFormAgent = want.GetBoolParam(Constants::IS_FORM_AGENT, false);
    HILOG_INFO("RequestPublishForm called, isFormAgent: %{public}d", isFormAgent);
    if (isFormAgent) {
        ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_AGENT_REQUIRE_FORM);
        if (ret != ERR_OK) {
            HILOG_ERROR("fail, request form permission denied");
            return ret;
        }
    } else {
        if (!CheckCallerIsSystemApp()) {
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
        }
    }
    return FormMgrAdapter::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId);
}

ErrCode FormMgrService::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_REQUIRE_FORM);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    return FormMgrAdapter::GetInstance().SetPublishFormResult(formId, errorCodeInfo);
}

ErrCode FormMgrService::AcquireAddFormResult(const int64_t formId)
{
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_AGENT_REQUIRE_FORM);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    return FormMgrAdapter::GetInstance().AcquireAddFormResult(formId);
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
    HILOG_DEBUG("called.");

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, event notify visible permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
}

/**
 * @brief Query whether has visible form by tokenId.
 * @param tokenId Unique identification of application.
 * @return Returns true if has visible form, false otherwise.
 */
bool FormMgrService::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("called.");

    if (!FormUtil::IsSACall()) {
        HILOG_ERROR("fail, query form visible with tokenid not a SACall");
        return false;
    }
    return FormMgrAdapter::GetInstance().HasFormVisible(tokenId);
}

/**
 * @brief temp form to normal form.
 * @param formId The Id of the form.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, cast temp form permission denied");
        return ret;
    }
    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, the form id is invalid or not under the current active user.");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    FormEventReport::SendSecondFormEvent(FormEventName::CASTTEMP_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().CastTempForm(formId, callerToken);
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
    HILOG_INFO("lifecycleUpdate. %{public}d", updateType);

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, delete form permission denied");
        return ret;
    }

    if (updateType) {
        return FormMgrAdapter::GetInstance().EnableUpdateForm(formIds, callerToken);
    } else {
        return FormMgrAdapter::GetInstance().DisableUpdateForm(formIds, callerToken);
    }
}
/**
 * @brief Dump all of form storage infos.
 * @param formInfos All of form storage infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpStorageFormInfos(std::string &formInfos)
{
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return FormMgrAdapter::GetInstance().DumpStorageFormInfos(formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param bundleName The bundle name of form provider.
 * @param formInfos Form infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos)
{
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return FormMgrAdapter::GetInstance().DumpFormInfoByBundleName(bundleName, formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo)
{
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return FormMgrAdapter::GetInstance().DumpFormInfoByFormId(formId, formInfo);
}
/**
 * @brief Dump form timer by form id.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService)
{
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return FormMgrAdapter::GetInstance().DumpFormTimerByFormId(formId, isTimingService);
}

/**
 * @brief Process js message event.
 * @param formId Indicates the unique id of form.
 * @param want information passed to supplier.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrService::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FMS MessageEvent called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, request form permission denied");
        return ret;
    }
    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, the form id is invalid or not under the current active user.");
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
    FormEventReport::SendFormEvent(FormEventName::MESSAGE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().MessageEvent(formId, want, callerToken);
}

/**
 * @brief Process js router event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrService::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FMS RouterEvent called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("error, request form permission denied");
        return ret;
    }
    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("error, the form id is invalid or not under the current active user.");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    if (formHostRecords.size() != 0) {
        eventInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    }
    FormEventReport::SendFormEvent(FormEventName::ROUTE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().RouterEvent(formId, want, callerToken);
}

/**
 * @brief Process Background event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrService::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FMS BackgroundEvent called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, request form permission denied.");
        return ret;
    }
    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, the form id is not under the current active user or invalid.");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.formId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendSecondFormEvent(FormEventName::BACKGROUND_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().BackgroundEvent(formId, want, callerToken);
}

/**
 * @brief Start event for the form manager service.
 */
void FormMgrService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOG_WARN("fail, Failed to start service since it's already running");
        return;
    }

    onStartBeginTime_ = GetCurrentDateTime();
    HILOG_INFO("Form Mgr Service start, time: %{public}s", onStartBeginTime_.c_str());
    ErrCode errCode = Init();
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail, Failed to init, errCode: %{public}08x", errCode);
        return;
    }

    state_ = ServiceRunningState::STATE_RUNNING;
    // listener for FormDataProxyMgr
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
#ifdef RES_SCHEDULE_ENABLE
    AddSystemAbilityListener(RES_SCHED_SYS_ABILITY_ID);
#endif // RES_SCHEDULE_ENABLE
    onStartEndTime_ = GetCurrentDateTime();
    HILOG_INFO("Form Mgr Service start success, time: %{public}s, onKvDataServiceAddTime: %{public}s",
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
}
/**
 * @brief Stop event for the form manager service.
 */
void FormMgrService::OnStop()
{
    HILOG_INFO("stop service");

    state_ = ServiceRunningState::STATE_NOT_START;

    if (serialQueue_) {
        serialQueue_.reset();
    }

    if (handler_) {
        handler_.reset();
    }
}

ErrCode FormMgrService::ReadFormConfigXML()
{
    FormXMLParser parser;
    int32_t ret = parser.Parse();
    if (ret != ERR_OK) {
        HILOG_WARN("parse form config failed, use the default vaule.");
        return ret;
    }
    const std::map<std::string, int32_t> &configMap = parser.GetConfigMap();
    FormDataMgr::GetInstance().SetConfigMap(configMap);
    return ERR_OK;
}


void FormMgrService::SubscribeSysEventReceiver()
{
    if (formSysEventReceiver_ == nullptr) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
        // init TimerReceiver
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
        formSysEventReceiver_ = std::make_shared<FormSysEventReceiver>(subscribeInfo);
        formSysEventReceiver_->SetSerialQueue(serialQueue_);
        EventFwk::CommonEventManager::SubscribeCommonEvent(formSysEventReceiver_);
    }
}

/**
 * @brief initialization of form manager service.
 */
ErrCode FormMgrService::Init()
{
    HILOG_INFO("called");
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_MGR_SERVICE_QUEUE.c_str());
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("Init fail, Failed to init due to create serialQueue_ error");
        return ERR_INVALID_OPERATION;
    }

    handler_ = std::make_shared<FormEventHandler>(serialQueue_);
    if (handler_ == nullptr) {
        HILOG_ERROR("fail, Failed to init due to create handler error");
        return ERR_INVALID_OPERATION;
    }
    FormTaskMgr::GetInstance().SetSerialQueue(serialQueue_);
    FormAmsHelper::GetInstance().SetSerialQueue(serialQueue_);
    /* Publish service maybe failed, so we need call this function at the last,
     * so it can't affect the TDD test program */
    if (!Publish(DelayedSingleton<FormMgrService>::GetInstance().get())) {
        HILOG_ERROR("FormMgrService::Init Publish failed!");
        return ERR_INVALID_OPERATION;
    }
    onStartPublishTime_ = GetCurrentDateTime();
    HILOG_INFO("FMS onStart publish done, time: %{public}s", onStartPublishTime_.c_str());

    SubscribeSysEventReceiver();

    memStatusListener_ = std::make_shared<MemStatusListener>();
    Memory::MemMgrClient::GetInstance().SubscribeAppState(*memStatusListener_);

    FormInfoMgr::GetInstance().Start();
    FormDbCache::GetInstance().Start();
    FormTimerMgr::GetInstance(); // Init FormTimerMgr
    FormCacheMgr::GetInstance().Start();

    formSysEventReceiver_->InitFormInfosAndRegister();

    // read param form form_config.xml.
    if (ReadFormConfigXML() != ERR_OK) {
        HILOG_WARN("parse form config failed, use the default vaule.");
    }
    FormMgrAdapter::GetInstance().Init();
    return ERR_OK;
}

ErrCode FormMgrService::CheckFormPermission(const std::string &permission)
{
    HILOG_DEBUG("called.");

    if (FormUtil::IsSACall()) {
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
        HILOG_ERROR("Across local accounts permission failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    HILOG_DEBUG("Permission verification ok!");
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
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, delete form permission denied");
        return ret;
    }
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(FormEventName::DELETE_INVALID_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
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
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, acquire form state permission denied");
        return ret;
    }
    FormEventInfo eventInfo;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    FormEventReport::SendFormEvent(FormEventName::ACQUIREFORMSTATE_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().AcquireFormState(want, callerToken, stateInfo);
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
    HILOG_DEBUG("Called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("Fail, register form router proxy permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
}

/**
* @brief Unregister form router event proxy.
* @param formIds Indicates the ID of the forms.
* @return Returns ERR_OK on success, others on failure.
*/
int FormMgrService::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("Called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("Fail, unregister form router proxy permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
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
    HILOG_INFO("FMS NotifyFormsVisible called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, notify form visible permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrService::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, notify form is privacy protected permission denied");
        return ret;
    }
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
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, notify form enable update permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
}

/**
 * @brief Get All FormsInfo.
 * @param formInfos Return the form information of all forms provided.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    if (!CheckAcrossLocalAccountsPermission()) {
        HILOG_ERROR("Across local accounts permission failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().GetAllFormsInfo(formInfos);
}

/**
 * @brief Get forms info by bundle name.
 * @param bundleName Application name.
 * @param formInfos Return the form information of the specify application name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    if (!CheckAcrossLocalAccountsPermission()) {
        HILOG_ERROR("Across local accounts permission failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
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
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    if (!CheckAcrossLocalAccountsPermission()) {
        HILOG_ERROR("Across local accounts permission failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

int FormMgrService::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("Need system authority");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    if (!CheckAcrossLocalAccountsPermission()) {
        HILOG_ERROR("Across local accounts permission failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().GetFormsInfoByFilter(filter, formInfos);
}

int32_t FormMgrService::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("called.");
    std::string callerBundleName;
    ErrCode ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get host bundle name failed");
        return ret;
    }
    // retrieve moduleName from filter.
    std::string moduleName = filter.moduleName;
    if (moduleName.empty()) {
        // fulfill formInfos, the process should be the same as GetFormsInfoByApp.
        HILOG_INFO("GetFormsInfo flows to GetFormsInfoByAPP");
        return FormMgrAdapter::GetInstance().GetFormsInfoByApp(callerBundleName, formInfos);
    }
    HILOG_INFO("GetFormsInfo flows to GetFormsInfoByModule");
    return FormMgrAdapter::GetInstance().GetFormsInfoByModule(callerBundleName, moduleName, formInfos);
}

int32_t FormMgrService::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    HILOG_DEBUG("called.");
    if (formId <= 0) {
        HILOG_ERROR("form formId  is invalid.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is nullptr");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (requestCode <= 0) {
        HILOG_ERROR("form requestCode is invalid");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, request form permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().AcquireFormData(formId, requestCode, callerToken, formData);
}

bool FormMgrService::IsRequestPublishFormSupported()
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return false;
    }
    return FormMgrAdapter::GetInstance().IsRequestPublishFormSupported();
}

int32_t FormMgrService::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FMS StartAbility called, startTime: begin: %{public}s, publish: %{public}s, end: %{public}s, "
        "onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    // check abilityName to void implicit want.
    if (want.GetElement().GetAbilityName() == "") {
        HILOG_ERROR("error, AbilityName is empty");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }
    sptr<AAFwk::IAbilityManager> ams = FormAmsHelper::GetInstance().GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("error, failed to get abilityMgr.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ams->StartAbility(want, callerToken, -1, -1);
}

void FormMgrService::InitFormShareMgrSerialQueue()
{
    DelayedSingleton<FormShareMgr>::GetInstance()->SetSerialQueue(serialQueue_);
    DelayedSingleton<FormShareMgr>::GetInstance()->SetEventHandler(handler_);
}

int32_t FormMgrService::ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
    int64_t requestCode)
{
    HILOG_DEBUG("FormMgrService ShareForm called deviceId : %{public}s, formId: %{public}" PRId64 "",
        deviceId.c_str(), formId);
    if (formId <= 0) {
        HILOG_ERROR("form formId  is invalid.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (deviceId.empty()) {
        HILOG_ERROR("form deviceId is empty.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is nullptr.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (requestCode <= 0) {
        HILOG_ERROR("form requestCode is invalid.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("share form permission denied.");
        return ret;
    }

    ret = FormDataMgr::GetInstance().CheckInvalidForm(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, the form id is invalid or not under the current active user.");
        return ret;
    }

    InitFormShareMgrSerialQueue();

    return DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(formId, deviceId, callerToken, requestCode);
}

int32_t FormMgrService::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    HILOG_DEBUG("called.");
    if (!FormUtil::IsSACall()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    InitFormShareMgrSerialQueue();

    return DelayedSingleton<FormShareMgr>::GetInstance()->RecvFormShareInfoFromRemote(info);
}

void FormMgrService::DumpInit()
{
    dumpFuncMap_[DumpKey::KEY_DUMP_HELP] = &FormMgrService::HiDumpHelp;
    dumpFuncMap_[DumpKey::KEY_DUMP_STATIC] = &FormMgrService::HiDumpStaticBundleFormInfos;
    dumpFuncMap_[DumpKey::KEY_DUMP_STORAGE] = &FormMgrService::HiDumpStorageFormInfos;
    dumpFuncMap_[DumpKey::KEY_DUMP_VISIBLE] = &FormMgrService::HiDumpHasFormVisible;
    dumpFuncMap_[DumpKey::KEY_DUMP_TEMPORARY] = &FormMgrService::HiDumpTemporaryFormInfos;
    dumpFuncMap_[DumpKey::KEY_DUMP_BY_BUNDLE_NAME] = &FormMgrService::HiDumpFormInfoByBundleName;
    dumpFuncMap_[DumpKey::KEY_DUMP_BY_FORM_ID] = &FormMgrService::HiDumpFormInfoByFormId;
    dumpFuncMap_[DumpKey::KEY_DUMP_RUNNING] = &FormMgrService::HiDumpFormRunningFormInfos;
    dumpFuncMap_[DumpKey::KEY_DUMP_BLOCKED_APPS] = &FormMgrService::HiDumpFormBlockedApps;
}


int FormMgrService::Dump(int fd, const std::vector<std::u16string> &args)
{
    if (!CheckFMSReady()) {
        HILOG_ERROR("fms is not ready.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::string result;
    Dump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        HILOG_ERROR("format dprintf error.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

void FormMgrService::Dump(const std::vector<std::u16string> &args, std::string &result)
{
    DumpKey key;
    std::string value;
    if (!ParseOption(args, key, value, result)) {
        result.append('\n' + FORM_DUMP_HELP);
        return;
    }

    auto iter = dumpFuncMap_.find(key);
    if (iter == dumpFuncMap_.end() || iter->second == nullptr) {
        result = "error: unknow function.";
        return;
    }

    auto dumpFunc = iter->second;
    (this->*dumpFunc)(value, result);
}

int32_t FormMgrService::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("called.");
    sptr<IBundleMgr> bundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOG_ERROR("error to get bundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    // check if system app
    auto callingUid = IPCSkeleton::GetCallingUid();
    auto isSystemApp = bundleMgr->CheckIsSystemAppByUid(callingUid);
    if (!isSystemApp) {
        HILOG_ERROR("no permission.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().RegisterPublishFormInterceptor(interceptorCallback);
}

int32_t FormMgrService::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("called.");
    sptr<IBundleMgr> bundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOG_ERROR("failed to get bundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    // check if system app
    auto callingUid = IPCSkeleton::GetCallingUid();
    auto isSystemApp = bundleMgr->CheckIsSystemAppByUid(callingUid);
    if (!isSystemApp) {
        HILOG_ERROR("permission denied.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    return FormMgrAdapter::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
}

void FormMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
#ifdef RES_SCHEDULE_ENABLE
    if (systemAbilityId == RES_SCHED_SYS_ABILITY_ID) {
        auto formSystemloadLevelCb = std::bind(&FormMgrService::OnSystemloadLevel, this, std::placeholders::_1);
        sptr<FormSystemloadListener> formSystemloadListener
            = new (std::nothrow) FormSystemloadListener(formSystemloadLevelCb);
        ResourceSchedule::ResSchedClient::GetInstance().RegisterSystemloadNotifier(formSystemloadListener);
        HILOG_INFO("RegisterSystemloadNotifier for Systemloadlevel change");
        return;
    }
#endif // RES_SCHEDULE_ENABLE

    if (systemAbilityId == MEMORY_MANAGER_SA_ID) {
        HILOG_INFO("MEMORY_MANAGER_SA start, SubscribeAppState");
        Memory::MemMgrClient::GetInstance().SubscribeAppState(*memStatusListener_);
        return;
    }
    if (systemAbilityId != DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        return;
    }
    onKvDataServiceAddTime_ = GetCurrentDateTime();
    FormDataProxyMgr::GetInstance().RetryFailureSubscribes();
    HILOG_INFO("FMS KV data service add time: %{public}s", onKvDataServiceAddTime_.c_str());
}

bool FormMgrService::ParseOption(const std::vector<std::u16string> &args, DumpKey &key, std::string &value,
    std::string &result)
{
    auto size = args.size();
    if (size == 0) {
        result = "error: must contain arguments.";
        return false;
    }

    if (size > FORM_DUMP_ARGC_MAX) {
        result = "error: arguments numer out of limit.";
        return false;
    }

    std::string optionKey = Str16ToStr8(args[0]);
    auto iter = dumpKeyMap_.find(optionKey);
    if (iter == dumpKeyMap_.end()) {
        result = "error: unknown option.";
        return false;
    }

    key = iter->second;

    if (args.size() == FORM_DUMP_ARGC_MAX) {
        value = Str16ToStr8(args[1]);
    }

    return true;
}

void FormMgrService::HiDumpFormRunningFormInfos([[maybe_unused]]const std::string &args, std::string &result)
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return;
    }
    FormMgrAdapter::GetInstance().DumpFormRunningFormInfos(result);
}

void FormMgrService::HiDumpHelp([[maybe_unused]] const std::string &args, std::string &result)
{
    result = FORM_DUMP_HELP;
}

void FormMgrService::HiDumpStorageFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    DumpStorageFormInfos(result);
}

void FormMgrService::HiDumpTemporaryFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    if (!CheckCallerIsSystemApp()) {
        return;
    }
    FormMgrAdapter::GetInstance().DumpTemporaryFormInfos(result);
}

void FormMgrService::HiDumpStaticBundleFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    if (!CheckCallerIsSystemApp()) {
        return;
    }
    FormMgrAdapter::GetInstance().DumpStaticBundleFormInfos(result);
}

void FormMgrService::HiDumpFormInfoByBundleName(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a bundle name.";
        return;
    }
    DumpFormInfoByBundleName(args, result);
}

void FormMgrService::HiDumpHasFormVisible(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error:request bundle info like bundleName_userId_instIndex.";
    }
    FormMgrAdapter::GetInstance().DumpHasFormVisible(args, result);
}

void FormMgrService::HiDumpFormBlockedApps([[maybe_unused]] const std::string &args, std::string &result)
{
    if (!CheckCallerIsSystemApp()) {
        return;
    }
    FormTrustMgr::GetInstance().GetUntrustAppNameList(result);
}

void FormMgrService::HiDumpFormInfoByFormId(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a form ID.";
        return;
    }
    int64_t formId = atoll(args.c_str());
    if (formId == 0) {
        result = "error: form ID is invalid.";
        return;
    }
    DumpFormInfoByFormId(formId, result);
}

bool FormMgrService::CheckCallerIsSystemApp() const
{
    auto callerTokenID = IPCSkeleton::GetCallingFullTokenID();
    if (!FormUtil::IsSACall() && !Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(callerTokenID)) {
        HILOG_ERROR("The caller is not system-app, can not use system-api");
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
    // checks whether the current user is inactive
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = callingUid / GET_CALLING_UID_TRANSFORM_DIVISOR;
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    if (userId != currentActiveUserId) {
        HILOG_DEBUG("currentActiveUserId: %{public}d, userId: %{public}d", currentActiveUserId, userId);
        bool isCallingPermAccount =
            FormUtil::VerifyCallingPermission(AppExecFwk::Constants::PERMISSION_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        if (!isCallingPermAccount) {
            HILOG_ERROR("Across local accounts permission failed.");
            return false;
        }
    }
    return true;
}

ErrCode FormMgrService::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, register form add observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrService::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, register form remove observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);
}

int32_t FormMgrService::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_DEBUG("called.");
    return FormMgrAdapter::GetInstance().GetFormsCount(isTempFormFlag, formCount);
}

int32_t FormMgrService::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_DEBUG("called.");
    return FormMgrAdapter::GetInstance().GetHostFormsCount(bundleName, formCount);
}

ErrCode FormMgrService::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get running form infos permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrService::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get running form infos by bundle name permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().GetRunningFormInfosByBundleName(
        bundleName, isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrService::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get form instances by filter permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgrService::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get form instance by id permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgrService::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, get form instance by id permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgrService::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, register notifyVisible or notifyInVisible observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
}

ErrCode FormMgrService::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, unregister notifyVisible or notifyInVisible observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
}

ErrCode FormMgrService::UpdateProxyForm(int64_t formId, const FormProviderData &formBindingData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("called.");
    auto callingUid = IPCSkeleton::GetCallingUid();
    return FormMgrAdapter::GetInstance().UpdateForm(formId, callingUid, formBindingData, formDataProxies);
}

ErrCode FormMgrService::RequestPublishProxyForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("called.");
    if (!CheckCallerIsSystemApp()) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return FormMgrAdapter::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId,
        formDataProxies);
}

ErrCode FormMgrService::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Called.");
    if (observer == nullptr) {
        HILOG_ERROR("Caller token parameter is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("Fail, register form add observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RegisterClickEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgrService::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Called.");
    if (observer == nullptr) {
        HILOG_ERROR("Caller token parameter is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    ErrCode ret = CheckFormPermission(AppExecFwk::Constants::PERMISSION_OBSERVE_FORM_RUNNING);
    if (ret != ERR_OK) {
        HILOG_ERROR("Fail, register form add observer permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, observer);
}

int32_t FormMgrService::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("set forms recyclable permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().SetFormsRecyclable(formIds);
}

int32_t FormMgrService::RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("recycle forms permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RecycleForms(formIds, want);
}

int32_t FormMgrService::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("recover forms permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().RecoverForms(formIds, want);
}

ErrCode FormMgrService::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    HILOG_DEBUG("called.");
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("fail, update formLocation form infos permission denied");
        return ret;
    }
    return FormMgrAdapter::GetInstance().UpdateFormLocation(formId, formLocation);
}

ErrCode FormMgrService::RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    HILOG_INFO("FMS RequestPublishFormWithSnapshot called, startTime: begin: %{public}s, publish: %{public}s,\
        end:  %{public}s, onKvDataServiceAddTime: %{public}s", onStartBeginTime_.c_str(), onStartPublishTime_.c_str(),
        onStartEndTime_.c_str(), onKvDataServiceAddTime_.c_str());

    return FormMgrAdapter::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData,
                                                            formId, {}, false);
}
#ifdef RES_SCHEDULE_ENABLE
void FormMgrService::OnSystemloadLevel(int32_t level)
{
    if (level >= SYSTEMLOADLEVEL_TIMERSTOP_THRESHOLD) {
        FormMgrAdapter::GetInstance().SetTimerTaskNeeded(false);
    } else {
        FormMgrAdapter::GetInstance().SetTimerTaskNeeded(true);
    }
}
#endif // RES_SCHEDULE_ENABLE
}  // namespace AppExecFwk
}  // namespace OHOS
