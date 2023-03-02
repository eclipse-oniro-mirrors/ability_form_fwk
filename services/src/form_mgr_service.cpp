/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "common_event_manager.h"
#include "common_event_support.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_db_cache.h"
#include "form_event_handler.h"
#include "form_info_mgr.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_share_mgr.h"
#include "form_task_mgr.h"
#include "form_timer_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "permission_verification.h"
#include "system_ability_definition.h"
#include "event_report.h"
#include "hisysevent.h"
#include "xcollie/watchdog.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAIN_USER_ID = 100;
}
using namespace std::chrono;

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<FormMgrService>::GetInstance().get());

const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

constexpr int32_t FORM_DUMP_ARGC_MAX = 2;

const std::string FORM_DUMP_HELP = "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -s, --storage                            query form storage info\n"
    "  -n  <bundle-name>                        query form info by a bundle name\n"
    "  -i  <form-id>                            query form info by a form ID\n";

const std::map<std::string, FormMgrService::DumpKey> FormMgrService::dumpKeyMap_ = {
    {"-h", FormMgrService::DumpKey::KEY_DUMP_HELP},
    {"--help", FormMgrService::DumpKey::KEY_DUMP_HELP},
    {"-s", FormMgrService::DumpKey::KEY_DUMP_STORAGE},
    {"--storage", FormMgrService::DumpKey::KEY_DUMP_STORAGE},
    {"-n", FormMgrService::DumpKey::KEY_DUMP_BY_BUNDLE_NAME},
    {"-i", FormMgrService::DumpKey::KEY_DUMP_BY_FORM_ID},
};

FormMgrService::FormMgrService()
    : SystemAbility(FORM_MGR_SERVICE_ID, true),
      state_(ServiceRunningState::STATE_NOT_START),
      runner_(nullptr),
      handler_(nullptr)
{
    DumpInit();
}

FormMgrService::~FormMgrService()
{
    if (formSysEventReceiver_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(formSysEventReceiver_);
        formSysEventReceiver_ = nullptr;
        sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
        if (iBundleMgr == nullptr) {
            return;
        }
        if (!iBundleMgr->UnregisterBundleEventCallback(formBundleEventCallback_)) {
            HILOG_ERROR("%{public}s fail, UnregisterBundleEventCallback failed", __func__);
        }
        formBundleEventCallback_ = nullptr;
    }
}

bool FormMgrService::IsReady() const
{
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return false;
    }
    if (!handler_) {
        HILOG_ERROR("%{public}s fail, handler is null", __func__);
        return false;
    }
    int32_t userId = FormUtil::GetCurrentAccountId();
    if (userId == Constants::ANY_USERID) {
        HILOG_ERROR("%{public}s fail, account is empty", __func__);
        return false;
    }
    return true;
}

/**
* @brief Check form manager service ready.
* @return Return true if form manager service Ready; return false otherwise.
*/

bool FormMgrService::CheckFMSReady()
{
    return IsReady();
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
    ErrCode ret = CheckFormPermission();
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::ADD_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, add form permission denied", __func__);
        return ret;
    }
    return FormMgrAdapter::GetInstance().AddForm(formId, want, callerToken, formInfo);
}

/**
 * @brief Delete forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to delete.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, delete form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::DELETE_FORM, HiSysEventType::BEHAVIOR, eventInfo);

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
        HILOG_ERROR("%{public}s fail, delete form permission denied", __func__);
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
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, release form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::RELEASE_FORM, HiSysEventType::BEHAVIOR, eventInfo);

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
    std::string callerBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, get caller bundle name failed", __func__);
        return ret;
    }
    return FormMgrAdapter::GetInstance().UpdateForm(formId, callerBundleName, formBindingData);
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
    HILOG_INFO("%{public}s called.", __func__);

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::REQUEST_FORM, HiSysEventType::BEHAVIOR, eventInfo);

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
    HILOG_INFO("%{public}s called.", __func__);
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    AAFwk::EventReport::SendFormEvent(
        AAFwk::EventName::SET_NEXT_REFRESH_TIME_FORM, HiSysEventType::BEHAVIOR, eventInfo);

    return FormMgrAdapter::GetInstance().SetNextRefreshTime(formId, nextTime);
}

ErrCode FormMgrService::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    HILOG_INFO("%{public}s called.", __func__);

    return FormMgrAdapter::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId);
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
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, event notify visible permission denied", __func__);
        return ret;
    }

    return FormMgrAdapter::GetInstance().NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
}

/**
 * @brief temp form to normal form.
 * @param formId The Id of the form.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrService::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, cast temp form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::CASTTEMP_FORM, HiSysEventType::BEHAVIOR, eventInfo);

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
    HILOG_INFO("lifecycleUpdate.");

    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, delete form permission denied", __func__);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::MESSAGE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::ROUTE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, request form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.userId = formId;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::BACKGROUND_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().BackgroundEvent(formId, want, callerToken);
}

/**
 * @brief Start event for the form manager service.
 */
void FormMgrService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        HILOG_WARN("%{public}s fail, Failed to start service since it's already running", __func__);
        return;
    }

    HILOG_INFO("Form Mgr Service start...");
    ErrCode errCode = Init();
    if (errCode != ERR_OK) {
        HILOG_ERROR("%{public}s fail, Failed to init, errCode: %{public}08x", __func__, errCode);
        return;
    }

    state_ = ServiceRunningState::STATE_RUNNING;
    HILOG_INFO("Form Mgr Service start success.");
}
/**
 * @brief Stop event for the form manager service.
 */
void FormMgrService::OnStop()
{
    HILOG_INFO("stop service");

    state_ = ServiceRunningState::STATE_NOT_START;

    if (handler_) {
        handler_.reset();
    }

    if (runner_) {
        runner_.reset();
    }
}
/**
 * @brief initialization of form manager service.
 */
ErrCode FormMgrService::Init()
{
    HILOG_INFO("FormMgrService Init start");
    runner_ = EventRunner::Create(NAME_FORM_MGR_SERVICE);
    if (runner_ == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to init due to create runner error", __func__);
        return ERR_INVALID_OPERATION;
    }
    handler_ = std::make_shared<FormEventHandler>(runner_);
    if (handler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to init due to create handler error", __func__);
        return ERR_INVALID_OPERATION;
    }
    FormTaskMgr::GetInstance().SetEventHandler(handler_);
    FormAmsHelper::GetInstance().SetEventHandler(handler_);
    /* Publish service maybe failed, so we need call this function at the last,
     * so it can't affect the TDD test program */
    bool ret = Publish(DelayedSingleton<FormMgrService>::GetInstance().get());
    if (!ret) {
        HILOG_ERROR("%{public}s fail, FormMgrService::Init Publish failed!", __func__);
        return ERR_INVALID_OPERATION;
    }

    std::string threadName = NAME_FORM_MGR_SERVICE + "(" + std::to_string(runner_->GetThreadId()) + ")";
    if (HiviewDFX::Watchdog::GetInstance().AddThread(threadName, handler_) != 0) {
        HILOG_ERROR("HiviewDFX::Watchdog::GetInstance AddThread Fail");
    }

    if (formSysEventReceiver_ == nullptr) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
        // init TimerReceiver
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        formSysEventReceiver_ = std::make_shared<FormSysEventReceiver>(subscribeInfo);
        formSysEventReceiver_->SetEventHandler(handler_);
        EventFwk::CommonEventManager::SubscribeCommonEvent(formSysEventReceiver_);
    }
    FormInfoMgr::GetInstance().Start();
    FormInfoMgr::GetInstance().ReloadFormInfos(MAIN_USER_ID);
    FormDbCache::GetInstance().Start();
    FormTimerMgr::GetInstance(); // Init FormTimerMgr
    // Register formbundleEventCallback to receive hap updates
    formBundleEventCallback_ = new (std::nothrow) FormBundleEventCallback(handler_);
    if (formBundleEventCallback_ == nullptr) {
        HILOG_ERROR("%{public}s fail, allocate formBundleEventCallback_ failed!", __func__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    bool re = iBundleMgr->RegisterBundleEventCallback(formBundleEventCallback_);
    if (!re) {
        HILOG_ERROR("%{public}s fail, RegisterBundleEventCallback failed!", __func__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_INFO("init success");
    return ERR_OK;
}

ErrCode FormMgrService::CheckFormPermission()
{
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (isSaCall) {
        return ERR_OK;
    }

    // get IBundleMgr
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s error, failed to get IBundleMgr.", __func__);
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    // check if system app
    auto isSystemApp = iBundleMgr->CheckIsSystemAppByUid(IPCSkeleton::GetCallingUid());
    if (!isSystemApp) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }

    auto isCallingPerm = AAFwk::PermissionVerification::GetInstance()->VerifyCallingPermission(
        AppExecFwk::Constants::PERMISSION_REQUIRE_FORM);
    if (!isCallingPerm) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    HILOG_ERROR("Permission verification ok!");
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, delete form permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::DELETE_INVALID_FORM, HiSysEventType::BEHAVIOR, eventInfo);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, acquire form state permission denied", __func__);
        return ret;
    }
    AAFwk::EventInfo eventInfo;
    eventInfo.bundleName = want.GetElement().GetBundleName();
    eventInfo.moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    eventInfo.abilityName = want.GetElement().GetAbilityName();
    AAFwk::EventReport::SendFormEvent(AAFwk::EventName::ACQUIREFORMSTATE_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    return FormMgrAdapter::GetInstance().AcquireFormState(want, callerToken, stateInfo);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, notify form visible permission denied", __func__);
        return ret;
    }
    return FormMgrAdapter::GetInstance().NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrService::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, notify form is privacy protected permission denied", __func__);
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
    HILOG_INFO("%{public}s called.", __func__);
    ErrCode ret = CheckFormPermission();
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, notify form enable update permission denied", __func__);
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
    HILOG_INFO("%{public}s called.", __func__);
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
    HILOG_INFO("%{public}s called.", __func__);
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
    HILOG_INFO("%{public}s called.", __func__);
    return FormMgrAdapter::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

int32_t FormMgrService::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::string callerBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(callerBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("%{public}s fail, get host bundle name failed", __func__);
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

bool FormMgrService::IsRequestPublishFormSupported()
{
    HILOG_INFO("%{public}s called.", __func__);
    // get IBundleMgr
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s error, failed to get IBundleMgr.", __func__);
        return false;
    }
    // check if system app
    auto isSystemApp = iBundleMgr->CheckIsSystemAppByUid(IPCSkeleton::GetCallingUid());
    if (!isSystemApp) {
        return false;
    }
    return FormMgrAdapter::GetInstance().IsRequestPublishFormSupported();
}

int32_t FormMgrService::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s called.", __func__);
    sptr<IBundleMgr> bundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOG_ERROR("%{public}s error, failed to get bundleMgr.", __func__);
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    // check if system app
    auto callingUid = IPCSkeleton::GetCallingUid();
    auto isSystemApp = bundleMgr->CheckIsSystemAppByUid(callingUid);
    if (!isSystemApp) {
        HILOG_ERROR("%{public}s error, permission denied.", __func__);
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    // retrieve bundleName of the calling ability.
    std::string callerBundleName;
    if (!IN_PROCESS_CALL(bundleMgr->GetBundleNameForUid(callingUid, callerBundleName))) {
        HILOG_ERROR("StartAbility, failed to get form config info.");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    // caller and callee should be in the same bundle.
    if (want.GetElement().GetBundleName() != callerBundleName) {
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }
    // check abilityName to void implicit want.
    if (want.GetElement().GetAbilityName() == "") {
        HILOG_ERROR("%{public}s error, AbilityName is empty", __func__);
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }
    sptr<AAFwk::IAbilityManager> ams = FormAmsHelper::GetInstance().GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("%{public}s error, failed to get ams.", __func__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ams->StartAbility(want, callerToken, -1, -1);
}

void FormMgrService::InitFormShareMgrEventHandler()
{
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

    InitFormShareMgrEventHandler();

    return DelayedSingleton<FormShareMgr>::GetInstance()->ShareForm(formId, deviceId, callerToken, requestCode);
}

int32_t FormMgrService::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    InitFormShareMgrEventHandler();

    return DelayedSingleton<FormShareMgr>::GetInstance()->RecvFormShareInfoFromRemote(info);
}

void FormMgrService::DumpInit()
{
    dumpFuncMap_[DumpKey::KEY_DUMP_HELP] = &FormMgrService::HiDumpHelp;
    dumpFuncMap_[DumpKey::KEY_DUMP_STORAGE] = &FormMgrService::HiDumpStorageFormInfos;
    dumpFuncMap_[DumpKey::KEY_DUMP_BY_BUNDLE_NAME] = &FormMgrService::HiDumpFormInfoByBundleName;
    dumpFuncMap_[DumpKey::KEY_DUMP_BY_FORM_ID] = &FormMgrService::HiDumpFormInfoByFormId;
}

int FormMgrService::Dump(int fd, const std::vector<std::u16string> &args)
{
    if (!IsReady()) {
        HILOG_ERROR("%{public}s, fms is not ready.", __func__);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::string result;
    Dump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        HILOG_ERROR("%{public}s, dprintf error.", __func__);
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
        result = "error: unkown option.";
        return false;
    }

    key = iter->second;

    if (args.size() == FORM_DUMP_ARGC_MAX) {
        value = Str16ToStr8(args[1]);
    }

    return true;
}

void FormMgrService::HiDumpHelp([[maybe_unused]] const std::string &args, std::string &result)
{
    result = FORM_DUMP_HELP;
}

void FormMgrService::HiDumpStorageFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    DumpStorageFormInfos(result);
}

void FormMgrService::HiDumpFormInfoByBundleName(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a bundle name.";
        return;
    }
    DumpFormInfoByBundleName(args, result);
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
}  // namespace AppExecFwk
}  // namespace OHOS