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

#include "form_mgr/form_publish_adapter.h"

#include "app_mgr_interface.h"
#include "app_state_data.h"
#include "form_ecological_rule_param.h"
#include "form_info.h"
#include "form_provider_data.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "want.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/ecological_rule/form_ecological_rule_service.h"
#include "form_constants.h"
#include "form_event_report.h"
#include "form_mgr/form_callback_adapter.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider/form_provider_mgr.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char *FORM_SUPPORT_ECOLOGICAL_RULEMGRSERVICE = "persist.sys.fms.support.ecologicalrulemgrservice";
constexpr int ADD_FORM_REQUEST_TIMTOUT_PERIOD = 3000;
constexpr const char *FORM_ADD_FORM_TIMER_TASK_QUEUE = "FormMgrTimerTaskQueue";
enum class AddFormTaskType : int64_t {
    ADD_FORM_TIMER,
};
} // namespace

FormPublishAdapter::FormPublishAdapter(
    FormDataMgr* formDataMgr,
    FormInfoMgr* formInfoMgr,
    FormCommonAdapter* commonAdapter,
    FormCallbackAdapter* callbackAdapter)
    : formDataMgr_(formDataMgr),
      formInfoMgr_(formInfoMgr),
      commonAdapter_(commonAdapter),
      callbackAdapter_(callbackAdapter)
{
    serialQueue_ = std::make_unique<FormSerialQueue>(FORM_ADD_FORM_TIMER_TASK_QUEUE);
}

ErrCode FormPublishAdapter::CheckFormBundleName(Want &want, std::string &bundleName,
    bool needCheckFormPermission)
{
    if (!GetBundleName(bundleName, needCheckFormPermission)) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (!needCheckFormPermission && bundleName != want.GetBundle()) {
        HILOG_ERROR("not self bundle");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}

bool FormPublishAdapter::GetBundleName(std::string &bundleName, bool needCheckFormPermission)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return false;
    }

    int uid = IPCSkeleton::GetCallingUid();
    if (needCheckFormPermission && !IN_PROCESS_CALL(iBundleMgr->CheckIsSystemAppByUid(uid))) {
        HILOG_ERROR("form not systemApp.uid:%{public}d", uid);
        return false;
    }

    int32_t result = IN_PROCESS_CALL(iBundleMgr->GetNameForUid(uid, bundleName));
    if (result != ERR_OK || bundleName.empty()) {
        HILOG_ERROR("not get bundleName by uid:%{public}d", uid);
        return false;
    }
    return true;
}

bool FormPublishAdapter::CheckIsSystemAppByBundleName(const sptr<IBundleMgr> &iBundleMgr,
    const int32_t &userId, const std::string &bundleName)
{
    AppExecFwk::ApplicationInfo appInfo;
    if (IN_PROCESS_CALL(iBundleMgr->GetApplicationInfoV9(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
        userId, appInfo)) != ERR_OK) {
        HILOG_ERROR("get ApplicationInfo failed");
        return false;
    }

    HILOG_DEBUG("bundle:%{public}s. isSystemApp=%{public}d", bundleName.c_str(), appInfo.isSystemApp);
    return appInfo.isSystemApp;
}

bool FormPublishAdapter::IsValidPublishEvent(const sptr<IBundleMgr> &iBundleMgr,
    const std::string &bundleName, const Want &want, bool needCheckFormPermission)
{
    int32_t userId = commonAdapter_->GetCallingUserId();
    if (needCheckFormPermission && !CheckIsSystemAppByBundleName(iBundleMgr, userId, bundleName)) {
        HILOG_ERROR("Only system app can request publish form");
        return false;
    }
    std::vector<Want> wants{want};
    return IsErmsSupportPublishForm(bundleName, wants);
}

bool FormPublishAdapter::IsErmsSupportPublishForm(std::string bundleName, std::vector<Want> wants)
{
    bool isSupport = true;
    std::string supportErms = OHOS::system::GetParameter(FORM_SUPPORT_ECOLOGICAL_RULEMGRSERVICE, "true");
    if (supportErms == "false") {
        HILOG_ERROR("fms not support Erms between applications");
        return true;
    }
    FormErmsCallerInfo callerInfo;
    callerInfo.packageName = bundleName;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingPid();
    callerInfo.callerAppType = GetCallerType(bundleName);

    int32_t ret = FormEcologicalRuleClient::GetInstance().IsSupportPublishForm(wants, callerInfo, isSupport);
    if (ret != ERR_OK) {
        HILOG_ERROR("call IsSupportPublishForm failed:%{public}d, default is support.", ret);
        return true;
    }
    return isSupport;
}

int32_t FormPublishAdapter::GetCallerType(std::string bundleName)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    AppExecFwk::ApplicationInfo callerAppInfo;
    auto flag = AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO;
    int32_t userId = commonAdapter_->GetCallingUserId();
    bool getCallerResult = IN_PROCESS_CALL(iBundleMgr->GetApplicationInfo(bundleName, flag, userId, callerAppInfo));
    if (!getCallerResult) {
        HILOG_ERROR("Get callerAppInfo failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    switch (callerAppInfo.bundleType) {
        case AppExecFwk::BundleType::ATOMIC_SERVICE:
            return FormErmsCallerInfo::TYPE_ATOM_SERVICE;
        case AppExecFwk::BundleType::APP:
            return FormErmsCallerInfo::TYPE_HARMONY_APP;
        default:
            HILOG_WARN("the caller type is not harmony app or atom service:%{public}d", callerAppInfo.bundleType);
            break;
    }
    return FormErmsCallerInfo::TYPE_INVALID;
}

bool FormPublishAdapter::IsActionAllowToPublish(const std::string &action)
{
    const std::vector<std::string> actionAllowList = {
        Constants::FORM_PUBLISH_ACTION,
        Constants::FORM_PAGE_ACTION
    };

    for (const auto &item : actionAllowList) {
        if (item.compare(action) == 0) {
            return true;
        }
    }

    return false;
}

bool FormPublishAdapter::CheckSnapshotWant(const Want &want)
{
    if (want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY)) {
        std::string snapshot = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY);
        std::string width = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY);
        std::string height = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY);
        std::string screenX = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY);
        std::string screenY = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY);
        HILOG_INFO("SnapshotInfo screenX:%{public}s, screenY:%{public}s, width:%{public}s, height:%{public}s",
            screenX.c_str(), screenY.c_str(), width.c_str(), height.c_str());
        return true;
    } else {
        HILOG_DEBUG("CheckSnapshotWant: want has no component snapshot info");
        return false;
    }
}

ErrCode FormPublishAdapter::CheckPublishForm(Want &want, bool needCheckFormPermission)
{
    std::string bundleName;
    ErrCode errCode = CheckFormBundleName(want, bundleName, needCheckFormPermission);
    if (errCode != ERR_OK) {
        return errCode;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (needCheckFormPermission && !IsValidPublishEvent(iBundleMgr, bundleName, want)) {
        HILOG_ERROR("Check valid publish event failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }

    if (want.GetElement().GetBundleName().empty()) {
        HILOG_WARN("emptybundleName.set to currentCallingBundle");
        want.SetBundle(bundleName);
    }

    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (moduleName.empty()) {
        HILOG_ERROR("empty moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    bool isTemporary = want.GetBoolParam(AppExecFwk::Constants::PARAM_FORM_TEMPORARY_KEY, false);
    if (isTemporary) {
        HILOG_WARN("The published form should not be temp");
        want.SetParam(AppExecFwk::Constants::PARAM_FORM_TEMPORARY_KEY, false);
    }

    std::string abilityName = want.GetElement().GetAbilityName();
    std::string formName = want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY);
    std::vector<FormInfo> formInfos {};
    errCode = formInfoMgr_->GetFormsInfoByModuleWithoutCheck(want.GetElement().GetBundleName(), moduleName, formInfos);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get forms info");
        return errCode;
    }
    for (auto &formInfo: formInfos) {
        int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
        if ((formInfo.abilityName == abilityName) && (formInfo.name == formName) &&
            (commonAdapter_->IsDimensionValid(formInfo, dimensionId))) {
            want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
            return ERR_OK;
        }
    }
    HILOG_ERROR("fail find match form info");
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormPublishAdapter::QueryPublishFormToHost(Want &wantToHost)
{
    AppExecFwk::AbilityInfo formAbilityInfo;
    AppExecFwk::ExtensionAbilityInfo formExtensionAbilityInfo;

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);

    std::string action = Constants::FORM_PUBLISH_ACTION;
    if (!wantToHost.GetAction().empty()) {
        action = wantToHost.GetAction();
        HILOG_INFO("GetAction:%{public}s", action.c_str());
        if (!IsActionAllowToPublish(action)) {
            HILOG_ERROR("action is not allowed for publishing form");
            return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
        }
    }

    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        action, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("fail ImplicitQueryInfoByPriority for publishing form");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("Query highest priority ability failed, no form host ability found");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    if (!abilityInfo.name.empty()) {
        HILOG_DEBUG("Query highest priority ability success. bundleName:%{public}s, ability:%{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        wantToHost.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    } else {
        HILOG_DEBUG("Query highest priority extension ability success. bundleName:%{public}s, ability:%{public}s",
            extensionAbilityInfo.bundleName.c_str(), extensionAbilityInfo.name.c_str());
        wantToHost.SetElementName(extensionAbilityInfo.bundleName, extensionAbilityInfo.name);
    }
    return ERR_OK;
}

void FormPublishAdapter::IncreaseAddFormRequestTimeOutTask(const int64_t formId)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
    auto timerTask = [this, formId]() {
        std::lock_guard<std::mutex> lock(formResultMutex_);
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            iter->second = AddFormResultErrorCodes::TIMEOUT;
            condition_.notify_all();
        }
        serialQueue_->CancelDelayTask(std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId));
    };
    serialQueue_->ScheduleDelayTask(std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId),
        ADD_FORM_REQUEST_TIMTOUT_PERIOD, timerTask);
}

void FormPublishAdapter::CancelAddFormRequestTimeOutTask(const int64_t formId, const int result)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
    serialQueue_->CancelDelayTask(std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId));
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto iter = formIdMap_.find(formId);
    if (iter != formIdMap_.end()) {
        const auto state = (result != ERR_OK ? AddFormResultErrorCodes::FAILED : AddFormResultErrorCodes::SUCCESS);
        iter->second = state;
        condition_.notify_all();
    }
}

ErrCode FormPublishAdapter::AcquireAddFormResult(const int64_t formId)
{
    HILOG_INFO("call");
    auto apiRet = std::make_shared<ErrCode>(ERR_OK);
    std::unique_lock<std::mutex> lock(formResultMutex_);
    condition_.wait(lock, [this, formId, ret = apiRet]() {
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            if (iter->second == AddFormResultErrorCodes::SUCCESS) {
                HILOG_INFO("Acquire the result of the success");
                *ret = ERR_OK;
                return true;
            } else if (iter->second == AddFormResultErrorCodes::FAILED) {
                HILOG_ERROR("Acquire the result of the failed");
                *ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
                return true;
            } else if (iter->second == AddFormResultErrorCodes::TIMEOUT) {
                HILOG_ERROR("Acquire the result of the timeout");
                *ret = ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT;
                return true;
            } else {
                HILOG_INFO("Add form result state is unknown");
                return true;
            }
        }
        HILOG_ERROR("The formid hasn't find");
        *ret = ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        return true;
    });
    return *apiRet;
}

ErrCode FormPublishAdapter::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    std::pair<int64_t, int64_t> eventMsg(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId);
    serialQueue_->CancelDelayTask(eventMsg);
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto iter = formIdMap_.find(formId);
    if (iter != formIdMap_.end()) {
        if (errorCodeInfo.code == Constants::PublishFormErrorCode::SUCCESS) {
            iter->second = AddFormResultErrorCodes::SUCCESS;
            errorCodeInfo.message = "set add form success, PublishFormErrorCode is success";
        } else {
            iter->second = AddFormResultErrorCodes::FAILED;
            errorCodeInfo.message = "set add form fail, PublishFormErrorCode is not success";
        }
        condition_.notify_all();
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}

bool FormPublishAdapter::IsRequestPublishFormSupported()
{
    HILOG_DEBUG("call");
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);

    std::string action = Constants::FORM_PUBLISH_ACTION;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        action, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("fail ImplicitQueryInfoByPriority for publishing form");
        return false;
    }

    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("Query highest priority ability failed, no form host ability found");
        return false;
    }

    HILOG_DEBUG("IsRequestPublishFormSupported: true");
    return true;
}

ErrCode FormPublishAdapter::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    HILOG_DEBUG("call");
    ErrCode errCode = CheckPublishForm(want, needCheckFormPermission);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t userId = commonAdapter_->GetCallingUserId();
    want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    want.SetAction(Constants::FORM_PUBLISH_ACTION);

    // generate formId
    formId = formDataMgr_->GenerateFormId();
    if (formId < 0) {
        HILOG_ERROR("generateFormId no invalid formId");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    {
        std::lock_guard<std::mutex> lock(formResultMutex_);
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            iter->second = AddFormResultErrorCodes::UNKNOWN;
        } else {
            formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCodes::UNKNOWN));
        }
    }
    HILOG_DEBUG("formId:%{public}" PRId64 "", formId);
    std::string strFormId = std::to_string(formId);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, strFormId);

    if (withFormBindingData) {
        errCode = formDataMgr_->AddRequestPublishFormInfo(formId, want, formBindingData);
    } else {
        std::unique_ptr<FormProviderData> noFormBindingData = nullptr;
        errCode = formDataMgr_->AddRequestPublishFormInfo(formId, want, noFormBindingData);
    }
    if (errCode != ERR_OK) {
        HILOG_ERROR("add form info error");
        return errCode;
    }
    errCode = RequestPublishFormToHost(want);
    if (errCode != ERR_OK) {
        formDataMgr_->RemoveRequestPublishFormInfo(formId);
        NewFormEventInfo eventInfo;
        FormEventReport::SendFourthFormEvent(FormEventName::INVALID_PUBLISH_FORM_TO_HOST,
            HiSysEventType::STATISTIC, eventInfo, want);
    }

    IncreaseAddFormRequestTimeOutTask(formId);
    if (!formDataProxies.empty()) {
        FormDataProxyMgr::GetInstance().ProduceFormDataProxies(formId, formDataProxies);
    }
    return errCode;
}

ErrCode FormPublishAdapter::RequestPublishFormToHost(Want &want)
{
    Want wantToHost(want);
    ElementName elementName = want.GetElement();
    wantToHost.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, elementName.GetBundleName());
    wantToHost.SetParam(Constants::PARAM_ABILITY_NAME_KEY, elementName.GetAbilityName());
    std::string bundleName = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_BUNDLE_KEY);
    std::string abilityName = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_ABILITY_KEY);
    wantToHost.SetElementName(bundleName, abilityName);
    wantToHost.SetAction(Constants::FORM_PUBLISH_ACTION);
    CheckSnapshotWant(wantToHost);

    ErrCode errCode = QueryPublishFormToHost(wantToHost);
    if (errCode == ERR_OK) {
        int32_t userId = want.GetIntParam(Constants::PARAM_FORM_USER_ID, -1);
        int ret = FormAmsHelper::GetInstance().StartAbility(wantToHost, userId);
        if (ret != ERR_OK) {
            HILOG_ERROR("fail StartAbility");
            return ret;
        }
    }

    // Handle by interceptor callback when the system handler is not found.
    int64_t formId = 0;
    if (!FormUtil::ConvertStringToInt64(want.GetStringParam(Constants::PARAM_FORM_IDENTITY_KEY), formId)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IFormPublishInterceptor> interceptor = callbackAdapter_->GetFormPublishInterceptor();
    if (interceptor == nullptr) {
        return AcquireAddFormResult(formId);
    }

    int ret = interceptor->ProcessPublishForm(wantToHost);
    if (ret == ERR_OK) {
        HILOG_DEBUG("success to ProcessPublishForm");
        return AcquireAddFormResult(formId);
    } else {
        HILOG_ERROR("fail ProcessPublishForm");
    }
    return ret;
}

ErrCode FormPublishAdapter::CheckAddFormTaskTimeoutOrFailed(const int64_t formId, AddFormResultErrorCodes &formStates)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto result = std::find_if(formIdMap_.begin(), formIdMap_.end(), [formId, &formStates] (const auto elem) {
        if (elem.first == formId) {
            if (elem.second == AddFormResultErrorCodes::FAILED || elem.second == AddFormResultErrorCodes::TIMEOUT) {
                return true;
            }
            formStates = elem.second;
        }
        return false;
    });
    if (result != formIdMap_.end()) {
        formIdMap_.erase(formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

void FormPublishAdapter::RemoveFormIdMapElement(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formResultMutex_);
    if (formIdMap_.find(formId) != formIdMap_.end()) {
        formIdMap_.erase(formId);
    }
}

} // namespace AppExecFwk
} // namespace OHOS
