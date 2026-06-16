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

#include "form_mgr/form_query_adapter.h"

#include "form_js_info.h"
#include "form_provider_data.h"
#include "form_provider_data_proxy.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "want.h"

#include "ams_mgr/form_ams_helper.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "form_constants.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider/connection/form_acquire_data_connection.h"
#include "form_provider/connection/form_acquire_state_connection.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormQueryAdapter::FormQueryAdapter()
{
    HILOG_DEBUG("FormQueryAdapter created");
}

FormQueryAdapter::~FormQueryAdapter()
{
}

int FormQueryAdapter::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetAllFormsInfo(formInfos, userId);
}

int FormQueryAdapter::GetFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetFormsInfoByBundle(bundleName, formInfos, userId);
}

int FormQueryAdapter::GetFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos, userId);
}

int FormQueryAdapter::GetFormsInfoByFilter(const FormInfoFilter &filter,
    std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos, userId);
}

int FormQueryAdapter::GetFormInstanceById(const int64_t formId, FormInstance &FormInstance)
{
    HILOG_DEBUG("call, formId:%{public}" PRId64, formId);
    return FormDataMgr::GetInstance().GetFormInstanceById(formId, FormInstance);
}

int FormQueryAdapter::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
    FormInstance &FormInstance)
{
    HILOG_DEBUG("call, formId:%{public}" PRId64, formId);
    return FormDataMgr::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, FormInstance);
}

ErrCode FormQueryAdapter::GetRunningFormInfos(bool isUnusedIncluded,
    std::vector<RunningFormInfo> &runningFormInfos, const int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, userId:%{public}d", userId);
    return FormDataMgr::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos, userId);
}

int FormQueryAdapter::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetAllTemplateFormsInfo(formInfos, userId);
}

int FormQueryAdapter::GetTemplateFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetTemplateFormsInfoByBundle(bundleName, formInfos, userId);
}

int FormQueryAdapter::GetTemplateFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormInfoMgr::GetInstance().GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos, userId);
}

int32_t FormQueryAdapter::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_DEBUG("call, isTempFormFlag:%{public}d", isTempFormFlag);
    if (isTempFormFlag) {
        return FormDataMgr::GetInstance().GetTempFormsCount(formCount);
    }
    return FormDataMgr::GetInstance().GetCastFormsCount(formCount);
}

int32_t FormQueryAdapter::GetHostFormsCount(const std::string &bundleName, int32_t &formCount)
{
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    return FormDataMgr::GetInstance().GetHostFormsCount(bundleName, formCount);
}

ErrCode FormQueryAdapter::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded,
    std::vector<RunningFormInfo> &runningFormInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call, bundleName:%{public}s", bundleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    return FormDataMgr::GetInstance().GetRunningFormInfosByBundleName(
        bundleName, isUnusedIncluded, runningFormInfos, userId);
}

ErrCode FormQueryAdapter::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("call");
    return FormDataMgr::GetInstance().GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormQueryAdapter::AcquireFormStateCheck(const std::string &bundleName,
    const std::string &abilityName, const Want &want, std::string &provider)
{
    if (bundleName.empty() || abilityName.empty()) {
        HILOG_ERROR("empty bundleName or abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    std::string formName = want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY);
    int32_t dimensionId = want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 1);

    if (moduleName.empty() || formName.empty()) {
        HILOG_ERROR("empty moduleName or formName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormInfo> formInfos {};
    ErrCode errCode = FormInfoMgr::GetInstance().GetFormsInfoByModuleWithoutCheck(
        want.GetElement().GetBundleName(), moduleName, formInfos);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get forms info");
        return errCode;
    }

    bool found = false;
    for (auto &formInfo : formInfos) {
        if ((formInfo.abilityName == abilityName) && (formInfo.name == formName) &&
            (FormCommonAdapter::GetInstance().IsDimensionValid(formInfo, dimensionId))) {
            found = true;
            HILOG_INFO("form info found");
            break;
        }
    }
    if (!found) {
        HILOG_INFO("find matchFormInfo failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    const std::string doubleColon = "::";
    provider.append(bundleName).append(doubleColon).append(abilityName).append(doubleColon)
        .append(moduleName).append(doubleColon).append(formName).append(doubleColon)
        .append(std::to_string(dimensionId)).append(doubleColon).append(std::to_string(callingUid));
    return ERR_OK;
}

int FormQueryAdapter::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
    FormStateInfo &stateInfo)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetElement().GetModuleName();

    std::string provider;
    ErrCode errCode = AcquireFormStateCheck(bundleName, abilityName, want, provider);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    FormItemInfo info;
    FormDataMgr::GetInstance().CreateFormStateRecord(provider, info, callerToken, callingUid);

    HILOG_DEBUG("bundleName:%{public}s, abilityName:%{public}s, moduleName:%{public}s", bundleName.c_str(),
        abilityName.c_str(), moduleName.c_str());
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    sptr<IAbilityConnection> connection =
        new (std::nothrow) FormAcquireStateConnection(bundleName, abilityName, want, provider, userId);
    if (connection == nullptr) {
        HILOG_ERROR("create FormAcquireStateConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want targetWant;
    targetWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    targetWant.SetElementName(bundleName, abilityName);
    if (!moduleName.empty()) {
        targetWant.SetModuleName(moduleName);
    }
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(targetWant, connection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    stateInfo.state = FormState::DEFAULT;
    return ERR_OK;
}

int FormQueryAdapter::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form info get formRecord failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    std::string bundleName = formRecord.bundleName;
    std::string abilityName = formRecord.abilityName;
    std::string moduleName = formRecord.moduleName;

    HILOG_DEBUG("bundleName:%{public}s, abilityName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), abilityName.c_str(), moduleName.c_str());
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    FormItemInfo info;
    FormDataMgr::GetInstance().CreateFormAcquireDataRecord(requestCode, info, callerToken, callingUid);
    sptr<IAbilityConnection> connection =
        new (std::nothrow) FormAcquireDataConnection(formId, bundleName, abilityName, requestCode, userId);
    if (connection == nullptr) {
        HILOG_ERROR("create FormAcquireDataConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want targetWant;
    targetWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    targetWant.SetElementName(bundleName, abilityName);
    if (!moduleName.empty()) {
        targetWant.SetModuleName(moduleName);
    }
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(targetWant, connection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

} // namespace AppExecFwk
} // namespace OHOS
