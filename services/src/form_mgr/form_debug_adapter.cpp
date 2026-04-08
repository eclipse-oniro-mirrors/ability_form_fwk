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

#include "form_mgr/form_debug_adapter.h"

#include "accesstoken_kit.h"
#include "app_state_data.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "iservice_registry.h"
#include "running_form_info.h"
#include "system_ability_definition.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_dump_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormDebugAdapter::FormDebugAdapter()
{
    HILOG_DEBUG("FormDebugAdapter constructed");
}

int FormDebugAdapter::DumpStorageFormInfos(std::string &formInfos) const
{
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    if (formDBInfos.empty()) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    std::sort(formDBInfos.begin(), formDBInfos.end(),
        [] (const FormDBInfo &formDBInfoA, const FormDBInfo &formDBInfoB) -> bool {
        return formDBInfoA.formId < formDBInfoB.formId;
    });
    FormDumpMgr::GetInstance().DumpStorageFormInfos(formDBInfos, formInfos);
    return ERR_OK;
}

int FormDebugAdapter::DumpTemporaryFormInfos(std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormRecord> formRecordInfos;
    if (!FormDataMgr::GetInstance().GetTempFormRecord(formRecordInfos)) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    return ERR_OK;
}

int FormDebugAdapter::DumpStaticBundleFormInfos(std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormInfo> bundleFormInfos;
    if (FormInfoMgr::GetInstance().GetAllFormsInfo(bundleFormInfos) != ERR_OK) {
        HILOG_ERROR("GetAllFormsInfo failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    return ERR_OK;
}

int FormDebugAdapter::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormRecord> formRecordInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formRecordInfos)) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    /**
     * The updateDuration stored in FormRecord is the config.json configuration.
     * The app gallery may modify the updateDuration.
     * The real updateDuration value needs to be obtained from FormTimerMgr.
     */
    for (auto &formRecord : formRecordInfos) {
        FormTimer formTimer;
        if (formRecord.isEnableUpdate && formRecord.updateDuration > 0 &&
            FormTimerMgr::GetInstance().GetIntervalTimer(formRecord.formId, formTimer)) {
            formRecord.updateDuration = formTimer.period;
        }
    }
    FormDumpMgr::GetInstance().DumpFormInfos(formRecordInfos, formInfos);
    return ERR_OK;
}

int FormDebugAdapter::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const
{
    HILOG_INFO("call");
    int reply = ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    FormRecord formRecord;
    if (FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        /**
         * The updateDuration stored in FormRecord is the config.json configuration.
         * The app gallery may modify the updateDuration.
         * The real updateDuration value needs to be obtained from FormTimerMgr.
         */
        FormTimer formTimer;
        if (formRecord.isEnableUpdate && formRecord.updateDuration > 0 &&
            FormTimerMgr::GetInstance().GetIntervalTimer(formRecord.formId, formTimer)) {
            formRecord.updateDuration = formTimer.period;
        }
        FormDumpMgr::GetInstance().DumpFormInfo(formRecord, formInfo);
        reply = ERR_OK;
    }

    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    if (reply == ERR_OK) {
        FormDataProxyMgr::GetInstance().GetFormSubscribeInfo(formId, subscribedKeys, count);
        FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    }

    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    for (const auto &iter : formHostRecords) {
        FormDumpMgr::GetInstance().DumpFormHostInfo(iter, formInfo);
        reply = ERR_OK;
    }

    return reply;
}

int FormDebugAdapter::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const
{
    HILOG_INFO("call");
    FormTimer formTimer;
    UpdateAtItem updateAtItem;
    DynamicRefreshItem dynamicItem;
    bool resultInter = FormTimerMgr::GetInstance().GetIntervalTimer(formId, formTimer);
    bool resultUpdate = FormTimerMgr::GetInstance().GetUpdateAtTimer(formId, updateAtItem);
    bool resultDynamic = FormTimerMgr::GetInstance().GetDynamicItem(formId, dynamicItem);
    HILOG_INFO("resultInter:%{public}d,resultUpdate:%{public}d,resultDynamic:%{public}d",
        resultInter, resultUpdate, resultDynamic);
    if (resultInter || resultUpdate || resultDynamic) {
        isTimingService = "true";
    } else {
        isTimingService = "false";
    }
    return ERR_OK;
}

int FormDebugAdapter::DumpHasFormVisible(const std::string &bundleInfo, std::string &formInfos) const
{
    HILOG_INFO("bundleInfo:%{public}s", bundleInfo.c_str());
    std::vector<std::string> bundleInfoList = FormUtil::StringSplit(bundleInfo, BUNDLE_INFO_SEPARATOR);
    size_t size = bundleInfoList.size();
    if (size == 0) {
        HILOG_ERROR("args size is zero");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string bundleName = bundleInfoList[BUNDLE_NAME_INDEX];
    int32_t userId = DEFAULT_USER_ID;
    int32_t instIndex = 0;
    if (size > USER_ID_INDEX) {
        userId = static_cast<int32_t>(FormUtil::ConvertStringToInt(bundleInfoList[USER_ID_INDEX]));
        if (size > INSTANCE_SEQ_INDEX) {
            instIndex = static_cast<int32_t>(FormUtil::ConvertStringToInt(bundleInfoList[INSTANCE_SEQ_INDEX]));
        }
    }
    HILOG_INFO("resolve bundleInfo, bundleName:%{public}s, userId:%{public}d, instIndex:%{public}d",
        bundleName.c_str(), userId, instIndex);
    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, instIndex);
    FormDumpMgr::GetInstance().DumpHasFormVisible(tokenId, bundleName, userId, instIndex, formInfos);
    return ERR_OK;
}

int FormDebugAdapter::DumpFormRunningFormInfos(std::string &runningFormInfosResult) const
{
    HILOG_INFO("call");
    std::vector<RunningFormInfo> runningFormInfos;
    int32_t userId = FormUtil::GetCurrentAccountId();
    auto ret = FormDataMgr::GetInstance().GetRunningFormInfos(true, runningFormInfos, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("GetRunningFormInfos error");
        return ret;
    }
    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, runningFormInfosResult);
    return ERR_OK;
}

} // namespace AppExecFwk
} // namespace OHOS
