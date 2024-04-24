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

#include "form_dump_mgr.h"

#include "fms_log_wrapper.h"
#include "form_cache_mgr.h"
#include "form_mgr_adapter.h"
#include <utility>
#include <map>

namespace OHOS {
namespace AppExecFwk {
const std::string LINE_FEED = "\n";

FormDumpMgr::FormDumpMgr() {}
FormDumpMgr::~FormDumpMgr() {}
/**
 * @brief Dump all of form storage infos.
 * @param storageInfos Form storage infos
 * @param formInfos Form storage dump info.
 */
void FormDumpMgr::DumpStorageFormInfos(const std::vector<FormDBInfo> &storageInfos, std::string &formInfos) const
{
    formInfos += "  Total Storage-Form count is " + std::to_string(storageInfos.size()) + "\n" + LINE_FEED;
    for (const auto &info : storageInfos) {
        formInfos += "  FormId #" + std::to_string(info.formId) + "\n";
        formInfos += "    formName [" + info.formName + "]\n";
        formInfos += "    userId [" + std::to_string(info.userId) + "]\n";
        formInfos += "    bundleName [" + info.bundleName + "]\n";
        formInfos += "    moduleName [" + info.moduleName + "]\n";
        formInfos += "    abilityName [" + info.abilityName + "]\n";
        formInfos += "    formUserUids [";
        for (const auto &uId : info.formUserUids) {
            formInfos += " Uid[" + std::to_string(uId) + "] ";
        }
        formInfos += "]\n" + LINE_FEED;
    }
}
/**
 * @brief Dump all of temporary form infos.
 * @param formRecordInfos Form record infos.
 * @param formInfos Form dump infos.
 */
void FormDumpMgr::DumpTemporaryFormInfos(const std::vector<FormRecord> &formRecordInfos, std::string &formInfos) const
{
    formInfos += "  Total Temporary-Form count is " + std::to_string(formRecordInfos.size()) + "\n" + LINE_FEED;
    for (const auto &info : formRecordInfos) {
        formInfos += "  FormId #" + std::to_string(info.formId) + "\n";
        formInfos += "    formName [" + info.formName + "]\n";
        formInfos += "    userId [" + std::to_string(info.userId) + "]\n";
        formInfos += "    bundleName [" + info.bundleName + "]\n";
        formInfos += "    moduleName [" + info.moduleName + "]\n";
        formInfos += "    abilityName [" + info.abilityName + "]\n";
        formInfos += "    type [" + std::string(info.uiSyntax == FormType::JS ? "JS" : "ArkTS") + "]\n";
        formInfos += "    isDynamic [" + std::to_string(info.isDynamic) + "]\n";
        formInfos += "    transparencyEnabled [" + std::to_string(info.transparencyEnabled) + "]\n";
        formInfos += "    formUserUids [";
        for (const auto &uId : info.formUserUids) {
            formInfos += " Uid[" + std::to_string(uId) + "] ";
        }
        formInfos += "]\n" + LINE_FEED;
    }
}

void FormDumpMgr::DumpStaticBundleFormInfos(const std::vector<FormInfo> &bundleFormInfos, std::string &formInfos) const
{
    formInfos += "  These are static-form-infos, it means un-added form's info will also be dumped\n" + LINE_FEED;
    for (const auto &info : bundleFormInfos) {
        formInfos += "  bundleName #" + info.bundleName + "\n";
        formInfos += "    moduleName [" + info.moduleName + "]\n";
        formInfos += "    abilityName [" + info.abilityName + "]\n";
        formInfos += "    formName [" + info.name + "]\n";
        formInfos += "    type [" + std::string(info.uiSyntax == FormType::JS ? "JS" : "ArkTS") + "]\n";
        formInfos += "    isDynamic [" + std::to_string(info.isDynamic) + "]\n";
        formInfos += "    transparencyEnabled [" + std::to_string(info.transparencyEnabled) + "]\n" + LINE_FEED;
    }
}

/**
 * @brief Dump has form visible with bundleInfo.
 * @param tokenId *Unique identifaication of application.
 * @param bundleName Bundle name.
 * @param userId User ID.
 * @param instIndex Index of application instance.
 * @param formInfos Form dump infos.
 */
void FormDumpMgr::DumpHasFormVisible(
    const uint32_t tokenId,
    const std::string &bundleName,
    const int32_t userId,
    const int32_t instIndex,
    std::string &formInfos) const
{
    formInfos += "Query whether has visible forms by bundleInfo\n";
    formInfos += "  tokenId [" + std::to_string(tokenId) + "]\n";
    formInfos += "    bundleName [" + bundleName + "]\n";
    formInfos += "    userId [" + std::to_string(userId) + "]\n";
    formInfos += "    instIndex [" + std::to_string(instIndex) + "]\n";
    formInfos += "    hasFormVisible [" + std::to_string(FormMgrAdapter::GetInstance().HasFormVisible(tokenId)) + "]\n";
}

/**
 * @brief Dump form infos.
 * @param formRecordInfos Form record infos.
 * @param formInfos Form dump infos.
 */
void FormDumpMgr::DumpFormInfos(const std::vector<FormRecord> &formRecordInfos, std::string &formInfos) const
{
    HILOG_INFO("%{public}s called.", __func__);
    for (const auto &info : formRecordInfos) {
        formInfos += "  FormId [" + std::to_string(info.formId)  + "]\n";
        formInfos += "    formName [" + info.formName + "]\n";
        formInfos += "    bundleName [" + info.bundleName + "]\n";
        formInfos += "    moduleName [" + info.moduleName + "]\n";
        formInfos += "    abilityName [" + info.abilityName + "]\n";
        formInfos += "    isInited [" + std::to_string(info.isInited) + "]\n";
        formInfos += "    needRefresh [" + std::to_string(info.needRefresh) + "]\n";
        formInfos += "    isEnableUpdate [" + std::to_string(info.isEnableUpdate) + "]\n";
        formInfos += "    isCountTimerRefresh [" + std::to_string(info.isCountTimerRefresh) + "]\n";
        formInfos += "    specification [" + std::to_string(info.specification) + "]\n";
        formInfos += "    updateDuration [" + std::to_string(info.updateDuration) + "]\n";
        formInfos += "    updateAtHour [" + std::to_string(info.updateAtHour) + "]\n";
        formInfos += "    updateAtMin [" + std::to_string(info.updateAtMin) + "]\n";
        formInfos += "    formTempFlag [" + std::to_string(info.formTempFlag) + "]\n";
        formInfos += "    formVisibleNotify [" + std::to_string(info.formVisibleNotify) + "]\n";
        formInfos += "    formVisibleNotifyState [" + std::to_string(info.formVisibleNotifyState) + "]\n";
        formInfos += "    userId [" + std::to_string(info.userId) + "]\n";
        formInfos += "    type [" + std::string(info.uiSyntax == FormType::JS ? "JS" : "ArkTS") + "]\n";
        formInfos += "    isDynamic [" + std::to_string(info.isDynamic) + "]\n";
        formInfos += "    transparencyEnabled [" + std::to_string(info.transparencyEnabled) + "]\n";

        if (!info.hapSourceDirs.empty()) {
            formInfos += "    hapSourceDirs [";
            for (const auto &hapDir : info.hapSourceDirs) {
                formInfos += " hapSourceDir[" + hapDir + "]";
            }
            formInfos += "]\n";
        }

        if (!info.formUserUids.empty()) {
            formInfos += "    formUserUids [";
            for (const auto &uId : info.formUserUids) {
                formInfos += " Uid[" + std::to_string(uId) + "] ";
            }
            formInfos += "]\n";
        }

        AppendBundleFormInfo(info, formInfos);
        AppendRecycleStatus(info.recycleStatus, formInfos);
        formInfos += LINE_FEED;
    }

    HILOG_DEBUG("%{public}s success. Form infos:%{private}s", __func__, formInfos.c_str());
}
/**
 * @brief Dump form infos.
 * @param formRecordInfo Form Host record info.
 * @param formInfo Form dump info.
 */
void FormDumpMgr::DumpFormHostInfo(const FormHostRecord &formHostRecord, std::string &formInfo) const
{
    HILOG_INFO("%{public}s called.", __func__);
    formInfo += "  ================FormHostRecord=================\n";
    formInfo += "  callerUid [" + std::to_string(formHostRecord.GetCallerUid()) + "]\n";
    formInfo += "  hostBundleName [" + formHostRecord.GetHostBundleName() + "]\n";
    HILOG_DEBUG("%{public}s success. Host Form infos:%{private}s", __func__, formInfo.c_str());
}

/**
 * @brief Dump form infos.
 * @param formRecordInfo Form record info.
 * @param formInfo Form dump info.
 */
void FormDumpMgr::DumpFormInfo(const FormRecord &formRecordInfo, std::string &formInfo) const
{
    HILOG_INFO("%{public}s called.", __func__);
    formInfo += "  ================FormRecord=================\n";
    formInfo += "  FormId [" + std::to_string(formRecordInfo.formId) + "]\n";
    formInfo += "    formName [" + formRecordInfo.formName + "]\n";
    formInfo += "    bundleName [" + formRecordInfo.bundleName + "]\n";
    formInfo += "    moduleName [" + formRecordInfo.moduleName + "]\n";
    formInfo += "    abilityName [" + formRecordInfo.abilityName + "]\n";
    formInfo += "    isInited [" + std::to_string(formRecordInfo.isInited) + "]\n";
    formInfo += "    needRefresh [" + std::to_string(formRecordInfo.needRefresh) + "]\n";
    formInfo += "    isEnableUpdate [" + std::to_string(formRecordInfo.isEnableUpdate) + "]\n";
    formInfo += "    isCountTimerRefresh [" + std::to_string(formRecordInfo.isCountTimerRefresh) + "]\n";
    formInfo += "    specification [" + std::to_string(formRecordInfo.specification) + "]\n";
    formInfo += "    updateDuration [" + std::to_string(formRecordInfo.updateDuration) + "]\n";
    formInfo += "    updateAtHour [" + std::to_string(formRecordInfo.updateAtHour) + "]\n";
    formInfo += "    updateAtMin [" + std::to_string(formRecordInfo.updateAtMin) + "]\n";
    formInfo += "    formTempFlag [" + std::to_string(formRecordInfo.formTempFlag) + "]\n";
    formInfo += "    formVisibleNotify [" + std::to_string(formRecordInfo.formVisibleNotify) + "]\n";
    formInfo += "    formVisibleNotifyState [" + std::to_string(formRecordInfo.formVisibleNotifyState) + "]\n";
    formInfo += "    formSrc [" + formRecordInfo.formSrc + "]\n";
    formInfo += "    designWidth [" + std::to_string(formRecordInfo.formWindow.designWidth) + "]\n";
    formInfo += "    autoDesignWidth [" + std::to_string(formRecordInfo.formWindow.autoDesignWidth) + "]\n";
    formInfo += "    versionCode [" + std::to_string(formRecordInfo.versionCode) + "]\n";
    formInfo += "    versionName [" + formRecordInfo.versionName + "]\n";
    formInfo += "    compatibleVersion [" + std::to_string(formRecordInfo.compatibleVersion) + "]\n";
    formInfo += "    userId [" + std::to_string(formRecordInfo.userId) + "]\n";
    formInfo += "    type [" + std::string(formRecordInfo.uiSyntax == FormType::JS ? "JS" : "ArkTS") + "]\n";
    formInfo += "    isDynamic [" + std::to_string(formRecordInfo.isDynamic) + "]\n";
    formInfo += "    transparencyEnabled [" + std::to_string(formRecordInfo.transparencyEnabled) + "]\n";

    if (!formRecordInfo.hapSourceDirs.empty()) {
        formInfo += "    hapSourceDirs [";
        for (const auto &hapDir : formRecordInfo.hapSourceDirs) {
            formInfo += " hapSourceDir[" + hapDir + "] ";
        }
        formInfo += "]\n";
    }

    if (!formRecordInfo.formUserUids.empty()) {
        formInfo += "    formUserUids [";
        for (const auto &uId : formRecordInfo.formUserUids) {
            formInfo += " Uid[" + std::to_string(uId) + "] ";
        }
        formInfo += "]\n";
    }

    AppendBundleFormInfo(formRecordInfo, formInfo);
    AppendRecycleStatus(formRecordInfo.recycleStatus, formInfo);

    HILOG_DEBUG("%{public}s success. Form infos:%{private}s", __func__, formInfo.c_str());
}

/**
 * @brief Dump form subscribe info.
 * @param subscribedKeys Form subscribe key info.
 * @param count Form received data count
 * @param formInfo Form dump info.
 */
void FormDumpMgr::DumpFormSubscribeInfo(
    const std::vector<std::string> &subscribedKeys, const int64_t &count, std::string &formInfo) const
{
    formInfo += "    formDataProxy [ key [";
    for (size_t i = 0; i < subscribedKeys.size(); i++) {
        formInfo += " [" + subscribedKeys[i] + "]";
    }
    formInfo += " ] updatedCount [" + std::to_string(count) + "] ]\n";
    formInfo += LINE_FEED;
}

void FormDumpMgr::AppendRunningFormInfos(const std::string &formHostBundleName,
    const std::vector<RunningFormInfo> &runningFormInfos,
    std::string &infosResult) const
{
    HILOG_INFO("%{public}s called.", __func__);

    for (const auto& info : runningFormInfos) {
        if (info.hostBundleName == formHostBundleName) {
            infosResult += "  FormId [ " + std::to_string(info.formId) + " ] \n";
            infosResult += "    formName [ " + info.formName + " ]\n";
            infosResult += "    bundleName [ " + info.bundleName + " ] \n";
            infosResult += "    moduleName [ " + info.moduleName + " ] \n";
            infosResult += "    abilityName [ " + info.abilityName + " ] \n";
            infosResult += "    description [ " + info.description + " ] \n";
            infosResult += "    dimension [ " + std::to_string(info.dimension) + " ] \n";

            infosResult += "    formVisibility ";
            switch (info.formVisiblity) {
                case FormVisibilityType::UNKNOWN:
                    infosResult += "[ UNKNOWN ] \n";
                    break;
                case FormVisibilityType::VISIBLE:
                    infosResult += "[ VISIBLE ] \n";
                    break;
                case FormVisibilityType::INVISIBLE:
                    infosResult += "[ INVISIBLE ] \n";
                    break;
                default:
                    infosResult += "[ UNKNOWN_TYPE ] \n";
                    break;
            }

            infosResult += "    FormUsageState ";
            switch (info.formUsageState) {
                case FormUsageState::USED:
                    infosResult += "[ USED ] \n";
                    break;
                case FormUsageState::UNUSED:
                    infosResult += "[ UNUSED ] \n";
                    break;
                default:
                    infosResult += "[ UNKNOWN_TYPE ] \n";
                    break;
            }

            AppendFormLocation(info.formLocation, infosResult);
            AppendRecycleStatus(info.recycleStatus, infosResult);
            infosResult += " \n";
        }
    }
}

void FormDumpMgr::AppendFormLocation(Constants::FormLocation formLocation, std::string &infosResult) const
{
    infosResult += "    formLocation ";
    switch (formLocation) {
        case Constants::FormLocation::OTHER:
            infosResult += "[ OTHER ] \n";
            break;
        case Constants::FormLocation::DESKTOP:
            infosResult += "[ DESKTOP ] \n";
            break;
        case Constants::FormLocation::FORM_CENTER:
            infosResult += "[ FORM_CENTER ] \n";
            break;
        case Constants::FormLocation::FORM_MANAGER:
            infosResult += "[ FORM_MANAGER ] \n";
            break;
        case Constants::FormLocation::NEGATIVE_SCREEN:
            infosResult += "[ NEGATIVE_SCREEN ] \n";
            break;
        case Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN:
            infosResult += "[ FORM_CENTER_NEGATIVE_SCREEN ] \n";
            break;
        case Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN:
            infosResult += "[ FORM_MANAGER_NEGATIVE_SCREEN ] \n";
            break;
        case Constants::FormLocation::SCREEN_LOCK:
            infosResult += "[ SCREEN_LOCK ] \n";
            break;
        case Constants::FormLocation::AI_SUGGESTION:
            infosResult += "[ AI_SUGGESTION ] \n";
            break;
        default:
            infosResult += "[ UNKNOWN_TYPE ] \n";
            break;
    }
}

/**
 * @brief Dump Running form info.
 * @param runningFormInfos Form Running Form infos.
 * @param infosResult Running Form dump info.
 */
void FormDumpMgr::DumpRunningFormInfos(const std::vector<RunningFormInfo> &runningFormInfos,
    std::string &infosResult) const
{
    HILOG_INFO("%{public}s called.", __func__);

    std::unordered_map<std::string, int> countMap;

    for (const auto& info : runningFormInfos) {
        countMap[info.hostBundleName]++;
    }

    for (const auto& infoPair : countMap) {
        infosResult += "hostBundleName [ " + infoPair.first + " ]\n";
        infosResult += "Total running form count: " + std::to_string(infoPair.second)  + " ] \n";
        infosResult += "  ================RunningFormInfo=================\n";

        AppendRunningFormInfos(infoPair.first, runningFormInfos, infosResult);
    }
}

void FormDumpMgr::AppendBundleFormInfo(const FormRecord &formRecordInfo, std::string &formInfo) const
{
    FormInfo bundleFormInfo;
    if (FormInfoMgr::GetInstance().GetFormsInfoByRecord(formRecordInfo, bundleFormInfo) != ERR_OK) {
        formInfo += "    ERROR! Can not get formInfo from BMS! \n";
    }
    formInfo += "    colorMode [" + std::to_string(static_cast<int32_t>(bundleFormInfo.colorMode)) + "]\n";
    formInfo += "    defaultDimension [" + std::to_string(bundleFormInfo.defaultDimension) + "]\n";
    if (!bundleFormInfo.supportDimensions.empty()) {
        formInfo += "    supportDimensions [";
        for (const auto &dimension : bundleFormInfo.supportDimensions) {
            formInfo += " [" + std::to_string(dimension) + "] ";
        }
        formInfo += "]\n";
    }
}

void FormDumpMgr::AppendRecycleStatus(const RecycleStatus recycleStatus, std::string &formInfo) const
{
    formInfo += "    recycleStatus ";
    if (recycleStatus == RecycleStatus::RECYCLABLE) {
        formInfo += "[ RECYCLABLE ]\n";
    } else if (recycleStatus == RecycleStatus::RECYCLED) {
        formInfo += "[ RECYCLED ]\n";
    } else {
        formInfo += "[ NON_RECYCLABLE ]\n";
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
