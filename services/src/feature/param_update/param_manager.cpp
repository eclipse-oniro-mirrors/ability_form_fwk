/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "feature/param_update/param_manager.h"

#include <iostream>
#include <fstream>
#include "form_constants.h"
#include "feature/param_update/param_reader.h"
#include "common/util/string_utils.h"
#include "data_center/database/form_rdb_data_mgr.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string PARAM_INSTALL_PATH = "/data/service/el1/public/update/param_service/install/system/";
    constexpr const char* FORM_MGR_CONFIG_VERSION = "FormMgrConfig_version";
    constexpr const char* FORM_MGR_CONFIG_DATA = "FormMgrConfig_data";
    const std::string CONFIG_FILE_NAME = "form_mgr_config.json";
    const std::string PARAM_PRESET_PATH = "/system/etc/FormMgrConfig/";
}

ParamManager::ParamManager()
{
    HILOG_INFO("init");
}

ParamManager::~ParamManager()
{
    HILOG_INFO("destory");
}

void ParamManager::InitParam()
{
    HILOG_INFO("call");
    g_paramStr = LoadParamStr();
    g_currentVersion = LoadVersion();
    std::string presetVersion = ParamReader::GetInstance().GetPathVersion(PARAM_PRESET_PATH);
    long long presetVersionNum;
    if (!StringUtils::VersionStrToNumber(presetVersion, presetVersionNum)) {
        HILOG_ERROR("path version error:%{public}s", presetVersion.c_str());
        return;
    }
    std::string pathVersion = ParamReader::GetInstance().GetPathVersion(Constants::FORM_MGR_CONFIG_DIR);
    long long pathVersionNum;
    if (!StringUtils::VersionStrToNumber(pathVersion, pathVersionNum)) {
        HILOG_ERROR("path version error:%{public}s", pathVersion.c_str());
        return;
    }
    HILOG_INFO("presetVersion: %{public}s  pathVersion:%{public}s", presetVersion.c_str(), pathVersion.c_str());
    std::string path = Constants::FORM_MGR_CONFIG_DIR;
    if (presetVersionNum > pathVersionNum) {
        pathVersionNum = presetVersionNum;
        path = PARAM_PRESET_PATH;
    }
    std::string currentVersion = g_currentVersion;
    long long currentVersionNum;
    if (!StringUtils::VersionStrToNumber(currentVersion, currentVersionNum)) {
        HILOG_ERROR("current version error:%{public}s", currentVersion.c_str());
        return;
    }
    HILOG_INFO("currentVersion: %{public}s", currentVersion.c_str());
    if (currentVersionNum < pathVersionNum) {
        ReloadParam(pathVersion, path);
    }
}

const std::string &ParamManager::GetParamStr()
{
    return g_paramStr;
}

const std::string &ParamManager::GetParamVersion()
{
    return g_currentVersion;
}

void ParamManager::ReloadParam(const std::string &versionStr, const std::string path)
{
    HILOG_INFO("reloadParam version:%{public}s,path:%{public}s", versionStr.c_str(), path.c_str());
    if (path.find(PARAM_INSTALL_PATH) != std::string::npos) {
        if (!ParamReader::GetInstance().VerifyCertSfFile()) {
            HILOG_ERROR("verify CertSf file error");
            return;
        }
        if (!ParamReader::GetInstance().VerifyParamFile(Constants::VERSION_FILE_NAME)) {
            HILOG_ERROR("vrify version file error");
            return;
        }

        if (!ParamReader::GetInstance().VerifyParamFile(CONFIG_FILE_NAME)) {
            HILOG_ERROR("vrify config file error");
            return;
        }
    }   
    g_paramStr = ParamReader::GetInstance().GetParamInfoStr(path + CONFIG_FILE_NAME);
    g_currentVersion = versionStr;
    SaveVersionStr(g_currentVersion);
    SaveParamStr(g_paramStr);
}

std::string ParamManager::LoadVersion()
{
    std::string versionStr;
    ErrCode result = FormRdbDataMgr::GetInstance().QueryData(
        Constants::FORM_RDB_TABLE_NAME, FORM_MGR_CONFIG_VERSION, versionStr);
    if (result != ERR_OK) {
        HILOG_ERROR("get formMgrConfig version error");
        return Constants::FMC_DEFAULT_VERSION;
    }
    return versionStr;
}

std::string ParamManager::LoadParamStr()
{
    std::string paramStr;
    ErrCode result = FormRdbDataMgr::GetInstance().QueryData(
        Constants::FORM_RDB_TABLE_NAME, FORM_MGR_CONFIG_DATA, paramStr);
    if (result != ERR_OK) {
        HILOG_ERROR("get formMgrConfig param error");
    }
    return paramStr;
}

void ParamManager::SaveVersionStr(const std::string &versionStr)
{
    ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME,
        FORM_MGR_CONFIG_VERSION, versionStr);
    if (result != ERR_OK) {
        HILOG_ERROR("update formMgrConfig version to rdbstore failed, code is %{public}d", result);
    }
}

void ParamManager::SaveParamStr(const std::string &paramStr)
{
     ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME,
        FORM_MGR_CONFIG_DATA, paramStr);
    if (result != ERR_OK) {
        HILOG_ERROR("update formMgrConfig param to rdbstore failed, code is %{public}d", result);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS