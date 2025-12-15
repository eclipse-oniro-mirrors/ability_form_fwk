/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_PARAM_MANAGER_H
#define OHOS_FORM_FWK_PARAM_MANAGER_H

#include <singleton.h>
#include <string>

namespace OHOS {
namespace AppExecFwk {

/**
 * @class ParamManager
 * Param manager.
 */   
class ParamManager final : public DelayedRefSingleton<ParamManager> {
    DECLARE_DELAYED_REF_SINGLETON(ParamManager)
public:
    DISALLOW_COPY_AND_MOVE(ParamManager);
    void InitParam();
    const std::string &GetParamStr();
    const std::string &GetParamVersion();

private:
    void ReloadParam(const std::string &versionStr, const std::string path);
    std::string LoadVersion();
    std::string LoadParamStr();
    void SaveVersionStr(const std::string &versionStr);
    void SaveParamStr(const std::string &paramStr);
    bool VersionStrToNumber(const std::string &versionStr, long long &versionNum);
    
    std::string g_paramStr;
    std::string g_currentVersion;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_PARAM_MANAGER_H