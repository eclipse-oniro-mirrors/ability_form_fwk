/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_adapter.h"
#include "data_center/form_info/form_info_mgr.h"
namespace {
    bool g_mockRequestPublishFormToHost = true;
}

void MockRequestPublishFormToHost(bool mockRet)
{
    g_mockRequestPublishFormToHost = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

ErrCode FormInfoMgr::GetFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    FormInfo formInfo;
    formInfo.abilityName = "mm";
    formInfo.name = "bb";
    formInfo.supportDimensions.push_back(0);
    formInfo.supportDimensions.push_back(1);
    formInfos.push_back(formInfo);
    return ERR_OK;
}

ErrCode FormMgrAdapter::RequestPublishFormToHost(Want &want)
{
    if (g_mockRequestPublishFormToHost) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
}
}
