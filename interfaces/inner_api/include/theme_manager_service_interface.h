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

#ifndef OHOS_FORM_FWK_THEME_MANAGER_SERVICE_INTERFACE_H
#define OHOS_FORM_FWK_THEME_MANAGER_SERVICE_INTERFACE_H
#ifdef THEME_MGR_ENABLE

#include <vector>
#include <iremote_broker.h>
#include <string_ex.h>
#include "theme_manager_service_param.h"

namespace OHOS::AppExecFwk {
using std::vector;
class IThemeManagerService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ThemeManager.IThemeManagerService");

    virtual ErrCode AddForm(
        const ThemeManagerThemeFormInfoByParcel& themeFormInfo) = 0;

    virtual ErrCode DeleteForm(
        const vector<int64_t> &formId) = 0;
};

enum class IThemeManagerServiceIpcCode {
    COMMAND_ADD_FORM = MIN_TRANSACTION_ID + 3,
    COMMAND_DELETE_FORM,
};

} // namespace OHOS::AppExecFwk
#endif // THEME_MGR_ENABLE
#endif // OHOS_FORM_FWK_THEME_MANAGER_SERVICE_INTERFACE_H