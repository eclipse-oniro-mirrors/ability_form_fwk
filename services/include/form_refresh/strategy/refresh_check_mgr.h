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

#ifndef OHOS_FORM_FWK_REFRESH_CHECK_MGR_H
#define OHOS_FORM_FWK_REFRESH_CHECK_MGR_H

#include <singleton.h>

#include "form_refresh/check_mgr/base_checker_interface.h"

namespace OHOS {
namespace AppExecFwk {

enum CheckValidType {
    TYPE_SYSTEM_APP,
    TYPE_SELF_FORM,
    TYPE_CALLING_USER,
    TYPE_CALLING_BUNDLE,
    TYPE_ACTIVE_USER,
    TYPE_ADD_FINISH,
    TYPE_UNTRUST_APP,
    TYPE_MULTI_ACTIVE_USERS,
};

/**
* @class RefreshCheckMgr
* RefreshCheckMgr is used to check refresh task valid.
*/
class RefreshCheckMgr : public DelayedRefSingleton<RefreshCheckMgr> {
    DECLARE_DELAYED_REF_SINGLETON(RefreshCheckMgr);
public:
    DISALLOW_COPY_AND_MOVE(RefreshCheckMgr);

    int IsBaseValidPass(const std::vector<int32_t> &types, const CheckValidFactor &factor);

private:
    int HandleCheckValid(const CheckValidFactor &factor, const int32_t checkType);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_REFRESH_CHECK_MGR_H