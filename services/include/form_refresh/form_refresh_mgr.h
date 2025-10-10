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

#ifndef OHOS_FORM_FWK_FORM_REFRESH_MGR_H
#define OHOS_FORM_FWK_FORM_REFRESH_MGR_H

#include <singleton.h>

#include "form_refresh/refresh_impl/form_refresh_interface.h"

namespace OHOS {
namespace AppExecFwk {

enum FormRefreshType {
    TYPE_HOST,
    TYPE_NETWORK,
    TYPE_NEXT_TIME,
    TYPE_TIMER,
    TYPE_DATA,
    TYPE_FORCE,
    TYPE_UNCONTROL,
    TYPE_APP_UPGRADE,
    TYPE_PROVIDER,
};

/**
* @class FormRefreshMgr
* FormRefreshMgr is used to deal form refresh request.
*/
class FormRefreshMgr : public DelayedRefSingleton<FormRefreshMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRefreshMgr);
public:
    DISALLOW_COPY_AND_MOVE(FormRefreshMgr);

    int RequestRefresh(RefreshData &data, const int32_t refreshType);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_REFRESH_MGR_H