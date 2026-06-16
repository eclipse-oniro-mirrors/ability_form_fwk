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

#ifndef OHOS_FORM_FWK_FORM_DEBUG_ADAPTER_H
#define OHOS_FORM_FWK_FORM_DEBUG_ADAPTER_H

#include <cstdint>
#include <string>

#include "app_mgr_interface.h"
#include "singleton.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_dump_mgr.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/database/form_db_info.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"

namespace OHOS {
namespace AppExecFwk {

class FormDebugAdapter final : public DelayedRefSingleton<FormDebugAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormDebugAdapter)

public:

    int DumpStorageFormInfos(std::string &formInfos) const;

    int DumpTemporaryFormInfos(std::string &formInfos) const;

    int DumpStaticBundleFormInfos(std::string &formInfos) const;

    int DumpFormInfoByBundleName(const std::string &bundleName,
        std::string &formInfos) const;

    int DumpFormInfoByFormId(const int64_t formId,
        std::string &formInfo) const;

    int DumpFormTimerByFormId(const int64_t formId,
        std::string &isTimingService) const;

    int DumpHasFormVisible(const std::string &bundleInfo,
        std::string &formInfos) const;

    int DumpFormRunningFormInfos(std::string &runningFormInfosResult) const;
};


} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DEBUG_ADAPTER_H
