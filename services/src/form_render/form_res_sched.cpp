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

#include "form_render/form_res_sched.h"

#ifdef RES_SCHEDULE_ENABLE
#include "res_sched_client.h"
#include "res_type.h"
#endif
#include "system_ability_definition.h"

#include "ams_mgr/form_app_mgr_helper.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
/**
 * @brief form render state
 */
enum FormRenderStatus : int64_t {
    FORM_RENDER_START = 0,
    FORM_RENDER_END = 1,
};
}  // namespace

FormResSched::FormResSched(int32_t userId) : userId_(userId)
{
    HILOG_INFO("Call userId:%{public}d", userId);
    RunningProcessInfo info;
    bool success = FormAppMgrHelper::GetInstance().GetRunningProcessInfo(Constants::FRS_BUNDLE_NAME, userId, info);
    if (!success) {
        HILOG_ERROR("Get running process id failed");
        return;
    }
    pid_ = info.pid_;
    uid_ = info.uid_;
    HILOG_INFO("userId:%{public}d pid:%{public}d uid:%{public}d", userId, pid_, uid_);
}

FormResSched::~FormResSched()
{
    HILOG_INFO("Call");
}

void FormResSched::ReportFormLayoutStart()
{
    HILOG_INFO("Call");
    if (pid_ <= 0 || uid_ <= 0) {
        return;
    }
    ReportToRss(pid_, uid_, true);
}

void FormResSched::ReportFormLayoutEnd()
{
    HILOG_INFO("Call");
    if (pid_ <= 0 || uid_ <= 0) {
        return;
    }
    ReportToRss(pid_, uid_, false);
}

void FormResSched::ReportToRss(pid_t pid, int32_t uid, bool isStart)
{
#ifdef RES_SCHEDULE_ENABLE
    HILOG_INFO("pid:%{public}d uid:%{public}d isStart:%{public}d", pid, uid, isStart);
    auto status = isStart ? FormRenderStatus::FORM_RENDER_START : FormRenderStatus::FORM_RENDER_END;
    std::unordered_map<std::string, std::string> payload = {
        {"saId", std::to_string(FORM_MGR_SERVICE_ID)},
        {"pid", std::to_string(pid)},
        {"uid", std::to_string(uid)}
    };
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        ResourceSchedule::ResType::RES_TYPE_FORM_RENDER_EVENT, status, payload);
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS