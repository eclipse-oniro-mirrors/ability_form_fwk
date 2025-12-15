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

#include "mock_form_host_task_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_host/form_host_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormHostTaskMgr> MockFormHostTaskMgr::obj = nullptr;

FormHostTaskMgr::FormHostTaskMgr()
{}

FormHostTaskMgr::~FormHostTaskMgr()
{}

void FormHostTaskMgr::PostAcquireTaskToHost(
    const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostAcquireTaskToHost called";
}

void FormHostTaskMgr::PostUpdateTaskToHost(
    const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostUpdateTaskToHost called";
}

void FormHostTaskMgr::PostUninstallTaskToHost(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostUninstallTaskToHost called";
}

void FormHostTaskMgr::PostAcquireStateTaskToHost(
    AppExecFwk::FormState state, const AAFwk::Want &want, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostAcquireStateTaskToHost called";
}

void FormHostTaskMgr::PostAcquireDataTaskToHost(
    const AAFwk::WantParams &wantParams, int64_t requestCode, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostAcquireDataTaskToHost called";
}

void FormHostTaskMgr::PostEnableFormsTaskToHost(
    const std::vector<int64_t> &formIds, const bool enable, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostEnableFormsTaskToHost called";
}

void FormHostTaskMgr::PostLockFormsTaskToHost(
    const std::vector<int64_t> &formIds, const bool lock, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostLockFormsTaskToHost called";
}

void FormHostTaskMgr::PostDueControlFormsTaskToHost(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
    const bool isControl, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostDueControlFormsTaskToHost called";
}

void FormHostTaskMgr::PostCheckFormsTaskToHost(
    const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject)
{
    GTEST_LOG_(INFO) << "PostCheckFormsTaskToHost called";
    if (AppExecFwk::MockFormHostTaskMgr::obj) {
        return AppExecFwk::MockFormHostTaskMgr::obj->PostCheckFormsTaskToHost(formIds, remoteObject);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS