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

#include "form_observer/net_conn_callback_manager.h"

#include "common/util/form_util.h"
#include "common/util/form_task_common.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_queue.h"
#include "net_conn_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_CON_NET_MAX = 100;
constexpr int32_t CONDITION_NETWORK = 1;
}
using namespace OHOS::NetManagerStandard;

NetConnCallbackManager::NetConnCallbackManager()
{
    netConTime_.store(0);
    isRegistered_.store(false);
}

NetConnCallbackManager::~NetConnCallbackManager()
{
    UnregisterNetConnCallback();
}

int32_t NetConnCallbackManager::RegisterNetConnCallback()
{
    HILOG_INFO("Register NetConn begin");

    if (isRegistered_.load()) {
        HILOG_WARN("NetConnCallbackObserver already registered");
        return ERR_OK;
    }

    observer_ = sptr<NetConnCallbackObserver>(new (std::nothrow)NetConnCallbackObserver());
    if (observer_ == nullptr) {
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int result = NetConnClient::GetInstance().RegisterNetConnCallback(observer_);
    if (result == ERR_OK) {
        HILOG_INFO("Register NetConnCallbackObserver successful");
        isRegistered_.store(true);
        netConTime_.store(0); // Reset retry count on success

        std::list<sptr<NetHandle>> netList;
        NetConnClient::GetInstance().GetAllNets(netList);
        if (netList.size() > 0) {
            observer_->SetNetConnect();
        }
    } else {
        HILOG_ERROR("Register NetConnCallbackObserver failed, netConTime:%{public}d", netConTime_.load());
        netConTime_.fetch_add(1);
        if (netConTime_.load() >= FORM_CON_NET_MAX) {
            HILOG_ERROR("Register NetConnCallbackObserver failed FORM_CON_NET_MAX times");
            return result;
        }
        PostConnectNetWork();
    }

    return result;
}

int32_t NetConnCallbackManager::UnregisterNetConnCallback()
{
    HILOG_INFO("Unregister NetConn begin");

    int ret = ERR_OK;
    if (isRegistered_.load()) {
        if (observer_ != nullptr) {
            ret = NetConnClient::GetInstance().UnregisterNetConnCallback(observer_);
        }
        isRegistered_.store(false);
    }

    return ret;
}

void NetConnCallbackManager::PostConnectNetWork()
{
    HILOG_DEBUG("start");

    auto connectNetWork = []() {
        NetConnCallbackManager::GetInstance().RegisterNetConnCallback();
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_CON_NETWORK_DELAY_TIME, connectNetWork);
    HILOG_DEBUG("end");
}
} // AppExecFwk
} // OHOS
