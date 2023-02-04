/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_render_record.h"

#include "constants.h"
#include "form_constants.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {

std::shared_ptr<FormRenderRecord> FormRenderRecord::Create(const std::string &bundleName, int32_t uid)
{
    std::shared_ptr<FormRenderRecord> renderRecord = std::make_shared<FormRenderRecord>(bundleName, uid);
    if (!renderRecord) {
        HILOG_ERROR("Create FormRenderRecord failed.");
        return nullptr;
    }
    
    if (!renderRecord->CreateEventHandler(bundleName)) {
        return nullptr;
    }
    return renderRecord;
}

FormRenderRecord::FormRenderRecord(
    const std::string &bundleName, int32_t uid) : bundleName_(bundleName), uid_(uid) {}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    for (auto item = hostsMapForFormId_.begin(); item != hostsMapForFormId_.end();) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = item->second;
        hosts.erase(hostRemoteObj);
        if (hosts.size() == 0) {
            item = hostsMapForFormId_.erase(item);
        } else {
            ++item;
        }
    }
    return (hostsMapForFormId_.size() == 0);
}

bool FormRenderRecord::CreateEventHandler(const std::string &bundleName)
{
    if (eventHandler_) {
        return true;
    }

    // Create event runner
    if (eventRunner_ == nullptr) {
        eventRunner_ = EventRunner::Create(bundleName);
        if (eventRunner_ == nullptr) {
            HILOG_ERROR("Create event runner Failed.");
            return false;
        }
    }
    // Create event handler
    eventHandler_ = std::make_shared<EventHandler>(eventRunner_);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("Create event handler failed.");
        return false;
    }
    return true;
}

bool FormRenderRecord::UpdateRenderRecord(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> hostRemoteObj)
{
    // Some resources need to be initialized in a JS thread
    auto task = [renderRecord = shared_from_this(), formJsInfo]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleUpdateInJsThread(formJsInfo);
    };
    
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return false;
    }
    eventHandler_->PostTask(task);

    CreateContext(formJsInfo);
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto item = hostsMapForFormId_.find(formJsInfo.formId);
    if (item == hostsMapForFormId_.end()) {
        hostsMapForFormId_.emplace(formJsInfo.formId, std::unordered_set<sptr<IRemoteObject>, RemoteObjHash>());
        item = hostsMapForFormId_.begin();
    }
    item->second.emplace(hostRemoteObj);
    return true;
}

int32_t FormRenderRecord::GetUid() const
{
    return uid_;
}

bool FormRenderRecord::CreateRuntime(const FormJsInfo &formJsInfo)
{
    if (runtime_) {
        return true;
    }

    if (eventRunner_ == nullptr) {
        HILOG_ERROR("eventRunner_ is nullptr");
        return false;
    }
    AbilityRuntime::Runtime::Options options;
    options.bundleName = formJsInfo.bundleName;
    options.codePath = Constants::LOCAL_CODE_PATH;
    BundleInfo bundleInfo;
    options.eventRunner = eventRunner_;
    options.hapPath = formJsInfo.jsFormCodePath;
    options.loadAce = true;
    options.isBundle = true;
    options.isUnique = true;
    runtime_ = AbilityRuntime::Runtime::Create(options);
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed!");
        return false;
    }
    return true;
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::GetContext(const FormJsInfo &formJsInfo)
{
    {
        std::lock_guard<std::mutex> lock(contextsMapMutex_);
        auto item = contextsMapForModuleName_.find(formJsInfo.moduleName);
        if (item != contextsMapForModuleName_.end()) {
            return item->second;
        }
    }

    return CreateContext(formJsInfo);
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::CreateContext(const FormJsInfo &formJsInfo)
{
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (context == nullptr) {
        HILOG_ERROR("Create context failed!");
        return nullptr;
    }
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = formJsInfo.moduleName;
    hapModuleInfo.hapPath = formJsInfo.jsFormCodePath;
    context->InitHapModuleInfo(hapModuleInfo);
    auto applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = formJsInfo.bundleName;
    context->SetApplicationInfo(applicationInfo);
    HILOG_DEBUG("bundleName is %{public}s, moduleName is %{public}s",
        formJsInfo.bundleName.c_str(), formJsInfo.moduleName.c_str());
    
    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    contextsMapForModuleName_.emplace(formJsInfo.moduleName, context);
    return context;
}

void FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo)
{
    if (runtime_ == nullptr && CreateRuntime(formJsInfo)) {
        HILOG_ERROR("Create runtime failed.");
        return;
    }
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
