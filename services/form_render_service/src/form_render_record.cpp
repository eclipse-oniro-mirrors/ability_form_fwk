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

#include <chrono>
#include <utility>

#include "extractor.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_module_checker.h"
#include "form_render_impl.h"
#include "xcollie/watchdog.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t TIMEOUT = 3 * 1000;
constexpr int32_t CHECK_THREAD_TIME = 3;
constexpr char FORM_RENDERER_COMP_ID[] = "ohos.extra.param.key.form_comp_id";

namespace {
uint64_t GetCurrentTickMillseconds()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}

ThreadState::ThreadState(int32_t maxState) : maxState_(maxState) {}

void ThreadState::ResetState()
{
    state_ = 0;
}

void ThreadState::NextState()
{
    state_++;
}

int32_t ThreadState::GetCurrentState()
{
    return state_;
}

bool ThreadState::IsMaxState()
{
    return state_ >= maxState_;
}

std::shared_ptr<FormRenderRecord> FormRenderRecord::Create(
    const std::string &bundleName, const std::string &uid, bool needMonitored)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::shared_ptr<FormRenderRecord> renderRecord = std::make_shared<FormRenderRecord>(bundleName, uid);
    if (!renderRecord) {
        HILOG_ERROR("Create FormRenderRecord failed.");
        return nullptr;
    }

    if (!renderRecord->CreateEventHandler(bundleName, needMonitored)) {
        HILOG_ERROR("CreateEventHandler failed.");
        return nullptr;
    }
    return renderRecord;
}

FormRenderRecord::FormRenderRecord(
    const std::string &bundleName, const std::string &uid) : bundleName_(bundleName), uid_(uid)
{
    threadState_ = std::make_shared<ThreadState>(CHECK_THREAD_TIME);
}

FormRenderRecord::~FormRenderRecord()
{
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        return;
    }

    // Some resources need to be deleted in a JS thread
    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleDestroyInJsThread();
    };
    eventHandler->PostSyncTask(syncTask);
}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Form host is died, clean resources.");
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    for (auto iter = hostsMapForFormId_.begin(); iter != hostsMapForFormId_.end();) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
        hosts.erase(hostRemoteObj);
        if (hosts.empty()) {
            iter = hostsMapForFormId_.erase(iter);
        } else {
            ++iter;
        }
    }
    return hostsMapForFormId_.empty();
}

bool FormRenderRecord::CreateEventHandler(const std::string &bundleName, bool needMonitored)
{
    HILOG_INFO("%{public}s called.", __func__);
    if (eventHandler_) {
        HILOG_DEBUG("EventHandle is exist, no need to create a new one.");
        return true;
    }
    // Create event runner
    HILOG_INFO("Create eventHandle.");
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

    if (needMonitored) {
        AddWatchDogThreadMonitor();
    }

    return true;
}

void FormRenderRecord::AddWatchDogThreadMonitor()
{
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto watchdogTask = [thisWeakPtr]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord) {
            renderRecord->Timer();
        }
    };

    std::string eventHandleName;
    eventHandleName.append(bundleName_).append(std::to_string(GetCurrentTickMillseconds()));
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(eventHandleName, watchdogTask, TIMEOUT);
}

void FormRenderRecord::Timer()
{
    TaskState taskState = RunTask();
    if (taskState == TaskState::BLOCK) {
        HILOG_ERROR("FRS block happened when bundleName is %{public}s", bundleName_.c_str());
        OHOS::DelayedSingleton<FormRenderImpl>::GetInstance()->OnRenderingBlock(bundleName_);
    }
}

TaskState FormRenderRecord::RunTask()
{
    std::unique_lock<std::mutex> lock(watchDogMutex_);
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (eventHandler_ == nullptr) {
            HILOG_DEBUG("eventHandler is null when bundleName is %{public}s", bundleName_.c_str());
            return TaskState::NO_RUNNING;
        }
    }

    if (!threadIsAlive_) {
        threadState_->NextState();
        HILOG_INFO("FRS block happened with threadState is %{public}d when bundleName is %{public}s",
            threadState_->GetCurrentState(), bundleName_.c_str());
        return threadState_->IsMaxState() ? TaskState::BLOCK : TaskState::RUNNING;
    }

    threadIsAlive_ = false;
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto checkTask = [thisWeakPtr] () {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }

        renderRecord->MarkThreadAlive();
    };

    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (eventHandler_ == nullptr) {
            return TaskState::NO_RUNNING;
        }

        if (!eventHandler_->PostTask(checkTask, "Watchdog Task", 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
            HILOG_ERROR("Watchdog checkTask postTask false.");
        }
    }

    return TaskState::RUNNING;
}

void FormRenderRecord::MarkThreadAlive()
{
    std::unique_lock<std::mutex> lock(watchDogMutex_);
    threadIsAlive_ = true;
    threadState_->ResetState();
}

int32_t FormRenderRecord::UpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Updated record.");
    Want newWant = GetRendererWant(formJsInfo, want);
    {
        // Some resources need to be initialized in a JS thread
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (!CheckEventHandler(true, formJsInfo.isDynamic)) {
            HILOG_ERROR("eventHandler_ is nullptr");
            return RENDER_FORM_FAILED;
        }

        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr, formJsInfo, newWant]() {
            HILOG_DEBUG("HandleUpdateInJsThread begin.");
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("renderRecord is nullptr.");
                return;
            }
            renderRecord->HandleUpdateInJsThread(formJsInfo, newWant);
        };
        eventHandler_->PostTask(task);
    }

    if (hostRemoteObj == nullptr) {
        HILOG_ERROR("hostRemoteObj is nullptr");
        return RENDER_FORM_FAILED;
    }
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto iter = hostsMapForFormId_.find(formJsInfo.formId);
    if (iter == hostsMapForFormId_.end()) {
        hostsMapForFormId_.emplace(formJsInfo.formId, IRemoteObjectSet({ hostRemoteObj }));
        return ERR_OK;
    }
    iter->second.emplace(hostRemoteObj);
    return ERR_OK;
}

bool FormRenderRecord::NeedReAddRenderer(const FormJsInfo &formJsInfo, int32_t renderType)
{
    bool hasRenderer = false;
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        hasRenderer = formRendererGroupMap_.find(formJsInfo.formId) != formRendererGroupMap_.end();
    }

    return !formJsInfo.isDynamic && !hasRenderer && renderType != Constants::RENDER_FORM;
}

Want FormRenderRecord::GetRendererWant(const FormJsInfo &formJsInfo, const Want &want)
{
    if (!NeedReAddRenderer(formJsInfo,
        want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM))) {
        return want;
    }

    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    auto iter = staticFormRequests_.find(formJsInfo.formId);
    if (iter == staticFormRequests_.end()) {
        return want;
    }

    auto compId = want.GetStringParam(FORM_RENDERER_COMP_ID);
    auto innerIter = iter->second.find(compId);
    if (innerIter == iter->second.end()) {
        return want;
    }

    Want newWant = innerIter->second.want;
    newWant.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    newWant.SetParams(want.GetParams());
    return newWant;
}

void FormRenderRecord::DeleteRenderRecord(int64_t formId, const std::string &compId, const sptr<IRemoteObject> hostRemoteObj, bool &isRenderGroupEmpty)
{
    // Some resources need to be deleted in a JS thread
    HILOG_INFO("Delete some resources formId: %{public}" PRId64 ", %{public}s", formId, compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("eventHandler is nullptr");
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }

        isRenderGroupEmpty = renderRecord->HandleDeleteInJsThread(formId, compId);
        renderRecord->DeleteStaticFormRequest(formId, compId);
    };

    if (hostRemoteObj != nullptr) {
        std::lock_guard<std::mutex> lock(hostsMapMutex_);
        auto iter = hostsMapForFormId_.find(formId);
        if (iter != hostsMapForFormId_.end()) {
            std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
            hosts.erase(hostRemoteObj);
        }
    }
    eventHandler_->PostSyncTask(task);
}

bool FormRenderRecord::IsEmpty()
{
    bool rendererEmpty = false;
    bool staticFormRequestsEmpty = false;
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        rendererEmpty = formRendererGroupMap_.empty();
    }
    {
        std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
        staticFormRequestsEmpty = staticFormRequests_.empty();
    }

    return rendererEmpty && staticFormRequestsEmpty;
}

std::string FormRenderRecord::GetUid() const
{
    return uid_;
}

bool FormRenderRecord::CreateRuntime(const FormJsInfo &formJsInfo)
{
    if (runtime_) {
        HILOG_DEBUG("runtime is exist, no need to create a new one.");
        return true;
    }

    HILOG_INFO("Create a new runtime.");
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
    options.moduleCheckerDelegate = std::make_shared<FormModuleChecker>();
    runtime_ = AbilityRuntime::Runtime::Create(options);
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed!");
        return false;
    }
    hapPath_ = formJsInfo.jsFormCodePath;
    return true;
}

void FormRenderRecord::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    configuration_ = config;
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::GetContext(const FormJsInfo &formJsInfo, const Want &want)
{
    {
        std::lock_guard<std::mutex> lock(contextsMapMutex_);
        auto iter = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
        if (iter != contextsMapForModuleName_.end()) {
            HILOG_DEBUG("Find context.");
            return iter->second;
        }
    }

    return CreateContext(formJsInfo, want);
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::CreateContext(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Create a new context.");
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (context == nullptr) {
        HILOG_ERROR("Create context failed!");
        return nullptr;
    }

    context->SetConfiguration(configuration_);
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = formJsInfo.moduleName;
    hapModuleInfo.hapPath = formJsInfo.jsFormCodePath;
    hapModuleInfo.compileMode = static_cast<CompileMode>(want.GetIntParam(Constants::FORM_COMPILE_MODE_KEY,
        static_cast<int32_t>(CompileMode::ES_MODULE)));
    context->InitHapModuleInfo(hapModuleInfo);
    auto applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = formJsInfo.bundleName;
    applicationInfo->minCompatibleVersionCode = want.GetIntParam(Constants::FORM_COMPATIBLE_VERSION_CODE_KEY, 0);
    context->SetApplicationInfo(applicationInfo);
    HILOG_DEBUG("bundleName is %{public}s, moduleName is %{public}s",
        formJsInfo.bundleName.c_str(), formJsInfo.moduleName.c_str());

    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    contextsMapForModuleName_.emplace(GenerateContextKey(formJsInfo), context);
    return context;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::GetFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    HILOG_INFO("Get formRendererGroup.");
    auto key = formJsInfo.formId;
    auto iter = formRendererGroupMap_.find(key);
    if (iter != formRendererGroupMap_.end()) {
        return iter->second;
    }

    auto formRendererGroup = CreateFormRendererGroupLock(formJsInfo, context, runtime);
    if (formRendererGroup != nullptr) {
        HILOG_INFO("formRendererGroupMap emplace formId:%{public}s", std::to_string(key).c_str());
        formRendererGroupMap_.emplace(key, formRendererGroup);
    }
    return formRendererGroup;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    HILOG_INFO("Create formRendererGroup.");
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

void FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Update record in js thread.");
    MarkThreadAlive();
    if (runtime_ == nullptr && !CreateRuntime(formJsInfo)) {
        HILOG_ERROR("Create runtime failed.");
        return;
    }
    auto context = GetContext(formJsInfo, want);
    if (context == nullptr) {
        HILOG_ERROR("Create Context failed.");
        return;
    }
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_INFO("renderType is %{public}d.", renderType);
    if (renderType == Constants::RENDER_FORM) {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto formRendererGroup = GetFormRendererGroup(formJsInfo, context, runtime_);
        if (formRendererGroup == nullptr) {
            HILOG_ERROR("Create formRendererGroup failed.");
            return;
        }
        formRendererGroup->AddForm(want, formJsInfo);
        HILOG_INFO("AddForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    } else {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        if (auto search = formRendererGroupMap_.find(formJsInfo.formId);
            search != formRendererGroupMap_.end()) {
            auto group = search->second;
            group->UpdateForm(formJsInfo);
        }
        HILOG_INFO("UpdateForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    }

    if (!formJsInfo.isDynamic) {
        AddStaticFormRequest(formJsInfo, want);
    } else {
        auto compId = want.GetStringParam(FORM_RENDERER_COMP_ID);
        DeleteStaticFormRequest(formJsInfo.formId, compId);
    }
    return;
}

bool FormRenderRecord::HandleDeleteInJsThread(int64_t formId, const std::string &compId)
{
    HILOG_INFO("Delete some resources in js thread.");
    MarkThreadAlive();
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_INFO("HandleDeleteInJsThread failed. FormRendererGroup was not founded.");
            return false;
        }
        if (!search->second) {
            HILOG_INFO("HandleDeleteInJsThread failed. FormRendererGroup was founded but is null.");
            return false;
        }
        if (!compId.empty()) {
            search->second->DeleteForm(compId);
            HILOG_INFO("HandleDeleteInJsThread compid is %{public}s", compId.c_str());
            return false;
        }
        search->second->DeleteForm();
        formRendererGroupMap_.erase(formId);
    }
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    hostsMapForFormId_.erase(formId);
    return true;
}

bool FormRenderRecord::CheckEventHandler(bool createThead, bool needMonitored)
{
    if (eventHandler_ == nullptr && createThead) {
        CreateEventHandler(bundleName_, needMonitored);
    }

    return eventHandler_ != nullptr;
}

void FormRenderRecord::AddStaticFormRequest(const FormJsInfo &formJsInfo, const Want &want)
{
    auto compId = want.GetStringParam(FORM_RENDERER_COMP_ID);
    HILOG_INFO("AddStaticFormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formJsInfo.formId).c_str(), compId.c_str());
    if (compId.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    Ace::FormRequest formRequest;
    formRequest.compId = compId;
    formRequest.want = want;
    formRequest.want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    formRequest.isDynamic = formJsInfo.isDynamic;
    formRequest.formJsInfo = formJsInfo;
    auto iter = staticFormRequests_.find(formJsInfo.formId);
    if (iter == staticFormRequests_.end()) {
        std::unordered_map<std::string, Ace::FormRequest> formRequests;
        formRequests.emplace(compId, formRequest);
        staticFormRequests_.emplace(formJsInfo.formId, formRequests);
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter != iter->second.end()) {
        auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
        if (renderType != Constants::RENDER_FORM) {
            formRequest.want = innerIter->second.want;
            formRequest.want.SetParams(want.GetParams());
        }
        iter->second.erase(innerIter);
    }
    iter->second.emplace(compId, formRequest);
}

void FormRenderRecord::AddStaticFormRequest(int64_t formId, const Ace::FormRequest &formRequest)
{
    HILOG_INFO("AddStaticFormRequest by FormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formId).c_str(), formRequest.compId.c_str());
    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    auto iter = staticFormRequests_.find(formId);
    if (iter == staticFormRequests_.end()) {
        std::unordered_map<std::string, Ace::FormRequest> formRequests;
        formRequests.emplace(formRequest.compId, formRequest);
        staticFormRequests_.emplace(formId, formRequests);
        return;
    }

    auto innerIter = iter->second.find(formRequest.compId);
    if (innerIter != iter->second.end()) {
        iter->second.erase(innerIter);
    }
    iter->second.emplace(formRequest.compId, formRequest);
}

void FormRenderRecord::DeleteStaticFormRequest(int64_t formId, const std::string &compId)
{
    HILOG_INFO("DeleteStaticFormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formId).c_str(), compId.c_str());
    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    auto iter = staticFormRequests_.find(formId);
    if (iter == staticFormRequests_.end()) {
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter != iter->second.end()) {
        iter->second.erase(innerIter);
        if (iter->second.empty()) {
            staticFormRequests_.erase(iter);
        }
    }
}

void FormRenderRecord::UpdateStaticFormRequestReleaseState(
    int64_t formId, const std::string &compId, bool hasRelease)
{
    HILOG_INFO("UpdateStatic ReleaseState formId: %{public}s, compId: %{public}s, hasRelease: %{public}d.",
        std::to_string(formId).c_str(), compId.c_str(), hasRelease);
    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    auto iter = staticFormRequests_.find(formId);
    if (iter == staticFormRequests_.end()) {
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter == iter->second.end()) {
        return;
    }

    if (innerIter->second.isDynamic) {
        return;
    }

    innerIter->second.hasRelease = hasRelease;
}

void FormRenderRecord::ReleaseRenderer(
    int64_t formId, const std::string &compId, bool &isRenderGroupEmpty)
{
    HILOG_INFO("Release renderer which formId: %{public}s, compId: %{public}s start.",
        std::to_string(formId).c_str(), compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("eventHandler is nullptr");
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }

        bool ret = renderRecord->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty);
        if (ret) {
            renderRecord->UpdateStaticFormRequestReleaseState(formId, compId, true);
        }
    };
    eventHandler->PostSyncTask(task);
}

bool FormRenderRecord::HandleReleaseRendererInJsThread(
    int64_t formId, const std::string &compId, bool &isRenderGroupEmpty)
{
    HILOG_INFO("Release renderer which formId: %{public}s, compId: %{public}s in js thread.",
        std::to_string(formId).c_str(), compId.c_str());
    MarkThreadAlive();
    if (compId.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto search = formRendererGroupMap_.find(formId);
    if (search == formRendererGroupMap_.end()) {
        HILOG_INFO("HandleReleaseRenderer failed. FormRendererGroup was not founded.");
        return false;
    }

    if (!search->second) {
        HILOG_INFO("HandleReleaseRenderer failed. FormRendererGroup was founded but is null.");
        return false;
    }

    search->second->DeleteForm(compId);
    if (search->second->IsFormRequestsEmpty()) {
        formRendererGroupMap_.erase(formId);
    }

    isRenderGroupEmpty = formRendererGroupMap_.empty();
    return true;
}

void FormRenderRecord::Release()
{
    HILOG_INFO("Release runtime and eventHandler.");
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (runtime_) {
        runtime_.reset();
    }

    ReleaseHapFileHandle();
    if (eventRunner_) {
        eventRunner_->Stop();
        eventRunner_.reset();
    }

    if (eventHandler_) {
        eventHandler_.reset();
    }
}

void FormRenderRecord::ReAddAllStaticForms()
{
    HILOG_INFO("ReAdd all static forms start.");
    if (!CheckEventHandler(false)) {
        HILOG_ERROR("CheckEventHandler failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    for (const auto& staticFormRequests : staticFormRequests_) {
        for (const auto& staticFormRequest : staticFormRequests.second) {
            if (staticFormRequest.second.isDynamic || !staticFormRequest.second.hasRelease) {
                continue;
            }

            std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
            auto task = [thisWeakPtr, formJsInfo = staticFormRequest.second.formJsInfo,
                want = staticFormRequest.second.want]() {
                auto renderRecord = thisWeakPtr.lock();
                if (renderRecord) {
                    renderRecord->HandleUpdateInJsThread(formJsInfo, want);
                }
            };
            eventHandler_->PostTask(task);
        }
    }

    HILOG_INFO("ReAdd all static forms end.");
}

void FormRenderRecord::ReAddStaticForms(const std::vector<FormJsInfo> &formJsInfos)
{
    HILOG_INFO("ReAdd static form start");
    if (!CheckEventHandler(false)) {
        HILOG_ERROR("CheckEventHandler failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
    for (const auto &form : formJsInfos) {
        auto iter = staticFormRequests_.find(form.formId);
        if (iter == staticFormRequests_.end()) {
            continue;
        }

        for (const auto& staticFormRequest : iter->second) {
            if (!staticFormRequest.second.hasRelease) {
                continue;
            }

            std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
            auto task = [thisWeakPtr, form,
                    want = staticFormRequest.second.want]() {
                auto renderRecord = thisWeakPtr.lock();
                if (renderRecord) {
                    renderRecord->HandleUpdateInJsThread(form, want);
                }
            };
            eventHandler_->PostTask(task);
        }
    }

    HILOG_INFO("ReAdd static form end.");
}

void FormRenderRecord::HandleDestroyInJsThread()
{
    HILOG_INFO("FormRenderService is exiting, destroy some resources in js thread.");
    MarkThreadAlive();
    {
        std::lock_guard<std::mutex> lock(staticFormRequestsMutex_);
        staticFormRequests_.clear();
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    formRendererGroupMap_.clear();
    runtime_.reset();
    ReleaseHapFileHandle();
}

void FormRenderRecord::ReleaseHapFileHandle()
{
    HILOG_INFO("ReleaseHapFileHandle: %{public}s", hapPath_.c_str());
    if (hapPath_.empty()) {
        return;
    }

    std::string loadFilePath = AbilityBase::ExtractorUtil::GetLoadFilePath(hapPath_);
    AbilityBase::ExtractorUtil::DeleteExtractor(loadFilePath);
}

inline std::string FormRenderRecord::GenerateContextKey(const FormJsInfo &formJsInfo)
{
    return formJsInfo.bundleName + ":" +  formJsInfo.moduleName;
}

int32_t FormRenderRecord::ReloadFormRecord(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
{
    HILOG_INFO("Reload form record");
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        if (!CheckEventHandler(true, false)) {
            HILOG_ERROR("eventHandler is nullptr");
            return RELOAD_FORM_FAILED;
        }

        ReAddStaticForms(formJsInfos);
        return ERR_OK;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, ids = std::forward<decltype(formJsInfos)>(formJsInfos), want]() {
        HILOG_DEBUG("HandleReloadFormRecord begin.");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleReloadFormRecord(std::move(ids), want);
    };
    eventHandler_->PostTask(task);
    ReAddStaticForms(formJsInfos);
    return ERR_OK;
}

int32_t FormRenderRecord::HandleReloadFormRecord(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
{
    HILOG_INFO("Reload record in js thread.");
    MarkThreadAlive();
    if (runtime_ == nullptr) {
        HILOG_ERROR("runtime_ is null.");
        return RELOAD_FORM_FAILED;
    }
    if (runtime_->GetLanguage() == AbilityRuntime::Runtime::Language::JS) {
        // In the card upgrade condition, new components may be added and need to be reloaded
        HILOG_DEBUG("ReloadFormComponent.");
        (static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).ReloadFormComponent();
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    for (auto form : formJsInfos) {
        auto search = formRendererGroupMap_.find(form.formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("HandleReloadFormRecord failed. FormRendererGroup was not found.");
            continue;
        }
        auto group = search->second;
        if (!group) {
            HILOG_ERROR("HandleReloadFormRecord failed. FormRendererGroup is null.");
            continue;
        }
        if (!form.isDynamic) {
            for (auto formRequest : group->GetAllRendererFormRequests()) {
                formRequest.isDynamic = false;
                formRequest.formJsInfo = form;
                AddStaticFormRequest(form.formId, formRequest);
            }
        }
        group->ReloadForm(form);
    }
    return ERR_OK;
}

void FormRenderRecord::UpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    HILOG_INFO("UpdateConfiguration begin");
    if (!config) {
        HILOG_ERROR("UpdateConfiguration failed due to config is nullptr");
        return;
    }

    SetConfiguration(config);
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        if (!CheckEventHandler(true, false)) {
            HILOG_ERROR("eventHandler is nullptr");
            return;
        }

        ReAddAllStaticForms();
        return;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, config]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleUpdateConfiguration(config);
    };

    eventHandler_->PostTask(task);
    ReAddAllStaticForms();
}

void FormRenderRecord::HandleUpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    HILOG_INFO("HandleUpdateConfiguration begin.");
    MarkThreadAlive();
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    if (!config) {
        HILOG_ERROR("configuration is nullptr");
        return;
    }

    for (auto iter = formRendererGroupMap_.begin(); iter != formRendererGroupMap_.end(); ++iter) {
        if (iter->second) {
            iter->second->UpdateConfiguration(config);
        }
    }
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
