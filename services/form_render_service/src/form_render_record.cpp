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
#include <cstdio>
#include <iostream>
#include <securec.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>

#include "ecmascript/napi/include/jsnapi.h"
#include "extractor.h"
#include "fms_log_wrapper.h"
#include "form_bundle_mgr_helper.h"
#include "form_constants.h"
#include "form_memory_guard.h"
#include "form_module_checker.h"
#include "form_render_event_report.h"
#include "form_render_impl.h"
#include "xcollie/watchdog.h"

using namespace OHOS::AAFwk::GlobalConfigurationKey;

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr int32_t TIMEOUT = 10 * 1000;
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

void HandlerDumper::Dump(const std::string &message)
{
    HILOG_INFO("Message = %{public}s", message.c_str());
    dumpInfo_ += message;
}

std::string HandlerDumper::GetTag()
{
    return "";
}

std::string HandlerDumper::GetDumpInfo()
{
    return dumpInfo_;
}

std::shared_ptr<FormRenderRecord> FormRenderRecord::Create(
    const std::string &bundleName, const std::string &uid, bool needMonitored)
{
    HILOG_INFO("bundleName is %{public}s, uid is %{public}s.", bundleName.c_str(), uid.c_str());
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
    HILOG_INFO("bundleName is %{public}s, uid is %{public}s.", bundleName.c_str(), uid.c_str());
    threadState_ = std::make_shared<ThreadState>(CHECK_THREAD_TIME);
}

FormRenderRecord::~FormRenderRecord()
{
    HILOG_INFO("called");
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_WARN("eventHandler is nullptr");
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
    eventHandler->PostSyncTask(syncTask, "Destory FormRenderRecord");
}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Form host is died, clean resources.");
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    for (auto iter = hostsMapForFormId_.begin(); iter != hostsMapForFormId_.end();) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
        hosts.erase(hostRemoteObj);
        if (hosts.empty()) {
            int64_t formId = iter->first;
            iter = hostsMapForFormId_.erase(iter);
            DeleteRendererGroup(formId);
        } else {
            ++iter;
        }
    }
    return hostsMapForFormId_.empty();
}

void FormRenderRecord::DeleteRendererGroup(int64_t formId)
{
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("eventHandler is null");
        return;
    }

    auto task = [weak = weak_from_this(), formId]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is null.");
            return;
        }

        renderRecord->HandleDeleteRendererGroup(formId);
    };

    eventHandler->PostSyncTask(task, "DeleteRendererGroup");
}

void FormRenderRecord::HandleDeleteRendererGroup(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    formRendererGroupMap_.erase(formId);
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

    if (needMonitored && !hasMonitor_) {
        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr]() {
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("renderRecord is nullptr.");
                return;
            }
            renderRecord->jsThreadId_ = getproctid();
            renderRecord->processId_ = getprocpid();
            HILOG_INFO("Get thread %{public}d and psid %{public}d", renderRecord->jsThreadId_,
                renderRecord->processId_);
        };
        eventHandler_->PostHighPriorityTask(task, "GotJSThreadId");

        hasMonitor_.store(true);
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
        FormRenderEventReport::SendBlockFaultEvent(processId_, jsThreadId_, bundleName_);
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
        DumpEventHandler();
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

void FormRenderRecord::DumpEventHandler()
{
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        return;
    }

    HandlerDumper handlerDumper;
    eventHandler_->Dump(handlerDumper);
}

void FormRenderRecord::MarkThreadAlive()
{
    std::unique_lock<std::mutex> lock(watchDogMutex_);
    threadIsAlive_ = true;
    threadState_->ResetState();
}

int32_t FormRenderRecord::UpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_DEBUG("Updated record.");
    {
        // Some resources need to be initialized in a JS thread
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (!CheckEventHandler(true, formJsInfo.isDynamic)) {
            HILOG_ERROR("eventHandler_ is nullptr");
            return RENDER_FORM_FAILED;
        }

        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr, formJsInfo, want]() {
            HILOG_DEBUG("HandleUpdateInJsThread begin.");
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("renderRecord is nullptr.");
                return;
            }
            renderRecord->HandleUpdateInJsThread(formJsInfo, want);
        };
        eventHandler_->PostTask(task, "UpdateRenderRecord");
    }

    if (hostRemoteObj == nullptr) {
        HILOG_WARN("hostRemoteObj is nullptr");
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

void FormRenderRecord::DeleteRenderRecord(int64_t formId, const std::string &compId,
    const sptr<IRemoteObject> hostRemoteObj, bool &isRenderGroupEmpty)
{
    // Some resources need to be deleted in a JS thread
    HILOG_INFO("Delete some resources formId: %{public}" PRId64 ", %{public}s", formId, compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("eventHandler is null");
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is null.");
            return;
        }

        FormMemoryGuard memoryGuard;
        isRenderGroupEmpty = renderRecord->HandleDeleteInJsThread(formId, compId);
        renderRecord->DeleteFormRequest(formId, compId);
    };

    if (hostRemoteObj != nullptr) {
        std::lock_guard<std::mutex> lock(hostsMapMutex_);
        auto iter = hostsMapForFormId_.find(formId);
        if (iter != hostsMapForFormId_.end()) {
            std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
            hosts.erase(hostRemoteObj);
        }
    }
    eventHandler_->PostSyncTask(task, "DeleteRenderRecord");
}

bool FormRenderRecord::IsEmpty()
{
    bool rendererEmpty = false;
    bool formRequestsEmpty = false;
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        rendererEmpty = formRendererGroupMap_.empty();
    }
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        formRequestsEmpty = formRequests_.empty();
    }
    return rendererEmpty && formRequestsEmpty;
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

    SetPkgContextInfoMap(formJsInfo, options, uid_);

    runtime_ = AbilityRuntime::Runtime::Create(options);
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed!");
        return false;
    }
    hapPath_ = formJsInfo.jsFormCodePath;
    return true;
}

bool FormRenderRecord::SetPkgContextInfoMap(const FormJsInfo &formJsInfo, AbilityRuntime::Runtime::Options &options,
    std::string &uid)
{
    auto bundleMgrHelper = DelayedSingleton<FormBundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        HILOG_ERROR("The bundleMgrHelper is nullptr.");
        return false;
    }

    std::map<std::string, std::string> pkgContextInfoJsonStringMap;
    for (auto modulePkgNamePair : formJsInfo.modulePkgNameMap) {
        std::string pkgContextInfoJsonString;
        ErrCode errCode = bundleMgrHelper->GetJsonProfile(
            AppExecFwk::PKG_CONTEXT_PROFILE, formJsInfo.bundleName, modulePkgNamePair.first, pkgContextInfoJsonString,
            static_cast<int32_t>(std::stoi(uid)));
        if (errCode != ERR_OK) {
            HILOG_ERROR("GetJsonProfile failed: %{public}d.", errCode);
            return false;
        }
        if (!pkgContextInfoJsonString.empty()) {
            pkgContextInfoJsonStringMap[modulePkgNamePair.first] = pkgContextInfoJsonString;
        }
        options.packageNameList[modulePkgNamePair.first] = modulePkgNamePair.second;
    }
    if (!pkgContextInfoJsonStringMap.empty()) {
        HILOG_INFO("set pkgContextInfoJsonStringMap for %{public}s.", formJsInfo.bundleName.c_str());
        options.pkgContextInfoJsonStringMap = pkgContextInfoJsonStringMap;
    }
    return true;
}

void FormRenderRecord::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    if (config != nullptr && configuration_ != nullptr) {
        std::string colorMode = config->GetItem(SYSTEM_COLORMODE);
        std::string languageTag = config->GetItem(SYSTEM_LANGUAGE);
        std::string colorModeOld = configuration_->GetItem(SYSTEM_COLORMODE);
        std::string languageTagOld = configuration_->GetItem(SYSTEM_LANGUAGE);
        configuration_ = config;
        if (colorMode.empty()) {
            configuration_->AddItem(SYSTEM_COLORMODE, colorModeOld);
        }
        if (languageTag.empty()) {
            configuration_->AddItem(SYSTEM_LANGUAGE, languageTagOld);
        }
        return;
    }

    configuration_ = config;
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::GetContext(const FormJsInfo &formJsInfo, const Want &want)
{
    {
        std::lock_guard<std::mutex> lock(contextsMapMutex_);
        auto iter = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
        if (iter != contextsMapForModuleName_.end()) {
            if (iter->second == nullptr) {
                HILOG_WARN("Context is nullptr, bundle name is %{public}s", formJsInfo.bundleName.c_str());
                return nullptr;
            }
            auto applicationInfo = iter->second->GetApplicationInfo();
            if (applicationInfo != nullptr) {
                uint32_t apiCompatibleVersion = static_cast<uint32_t>(
                    want.GetIntParam(Constants::FORM_COMPATIBLE_VERSION_KEY, 0));
                if (apiCompatibleVersion != 0) {
                    applicationInfo->apiCompatibleVersion = apiCompatibleVersion;
                }
                HILOG_INFO("GetContext bundleName %{public}s, apiCompatibleVersion = %{public}d",
                    formJsInfo.bundleName.c_str(), applicationInfo->apiCompatibleVersion);
            }

            std::shared_ptr<OHOS::AppExecFwk::Configuration> config = iter->second->GetConfiguration();
            if (config != nullptr && configuration_ != nullptr) {
                std::string colorMode = configuration_->GetItem(SYSTEM_COLORMODE);
                std::string languageTag = configuration_->GetItem(SYSTEM_LANGUAGE);
                config->AddItem(SYSTEM_COLORMODE, colorMode);
                config->AddItem(SYSTEM_LANGUAGE, languageTag);
            }
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
    applicationInfo->apiCompatibleVersion = static_cast<uint32_t>(want.GetIntParam(
        Constants::FORM_COMPATIBLE_VERSION_KEY, 0));
    applicationInfo->apiTargetVersion = static_cast<int32_t>(want.GetIntParam(
        Constants::FORM_TARGET_VERSION_KEY, 0));
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
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime, eventHandler_);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

void FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Update record in js thread, formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    bool ret = BeforeHandleUpdateForm(formJsInfo);
    if (!ret) {
        HILOG_ERROR("Handle Update Form prepare failed");
        return;
    }

    HandleUpdateForm(formJsInfo, want);
}

bool FormRenderRecord::BeforeHandleUpdateForm(const FormJsInfo &formJsInfo)
{
    MarkThreadAlive();
    if (runtime_ == nullptr && !CreateRuntime(formJsInfo)) {
        HILOG_ERROR("Create runtime failed.");
        return false;
    }
    HILOG_DEBUG("BeforeHandleUpdateForm end");
    return true;
}

void FormRenderRecord::HandleUpdateForm(const FormJsInfo &formJsInfo, const Want &want)
{
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_DEBUG("renderType is %{public}d.", renderType);
    if (renderType == Constants::RENDER_FORM) {
        AddRenderer(formJsInfo, want);
        AddFormRequest(formJsInfo, want);
        return;
    }

    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        auto iter = formRequests_.find(formJsInfo.formId);
        if (iter == formRequests_.end()) {
            return;
        }

        formRequests = iter->second;
    }
    std::string compMaxId = "0";
    for (const auto& iter : formRequests) {
        if (iter.second.compId > compMaxId) {
            compMaxId = iter.second.compId;
        }
    }

    for (const auto& iter : formRequests) {
        auto formRequest = iter.second;
        MergeFormData(formRequest, formJsInfo);
        if (!formRequest.hasRelease) {
            UpdateRenderer(formJsInfo);
            AddFormRequest(formJsInfo.formId, formRequest);
            continue;
        }
        if (compMaxId != formRequest.compId) {
            continue;
        }
        if (formJsInfo.isDynamic) {
            // recover form
            Want oldWant = formRequest.want;
            std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
            oldWant.SetParam(Constants::FORM_STATUS_DATA, statusData);
            oldWant.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, true);

            AddRenderer(formRequest.formJsInfo, oldWant);
            formRequest.hasRelease = false;
            AddFormRequest(formJsInfo.formId, formRequest);

            // update form
            UpdateRenderer(formJsInfo);
        } else {
            AddRenderer(formJsInfo, formRequest.want);
            formRequest.hasRelease = false;
            AddFormRequest(formJsInfo.formId, formRequest);
        }
    }
}

void FormRenderRecord::MergeFormData(Ace::FormRequest &formRequest, const FormJsInfo &formJsInfo)
{
    FormProviderData formProviderData = FormProviderData(formRequest.formJsInfo.formData);
    nlohmann::json newFormData = formJsInfo.formProviderData.GetData();
    formProviderData.MergeData(newFormData);

    formRequest.formJsInfo = formJsInfo;
    formRequest.formJsInfo.formData = formProviderData.GetDataString();
}

void FormRenderRecord::AddRenderer(const FormJsInfo &formJsInfo, const Want &want)
{
    auto context = GetContext(formJsInfo, want);
    if (context == nullptr) {
        HILOG_ERROR("Create Context failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto formRendererGroup = GetFormRendererGroup(formJsInfo, context, runtime_);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed.");
        return;
    }
    formRendererGroup->AddForm(want, formJsInfo);
    HILOG_INFO("AddForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
}

void FormRenderRecord::UpdateRenderer(const FormJsInfo &formJsInfo)
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    if (auto search = formRendererGroupMap_.find(formJsInfo.formId);
        search != formRendererGroupMap_.end()) {
        auto group = search->second;
        group->UpdateForm(formJsInfo);
    }
    HILOG_INFO("UpdateForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
}

bool FormRenderRecord::HandleDeleteInJsThread(int64_t formId, const std::string &compId)
{
    HILOG_INFO("Delete some resources in js thread.");
    MarkThreadAlive();
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("HandleDeleteInJsThread failed. FormRendererGroup was not founded.");
            return false;
        }
        if (!search->second) {
            HILOG_ERROR("HandleDeleteInJsThread failed. FormRendererGroup was founded but is null.");
            return false;
        }
        if (!compId.empty()) {
            search->second->DeleteForm(compId);
            HILOG_ERROR("HandleDeleteInJsThread compid is %{public}s", compId.c_str());
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

void FormRenderRecord::AddFormRequest(const FormJsInfo &formJsInfo, const Want &want)
{
    auto compId = want.GetStringParam(FORM_RENDERER_COMP_ID);
    HILOG_INFO("AddFormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formJsInfo.formId).c_str(), compId.c_str());
    if (compId.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    Ace::FormRequest formRequest;
    formRequest.compId = compId;
    formRequest.want = want;
    formRequest.want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    formRequest.isDynamic = formJsInfo.isDynamic;
    formRequest.formJsInfo = formJsInfo;
    auto iter = formRequests_.find(formJsInfo.formId);
    if (iter == formRequests_.end()) {
        std::unordered_map<std::string, Ace::FormRequest> formRequests;
        formRequests.emplace(compId, formRequest);
        formRequests_.emplace(formJsInfo.formId, formRequests);
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter != iter->second.end()) {
        iter->second.erase(innerIter);
    }
    iter->second.emplace(compId, formRequest);
}

void FormRenderRecord::AddFormRequest(int64_t formId, const Ace::FormRequest &formRequest)
{
    HILOG_INFO("AddFormRequest by FormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formId).c_str(), formRequest.compId.c_str());
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    auto iter = formRequests_.find(formId);
    if (iter == formRequests_.end()) {
        std::unordered_map<std::string, Ace::FormRequest> formRequests;
        formRequests.emplace(formRequest.compId, formRequest);
        formRequests_.emplace(formId, formRequests);
        return;
    }

    auto innerIter = iter->second.find(formRequest.compId);
    if (innerIter != iter->second.end()) {
        iter->second.erase(innerIter);
    }
    iter->second.emplace(formRequest.compId, formRequest);
}

void FormRenderRecord::DeleteFormRequest(int64_t formId, const std::string &compId)
{
    HILOG_INFO("DeleteFormRequest formId: %{public}s, compId: %{public}s.",
        std::to_string(formId).c_str(), compId.c_str());
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    auto iter = formRequests_.find(formId);
    if (iter == formRequests_.end()) {
        return;
    }

    if (compId.empty()) {
        formRequests_.erase(iter);
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter != iter->second.end()) {
        iter->second.erase(innerIter);
        if (iter->second.empty()) {
            formRequests_.erase(iter);
        }
    }
}

void FormRenderRecord::UpdateFormRequestReleaseState(
    int64_t formId, const std::string &compId, bool hasRelease)
{
    HILOG_INFO("Update ReleaseState formId: %{public}s, compId: %{public}s, hasRelease: %{public}d.",
        std::to_string(formId).c_str(), compId.c_str(), hasRelease);
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    auto iter = formRequests_.find(formId);
    if (iter == formRequests_.end()) {
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter == iter->second.end()) {
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

        FormMemoryGuard memoryGuard;
        bool ret = renderRecord->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty);
        if (ret) {
            renderRecord->UpdateFormRequestReleaseState(formId, compId, true);
        }
    };
    eventHandler->PostSyncTask(task, "ReleaseRenderer");
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
    if (eventHandler_ == nullptr) {
        HILOG_INFO("eventHandler is null.");
        return;
    }

    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleReleaseInJsThread();
    };
    eventHandler_->PostSyncTask(syncTask, "HandleReleaseInJsThread");
    if (eventRunner_) {
        eventRunner_->Stop();
        eventRunner_.reset();
    }

    eventHandler_.reset();
}

void FormRenderRecord::HandleReleaseInJsThread()
{
    if (runtime_) {
        runtime_.reset();
    }
    ReleaseHapFileHandle();
}

void FormRenderRecord::ReAddAllRecycledForms()
{
    HILOG_INFO("ReAdd all recycled forms start.");
    if (!CheckEventHandler(false, true)) {
        HILOG_ERROR("CheckEventHandler failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    for (const auto& formRequests : formRequests_) {
        for (const auto& formRequest : formRequests.second) {
            if (!formRequest.second.hasRelease) {
                continue;
            }

            std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
            auto task = [thisWeakPtr, formJsInfo = formRequest.second.formJsInfo,
                want = formRequest.second.want]() {
                auto renderRecord = thisWeakPtr.lock();
                if (renderRecord) {
                    renderRecord->HandleUpdateInJsThread(formJsInfo, want);
                }
            };
            eventHandler_->PostTask(task, "ReAddAllRecycledForms");
        }
    }

    HILOG_INFO("ReAdd all recycled forms end.");
}

void FormRenderRecord::ReAddRecycledForms(const std::vector<FormJsInfo> &formJsInfos)
{
    HILOG_INFO("ReAdd recycled form start");
    if (!CheckEventHandler(false, true)) {
        HILOG_ERROR("CheckEventHandler failed.");
        return;
    }

    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    for (const auto &form : formJsInfos) {
        auto iter = formRequests_.find(form.formId);
        if (iter == formRequests_.end()) {
            continue;
        }

        for (const auto& formRequest : iter->second) {
            if (!formRequest.second.hasRelease) {
                continue;
            }

            std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
            auto task = [thisWeakPtr, form,
                    want = formRequest.second.want]() {
                auto renderRecord = thisWeakPtr.lock();
                if (renderRecord) {
                    renderRecord->HandleUpdateInJsThread(form, want);
                }
            };
            eventHandler_->PostTask(task, "ReAddRecycledForms");
        }
    }

    HILOG_INFO("ReAdd recycled forms end.");
}

void FormRenderRecord::HandleDestroyInJsThread()
{
    HILOG_INFO("FormRenderService is exiting, destroy some resources in js thread.");
    MarkThreadAlive();
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        formRequests_.clear();
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
        if (!CheckEventHandler(true, true)) {
            HILOG_ERROR("eventHandler is nullptr");
            return RELOAD_FORM_FAILED;
        }

        ReAddRecycledForms(formJsInfos);
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
    eventHandler_->PostTask(task, "ReloadFormRecord");
    ReAddRecycledForms(formJsInfos);
    return ERR_OK;
}

int32_t FormRenderRecord::OnUnlock()
{
    HILOG_DEBUG("OnUnlock called");
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr]() {
        HILOG_DEBUG("HandleOnUnlock begin.");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleOnUnlock();
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return RENDER_FORM_FAILED;
    }
    eventHandler_->PostTask(task, "OnUnlock");
    return ERR_OK;
}

int32_t FormRenderRecord::HandleOnUnlock()
{
    HILOG_INFO("HandleOnUnlock called.");
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        for (const auto& formRequests : formRequests_) {
            for (auto& formRequestElement : formRequests.second) {
                Want* want = const_cast<Want*>(&formRequestElement.second.want);
                want->SetParam(Constants::FORM_RENDER_STATE, true);
            }
        }
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    for (const auto& iter : formRendererGroupMap_) {
        if (iter.second) {
            iter.second->OnUnlock();
        }
    }
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
        for (auto formRequest : group->GetAllRendererFormRequests()) {
            formRequest.isDynamic = form.isDynamic;
            formRequest.formJsInfo = form;
            AddFormRequest(form.formId, formRequest);
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
        if (!CheckEventHandler(true, true)) {
            HILOG_ERROR("eventHandler is nullptr");
            return;
        }

        ReAddAllRecycledForms();
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

    eventHandler_->PostTask(task, "UpdateConfiguration");
    ReAddAllRecycledForms();
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

void FormRenderRecord::FormRenderGC()
{
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleFormRenderGC();
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return;
    }
    eventHandler_->PostSyncTask(task, "HandleFormRenderGC");
}

void FormRenderRecord::HandleFormRenderGC()
{
    HILOG_INFO("HandleFormRenderGC.");
    if (runtime_ == nullptr) {
        HILOG_ERROR("runtime_ is null.");
        return;
    }
    panda::JSNApi::TriggerGC((static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).GetEcmaVm(),
        panda::JSNApi::TRIGGER_GC_TYPE::FULL_GC);
}

int32_t FormRenderRecord::RecycleForm(const int64_t &formId, std::string &statusData)
{
    HILOG_INFO("RecycleForm begin, formId: %{public}s.", std::to_string(formId).c_str());
    int32_t result = RECYCLE_FORM_FAILED;
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return RENDER_FORM_FAILED;
    }

    auto task = [thisWeakPtr = weak_from_this(), formId, &statusData, &result]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }

        result = renderRecord->HandleRecycleForm(formId, statusData);
    };
    eventHandler_->PostSyncTask(task, "RecycleForm");
    return result;
}

int32_t FormRenderRecord::HandleRecycleForm(const int64_t &formId, std::string &statusData)
{
    HILOG_INFO("HandleRecycleForm begin, formId: %{public}s.", std::to_string(formId).c_str());
    MarkThreadAlive();

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto search = formRendererGroupMap_.find(formId);
    if (search == formRendererGroupMap_.end()) {
        HILOG_ERROR("HandleRecycleForm failed. FormRendererGroup was not founded.");
        return RECYCLE_FORM_FAILED;
    }
    if (!search->second) {
        HILOG_ERROR("HandleRecycleForm failed. FormRendererGroup was founded but is null.");
        return RECYCLE_FORM_FAILED;
    }

    search->second->RecycleForm(statusData);
    return ERR_OK;
}

int32_t FormRenderRecord::RecoverForm(const int64_t &formId,
    const std::string &statusData, const bool &isRecoverFormToHandleClickEvent)
{
    HILOG_INFO("RecoverForm begin, formId: %{public}s.", std::to_string(formId).c_str());
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return RENDER_FORM_FAILED;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formId, statusData, isRecoverFormToHandleClickEvent]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr");
            return;
        }
        renderRecord->HandleRecoverForm(formId, statusData, isRecoverFormToHandleClickEvent);
    };
    eventHandler_->PostTask(task, "RecoverForm");
    return ERR_OK;
}

void FormRenderRecord::HandleRecoverForm(const int64_t &formId,
    const std::string &statusData, const bool &isRecoverFormToHandleClickEvent)
{
    HILOG_INFO("HandleRecoverForm begin, formId: %{public}s, uid: %{public}s.", std::to_string(formId).c_str(),
        uid_.c_str());
    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        auto iter = formRequests_.find(formId);
        if (iter == formRequests_.end()) {
            HILOG_ERROR("%{public}s doesn't has formRequest", std::to_string(formId).c_str());
            return;
        }
        formRequests = iter->second;
    }
    if (formRequests.empty()) {
        HILOG_ERROR("formRequests is empty");
        return;
    }

    if (!BeforeHandleUpdateForm(formRequests.begin()->second.formJsInfo)) {
        HILOG_ERROR("recover form prepare failed");
        return;
    }

    if (formRequests.size() == 1) {
        auto formRequest = formRequests.begin()->second;
        if (formRequest.hasRelease) {
            Want want = formRequest.want;
            want.SetParam(Constants::FORM_STATUS_DATA, statusData);
            want.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, isRecoverFormToHandleClickEvent);

            AddRenderer(formRequest.formJsInfo, want);
            formRequest.hasRelease = false;
            AddFormRequest(formId, formRequest);
        }
    }
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
