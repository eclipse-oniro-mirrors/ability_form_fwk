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
#include "form_constants.h"
#include "form_memory_guard.h"
#include "form_module_checker.h"
#include "form_render_event_report.h"
#include "nlohmann/json.hpp"
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
    HILOG_INFO("Message=%{public}s", message.c_str());
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
    const std::string &bundleName, const std::string &uid, bool needMonitored, sptr<IFormSupply> client)
{
    HILOG_INFO("bundleName is %{public}s, uid is %{public}s", bundleName.c_str(), uid.c_str());
    std::shared_ptr<FormRenderRecord> renderRecord = std::make_shared<FormRenderRecord>(bundleName, uid, client);
    if (!renderRecord) {
        HILOG_ERROR("Create FormRenderRecord failed");
        return nullptr;
    }

    if (!renderRecord->CreateEventHandler(bundleName, needMonitored)) {
        HILOG_ERROR("CreateEventHandler failed");
        return nullptr;
    }
    return renderRecord;
}

FormRenderRecord::FormRenderRecord(
    const std::string &bundleName, const std::string &uid, const sptr<IFormSupply> client)
    : bundleName_(bundleName), uid_(uid), formSupplyClient_(client)
{
    HILOG_INFO("bundleName is %{public}s,uid is %{public}s", bundleName.c_str(), uid.c_str());
    threadState_ = std::make_shared<ThreadState>(CHECK_THREAD_TIME);
    formSupplyClient_ = client;
}

FormRenderRecord::~FormRenderRecord()
{
    HILOG_INFO("call");
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_WARN("null eventHandler");
        return;
    }

    // Some resources need to be deleted in a JS thread
    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleDestroyInJsThread();
    };
    eventHandler->PostSyncTask(syncTask, "Destory FormRenderRecord");
}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Form host is died,clean resources");
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
        HILOG_ERROR("null eventHandler");
        return;
    }

    auto task = [weak = weak_from_this(), formId]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
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
    HILOG_INFO("call");
    if (eventHandler_) {
        HILOG_DEBUG("EventHandle is exist,no need to create a new one");
        return true;
    }
    // Create event runner
    HILOG_INFO("Create eventHandle");
    if (eventRunner_ == nullptr) {
        eventRunner_ = EventRunner::Create(bundleName);
        if (eventRunner_ == nullptr) {
            HILOG_ERROR("Create event runner Failed");
            return false;
        }
    }
    // Create event handler
    eventHandler_ = std::make_shared<EventHandler>(eventRunner_);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("Create event handler failed");
        return false;
    }

    if (needMonitored && !hasMonitor_) {
        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr]() {
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("null renderRecord");
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
    HILOG_INFO("add watchDog monitor, bundleName is %{public}s, uid is %{public}s",
        bundleName_.c_str(), uid_.c_str());
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

void FormRenderRecord::OnRenderingBlock(const std::string &bundleName)
{
    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }

    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    formSupplyClient->OnRenderingBlock(bundleName);
}

void FormRenderRecord::Timer()
{
    TaskState taskState = RunTask();
    if (taskState == TaskState::BLOCK) {
        HILOG_ERROR("FRS block happened when bundleName is %{public}s, uid is %{public}s",
            bundleName_.c_str(), uid_.c_str());
        FormRenderEventReport::SendBlockFaultEvent(processId_, jsThreadId_, bundleName_);
        OnRenderingBlock(bundleName_);
    }
}

TaskState FormRenderRecord::RunTask()
{
    std::unique_lock<std::mutex> lock(watchDogMutex_);
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (eventHandler_ == nullptr) {
            HILOG_DEBUG("null eventHandler when bundleName %{public}s", bundleName_.c_str());
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
            HILOG_ERROR("null renderRecord");
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
            HILOG_ERROR("Watchdog checkTask postTask false");
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
    HILOG_DEBUG("Updated record");
    {
        // Some resources need to be initialized in a JS thread
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        if (!CheckEventHandler(true, formJsInfo.isDynamic)) {
            HILOG_ERROR("null eventHandler_ ");
            return RENDER_FORM_FAILED;
        }

        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr, formJsInfo, want]() {
            HILOG_DEBUG("HandleUpdateInJsThread begin");
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("null renderRecord");
                return;
            }
            renderRecord->HandleUpdateInJsThread(formJsInfo, want);
        };
        eventHandler_->PostTask(task, "UpdateRenderRecord");
    }

    if (hostRemoteObj == nullptr) {
        HILOG_WARN("null hostRemoteObj");
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
    HILOG_INFO("Delete some resources formId:%{public}" PRId64 ",%{public}s", formId, compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        DeleteFormRequest(formId, compId);
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
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
        HILOG_DEBUG("runtime is exist,no need to create a new one");
        return true;
    }

    HILOG_INFO("Create a new runtime");
    if (eventRunner_ == nullptr) {
        HILOG_ERROR("null eventRunner_");
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

    SetPkgContextInfoMap(formJsInfo, options);

    runtime_ = AbilityRuntime::Runtime::Create(options);
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed");
        return false;
    }
    hapPath_ = formJsInfo.jsFormCodePath;
    return true;
}

bool FormRenderRecord::UpdateRuntime(const FormJsInfo &formJsInfo)
{
    auto moduleInfo = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
    if (moduleInfo != contextsMapForModuleName_.end()) {
        return false;
    }
    if (!runtime_) {
        HILOG_ERROR("runtime is not exist. %{public}s", formJsInfo.bundleName.c_str());
        return false;
    }
    std::string moduleName = formJsInfo.moduleName;
    HILOG_INFO("update runtime for bundle:%{public}s, module %{public}s",
        formJsInfo.bundleName.c_str(), moduleName.c_str());
    AbilityRuntime::Runtime::Options options;
    SetPkgContextInfoMap(formJsInfo, options);
    auto contextInfo = options.pkgContextInfoJsonStringMap.find(moduleName);
    if (contextInfo != options.pkgContextInfoJsonStringMap.end()) {
        auto pkgNameInfo = options.packageNameList.find(moduleName);
        std::string packageName;
        if (pkgNameInfo != options.packageNameList.end()) {
            packageName = pkgNameInfo->second;
        }
        runtime_->UpdatePkgContextInfoJson(moduleName, contextInfo->second, packageName);
        if (runtime_->GetLanguage() == AbilityRuntime::Runtime::Language::JS) {
            HILOG_INFO("%{public}s load components of new module %{public}s",
                formJsInfo.bundleName.c_str(), moduleName.c_str());
            (static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).ReloadFormComponent();
        }
    }
    return true;
}

bool FormRenderRecord::SetPkgContextInfoMap(const FormJsInfo &formJsInfo, AbilityRuntime::Runtime::Options &options)
{
    std::map<std::string, std::string> pkgContextInfoJsonStringMap;
    for (auto modulePkgNamePair : formJsInfo.modulePkgNameMap) {
        nlohmann::json moduleInfos = nlohmann::json::parse(modulePkgNamePair.second, nullptr, false);
        if (moduleInfos.is_discarded()) {
            HILOG_ERROR("fail parse modulePkgNamePair");
            continue;
        }
        std::string pkgName = "";
        std::string hapPath = "";
        if (moduleInfos.contains(Constants::MODULE_PKG_NAME_KEY) &&
            moduleInfos.at(Constants::MODULE_PKG_NAME_KEY).is_string()) {
            pkgName = moduleInfos[Constants::MODULE_PKG_NAME_KEY].get<std::string>();
            options.packageNameList[modulePkgNamePair.first] = pkgName;
        }
        if (moduleInfos.contains(Constants::MODULE_HAP_PATH_KEY) &&
            moduleInfos.at(Constants::MODULE_HAP_PATH_KEY).is_string()) {
            hapPath = moduleInfos[Constants::MODULE_HAP_PATH_KEY].get<std::string>();
            pkgContextInfoJsonStringMap[modulePkgNamePair.first] = hapPath;
        }
        HILOG_DEBUG("SetPkgContextInfoMap module:%{public}s, pkgName:%{public}s, hapPath:%{public}s",
            modulePkgNamePair.first.c_str(), pkgName.c_str(), hapPath.c_str());
    }
    if (!pkgContextInfoJsonStringMap.empty()) {
        HILOG_INFO("set pkgContextInfoJsonStringMap for %{public}s", formJsInfo.bundleName.c_str());
        options.pkgContextInfoJsonStringMap = pkgContextInfoJsonStringMap;
    }
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
            if (iter->second == nullptr) {
                HILOG_WARN("null Context, bundle name is %{public}s", formJsInfo.bundleName.c_str());
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
    HILOG_INFO("Create a new context");
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (context == nullptr) {
        HILOG_ERROR("Create context failed");
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
    HILOG_INFO("Get formRendererGroup");
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
    HILOG_INFO("Create formRendererGroup");
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
    if (runtime_ == nullptr) {
        if (!CreateRuntime(formJsInfo)) {
            HILOG_ERROR("Create runtime failed");
            return false;
        }
    } else {
        UpdateRuntime(formJsInfo);
    }
    HILOG_DEBUG("BeforeHandleUpdateForm end");
    return true;
}

void FormRenderRecord::HandleUpdateForm(const FormJsInfo &formJsInfo, const Want &want)
{
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_DEBUG("renderType is %{public}d", renderType);
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
            HILOG_WARN("Without this form:%{public}" PRId64 "", formJsInfo.formId);
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

    bool isDynamicFormNeedRecover = false;
    for (const auto& iter : formRequests) {
        auto formRequest = iter.second;
        MergeFormData(formRequest, formJsInfo);
        if (!formRequest.hasRelease) {
            UpdateRenderer(formJsInfo);
            AddFormRequest(formJsInfo.formId, formRequest);
            continue;
        }
        if (formJsInfo.isDynamic) {
            isDynamicFormNeedRecover = true;
            continue;
        }
        if (compMaxId == formRequest.compId) {
            AddRenderer(formJsInfo, formRequest.want);
            formRequest.hasRelease = false;
            AddFormRequest(formJsInfo.formId, formRequest);
        }
    }

    if (isDynamicFormNeedRecover) {
        std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
        bool isHandleClickEvent = false;
        HandleRecoverForm(formJsInfo, statusData, isHandleClickEvent);
        UpdateRenderer(formJsInfo);
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
        HILOG_ERROR("Create Context failed");
        return;
    }

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto formRendererGroup = GetFormRendererGroup(formJsInfo, context, runtime_);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
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
    HILOG_INFO("Delete some resources in js thread");
    MarkThreadAlive();
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("invalid FormRendererGroup");
            return false;
        }
        if (!search->second) {
            HILOG_ERROR("FormRendererGroup was founded but null");
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
    HILOG_INFO("AddFormRequest formId:%{public}s, compId:%{public}s",
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
    HILOG_INFO("AddFormRequest by FormRequest formId:%{public}s, compId:%{public}s",
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
    bool isRequestEmpty = false;
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        auto iter = formRequests_.find(formId);
        if (iter == formRequests_.end()) {
            HILOG_ERROR("invalid request,formId:%{public}" PRId64, formId);
            return;
        }

        if (compId.empty()) {
            formRequests_.erase(iter);
            isRequestEmpty = true;
        } else {
            auto innerIter = iter->second.find(compId);
            if (innerIter != iter->second.end()) {
                iter->second.erase(innerIter);
            }
            if (iter->second.empty()) {
                formRequests_.erase(iter);
                isRequestEmpty = true;
            }
        }
    }
    if (isRequestEmpty) {
        std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
        recycledFormCompIds_.erase(formId);
    }
    HILOG_INFO("delete request formId:%{public}" PRId64 " compId:%{public}s request empty:%{public}d",
        formId, compId.c_str(), isRequestEmpty);
}

void FormRenderRecord::UpdateFormRequestReleaseState(
    int64_t formId, const std::string &compId, bool hasRelease)
{
    HILOG_INFO("Update ReleaseState formId:%{public}" PRId64 ", compId:%{public}s, hasRelease:%{public}d",
        formId, compId.c_str(), hasRelease);
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    auto iter = formRequests_.find(formId);
    if (iter == formRequests_.end()) {
        HILOG_ERROR("invalid request,formId:%{public}" PRId64, formId);
        return;
    }

    auto innerIter = iter->second.find(compId);
    if (innerIter == iter->second.end()) {
        HILOG_ERROR("invalid compId,formId:%{public}" PRId64, formId);
        return;
    }

    for (auto& formRequest : iter->second) {
        formRequest.second.hasRelease = hasRelease;
    }
}

void FormRenderRecord::ReleaseRenderer(
    int64_t formId, const std::string &compId, bool &isRenderGroupEmpty)
{
    HILOG_INFO("Release renderer which formId:%{public}s, compId:%{public}s start.",
        std::to_string(formId).c_str(), compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }

    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }

        FormMemoryGuard memoryGuard;
        bool ret = renderRecord->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty);
        if (ret) {
            renderRecord->UpdateFormRequestReleaseState(formId, compId, true);
        } else {
            HILOG_ERROR("release renderer error, skip update state, formId:%{public}" PRId64, formId);
        }
    };
    eventHandler->PostSyncTask(task, "ReleaseRenderer");
}

bool FormRenderRecord::HandleReleaseRendererInJsThread(
    int64_t formId, const std::string &compId, bool &isRenderGroupEmpty)
{
    HILOG_INFO("Release renderer which formId:%{public}s, compId:%{public}s in js thread.",
        std::to_string(formId).c_str(), compId.c_str());
    MarkThreadAlive();
    if (compId.empty()) {
        HILOG_ERROR("compId empty");
        return false;
    }

    std::pair<std::vector<std::string>, std::string> compIds;
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("invalid rendererGroup");
            return false;
        }

        if (!search->second) {
            HILOG_ERROR("null rendererGroup");
            return false;
        }
        
        compIds = search->second->GetOrderedAndCurrentCompIds();
        search->second->DeleteForm();
        formRendererGroupMap_.erase(formId);
        isRenderGroupEmpty = formRendererGroupMap_.empty();
    }
    {
        std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
        recycledFormCompIds_.erase(formId);
        recycledFormCompIds_.emplace(formId, compIds);
    }
    return true;
}

void FormRenderRecord::Release()
{
    HILOG_INFO("Release runtime and eventHandler");
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        HILOG_INFO("null eventHandler");
        return;
    }

    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
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
    contextsMapForModuleName_.clear();
}

void FormRenderRecord::HandleReleaseInJsThread()
{
    if (runtime_) {
        runtime_.reset();
    }
    ReleaseHapFileHandle();
}

void FormRenderRecord::RecoverFormsByConfigUpdate(std::vector<int64_t> &formIds,
    const sptr<IFormSupply> &formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    if (formIds.empty()) {
        HILOG_INFO("empty needRecoverFormIds");
        return;
    }

    formSupplyClient->OnRecoverFormsByConfigUpdate(formIds);
}

void FormRenderRecord::ReAddAllRecycledForms(const sptr<IFormSupply> &formSupplyClient)
{
    HILOG_INFO("ReAdd all recycled forms start");
    if (!CheckEventHandler(false, true)) {
        HILOG_ERROR("CheckEventHandler failed");
        return;
    }

    std::vector<int64_t> formIds;
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    for (const auto& formRequests : formRequests_) {
        for (const auto& formRequest : formRequests.second) {
            if (!formRequest.second.hasRelease) {
                continue;
            }

            if (formRequest.second.isDynamic) {
                formIds.push_back(formRequest.second.formJsInfo.formId);
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

    RecoverFormsByConfigUpdate(formIds, formSupplyClient);

    HILOG_INFO("ReAdd all recycled forms end");
}

void FormRenderRecord::ReAddRecycledForms(const std::vector<FormJsInfo> &formJsInfos)
{
    HILOG_INFO("ReAdd recycled form start");
    if (!CheckEventHandler(false, true)) {
        HILOG_ERROR("CheckEventHandler failed");
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

    HILOG_INFO("ReAdd recycled forms end");
}

void FormRenderRecord::HandleDestroyInJsThread()
{
    HILOG_INFO("FormRenderService is exiting, destroy some resources in js thread");
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
    HILOG_INFO("ReleaseHapFileHandle:%{public}s", hapPath_.c_str());
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
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }
    if (eventHandler == nullptr) {
        if (!CheckEventHandler(true, true)) {
            HILOG_ERROR("null eventHandler");
            return RELOAD_FORM_FAILED;
        }

        ReAddRecycledForms(formJsInfos);
        return ERR_OK;
    }

    if (ReAddIfHapPathChanged(formJsInfos)) {
        return ERR_OK;
    }
    
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, ids = std::forward<decltype(formJsInfos)>(formJsInfos), want]() {
        HILOG_DEBUG("HandleReloadFormRecord begin");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleReloadFormRecord(std::move(ids), want);
    };
    eventHandler->PostTask(task, "ReloadFormRecord");
    ReAddRecycledForms(formJsInfos);
    return ERR_OK;
}

bool FormRenderRecord::ReAddIfHapPathChanged(const std::vector<FormJsInfo> &formJsInfos)
{
    std::shared_ptr<EventHandler> eventHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(eventHandlerMutex_);
        eventHandler = eventHandler_;
    }
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        return false;
    }
    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    for (const auto &formJsInfo : formJsInfos) {
        auto iter = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
        if (iter == contextsMapForModuleName_.end()) {
            continue;
        }

        if (iter->second == nullptr) {
            HILOG_WARN("null Context, bundle name is %{public}s", formJsInfo.bundleName.c_str());
            continue;
        }
        auto hapModuleInfo = iter->second->GetHapModuleInfo();
        if (hapModuleInfo == nullptr || hapModuleInfo->hapPath == formJsInfo.jsFormCodePath) {
            continue;
        }
        HILOG_INFO("hap path changed:%{public}s. current:%{public}s", formJsInfo.jsFormCodePath.c_str(),
            hapModuleInfo->hapPath.c_str());
        auto task = [weak = weak_from_this()]() {
            auto renderRecord = weak.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("null renderRecord");
                return;
            }
            FormMemoryGuard memoryGuard;
            renderRecord->HandleReleaseAllRendererInJsThread();
        };
        eventHandler->PostSyncTask(task, "ReleaseAllRenderer");
        Release();
        ReAddRecycledForms(formJsInfos);
        return true;
    }
    return false;
}

void FormRenderRecord::HandleReleaseAllRendererInJsThread()
{
    bool isRenderGroupEmpty = false;
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    for (auto& formRequests : formRequests_) {
        auto formId = formRequests.first;
        for (auto& formRequestElement : formRequests.second) {
            auto compId = formRequestElement.first;
            bool ret = HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty);
            if (ret) {
                formRequestElement.second.hasRelease = true;
            } else {
                HILOG_ERROR("release renderer error, skip update state, formId:%{public}" PRId64, formId);
            }
        }
    }
}

int32_t FormRenderRecord::OnUnlock()
{
    HILOG_DEBUG("call");
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr]() {
        HILOG_DEBUG("HandleOnUnlock begin");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleOnUnlock();
    };
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("null eventHandler_");
        return RENDER_FORM_FAILED;
    }
    eventHandler_->PostTask(task, "OnUnlock");
    return ERR_OK;
}

int32_t FormRenderRecord::HandleOnUnlock()
{
    HILOG_INFO("call");
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        for (auto& formRequests : formRequests_) {
            for (auto& formRequestElement : formRequests.second) {
                formRequestElement.second.want.SetParam(Constants::FORM_RENDER_STATE, true);
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
    HILOG_INFO("Reload record in js thread");
    MarkThreadAlive();
    if (runtime_ == nullptr) {
        HILOG_ERROR("null runtime_");
        return RELOAD_FORM_FAILED;
    }
    if (runtime_->GetLanguage() == AbilityRuntime::Runtime::Language::JS) {
        // In the card upgrade condition, new components may be added and need to be reloaded
        HILOG_DEBUG("ReloadFormComponent");
        (static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).ReloadFormComponent();
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    for (auto form : formJsInfos) {
        auto search = formRendererGroupMap_.find(form.formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("invalid FormRendererGroup");
            continue;
        }
        auto group = search->second;
        if (!group) {
            HILOG_ERROR("null FormRendererGroup");
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

size_t FormRenderRecord::FormCount()
{
    return formRequests_.size();
}

void FormRenderRecord::UpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config, const sptr<IFormSupply> &formSupplyClient)
{
    HILOG_INFO("UpdateConfiguration begin");
    if (!config) {
        HILOG_ERROR("UpdateConfiguration failed due to null config");
        return;
    }

    SetConfiguration(config);
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (eventHandler_ == nullptr) {
        if (!CheckEventHandler(true, true)) {
            HILOG_ERROR("null eventHandler");
            return;
        }

        ReAddAllRecycledForms(formSupplyClient);
        return;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, config]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleUpdateConfiguration(config);
    };

    eventHandler_->PostTask(task, "UpdateConfiguration");
    ReAddAllRecycledForms(formSupplyClient);
}

void FormRenderRecord::HandleUpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    HILOG_INFO("HandleUpdateConfiguration begin");
    MarkThreadAlive();
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    if (!config) {
        HILOG_ERROR("null configuration");
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
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleFormRenderGC();
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("null eventHandler_");
        return;
    }
    eventHandler_->PostSyncTask(task, "HandleFormRenderGC");
}

void FormRenderRecord::HandleFormRenderGC()
{
    HILOG_INFO("HandleFormRenderGC");
    if (runtime_ == nullptr) {
        HILOG_ERROR("null runtime_");
        return;
    }
    panda::JSNApi::TriggerGC((static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).GetEcmaVm(),
        panda::JSNApi::TRIGGER_GC_TYPE::FULL_GC);
}

int32_t FormRenderRecord::RecycleForm(const int64_t &formId, std::string &statusData)
{
    HILOG_INFO("RecycleForm begin, formId:%{public}s", std::to_string(formId).c_str());
    int32_t result = RECYCLE_FORM_FAILED;
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("null eventHandler_");
        return RENDER_FORM_FAILED;
    }

    auto task = [thisWeakPtr = weak_from_this(), formId, &statusData, &result]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }

        result = renderRecord->HandleRecycleForm(formId, statusData);
    };
    eventHandler_->PostSyncTask(task, "RecycleForm");
    return result;
}

int32_t FormRenderRecord::HandleRecycleForm(const int64_t &formId, std::string &statusData)
{
    HILOG_INFO("HandleRecycleForm begin,formId:%{public}s", std::to_string(formId).c_str());
    MarkThreadAlive();

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto search = formRendererGroupMap_.find(formId);
    if (search == formRendererGroupMap_.end()) {
        HILOG_ERROR("invalid FormRendererGroup");
        return RECYCLE_FORM_FAILED;
    }
    if (!search->second) {
        HILOG_ERROR("FormRendererGroup was founded but null");
        return RECYCLE_FORM_FAILED;
    }

    search->second->RecycleForm(statusData);
    return ERR_OK;
}

int32_t FormRenderRecord::RecoverForm(const FormJsInfo &formJsInfo,
    const std::string &statusData, const bool &isRecoverFormToHandleClickEvent)
{
    auto formId = formJsInfo.formId;
    HILOG_INFO("RecoverForm begin, formId:%{public}s", std::to_string(formId).c_str());
    std::lock_guard<std::mutex> lock(eventHandlerMutex_);
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("null eventHandler_");
        return RENDER_FORM_FAILED;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formJsInfo, statusData, isRecoverFormToHandleClickEvent]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord");
            return;
        }
        renderRecord->HandleRecoverForm(formJsInfo, statusData, isRecoverFormToHandleClickEvent);
    };
    eventHandler_->PostTask(task, "RecoverForm");
    return ERR_OK;
}

void FormRenderRecord::HandleRecoverForm(const FormJsInfo &formJsInfo,
    const std::string &statusData, const bool &isHandleClickEvent)
{
    auto formId = formJsInfo.formId;
    HILOG_INFO("HandleRecoverForm begin, formId:%{public}s, uid:%{public}s", std::to_string(formId).c_str(),
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
        HILOG_ERROR("empty formRequests");
        return;
    }

    if (!BeforeHandleUpdateForm(formRequests.begin()->second.formJsInfo)) {
        HILOG_ERROR("recover form prepare failed");
        return;
    }

    if (RecoverFormRequestsInGroup(formJsInfo, statusData, isHandleClickEvent, formRequests)) {
        for (auto formRequestIter : formRequests) {
            formRequestIter.second.hasRelease = false;
            AddFormRequest(formId, formRequestIter.second);
        }
    }
}

bool FormRenderRecord::RecoverFormRequestsInGroup(const FormJsInfo &formJsInfo, const std::string &statusData,
    const bool &isHandleClickEvent, const std::unordered_map<std::string, Ace::FormRequest> &recordFormRequests)
{
    auto formId = formJsInfo.formId;
    std::vector<std::string> orderedCompIds;
    std::string currentCompId;
    {
        std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
        auto pairIter = recycledFormCompIds_.find(formId);
        if (pairIter == recycledFormCompIds_.end()) {
            HILOG_ERROR("invalid compIdPair,formId:%{public}" PRId64, formId);
            return false;
        }
        orderedCompIds = pairIter->second.first;
        currentCompId = pairIter->second.second;
        HILOG_INFO("compIds size:%{public}zu,current compId:%{public}s,formId:%{public}" PRId64,
            orderedCompIds.size(), currentCompId.c_str(), formId);
    }

    std::vector<Ace::FormRequest> groupRequests;
    size_t currentRequestIndex;
    bool currentRequestFound = false;

    for (auto compId : orderedCompIds) {
        auto recordRequestIter = recordFormRequests.find(compId);
        if (recordRequestIter == recordFormRequests.end()) {
            HILOG_WARN("invalid formRequest,formId:%{public}" PRId64 " compId=%{public}s", formId, compId.c_str());
            continue;
        }
        auto recordRequest = recordRequestIter->second;
        Ace::FormRequest groupRequest;
        groupRequest.compId = compId;
        groupRequest.want = recordRequest.want;
        groupRequest.formJsInfo = recordRequest.formJsInfo; // get json data from record request
        groupRequest.formJsInfo.imageDataMap = formJsInfo.imageDataMap;

        if (compId == currentCompId) {
            groupRequest.want.SetParam(Constants::FORM_STATUS_DATA, statusData);
            groupRequest.want.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, isHandleClickEvent);
            currentRequestIndex = groupRequests.size();
            currentRequestFound = true;
        }
        groupRequests.emplace_back(groupRequest);
    }

    if (groupRequests.empty()) {
        HILOG_ERROR("group requests empty formId:%{public}" PRId64, formId);
        return false;
    }

    if (!currentRequestFound) {
        // maybe current comp deleted between recover, get last comp as new current comp to recover
        currentRequestIndex = groupRequests.size() - 1;
        HILOG_WARN("current request index:%{public}zu formId:%{public}" PRId64, currentRequestIndex, formId);
    }
    return RecoverRenderer(groupRequests, currentRequestIndex);
}

bool FormRenderRecord::RecoverRenderer(const std::vector<Ace::FormRequest> &groupRequests,
    const size_t &currentRequestIndex)
{
    if (currentRequestIndex >= groupRequests.size()) {
        HILOG_ERROR("current comp index %{public}zu invalid", currentRequestIndex);
        return false;
    }
    auto currentRequest = groupRequests[currentRequestIndex];
    auto context = GetContext(currentRequest.formJsInfo, currentRequest.want);
    if (context == nullptr) {
        HILOG_ERROR("Create Context failed");
        return false;
    }

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto formRendererGroup = GetFormRendererGroup(currentRequest.formJsInfo, context, runtime_);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return false;
    }
    formRendererGroup->RecoverRenderer(groupRequests, currentRequestIndex);
    HILOG_INFO("recover renderer, formId:%{public}" PRId64, currentRequest.formJsInfo.formId);
    return true;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
