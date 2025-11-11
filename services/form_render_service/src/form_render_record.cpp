/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <fstream>
#include <sstream>

#include "status_mgr_center/form_render_status_task_mgr.h"
#include "ecmascript/napi/include/jsnapi.h"
#include "extractor.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_memory_guard.h"
#include "form_module_checker.h"
#include "form_render_event_report.h"
#include "nlohmann/json.hpp"
#include "xcollie/watchdog.h"
#include "dfx_dump_catcher.h"
#include "form_render_service_mgr.h"

using namespace OHOS::AAFwk::GlobalConfigurationKey;

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
namespace {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr size_t THREAD_BLOCK_TIMEOUT = 10 * 1000;
constexpr int32_t MEMORY_MONITOR_INTERVAL = Constants::MS_PER_DAY * 3;
constexpr size_t RUNTIME_MEMORY_LIMIT = 16 * 1024 * 1024;
constexpr int32_t SET_VISIBLE_CHANGE_FAILED = -1;
constexpr int32_t CHECK_THREAD_TIME = 3;
constexpr size_t THREAD_NAME_LEN = 15;
constexpr char FORM_RENDERER_PROCESS_ON_ADD_SURFACE[] = "ohos.extra.param.key.process_on_add_surface";
constexpr char RENDERING_BLOCK_MONITOR_PREFIX[] = "RenderingBlockMonitorTask_";
constexpr char MEMORY_MONITOR_PREFIX[] = "MemoryMonitorTask_";

inline std::string GetThreadNameByBundle(const std::string &bundleName)
{
    if (bundleName.length() <= THREAD_NAME_LEN) {
        return bundleName;
    }
    return bundleName.substr(bundleName.length() - THREAD_NAME_LEN);
}

uint64_t GetPss()
{
    pid_t pid = getprocpid();
    std::string filePath = "/proc/" + std::to_string(pid) + "/smaps_rollup";
    std::ifstream file(filePath);
    if (!file.is_open()) {
        HILOG_ERROR("pid:%{public}d get pss failed", pid);
        return 0;
    }
    std::string line;
    int64_t pss = 0;
    int64_t swapPss = 0;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key;
        int64_t value;
        std::string unit;
        if (iss >> key >> value >> unit) {
            if (key == "Pss:") {
                pss = value;
            } else if (key == "SwapPss:") {
                swapPss = value;
            }
        }
    }
    file.close();
    return pss + swapPss;
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
    threadState_ = std::make_unique<ThreadState>(CHECK_THREAD_TIME);
    formSupplyClient_ = client;
}

FormRenderRecord::~FormRenderRecord()
{
    HILOG_INFO("call");
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
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
    Release();
    RemoveWatchDogThreadMonitor();
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
    FormRenderServiceMgr::GetInstance().SetCriticalTrueOnFormActivity();
    return hostsMapForFormId_.empty();
}

void FormRenderRecord::DeleteRendererGroup(int64_t formId)
{
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
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
    DeleteFormLocation(formId);
}

bool FormRenderRecord::CreateEventHandler(const std::string &bundleName, bool needMonitored)
{
    std::lock_guard<std::recursive_mutex> lock(eventHandlerMutex_);
    if (eventHandler_) {
        HILOG_DEBUG("EventHandle is exist,no need to create a new one");
        return true;
    }
    // Create event runner
    if (eventRunner_ == nullptr) {
        eventRunner_ = EventRunner::Create(GetThreadNameByBundle(bundleName));
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

    auto threadBlockMonitorTask = [weak = weak_from_this()]() {
        auto renderRecord = weak.lock();
        if (renderRecord) {
            renderRecord->Timer();
        }
    };
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(RENDERING_BLOCK_MONITOR_PREFIX + bundleName_,
        threadBlockMonitorTask, THREAD_BLOCK_TIMEOUT);

    auto memoryMonitorTask = [weak = weak_from_this()]() {
        auto renderRecord = weak.lock();
        if (renderRecord) {
            renderRecord->RuntimeMemoryMonitor();
        }
    };
    OHOS::HiviewDFX::Watchdog::GetInstance().RunPeriodicalTask(MEMORY_MONITOR_PREFIX + bundleName_, memoryMonitorTask,
        MEMORY_MONITOR_INTERVAL);
}

void FormRenderRecord::RemoveWatchDogThreadMonitor()
{
    HILOG_INFO("remove watchDog monitor, bundleName: %{public}s", bundleName_.c_str());
    OHOS::HiviewDFX::Watchdog::GetInstance().RemovePeriodicalTask(RENDERING_BLOCK_MONITOR_PREFIX + bundleName_);
    OHOS::HiviewDFX::Watchdog::GetInstance().RemovePeriodicalTask(MEMORY_MONITOR_PREFIX + bundleName_);
}

void FormRenderRecord::OnRenderingBlock(const std::string &bundleName)
{
    sptr<IFormSupply> formSupplyClient = GetFormSupplyClient();

    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    formSupplyClient->OnRenderingBlock(bundleName);
}

void FormRenderRecord::OnNotifyRefreshForm(const int64_t &formId)
{
    sptr<IFormSupply> formSupplyClient = GetFormSupplyClient();

    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    formSupplyClient->OnNotifyRefreshForm(formId);
    HILOG_WARN("Without this form:%{public}" PRId64 "", formId);
}

void FormRenderRecord::Timer()
{
    TaskState taskState = RunTask();
    if (taskState == TaskState::BLOCK) {
        HILOG_ERROR("FRS block happened when bundleName is %{public}s, uid is %{public}s",
            bundleName_.c_str(), uid_.c_str());
        OHOS::HiviewDFX::DfxDumpCatcher dumplog;
        std::string traceStr;
        bool ret = dumplog.DumpCatch(processId_, jsThreadId_, traceStr);
        if (ret) {
            HILOG_INFO("Print block form's process id %{public}d and thread %{public}d call stack %{public}s",
                processId_, jsThreadId_, traceStr.c_str());
        }
        FormRenderEventReport::SendBlockFaultEvent(bundleName_, "THREAD_BLOCK_" +
            std::to_string(THREAD_BLOCK_TIMEOUT) + "ms", traceStr);
        OnRenderingBlock(bundleName_);
    }
}

TaskState FormRenderRecord::RunTask()
{
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        HILOG_DEBUG("null eventHandler when bundleName %{public}s", bundleName_.c_str());
        return TaskState::NO_RUNNING;
    }

    std::unique_lock<std::mutex> lock(watchDogMutex_);
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

    if (eventHandler == nullptr) {
        return TaskState::NO_RUNNING;
    }

    if (!eventHandler->PostTask(checkTask, "Watchdog Task", 0, AppExecFwk::EventQueue::Priority::IMMEDIATE)) {
        HILOG_ERROR("Watchdog checkTask postTask false");
    }

    return TaskState::RUNNING;
}

void FormRenderRecord::DumpEventHandler()
{
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        return;
    }

    HandlerDumper handlerDumper;
    eventHandler->Dump(handlerDumper);
}

void FormRenderRecord::MarkThreadAlive()
{
    std::unique_lock<std::mutex> lock(watchDogMutex_);
    threadIsAlive_ = true;
    threadState_->ResetState();
}

void FormRenderRecord::MarkRenderFormTaskDone(int32_t renderType)
{
    if (renderType == Constants::RENDER_FORM) {
        renderFormTasksNum--;
    }
}

bool FormRenderRecord::HasRenderFormTask()
{
    return renderFormTasksNum > 0;
}

int32_t FormRenderRecord::UpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IRemoteObject> hostRemoteObj)
{
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    if (renderType == Constants::RENDER_FORM) {
        // Manager delegate proxy invalid, do not render form
        if (!CheckManagerDelegateValid(formJsInfo, want)) {
            HILOG_WARN("Form node has been released");
            return ERR_APPEXECFWK_FORM_FORM_NODE_RELEASED;
        }
        renderFormTasksNum++;
        bool formIsVisible = want.GetBoolParam(Constants::FORM_IS_VISIBLE, false);
        RecordFormVisibility(formJsInfo.formId, formIsVisible);
    }
    int32_t formLocation = want.GetIntParam(Constants::FORM_LOCATION_KEY, -1);
    FormLocationInfo location = { formJsInfo.formName, formLocation };
    RecordFormLocation(formJsInfo.formId, location);
    {
        // Some resources need to be initialized in a JS thread
        if (!CheckEventHandler(true, formJsInfo.isDynamic)) {
            HILOG_ERROR("null eventHandler_ ");
            return ERR_APPEXECFWK_FORM_EVENT_HANDLER_NULL;
        }
        std::shared_ptr<EventHandler> eventHandler = GetEventHandler();

        sptr<IFormSupply> formSupplyClient = GetFormSupplyClient();
        if (formSupplyClient == nullptr) {
            HILOG_ERROR("null formSupplyClient");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        UpdateFormRequest(formJsInfo, want);

        std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
        auto task = [thisWeakPtr, formJsInfo, want, formSupplyClient, renderType]() {
            auto renderRecord = thisWeakPtr.lock();
            if (renderRecord == nullptr) {
                HILOG_ERROR("null renderRecord, formId:%{public}" PRId64, formJsInfo.formId);
                std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
                FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(formJsInfo.formId,
                    FormFsmEvent::RENDER_FORM_FAIL, eventId, formSupplyClient);
                return;
            }
            renderRecord->HandleUpdateRenderRecord(formJsInfo, want, formSupplyClient, renderType);
        };
        if (eventHandler == nullptr) {
            HILOG_ERROR("null eventHandler_ ");
            return RENDER_FORM_FAILED;
        }
        eventHandler->PostTask(task, "UpdateRenderRecord");
    }

    return AddHostByFormId(formJsInfo.formId, hostRemoteObj);
}

void FormRenderRecord::HandleUpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IFormSupply> &formSupplyClient, int32_t renderType)
{
    HandleUpdateInJsThread(formJsInfo, want);
    MarkRenderFormTaskDone(renderType);
    std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(formJsInfo.formId,
        FormFsmEvent::RENDER_FORM_DONE, eventId, formSupplyClient);
    bool isVisible = IsFormVisible(formJsInfo.formId);
    if (renderType == Constants::RENDER_FORM && !isVisible) {
        // after FRS restart, if form invisible, need to reset form invisible status.
        HandleSetVisibleChange(formJsInfo.formId, isVisible);
    }
    HILOG_INFO("HandleUpdateRenderRecord end");
}

void FormRenderRecord::DeleteRenderRecord(int64_t formId, const std::string &compId,
    const sptr<IRemoteObject> hostRemoteObj, bool &isRenderGroupEmpty)
{
    // Some resources need to be deleted in a JS thread
    HILOG_INFO("Delete some resources formId:%{public}" PRId64 ",%{public}s", formId, compId.c_str());
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        DeleteFormRequest(formId, compId);
        RecordFormVisibility(formId, false);
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
        DeleteHostRemoteObjByFormId(formId, hostRemoteObj);
    }
    if (eventHandler == nullptr) {
        return;
    }
    eventHandler->PostSyncTask(task, "DeleteRenderRecord");
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

    runtime_ = std::make_shared<JsFormRuntime>();
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed");
        return false;
    }
    if (!runtime_->Init(options)) {
        HILOG_ERROR("Init runtime Failed");
    }
    hapPath_ = formJsInfo.jsFormCodePath;
    runtime_->SetLocalFontCollectionMaxSize();
    bool ret = runtime_->InsertHapPath(formJsInfo.bundleName, formJsInfo.moduleName, formJsInfo.jsFormCodePath);
    if (!ret) {
        HILOG_ERROR("InsertHapPath Failed");
    }
    RegisterUncatchableErrorHandler();
    return true;
}

bool FormRenderRecord::UpdateRuntime(const FormJsInfo &formJsInfo)
{
    if (IsFormContextExist(formJsInfo)) {
        HILOG_DEBUG("context is exist. %{public}s", formJsInfo.bundleName.c_str());
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
        if (runtime_->GetLanguage() == AbilityRuntime::Runtime::Language::JS) {
            (static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).SetPkgContextInfoJson(moduleName, contextInfo->second,
                packageName);
            HILOG_INFO("%{public}s load components of new module %{public}s",
                formJsInfo.bundleName.c_str(), moduleName.c_str());
            (static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).ReloadFormComponent();
        }
    }
    bool ret = runtime_->InsertHapPath(formJsInfo.bundleName, formJsInfo.moduleName, formJsInfo.jsFormCodePath);
    if (!ret) {
        HILOG_ERROR("InsertHapPath Failed");
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
        HILOG_INFO("SetPkgContextInfoMap module:%{public}s, pkgName:%{public}s, hapPath:%{public}s",
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
    if (configuration_) {
        auto checkConfigItem = {SYSTEM_COLORMODE, SYSTEM_LANGUAGE, SYSTEM_FONT_SIZE_SCALE, SYSTEM_FONT_WEIGHT_SCALE};
        for (const auto& item: checkConfigItem) {
            std::string value = config->GetItem(item);
            if (!value.empty()) {
                configuration_->AddItem(item, value);
            }
        }
    } else {
        configuration_ = config;
    }
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
    if (GetEventHandlerNeedReset()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto key = formJsInfo.formId;
    auto iter = formRendererGroupMap_.find(key);
    if (iter != formRendererGroupMap_.end()) {
        return iter->second;
    }

    auto formRendererGroup = CreateFormRendererGroupLock(formJsInfo, context, runtime);
    if (formRendererGroup != nullptr) {
        HILOG_INFO("formRendererGroupMap emplace formId:%{public}s", std::to_string(key).c_str());
        formRendererGroupMap_.emplace(key, formRendererGroup);
        RecordFormVisibility(key, true);
    }
    return formRendererGroup;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        return nullptr;
    }
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime, eventHandler);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

void FormRenderRecord::UpdateFormRequest(const FormJsInfo &formJsInfo, const Want &want)
{
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_DEBUG("renderType is %{public}d", renderType);
    if (renderType == Constants::RENDER_FORM) {
        AddFormRequest(formJsInfo, want);
        return;
    }

    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    if (!GetFormRequestByFormId(formJsInfo.formId, formRequests)) {
        return;
    }

    for (const auto &iter : formRequests) {
        auto formRequest = iter.second;
        MergeFormData(formRequest, formJsInfo);
        AddFormRequest(formJsInfo.formId, formRequest);
    }
}

int32_t FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Update record in js thread, formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    bool ret = BeforeHandleUpdateForm(formJsInfo);
    if (!ret) {
        HILOG_ERROR("Handle Update Form prepare failed");
        return ERR_APPEXECFWK_FORM_RUNTIME_FAILED;
    }

    return HandleUpdateForm(formJsInfo, want);
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
    return true;
}

int32_t FormRenderRecord::HandleUpdateForm(const FormJsInfo &formJsInfo, const Want &want)
{
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_DEBUG("renderType is %{public}d", renderType);
    if (renderType == Constants::RENDER_FORM) {
        AddRenderer(formJsInfo, want);
        return ERR_OK;
    }

    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    if (!GetFormRequestByFormId(formJsInfo.formId, formRequests)) {
        OnNotifyRefreshForm(formJsInfo.formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_FORM_REQUEST;
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
        if (!formRequest.hasRelease) {
            UpdateRenderer(formJsInfo);
            continue;
        }
        if (formJsInfo.isDynamic) {
            isDynamicFormNeedRecover = true;
            continue;
        }
        if (compMaxId == formRequest.compId) {
            AddRenderer(formRequest.formJsInfo, formRequest.want);
            UpdateFormRequestReleaseState(formJsInfo.formId, formRequest.compId, false);
        }
    }

    if (isDynamicFormNeedRecover) {
        std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
        bool isHandleClickEvent = false;
        HandleRecoverForm(formJsInfo, statusData, isHandleClickEvent);
    }

    return ERR_OK;
}

void FormRenderRecord::MergeFormData(Ace::FormRequest &formRequest, const FormJsInfo &formJsInfo)
{
    FormProviderData formProviderData = FormProviderData(formRequest.formJsInfo.formData, true);
    nlohmann::json newFormData = formJsInfo.formProviderData.GetData();
    formProviderData.MergeData(newFormData);

    std::map<std::string, sptr<FormAshmem>> imageMap = formRequest.formJsInfo.imageDataMap;
    formRequest.formJsInfo = formJsInfo;
    // if imageDataMap of formJsInfo is empty, do not replace
    if (formJsInfo.imageDataMap.size() == 0) {
        formRequest.formJsInfo.imageDataMap = imageMap;
    }
    formRequest.formJsInfo.formData = formProviderData.GetDataString();
}

void FormRenderRecord::AddRenderer(const FormJsInfo &formJsInfo, const Want &want)
{
    auto context = GetContext(formJsInfo, want);
    if (context == nullptr) {
        HILOG_ERROR("Create Context failed");
        return;
    }

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
        HILOG_INFO("UpdateForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    } else {
        HILOG_ERROR("UpdateForm failed:%{public}s", std::to_string(formJsInfo.formId).c_str());
    }
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
            RecordFormVisibility(formId, false);
            HILOG_ERROR("HandleDeleteInJsThread compid is %{public}s", compId.c_str());
            if (search->second->IsFormRequestsEmpty()) {
                formRendererGroupMap_.erase(formId);
                DeleteFormLocation(formId);
            }
            return false;
        }
        search->second->DeleteForm();
        formRendererGroupMap_.erase(formId);
        DeleteFormLocation(formId);
    }
    RemoveHostByFormId(formId);
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
    auto compId = want.GetStringParam(Constants::FORM_COMP_ID);
    HILOG_INFO("AddFormRequest formId: %{public}s, compId: %{public}s, formJsInfo.formData.size: %{public}zu.",
        std::to_string(formJsInfo.formId).c_str(),
        compId.c_str(),
        formJsInfo.formData.size());
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

void FormRenderRecord::AddFormRequest(int64_t formId, Ace::FormRequest &formRequest)
{
    HILOG_INFO("AddFormRequest by FormRequest formId: %{public}s, compId: %{public}s, formData.size: %{public}zu",
        std::to_string(formId).c_str(),
        formRequest.compId.c_str(),
        formRequest.formJsInfo.formData.size());
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
        DeleteRecycledFormCompIds(formId);
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
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
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
        DeleteFormLocation(formId);
        isRenderGroupEmpty = formRendererGroupMap_.empty();
    }
    DeleteRecycledFormCompIds(formId);
    InsertRecycledFormCompIds(formId, compIds);
    return true;
}

void FormRenderRecord::Release()
{
    std::shared_ptr<EventHandler> eventHandler = eventHandler_;
    std::shared_ptr<EventRunner> eventRunner = eventRunner_;
    {
        std::lock_guard<std::recursive_mutex> lock(eventHandlerMutex_);
        if (eventHandler_ == nullptr) {
            HILOG_INFO("null eventHandler");
            return;
        }
        eventHandler_ = nullptr;
        eventRunner_ = nullptr;
    }
    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        renderRecord->HandleReleaseInJsThread();
    };
    eventHandler->PostSyncTask(syncTask, "HandleReleaseInJsThread");
    if (eventRunner) {
        eventRunner->Stop();
        eventRunner.reset();
    }

    eventHandler.reset();

    std::lock_guard<std::mutex> lock(contextsMapMutex_);
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
            auto task = [thisWeakPtr, formJsInfo = formRequest.second.formJsInfo, want = formRequest.second.want]() {
                auto renderRecord = thisWeakPtr.lock();
                if (!renderRecord) {
                    HILOG_WARN("null renderRecord, formId:%{public}" PRId64, formJsInfo.formId);
                    return;
                }
                int32_t ret = renderRecord->HandleUpdateInJsThread(formJsInfo, want);
                if (ret == ERR_OK) {
                    const auto compId = want.GetStringParam(Constants::FORM_COMP_ID);
                    renderRecord->UpdateFormRequestReleaseState(formJsInfo.formId, compId, false);
                }
            };
            eventHandler_->PostTask(task, "ReAddAllRecycledForms");
        }
    }

    RecoverFormsByConfigUpdate(formIds, formSupplyClient);

    HILOG_INFO("ReAdd all recycled forms end");
}

void FormRenderRecord::PostReAddRecycledForms(const FormJsInfo &formJsInfo, const Want &want)
{
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formJsInfo, newWant = want]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord) {
            int32_t ret = renderRecord->HandleUpdateInJsThread(formJsInfo, newWant);
            if (ret != ERR_OK) {
                FormRenderEventReport::SendFormFailedEvent(FormEventName::RELOAD_FORM_FAILED,
                    formJsInfo.formId,
                    formJsInfo.bundleName,
                    formJsInfo.formName,
                    static_cast<int32_t>(ReloadFormErrorType::RELOAD_FORM_UPDATE_FORM_ERROR),
                    ret);
            }
        }
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("null eventHandler_");
        return;
    }
    eventHandler_->PostTask(task, "ReAddRecycledForms");
}

int32_t FormRenderRecord::ReAddRecycledForms(const std::vector<FormJsInfo> &formJsInfos)
{
    HILOG_INFO("ReAdd recycled forms start");
    if (!CheckEventHandler(false, true)) {
        HILOG_ERROR("CheckEventHandler failed");
        return ERR_APPEXECFWK_FORM_EVENT_HANDLER_NULL;
    }

    for (const auto &form : formJsInfos) {
        std::unordered_map<std::string, Ace::FormRequest> formRequests;
        if (!GetFormRequestByFormId(form.formId, formRequests)) {
            continue;
        }

        for (const auto &formRequest : formRequests) {
            if (!formRequest.second.hasRelease) {
                continue;
            }

            UpdateFormRequest(form, formRequest.second.want);
            PostReAddRecycledForms(form, formRequest.second.want);
        }
    }

    HILOG_INFO("ReAdd recycled forms end");
    return ERR_OK;
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
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        if (!CheckEventHandler(true, true)) {
            HILOG_ERROR("null eventHandler");
            return ERR_APPEXECFWK_FORM_EVENT_HANDLER_NULL;
        }

        return ReAddRecycledForms(formJsInfos);
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
    return ReAddRecycledForms(formJsInfos);
}

bool FormRenderRecord::ReAddIfHapPathChanged(const std::vector<FormJsInfo> &formJsInfos)
{
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        return false;
    }
    HILOG_INFO("restart runtime");
    auto task = [weak = weak_from_this()]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        FormMemoryGuard memoryGuard;
        renderRecord->HandleReleaseAllRendererInJsThread();
    };
    SetEventHandlerNeedResetFlag(true);
    eventHandler->PostSyncTask(task, "ReleaseAllRenderer");
    Release();
    UpdateAllFormRequest(formJsInfos, true);
    SetEventHandlerNeedResetFlag(false);
    {
        std::lock_guard<std::recursive_mutex> lock(eventHandlerMutex_);
        CreateEventHandler(bundleName_, true);
    }
    return ReAddRecycledForms(formJsInfos) == ERR_OK;
}

void FormRenderRecord::HandleReleaseAllRendererInJsThread()
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    MarkThreadAlive();
    for (const auto& iter : formRendererGroupMap_) {
        if (!iter.second) {
            HILOG_ERROR("null rendererGroup");
            continue;
        }
        int64_t formId = iter.first;
        HILOG_INFO("Release renderer which formId:%{public}" PRId64, formId);
        std::pair<std::vector<std::string>, std::string> compIds = iter.second->GetOrderedAndCurrentCompIds();
        iter.second->DeleteForm();
        DeleteRecycledFormCompIds(formId);
        InsertRecycledFormCompIds(formId, compIds);
    }
    formRendererGroupMap_.clear();
}

void FormRenderRecord::UpdateAllFormRequest(const std::vector<FormJsInfo> &formJsInfos, bool hasRelease)
{
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    for (const auto &formJsInfo : formJsInfos) {
        auto iter = formRequests_.find(formJsInfo.formId);
        if (iter == formRequests_.end()) {
            HILOG_ERROR("%{public}" PRId64 " doesn't has formRequest", formJsInfo.formId);
            continue;
        }
        for (auto& formRequestIter : iter->second) {
            auto& formRequest = formRequestIter.second;
            formRequest.isDynamic = formJsInfo.isDynamic;
            formRequest.formJsInfo = formJsInfo;
            formRequest.hasRelease = hasRelease;
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
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler_");
        return RENDER_FORM_FAILED;
    }
    eventHandler->PostTask(task, "OnUnlock");
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

int32_t FormRenderRecord::SetVisibleChange(const int64_t &formId, bool isVisible)
{
    HILOG_INFO("SetVisibleChange, formId:%{public}s", std::to_string(formId).c_str());
    RecordFormVisibility(formId, isVisible);
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler");
        return SET_VISIBLE_CHANGE_FAILED;
    }
    auto task = [thisWeakPtr = weak_from_this(), formId, isVisible]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }

        renderRecord->HandleSetVisibleChange(formId, isVisible);
    };

    eventHandler->PostTask(task, "SetVisibleChange");
    return ERR_OK;
}

int32_t FormRenderRecord::HandleSetVisibleChange(const int64_t &formId, bool isVisible)
{
    HILOG_INFO("HandleSetVisibleChange begin,formId:%{public}s", std::to_string(formId).c_str());
    MarkThreadAlive();

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto search = formRendererGroupMap_.find(formId);
    if (search == formRendererGroupMap_.end()) {
        HILOG_ERROR("invalid FormRendererGroup");
        return SET_VISIBLE_CHANGE_FAILED;
    }
    if (!search->second) {
        HILOG_ERROR("FormRendererGroup was founded but null");
        return SET_VISIBLE_CHANGE_FAILED;
    }
    search->second->SetVisibleChange(isVisible);
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
    std::lock_guard<std::recursive_mutex> lock(eventHandlerMutex_);
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
    panda::JSNApi::HintGC((static_cast<AbilityRuntime::JsRuntime&>(*runtime_)).GetEcmaVm(),
        panda::JSNApi::MemoryReduceDegree::MIDDLE, panda::ecmascript::GCReason::EXTERNAL_TRIGGER);
}

int32_t FormRenderRecord::RecycleForm(const int64_t &formId, std::string &statusData)
{
    HILOG_INFO("RecycleForm begin, formId:%{public}s", std::to_string(formId).c_str());
    int32_t result = ERR_APPEXECFWK_FORM_COMMON_CODE;
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("null eventHandler_");
        return ERR_APPEXECFWK_FORM_EVENT_HANDLER_NULL;
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
        return ERR_APPEXECFWK_FORM_NOT_EXIST_RENDERER_GROUP;
    }
    if (!search->second) {
        HILOG_ERROR("FormRendererGroup was founded but null");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_RENDERER_GROUP;
    }

    search->second->RecycleForm(statusData);
    return ERR_OK;
}

int32_t FormRenderRecord::RecoverForm(const FormJsInfo &formJsInfo, const std::string &statusData,
    const bool isRecoverFormToHandleClickEvent, const std::string &eventId)
{
    auto formId = formJsInfo.formId;
    HILOG_INFO("RecoverForm begin, formId:%{public}s", std::to_string(formId).c_str());
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("null eventHandler_");
        return RENDER_FORM_FAILED;
    }
    std::shared_ptr<EventHandler> eventHandler = GetEventHandler();

    sptr<IFormSupply> formSupplyClient = GetFormSupplyClient();
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return RENDER_FORM_FAILED;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formJsInfo, statusData, isRecoverFormToHandleClickEvent, formSupplyClient, eventId]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord");
            FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(formJsInfo.formId,
                FormFsmEvent::RECOVER_FORM_FAIL, eventId, formSupplyClient);
            return;
        }
        renderRecord->HandleRecoverForm(formJsInfo, statusData, isRecoverFormToHandleClickEvent);
        FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(formJsInfo.formId,
            FormFsmEvent::RECOVER_FORM_DONE, eventId, formSupplyClient);
    };
    if (eventHandler == nullptr) {
        HILOG_ERROR("null eventHandler_ ");
        return RENDER_FORM_FAILED;
    }
    eventHandler->PostTask(task, "RecoverForm");
    return ERR_OK;
}

void FormRenderRecord::HandleRecoverForm(const FormJsInfo &formJsInfo,
    const std::string &statusData, const bool &isHandleClickEvent)
{
    auto formId = formJsInfo.formId;
    HILOG_INFO("HandleRecoverForm begin, formId:%{public}s, uid:%{public}s", std::to_string(formId).c_str(),
        uid_.c_str());
    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    if (!GetFormRequestByFormId(formId, formRequests)) {
        HILOG_ERROR("not find formRequests");
        return;
    }
    if (formRequests.empty()) {
        HILOG_ERROR("empty formRequests");
        return;
    }

    if (!BeforeHandleUpdateForm(formRequests.begin()->second.formJsInfo)) {
        HILOG_ERROR("recover form prepare failed");
        return;
    }

    RecoverFormRequestsInGroup(formJsInfo, statusData, isHandleClickEvent, formRequests);
}

bool FormRenderRecord::GetAndDeleteRecycledCompIds(const int64_t &formId,
    std::vector<std::string> &orderedCompIds, std::string &currentCompId)
{
    std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
    auto pairIter = recycledFormCompIds_.find(formId);
    if (pairIter == recycledFormCompIds_.end()) {
        HILOG_ERROR("invalid compIdPair,formId:%{public}" PRId64, formId);
        return false;
    }
    orderedCompIds = pairIter->second.first;
    currentCompId = pairIter->second.second;
    recycledFormCompIds_.erase(formId);
    HILOG_INFO("compIds size:%{public}zu,currentCompId:%{public}s,formId:%{public}" PRId64,
        orderedCompIds.size(), currentCompId.c_str(), formId);
    return true;
}

bool FormRenderRecord::RecoverFormRequestsInGroup(const FormJsInfo &formJsInfo, const std::string &statusData,
    const bool &isHandleClickEvent, std::unordered_map<std::string, Ace::FormRequest> &recordFormRequests)
{
    auto formId = formJsInfo.formId;
    std::vector<std::string> orderedCompIds;
    std::string currentCompId;
    bool flag = GetAndDeleteRecycledCompIds(formId, orderedCompIds, currentCompId);
    if (!flag) {
        HILOG_ERROR("init compIds failed,formId:%{public}" PRId64, formId);
        return false;
    }

    std::vector<Ace::FormRequest> groupRequests;
    size_t currentRequestIndex = 0;
    bool currentRequestFound = false;
    if (!GetFormRequestByFormId(formId, recordFormRequests)) {
        HILOG_ERROR("find formRequest failed,formId:%{public}" PRId64, formId);
        return false;
    }

    UpdateGroupRequestsWhenRecover(formId, formJsInfo, orderedCompIds, currentCompId, statusData, isHandleClickEvent,
        currentRequestIndex, groupRequests, currentRequestFound, recordFormRequests);

    if (groupRequests.empty()) {
        HILOG_ERROR("group requests empty formId:%{public}" PRId64, formId);
        return false;
    }

    if (!currentRequestFound) {
        // maybe current comp deleted between recover, get last comp as new current comp to recover
        currentRequestIndex = groupRequests.size() - 1;
        HILOG_WARN("current request index:%{public}zu formId:%{public}" PRId64, currentRequestIndex, formId);
    }
    bool success = RecoverRenderer(groupRequests, currentRequestIndex);
    if (success) {
        UpdateFormRequestReleaseState(formId, currentCompId, false);
    }
    return success;
}

void FormRenderRecord::UpdateGroupRequestsWhenRecover(const int64_t &formId, const FormJsInfo &formJsInfo,
    const std::vector<std::string> &orderedCompIds, const std::string &currentCompId, const std::string &statusData,
    const bool &isHandleClickEvent, size_t &currentRequestIndex, std::vector<Ace::FormRequest> &groupRequests,
    bool &currentRequestFound, const std::unordered_map<std::string, Ace::FormRequest> &recordFormRequests)
{
    std::set<std::string> groupCompIds;
    for (auto compId : orderedCompIds) {
        auto recordRequestIter = recordFormRequests.find(compId);
        if (recordRequestIter == recordFormRequests.end()) {
            HILOG_WARN("invalid formRequest,formId:%{public}" PRId64 " compId=%{public}s", formId, compId.c_str());
            continue;
        }
        if (groupCompIds.find(compId) != groupCompIds.end()) {
            continue;
        }
        groupCompIds.insert(compId);
        auto& recordRequest = recordRequestIter->second;
        Ace::FormRequest groupRequest;
        groupRequest.compId = compId;
        groupRequest.want = recordRequest.want;
        groupRequest.formJsInfo = recordRequest.formJsInfo; // get json data from record request
        MergeMap(groupRequest.formJsInfo.imageDataMap, formJsInfo.imageDataMap);
        if (compId == currentCompId) {
            groupRequest.want.SetParam(Constants::FORM_STATUS_DATA, statusData);
            groupRequest.want.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, isHandleClickEvent);
            currentRequestIndex = groupRequests.size();
            currentRequestFound = true;
            HILOG_INFO("currentRequestIndex: %{public}zu, formData.size: %{public}zu",
                currentRequestIndex, groupRequest.formJsInfo.formData.size());
        }
        groupRequests.emplace_back(groupRequest);
    }
}

void FormRenderRecord::MergeMap(std::map<std::string, sptr<FormAshmem>> &dst,
    const std::map<std::string, sptr<FormAshmem>> &src)
{
    for (auto iter = src.begin(); iter != src.end(); ++iter) {
        auto search = dst.find(iter->first);
        if (search == dst.end()) {
            dst.emplace(*iter);
        } else {
            search->second = iter->second;
        }
    }
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

    auto formRendererGroup = GetFormRendererGroup(currentRequest.formJsInfo, context, runtime_);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return false;
    }
    bool isVisible = IsFormVisible(currentRequest.formJsInfo.formId);
    auto task = [formRendererGroup, groupRequests, currentRequestIndex, isVisible]() {
        formRendererGroup->RecoverRenderer(groupRequests, currentRequestIndex);
        // Re-notify visibility after form recovery.
        formRendererGroup->SetVisibleChange(isVisible);
    };
    // the formrenderer_ must be initialized using a sync task
    eventHandler_->PostSyncTask(task, "RecoverRenderer");
    HILOG_INFO("recover renderer, formId:%{public}" PRId64, currentRequest.formJsInfo.formId);
    return true;
}

void FormRenderRecord::UpdateFormSizeOfGroups(const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo)
{
    float width = formSurfaceInfo.width;
    float height = formSurfaceInfo.height;
    float borderWidth = formSurfaceInfo.borderWidth;
    float formViewScale = formSurfaceInfo.formViewScale;
    {
        std::lock_guard<std::mutex> lock(formRequestsMutex_);
        auto iter = formRequests_.find(formId);
        if (iter == formRequests_.end()) {
            HILOG_ERROR("%{public}s doesn't has formRequest", std::to_string(formId).c_str());
            return;
        }
        if (iter->second.empty()) {
            HILOG_ERROR("empty formRequests");
            return;
        }

        HILOG_INFO("formRequests length: %{public}zu formId: %{public}" PRId64 " width: %{public}f height: %{public}f"
            " borderWidth: %{public}f, formViewScale: %{public}f", iter->second.size(), formId, width, height,
            borderWidth, formViewScale);
        for (auto& formRequestIter : iter->second) {
            formRequestIter.second.want.SetParam(
                OHOS::AppExecFwk::Constants::PARAM_FORM_WIDTH_KEY, static_cast<double>(width));
            formRequestIter.second.want.SetParam(
                OHOS::AppExecFwk::Constants::PARAM_FORM_HEIGHT_KEY, static_cast<double>(height));
            formRequestIter.second.want.SetParam(
                OHOS::AppExecFwk::Constants::PARAM_FORM_BORDER_WIDTH_KEY, static_cast<float>(borderWidth));
            formRequestIter.second.want.SetParam(
                OHOS::AppExecFwk::Constants::PARAM_FORM_VIEW_SCALE, formViewScale);
        }
    }

    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto search = formRendererGroupMap_.find(formId);
    if (search != formRendererGroupMap_.end()) {
        auto group = search->second;
        group->UpdateFormSizeOfFormRequests(width, height, borderWidth, formViewScale);
    } else {
        HILOG_WARN("formRendererGroup not find, formId:%{public}" PRId64, formId);
        ReAddStaticRecycledForms(formId);
    }
}

void FormRenderRecord::ReAddStaticRecycledForms(const int64_t formId)
{
    if (!CheckEventHandler(true, true)) {
        HILOG_ERROR("null eventHandler");
        return;
    }

    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    if (!GetFormRequestByFormId(formId, formRequests)) {
        HILOG_ERROR("get form request failed, formId:%{public}" PRId64, formId);
        return;
    }

    for (auto &formRequest : formRequests) {
        if (formRequest.second.isDynamic || !formRequest.second.hasRelease) {
            continue;
        }

        formRequest.second.want.SetParam(OHOS::AppExecFwk::Constants::FORM_IS_STATIC_FORM_UPDATE_SIZE, true);
        PostReAddRecycledForms(formRequest.second.formJsInfo, formRequest.second.want);
    }
}

bool FormRenderRecord::CheckManagerDelegateValid(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_DEBUG("call");
    if (!want.HasParameter(FORM_RENDERER_PROCESS_ON_ADD_SURFACE)) {
        HILOG_INFO("not add surface, ingore it");
        return true;
    }

    auto context = GetContext(formJsInfo, want);
    if (context == nullptr) {
        return true;
    }

    {
        std::shared_lock<std::shared_mutex> lock(eventHandlerReset_);
        if (eventHandleNeedReset) {
            return true;
        }
    }
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto key = formJsInfo.formId;
    auto iter = formRendererGroupMap_.find(key);
    if (iter == formRendererGroupMap_.end() || iter->second == nullptr) {
        return true;
    }

    return iter->second->IsManagerDelegateValid(want);
}

void FormRenderRecord::SetFormSupplyClient(const sptr<IFormSupply> &formSupplyClient)
{
    std::lock_guard<std::mutex> lock(formSupplyMutex_);
    formSupplyClient_ = formSupplyClient;
}

sptr<IFormSupply> FormRenderRecord::GetFormSupplyClient()
{
    std::lock_guard<std::mutex> lock(formSupplyMutex_);
    return formSupplyClient_;
}

std::shared_ptr<EventHandler> FormRenderRecord::GetEventHandler()
{
    std::lock_guard<std::recursive_mutex> lock(eventHandlerMutex_);
    return eventHandler_;
}

int32_t FormRenderRecord::AddHostByFormId(int64_t formId, const sptr<IRemoteObject> hostRemoteObj)
{
    if (hostRemoteObj == nullptr) {
        return ERR_OK;
    }

    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto iter = hostsMapForFormId_.find(formId);
    if (iter == hostsMapForFormId_.end()) {
        hostsMapForFormId_.emplace(formId, IRemoteObjectSet({hostRemoteObj}));
        return ERR_OK;
    }
    iter->second.emplace(hostRemoteObj);
    return ERR_OK;
}

void FormRenderRecord::DeleteHostRemoteObjByFormId(int64_t formId, const sptr<IRemoteObject> hostRemoteObj)
{
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto iter = hostsMapForFormId_.find(formId);
    if (iter != hostsMapForFormId_.end()) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
        hosts.erase(hostRemoteObj);
    }
}

void FormRenderRecord::RemoveHostByFormId(int64_t formId)
{
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    hostsMapForFormId_.erase(formId);
}

bool FormRenderRecord::IsFormContextExist(const FormJsInfo &formJsInfo)
{
    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    auto moduleInfo = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
    return moduleInfo != contextsMapForModuleName_.end();
}

bool FormRenderRecord::GetFormRequestByFormId(
    int64_t formId, std::unordered_map<std::string, Ace::FormRequest> &formRequests)
{
    std::lock_guard<std::mutex> lock(formRequestsMutex_);
    auto iter = formRequests_.find(formId);
    if (iter == formRequests_.end()) {
        return false;
    }

    formRequests = iter->second;
    return true;
}

void FormRenderRecord::SetEventHandlerNeedResetFlag(bool needReset)
{
    std::lock_guard<std::shared_mutex> lock(eventHandlerReset_);
    HILOG_INFO("eventHandleNeedReset: %{public}d", needReset);
    eventHandleNeedReset = needReset;
}

bool FormRenderRecord::GetEventHandlerNeedReset()
{
    std::lock_guard<std::shared_mutex> lock(eventHandlerReset_);
    return eventHandleNeedReset;
}

void FormRenderRecord::DeleteRecycledFormCompIds(int64_t formId)
{
    std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
    recycledFormCompIds_.erase(formId);
}

void FormRenderRecord::InsertRecycledFormCompIds(
    int64_t formId, const std::pair<std::vector<std::string>, std::string> &compIds)
{
    std::lock_guard<std::mutex> lock(recycledFormCompIdsMutex_);
    recycledFormCompIds_.emplace(formId, compIds);
}

void FormRenderRecord::RegisterUncatchableErrorHandler()
{
    auto nativeEnginePtr = (static_cast<AbilityRuntime::JsRuntime &>(*runtime_)).GetNativeEnginePointer();
    if (nativeEnginePtr == nullptr) {
        HILOG_ERROR("null nativeEnginePtr");
        return;
    }
    auto uncatchableTask = [weak = weak_from_this()](panda::TryCatch &trycatch) {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("null renderRecord");
            return;
        }
        auto exception = trycatch.GetAndClearException();
        if (!exception.IsEmpty() && !exception->IsHole()) {
            napi_value obj = reinterpret_cast<napi_value>(*exception);
            renderRecord->OnJsError(obj);
        }
    };
    panda::JSNApi::RegisterUncatchableErrorHandler(const_cast<EcmaVM *>(nativeEnginePtr->GetEcmaVm()), uncatchableTask);
}

void FormRenderRecord::OnJsError(napi_value value)
{
    HILOG_ERROR("call, bundleName:  %{public}s", bundleName_.c_str());
    std::string errorName = GetNativeStrFromJsTaggedObj(value, "name");
    std::string errorMsg = GetNativeStrFromJsTaggedObj(value, "message");
    std::string stack = GetNativeStrFromJsTaggedObj(value, "stack");
    std::string errorCode = GetNativeStrFromJsTaggedObj(value, "code");
    std::string summary = "Error name:" + errorName + "\n" + "Error message:" + errorMsg + "\n";
    if (!errorCode.empty()) {
        summary += "Error code:" + errorCode + "\n";
    }
    HILOG_ERROR("summary: %{public}s", summary.c_str());
    HILOG_ERROR("stack: %{public}s", stack.c_str());
    FormRenderEventReport::SendBlockFaultEvent(bundleName_, summary, stack);
}

std::string FormRenderRecord::GetNativeStrFromJsTaggedObj(napi_value obj, const char* key)
{
    if (obj == nullptr) {
        HILOG_ERROR("get value failed");
        return "";
    }

    napi_value valueStr = nullptr;
    napi_env env = (static_cast<AbilityRuntime::JsRuntime &>(*runtime_)).GetNapiEnv();
    bool hasProperty = false;
    napi_has_named_property(env, obj, key, &hasProperty);
    if (!hasProperty) {
        return "";
    }
    napi_get_named_property(env, obj, key, &valueStr);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, valueStr, &valueType);
    if (valueType != napi_string) {
        HILOG_ERROR("convert value failed");
        return "";
    }

    size_t valueStrBufLength = 0;
    napi_get_value_string_utf8(env, valueStr, nullptr, 0, &valueStrBufLength);
    auto valueCStr = std::make_unique<char[]>(valueStrBufLength + 1);
    size_t valueStrLength = 0;
    napi_get_value_string_utf8(env, valueStr, valueCStr.get(), valueStrBufLength + 1, &valueStrLength);
    std::string ret(valueCStr.get(), valueStrLength);
    return ret;
}

bool FormRenderRecord::IsFormVisible(int64_t formId)
{
    std::lock_guard<std::mutex> lock(visibilityMapMutex_);
    auto iter = visibilityMap_.find(formId);
    if (iter != visibilityMap_.end()) {
        return iter->second;
    }
    return false;
}

bool FormRenderRecord::IsAllFormsInvisible()
{
    std::lock_guard<std::mutex> lock(visibilityMapMutex_);
    return visibilityMap_.empty();
}

void FormRenderRecord::RecordFormVisibility(int64_t formId, bool isVisible)
{
    HILOG_INFO("call formId: %{public}" PRId64 ", isVisible: %{public}d", formId, isVisible);
    std::lock_guard<std::mutex> lock(visibilityMapMutex_);
    if (isVisible) {
        visibilityMap_[formId] = isVisible;
    } else {
        visibilityMap_.erase(formId);
    }
}

void FormRenderRecord::RecordFormLocation(int64_t formId, const FormLocationInfo &formLocation)
{
    std::lock_guard<std::mutex> lock(formLocationMutex_);
    formLocationMap_[formId] = formLocation;
}

void FormRenderRecord::DeleteFormLocation(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formLocationMutex_);
    formLocationMap_.erase(formId);
}

void FormRenderRecord::ParseFormLocationMap(std::vector<std::string> &formName, std::vector<uint32_t> &formLocation)
{
    std::lock_guard<std::mutex> lock(formLocationMutex_);
    for (const auto &iter : formLocationMap_) {
        const FormLocationInfo &locationInfo = iter.second;
        formName.emplace_back(locationInfo.formName);
        formLocation.emplace_back(locationInfo.formLocation);
    }
}

void FormRenderRecord::RuntimeMemoryMonitor()
{
    if (runtime_ == nullptr || eventHandler_ == nullptr) {
        return;
    }

    auto nativeEnginePtr = (static_cast<AbilityRuntime::JsRuntime &>(*runtime_)).GetNativeEnginePointer();
    if (nativeEnginePtr == nullptr) {
        HILOG_ERROR("null nativeEnginePtr");
        return;
    }

    size_t totalSize = 0;
    size_t usedSize = 0;
    size_t objSize = 0;
    size_t limitSize = 0;
    // GetHeap must be called on the UI thread.
    auto task = [nativeEnginePtr, &totalSize, &usedSize, &objSize, &limitSize]() {
        totalSize = nativeEnginePtr->GetHeapTotalSize();
        usedSize = nativeEnginePtr->GetHeapUsedSize();
        objSize = nativeEnginePtr->GetHeapObjectSize();
        limitSize = nativeEnginePtr->GetHeapLimitSize();
    };
    eventHandler_->PostSyncTask(task, "RuntimeMemoryMonitorTask");

    uint64_t processMemory = GetPss();
    HILOG_INFO("processMemory: %{public}" PRIu64 ", bundleName: %{public}s, totalSize: %{public}zu, "
        "usedSize: %{public}zu, objSize: %{public}zu, limitSize: %{public}zu", processMemory, bundleName_.c_str(),
        totalSize, usedSize, objSize, limitSize);
    if (totalSize > RUNTIME_MEMORY_LIMIT) {
        std::vector<std::string> formName;
        std::vector<uint32_t> formLocation;
        ParseFormLocationMap(formName, formLocation);
        FormRenderEventReport::SendRuntimeMemoryLeakEvent(bundleName_, processMemory,
            static_cast<uint64_t>(totalSize), formName, formLocation);
    }
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS