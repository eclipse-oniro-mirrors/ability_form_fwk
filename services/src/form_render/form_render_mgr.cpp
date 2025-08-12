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

#include "form_render/form_render_mgr.h"

#include <mutex>

#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "common/event/form_event_report.h"
#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "form_render/form_sandbox_render_mgr_inner.h"
#include "form_provider/form_supply_callback.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr size_t LAST_CONNECTION = 1;
}
using Want = OHOS::AAFwk::Want;
FormRenderMgr::FormRenderMgr()
{
}
FormRenderMgr::~FormRenderMgr()
{
}

void FormRenderMgr::GetFormRenderState()
{
    // Check whether the account is authenticated.
    bool isVerified = false;
    int32_t userId = FormUtil::GetCurrentAccountId();
    AccountSA::OsAccountManager::IsOsAccountVerified(userId, isVerified);
    HILOG_INFO("isVerified:%{public}d,isVerified_:%{public}d,mounted:%{public}d,screen:%{public}d,userId:%{public}d",
        isVerified, isVerified_, isSecondMounted_, isScreenUnlocked_, userId);

    std::lock_guard<std::mutex> lock(isVerifiedMutex_);
    if (isVerified_ == isVerified) {
        return;
    }

    isVerified_ = isVerified;
    if (!isVerified) {
        return;
    }
    if (!isScreenUnlocked_) {
        PostOnUnlockTask();
    }
    if (isSecondMounted_) {
        ExecAcquireProviderTask(userId);
    }
}

bool FormRenderMgr::GetIsSecondMounted() const
{
    HILOG_DEBUG("GetIsSecondMounted");
    std::lock_guard<std::mutex> lock(isVerifiedMutex_);
    return isSecondMounted_;
}

ErrCode FormRenderMgr::RenderForm(
    const FormRecord &formRecord, const WantParams &wantParams, const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("formId:%{public}" PRId64 ", formUserId:%{public}d", formRecord.formId, formRecord.userId);
    GetFormRenderState();
    HILOG_INFO("the current user authentication status:%{public}d,%{public}d", isVerified_, isScreenUnlocked_);
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }
    if (formRecord.formId <= 0) {
        HILOG_ERROR("formId not greater than 0");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    Want want;
    want.SetParams(wantParams);
    std::string recordUid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
    want.SetParam(Constants::FORM_SUPPLY_UID, recordUid);
    bool renderState = false;
    {
        std::lock_guard<std::mutex> lock(isVerifiedMutex_);
        renderState = isVerified_ || isScreenUnlocked_;
        want.SetParam(Constants::FORM_RENDER_STATE, renderState);
    }
    if (!renderState && CheckMultiAppFormVersionCode(formRecord)) {
        want.SetParam(Constants::FORM_RENDER_WITHOUT_UNLOCK_STATE, true);
    }

    bool formIsVisible = FormDataMgr::GetInstance().GetFormVisible(formRecord.formId);
    want.SetParam(Constants::FORM_IS_VISIBLE, formIsVisible);
    want.SetParam(Constants::FORM_LOCATION_KEY, static_cast<int32_t>(formRecord.formLocation));

    if (formRecord.privacyLevel > 0) {
        InitRenderInner(true, formRecord.userId);
        return sandboxInners_[formRecord.userId]->RenderForm(formRecord, want, hostToken);
    } else {
        InitRenderInner(false, formRecord.userId);
        return renderInners_[formRecord.userId]->RenderForm(formRecord, want, hostToken);
    }
}

ErrCode FormRenderMgr::UpdateRenderingForm(int64_t formId, const FormProviderData &formProviderData,
    const WantParams &wantParams, bool mergeData)
{
    HILOG_INFO("update formId:%{public}" PRId64 ",%{public}zu", formId, formProviderData.GetDataString().length());

    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("get FormRecord fail, not exist such form, formId:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    int32_t formUserId = formRecord.userId;
    HILOG_INFO("update formUserId:%{public}d", formUserId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formUserId);
        if (iter == sandboxInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData);
    } else {
        auto iter = renderInners_.find(formUserId);
        if (iter == renderInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData);
    }
}

ErrCode FormRenderMgr::ReloadForm(
    const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId)
{
    HILOG_INFO("userId:%{public}d", userId);
    std::vector<FormRecord> sandboxRecords;
    std::vector<FormRecord> normalRecords;
    for (const auto &record : formRecords) {
        if (record.privacyLevel > 0) {
            sandboxRecords.emplace_back(record);
        } else {
            normalRecords.emplace_back(record);
        }
    }
    auto renderIter = renderInners_.find(userId);
    if (!normalRecords.empty() && renderIter != renderInners_.end()) {
        renderIter->second->ReloadForm(std::move(normalRecords), bundleName, userId);
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (!sandboxRecords.empty() && sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->ReloadForm(std::move(sandboxRecords), bundleName, userId);
    }
    return ERR_OK;
}

void FormRenderMgr::PostOnUnlockTask()
{
    int32_t userId = FormUtil::GetCurrentAccountId();
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->PostOnUnlockTask();
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->PostOnUnlockTask();
    }
}

void FormRenderMgr::AddAcquireProviderFormInfoTask(int32_t userId, std::function<void()> task)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    auto iter = taskQueueMap_.find(userId);
    if (iter == taskQueueMap_.end()) {
        std::queue<std::function<void()>> taskQueue;
        taskQueue.push(task);
        taskQueueMap_.emplace(userId, taskQueue);
        return;
    }
    iter->second.push(task);
}

void FormRenderMgr::ExecAcquireProviderTask(int32_t userId)
{
    HILOG_INFO("start, userId:%{public}d", userId);
    // start to execute asynchronous tasks in the queue
    std::lock_guard<std::mutex> lock(taskQueueMutex_);
    auto iter = taskQueueMap_.find(userId);
    if (iter == taskQueueMap_.end()) {
        HILOG_WARN("taskQueueMap_ not find userId:%{public}d", userId);
        return;
    }
    auto taskQueue = iter->second;
    while (!taskQueue.empty()) {
        auto task = taskQueue.front();
        task();
        taskQueue.pop();
    }
    taskQueueMap_.erase(userId);
    HILOG_INFO("end, userId:%{public}d", userId);
}

void FormRenderMgr::AddAcquireProviderForbiddenTask(const std::string &bundleName,
    int64_t formId, std::function<void()> task)
{
    std::lock_guard<std::mutex> lock(forbiddenTaskMapMutex_);

    auto search = forbiddenTaskMap_.find(bundleName);
    if (search == forbiddenTaskMap_.end()) {
        std::unordered_map<int64_t, std::function<void()>> taskQueue;
        taskQueue.emplace(formId, task);
        forbiddenTaskMap_.emplace(bundleName, taskQueue);
    } else {
        search->second[formId] = task;
    }
    HILOG_INFO("add ftask success, formId:%{public}" PRId64, formId);
}

void FormRenderMgr::ExecAcquireProviderForbiddenTask(const std::string &bundleName)
{
    HILOG_INFO("start");
    // start to execute asynchronous tasks in the map
    std::unordered_map<int64_t, std::function<void()>> taskQueue;
    {
        std::lock_guard<std::mutex> lock(forbiddenTaskMapMutex_);
        auto search = forbiddenTaskMap_.find(bundleName);
        if (search == forbiddenTaskMap_.end()) {
            return;
        }
        taskQueue = search->second;
        forbiddenTaskMap_.erase(search);
    }
    auto iter = taskQueue.begin();
    while (iter != taskQueue.end()) {
        auto task = iter->second;
        task();
        HILOG_INFO("exec ftask success, formId:%{public}" PRId64, iter->first);
        iter = taskQueue.erase(iter);
    }
}

void FormRenderMgr::ExecAcquireProviderForbiddenTaskByFormId(const int64_t formId)
{
    HILOG_INFO("start, formId %{public}" PRId64, formId);
    std::function<void()> task;
    {
        std::lock_guard<std::mutex> lock(forbiddenTaskMapMutex_);
        for (auto iter = forbiddenTaskMap_.begin(); iter != forbiddenTaskMap_.end(); ++iter) {
            auto search = iter->second.find(formId);
            if (search != iter->second.end()) {
                task = search->second;
                iter->second.erase(search);
                if (iter->second.empty()) {
                    forbiddenTaskMap_.erase(iter);
                }
                HILOG_INFO("add ftask success, formId:%{public}" PRId64, formId);
                break;
            }
        }
    }
    if (task) {
        task();
    }
}

void FormRenderMgr::DeleteAcquireForbiddenTasksByBundleName(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(forbiddenTaskMapMutex_);
    auto search = forbiddenTaskMap_.find(bundleName);
    if (search != forbiddenTaskMap_.end()) {
        forbiddenTaskMap_.erase(search);
        HILOG_INFO("delete ftasks success, bundlename:%{public}s", bundleName.c_str());
    }
}

void FormRenderMgr::DeleteAcquireForbiddenTaskByFormId(int64_t formId)
{
    std::lock_guard<std::mutex> lock(forbiddenTaskMapMutex_);

    for (auto iter = forbiddenTaskMap_.begin(); iter != forbiddenTaskMap_.end(); ++iter) {
        auto search = iter->second.find(formId);
        if (search != iter->second.end()) {
            iter->second.erase(search);
            if (iter->second.empty()) {
                forbiddenTaskMap_.erase(iter);
            }
            HILOG_INFO("delete ftask success, formId:%{public}" PRId64, formId);
            break;
        }
    }
}

void FormRenderMgr::AddPostRenderFormTask(int64_t formId, std::function<void()> task)
{
    std::lock_guard<std::mutex> lock(renderFormTaskMapMutex_);
    auto search = renderFormTaskMap_.find(formId);
    if (search == renderFormTaskMap_.end()) {
        renderFormTaskMap_.emplace(formId, task);
    } else {
        search->second = task;
    }
    HILOG_INFO("add PostRenderFormTask success, formId:%{public}" PRId64, formId);
}

void FormRenderMgr::ExecPostRenderFormTask(int64_t formId)
{
    std::function<void()> task;
    bool findTask = false;
    {
        std::lock_guard<std::mutex> lock(renderFormTaskMapMutex_);
        auto search = renderFormTaskMap_.find(formId);
        if (search != renderFormTaskMap_.end()) {
            task = search->second;
            findTask = true;
            renderFormTaskMap_.erase(search);
        }
    }
    if (findTask) {
        task();
        HILOG_INFO("exec task, formId:%{public}" PRId64, formId);
    }
}

void FormRenderMgr::DeletePostRenderFormTask(int64_t formId)
{
    std::lock_guard<std::mutex> lock(renderFormTaskMapMutex_);
    auto search = renderFormTaskMap_.find(formId);
    if (search != renderFormTaskMap_.end()) {
        renderFormTaskMap_.erase(search);
        HILOG_INFO("del task, formId:%{public}" PRId64, formId);
    }
}

void FormRenderMgr::NotifyScreenOn()
{
    int32_t userId = FormUtil::GetCurrentAccountId();
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->NotifyScreenOn();
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->NotifyScreenOn();
    }
}

void FormRenderMgr::OnScreenUnlock(int32_t userId)
{
    // Check whether the account is authenticated.
    bool isVerified = false;
    AccountSA::OsAccountManager::IsOsAccountVerified(userId, isVerified);
    HILOG_INFO("isVerified_:%{public}d, screenUnlocked:%{public}d, isVerified:%{public}d, userId:%{public}d",
        isVerified_, isScreenUnlocked_, isVerified, userId);
    std::lock_guard<std::mutex> lock(isVerifiedMutex_);
    if (isVerified && !isSecondMounted_) {
        isSecondMounted_ = true;
    }

    if (isScreenUnlocked_) {
        return;
    }

    // el2 path maybe not unlocked, should not acquire data
    isScreenUnlocked_ = true;
    if (!isVerified_) {
        PostOnUnlockTask();
    }
}

void FormRenderMgr::OnUnlock(int32_t userId)
{
    HILOG_INFO("call. %{public}d,%{public}d,%{public}d,%{public}d",
        isVerified_, isSecondMounted_, isScreenUnlocked_, userId);
    if (isSecondMounted_) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(isVerifiedMutex_);
        isSecondMounted_ = true;
        if (!isScreenUnlocked_) {
            PostOnUnlockTask();
        }
    }
    ExecAcquireProviderTask(userId);
}

void FormRenderMgr::SetVisibleChange(int64_t formId, bool isVisible)
{
    HILOG_INFO("call.");
    int32_t userId = FormUtil::GetCurrentAccountId();
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->PostSetVisibleChangeTask(formId, isVisible);
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->PostSetVisibleChangeTask(formId, isVisible);
    }
}

ErrCode FormRenderMgr::StopRenderingForm(
    int64_t formId, const FormRecord &formRecord, const std::string &compId, const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("formUserId:%{public}d", formRecord.userId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formRecord.userId);
        if (iter == sandboxInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->StopRenderingForm(formId, formRecord, compId, hostToken);
    } else {
        auto iter = renderInners_.find(formRecord.userId);
        if (iter == renderInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->StopRenderingForm(formId, formRecord, compId, hostToken);
    }
}

ErrCode FormRenderMgr::RenderFormCallback(int64_t formId, const Want &want)
{
    HILOG_DEBUG("call");
    return ERR_OK;
}

ErrCode FormRenderMgr::StopRenderingFormCallback(int64_t formId, const Want &want)
{
    int32_t callingUserId = IPCSkeleton::GetCallingUid() / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    HILOG_INFO("formId:%{public}" PRId64 ", callingUserId:%{public}d", formId, callingUserId);
    auto renderIter = renderInners_.find(callingUserId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->StopRenderingFormCallback(formId, want);
    }
    auto sandboxIter = sandboxInners_.find(callingUserId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->StopRenderingFormCallback(formId, want);
    }
    return ERR_OK;
}

ErrCode FormRenderMgr::ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId)
{
    HILOG_INFO("formId:%{public}" PRId64 ", formUserId:%{public}d", formId, formRecord.userId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formRecord.userId);
        if (iter == sandboxInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->ReleaseRenderer(formId, formRecord, compId);
    } else {
        auto iter = renderInners_.find(formRecord.userId);
        if (iter == renderInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->ReleaseRenderer(formId, formRecord, compId);
    }
}

ErrCode FormRenderMgr::AddConnection(
    int64_t formId, sptr<FormRenderConnection> connection, const FormRecord &formRecord)
{
    HILOG_INFO("formUserId: %{public}d", formRecord.userId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formRecord.userId);
        if (iter == sandboxInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->AddConnection(formId, connection);
    } else {
        auto iter = renderInners_.find(formRecord.userId);
        if (iter == renderInners_.end()) {
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return iter->second->AddConnection(formId, connection);
    }
}

void FormRenderMgr::RemoveConnection(int64_t formId, const FormRecord &formRecord)
{
    HILOG_INFO("formId:%{public}" PRId64 ", formUserId:%{public}d", formId, formRecord.userId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formRecord.userId);
        if (iter != sandboxInners_.end()) {
            iter->second->RemoveConnection(formId);
        }
    } else {
        auto iter = renderInners_.find(formRecord.userId);
        if (iter != renderInners_.end()) {
            iter->second->RemoveConnection(formId);
        }
    }
}

ErrCode FormRenderMgr::checkConnectionsFormIds(std::vector<int64_t> formIds, int32_t userId,
    std::vector<int64_t> &needconFormIds)
{
    auto iter = renderInners_.find(userId);
    if (iter == renderInners_.end()) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return iter->second->checkConnectionsFormIds(formIds, needconFormIds);
}

void FormRenderMgr::reAddConnections(std::vector<int64_t> formIds,
    int32_t userId, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_ERROR("reAddConnections - Connect formIds, ");

    sptr<IFormHost> hostClient = iface_cast<IFormHost>(remoteObject);
    if (hostClient == nullptr) {
        HILOG_ERROR("null hostClient");
        return;
    }
    hostClient->OnError(ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, "FormRenderService is dead.", formIds);
}

void FormRenderMgr::CleanFormHost(const sptr<IRemoteObject> &host, const int hostCallingUid)
{
    int32_t hostUserId = hostCallingUid / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    if (hostUserId == 0) {
        HILOG_WARN("hostUserId is 0, get current active userId ");
        hostUserId = FormUtil::GetCurrentAccountId();
    }
    HILOG_WARN("hostUserId:%{public}d", hostUserId);
    auto renderIter = renderInners_.find(hostUserId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->CleanFormHost(host);
    }
    auto sandboxIter = sandboxInners_.find(hostUserId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->CleanFormHost(host);
    }
}

void FormRenderMgr::AddRenderDeathRecipient(const sptr<IRemoteObject> &remoteObject, const FormRecord &formRecord)
{
    HILOG_INFO("formUserId:%{public}d", formRecord.userId);
    if (formRecord.privacyLevel > 0) {
        auto iter = sandboxInners_.find(formRecord.userId);
        if (iter != sandboxInners_.end()) {
            iter->second->AddRenderDeathRecipient(remoteObject);
        }
    } else {
        auto iter = renderInners_.find(formRecord.userId);
        if (iter != renderInners_.end()) {
            iter->second->AddRenderDeathRecipient(remoteObject);
        }
    }
}

void FormRenderMgr::OnRenderingBlock(const std::string &bundleName)
{
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
    FormEventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    FormEventReport::SendSecondFormEvent(
        FormEventName::FORM_RENDER_BLOCK, HiSysEventType::FAULT, eventInfo);

    FormTrustMgr::GetInstance().MarkTrustFlag(bundleName, false);

    Want want;
    want.SetElementName(Constants::FRS_BUNDLE_NAME, "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    FormAmsHelper::GetInstance().StopExtensionAbility(want);
}

bool FormRenderMgr::IsNeedRender(int64_t formId)
{
    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("not exist such form, formId:%{public}" PRId64 "", formId);
        return false;
    }
    if (formRecord.uiSyntax != FormType::ETS) {
        HILOG_DEBUG("no need render, formId:%{public}" PRId64 "", formId);
        return false;
    }
    return true;
}

void FormRenderMgr::HandleConnectFailed(int64_t formId, int32_t errorCode) const
{
    HILOG_ERROR("Connect render service failed, formId:%{public}" PRId64 ", errorCode:%{public}d",
        formId, errorCode);
    std::vector<sptr<IRemoteObject>> formHostObjs;
    FormDataMgr::GetInstance().GetFormHostRemoteObj(formId, formHostObjs);
    for (const auto &host : formHostObjs) {
        auto hostClient = iface_cast<IFormHost>(host);
        if (hostClient == nullptr) {
            HILOG_ERROR("null hostClient");
            continue;
        }
        hostClient->OnError(errorCode, "Connect FormRenderService failed");
    }
}

bool FormRenderMgr::IsRerenderForRenderServiceDied(int64_t formId)
{
    int32_t rerenderCount = 0;
    int32_t reSandboxRenderCount = 0;
    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("get FormRecord fail, not exist such form, formId:%{public}" PRId64 "", formId);
        return true;
    }
    HILOG_INFO("formId:%{public}" PRId64 ", formUserId:%{public}d", formId, formRecord.userId);
    auto renderIter = renderInners_.find(formRecord.userId);
    if (renderIter != renderInners_.end()) {
        rerenderCount = renderIter->second->GetReRenderCount();
    }
    auto sandboxIter = sandboxInners_.find(formRecord.userId);
    if (sandboxIter != sandboxInners_.end()) {
        reSandboxRenderCount = sandboxIter->second->GetReRenderCount();
    }
    bool ret = IsNeedRender(formId) && (rerenderCount > 0 || reSandboxRenderCount > 0);
    HILOG_DEBUG("Is need to rerender:%{public}d", ret);
    return ret;
}

void FormRenderMgr::InitRenderInner(bool isSandbox, int32_t userId)
{
    HILOG_INFO("isSandbox: %{public}d userId: %{public}d.", isSandbox, userId);
    std::lock_guard<std::mutex> lock(renderInnerMutex_);
    if (isSandbox) {
        auto iter = sandboxInners_.find(userId);
        if (iter == sandboxInners_.end()) {
            auto formSandboxRenderMgr = std::make_shared<FormSandboxRenderMgrInner>();
            formSandboxRenderMgr->SetUserId(userId);
            sandboxInners_.emplace(userId, formSandboxRenderMgr);
        }
    } else {
        auto iter = renderInners_.find(userId);
        if (iter == renderInners_.end()) {
            auto formRenderMgr = std::make_shared<FormRenderMgrInner>();
            formRenderMgr->SetUserId(userId);
            renderInners_.emplace(userId, formRenderMgr);
        }
    }
}

ErrCode FormRenderMgr::RecycleForms(
    const std::vector<int64_t> &formIds, const Want &want, const sptr<IRemoteObject> &remoteObjectOfHost)
{
    int callingUserId = want.GetIntParam(Constants::RECYCLE_FORMS_USER_ID, 0);
    if (callingUserId == 0) {
        callingUserId = IPCSkeleton::GetCallingUid() / Constants::CALLING_UID_TRANSFORM_DIVISOR;
        if (callingUserId == 0) {
            callingUserId = FormUtil::GetCurrentAccountId();
        }
        HILOG_INFO("callingUserId is 0, update callingUserId:%{public}d", callingUserId);
    }
    auto renderIter = renderInners_.find(callingUserId);
    if (renderIter != renderInners_.end()) {
        return renderIter->second->RecycleForms(formIds, want, remoteObjectOfHost);
    }
    auto sandboxIter = sandboxInners_.find(callingUserId);
    if (sandboxIter != sandboxInners_.end()) {
        return sandboxIter->second->RecycleForms(formIds, want, remoteObjectOfHost);
    }
    return ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED;
}

ErrCode FormRenderMgr::RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams)
{
    int32_t callingUserId = IPCSkeleton::GetCallingUid() / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    auto renderIter = renderInners_.find(callingUserId);
    if (renderIter != renderInners_.end()) {
        return renderIter->second->RecoverForms(formIds, wantParams);
    }
    auto sandboxIter = sandboxInners_.find(callingUserId);
    if (sandboxIter != sandboxInners_.end()) {
        return sandboxIter->second->RecoverForms(formIds, wantParams);
    }
    return ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED;
}

void FormRenderMgr::DisconnectAllRenderConnections(int userId)
{
    HILOG_INFO("userId: %{public}d", userId);
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->DisconnectAllRenderConnections();
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->DisconnectAllRenderConnections();
    }
}

void FormRenderMgr::RerenderAllFormsImmediate(int userId)
{
    HILOG_INFO("userId: %{public}d", userId);
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->RerenderAllFormsImmediate();
    }
    auto sandboxIter = sandboxInners_.find(userId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->RerenderAllFormsImmediate();
    }
}

void FormRenderMgr::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth)
{
    int32_t callingUserId = IPCSkeleton::GetCallingUid() / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    auto renderIter = renderInners_.find(callingUserId);
    if (renderIter != renderInners_.end()) {
        renderIter->second->UpdateFormSize(formId, width, height, borderWidth);
    }
    auto sandboxIter = sandboxInners_.find(callingUserId);
    if (sandboxIter != sandboxInners_.end()) {
        sandboxIter->second->UpdateFormSize(formId, width, height, borderWidth);
    }
}

bool FormRenderMgr::CheckMultiAppFormVersionCode(const FormRecord &formRecord)
{
    FormInfo formInfo;
    if (FormInfoMgr::GetInstance().GetFormsInfoByRecord(formRecord, formInfo) != ERR_OK) {
        return false;
    }
    bool isMultiAppForm = FormInfoMgr::GetInstance().IsMultiAppForm(formInfo) && formRecord.isSystemApp;
    if (!isMultiAppForm) {
        return false;
    }
    uint32_t versionCode = formInfo.versionCode;
    uint32_t cacheCode = FormDbCache::GetInstance().GetMultiAppFormVersionCode(formRecord.bundleName);
    if (versionCode >= cacheCode) {
        if (versionCode > cacheCode) {
            FormDbCache::GetInstance().UpdateMultiAppFormVersionCode(formRecord.bundleName, versionCode);
        }
        HILOG_INFO("check version code ok, bundleName: %{public}s, formId:%{public}" PRId64,
            formRecord.bundleName.c_str(), formRecord.formId);
        return true;
    }
    return false;
}

bool FormRenderMgr::GetFRSDiedInLowMemoryByUid(int userId)
{
    HILOG_INFO("call");
    auto renderIter = renderInners_.find(userId);
    if (renderIter != renderInners_.end()) {
        return renderIter->second->GetIsFRSDiedInLowMemory();
    }
    HILOG_WARN("not find renderInner userId: %{public}d", userId);
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS
