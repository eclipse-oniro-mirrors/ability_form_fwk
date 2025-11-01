/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_MOCK_ABILITY_MANAGER_H
#define OHOS_FORM_FWK_MOCK_ABILITY_MANAGER_H

#include <iremote_object.h>
#include <iremote_stub.h>
#include <iremote_proxy.h>

#include "ability_manager_interface.h"
#include "mock_form_provider_client.h"
#include "semaphore_ex.h"

namespace OHOS {
namespace AppExecFwk {
class MockAbilityMgrProxy : public IRemoteProxy<AAFwk::IAbilityManager> {
public:
    explicit MockAbilityMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<AAFwk::IAbilityManager>(impl)
    {}

    virtual~MockAbilityMgrProxy() = default;
    int StartAbility(
        const AAFwk::Want &want, int32_t userId = DEFAULT_INVAL_VALUE, int requestCode = -1) override
    {
        return 0;
    }
    int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int32_t userId = DEFAULT_INVAL_VALUE, int requestCode = -1) override
    {
        return 0;
    }
    int StartAbility(
        const Want &want,
        const StartOptions &startOptions,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE) override
    {
        return 0;
    }
    int TerminateAbility(
        const sptr<IRemoteObject> &token, int resultCode, const AAFwk::Want *resultWant = nullptr) override
    {
        return 0;
    }
    int ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t userId = DEFAULT_INVAL_VALUE) override
    {
        return 0;
    }
    int DisconnectAbility(sptr<AAFwk::IAbilityConnection> connect) override
    {
        return 0;
    }
    sptr<AAFwk::IAbilityScheduler> AcquireDataAbility(
        const Uri &uri, bool tryBind, const sptr<IRemoteObject> &callerToken) override
    {
        return nullptr;
    }
    int ReleaseDataAbility(
        sptr<AAFwk::IAbilityScheduler> dataAbilityScheduler, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }

    int AttachAbilityThread(
        const sptr<AAFwk::IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int AbilityTransitionDone(const sptr<IRemoteObject> &token, int state, const PacMap &saveData) override
    {
        return 0;
    }

    sptr<AAFwk::IWantSender> GetWantSender(
        const AAFwk::WantSenderInfo &wantSenderInfo, const sptr<IRemoteObject> &callerToken, int32_t uid) override
    {
        return nullptr;
    }
    int SendWantSender(sptr<AAFwk::IWantSender> target, AAFwk::SenderInfo &senderInfo) override
    {
        return 0;
    }
    void CancelWantSender(const sptr<AAFwk::IWantSender> &sender) override
    {
        return;
    }
    int GetPendingWantUid(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    int GetPendingWantUserId(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    std::string GetPendingWantBundleName(const sptr<AAFwk::IWantSender> &target) override
    {
        return "";
    }
    int GetPendingWantCode(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    int GetPendingWantType(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    void RegisterCancelListener(
        const sptr<AAFwk::IWantSender> &sender, const sptr<AAFwk::IWantReceiver> &receiver) override
    {
        return;
    }
    int32_t ReportDrawnCompleted(const sptr<IRemoteObject>& callerToken) override
    {
        return 0;
    }
    void UnregisterCancelListener(
        const sptr<AAFwk::IWantSender> &sender, const sptr<AAFwk::IWantReceiver> &receiver) override
    {
        return;
    }
    int GetPendingRequestWant(const sptr<AAFwk::IWantSender> &target, std::shared_ptr<Want> &want) override
    {
        return 0;
    }
    int ScheduleConnectAbilityDone(const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject)
    {
        return 0;
    }
    int ScheduleDisconnectAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int ScheduleCommandAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int ScheduleCommandAbilityWindowDone(
        const sptr<IRemoteObject> &token,
        const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd,
        AAFwk::AbilityCommand abilityCmd) override
    {
        return 0;
    }
    void DumpState(const std::string &args, std::vector<std::string> &state) override
    {
        return;
    }
    int StopServiceAbility(const AAFwk::Want &want, int32_t userId = DEFAULT_INVAL_VALUE,
        const sptr<IRemoteObject> &token = nullptr) override
    {
        return 0;
    }

    int32_t GetMissionIdByToken(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    void GetAbilityTokenByCalleeObj(const sptr<IRemoteObject> &callStub, sptr<IRemoteObject> &token) override
    {
        return;
    }

    int KillProcess(const std::string &bundleName, const bool clreaPageStack = true, int32_t appIndex = 0) override
    {
        return 0;
    }
    int UninstallApp(const std::string &bundleName, int32_t uid) override
    {
        return 0;
    }
    int TerminateAbilityByRecordId(const int64_t recordId = -1)
    {
        return 0;
    }

    int StartContinuation(const Want &want, const sptr<IRemoteObject> &abilityToken, int32_t status) override
    {
        return 0;
    }
    int NotifyContinuationResult(int32_t missionId, int32_t result) override
    {
        return 0;
    }
    int ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams) override
    {
        return 0;
    }
    int ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode) override
    {
        return 0;
    }
    void NotifyCompleteContinuation(const std::string &deviceId, int32_t sessionId, bool isSuccess) override
    {}

    int LockMissionForCleanup(int32_t missionId) override
    {
        return 0;
    }

    int UnlockMissionForCleanup(int32_t missionId) override
    {
        return 0;
    }

    int RegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 0;
    }

    int UnRegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 0;
    }

    int GetMissionInfos(const std::string& deviceId, int32_t numMax,
        std::vector<MissionInfo> &missionInfos) override
    {
        return 0;
    }

    int GetMissionInfo(const std::string& deviceId, int32_t missionId,
        MissionInfo &missionInfo) override
    {
        return 0;
    }

    int CleanMission(int32_t missionId) override
    {
        return 0;
    }

    int CleanAllMissions() override
    {
        return 0;
    }
    int MoveMissionToFront(int32_t missionId) override
    {
        return 0;
    }
    int MoveMissionToFront(int32_t missionId, const StartOptions &startOptions) override
    {
        return 0;
    }
#ifdef SUPPORT_GRAPHICS
    int SetMissionLabel(const sptr<IRemoteObject> &token,
        const std::string &lable) override
    {
        return 0;
    }

    int SetMissionIcon(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &icon) override
    {
        return 0;
    }

    void CompleteFirstFrameDrawing(const sptr<IRemoteObject> &abilityToken) override {}
#endif
    int StartUserTest(const Want &want, const sptr<IRemoteObject> &observer) override
    {
        return 0;
    }

    int FinishUserTest(
        const std::string &msg, const int64_t &resultCode, const std::string &bundleName) override
    {
        return 0;
    }

    int GetTopAbility(sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int DelegatorDoAbilityForeground(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int DelegatorDoAbilityBackground(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int DoAbilityForeground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 0;
    }

    int DoAbilityBackground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 0;
    }
    int32_t IsValidMissionIds(const std::vector<int32_t>& missionIds, std::vector<MissionValidResult>& results)
    {
        return 0;
    }

    int32_t ExecuteIntent(uint64_t key,  const sptr<IRemoteObject> &callerToken,
        const InsightIntentExecuteParam &param)
    {
        return 0;
    }

    int32_t ExecuteInsightIntentDone(const sptr<IRemoteObject> &token, uint64_t intentId,
        const InsightIntentExecuteResult &result)
    {
        return 0;
    }

    int32_t GetForegroundUIAbilities(std::vector<AppExecFwk::AbilityStateData> &list) override
    {
        return 0;
    }
};

class MockAbilityMgrStub : public IRemoteStub<AAFwk::IAbilityManager> {
public:
    using Uri = OHOS::Uri;
    MockAbilityMgrStub() = default;
    virtual ~MockAbilityMgrStub() = default;

    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    int32_t SetApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag) override
    {
        return 0;
    }

    int32_t CancelApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag) override
    {
        return 0;
    }
};
class MockAbilityMgrService : public MockAbilityMgrStub {
public:
    void Wait()
    {
        sem_.Wait();
    }

    int Post()
    {
        sem_.Post();
        return 0;
    }

    void PostVoid()
    {
        sem_.Post();
    }

    int StartAbility(
        const AAFwk::Want &want, int32_t userId = DEFAULT_INVAL_VALUE, int requestCode = -1) override
    {
        return startAbility_;
    }
    int StartAbility(const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken,
        int32_t userId = DEFAULT_INVAL_VALUE, int requestCode = -1) override
    {
        return startAbility_;
    }

    int32_t StartAbilityByInsightIntent(const Want &want, const sptr<IRemoteObject> &callerToken,
        uint64_t intentId, int32_t userId) override
    {
        return 0;
    }

    int StartAbility(
        const Want &want,
        const StartOptions &startOptions,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE) override
    {
        return startAbility_;
    }
    int TerminateAbility(
        const sptr<IRemoteObject> &token, int resultCode, const AAFwk::Want *resultWant = nullptr) override
    {
        return 0;
    }
    int CloseAbility(const sptr<IRemoteObject> &token, int resultCode = DEFAULT_INVAL_VALUE,
        const Want *resultWant = nullptr) override
    {
        return 0;
    }
    int MinimizeAbility(const sptr<IRemoteObject> &token, bool fromUser) override
    {
        return 0;
    }
    int ConnectAbility(const AAFwk::Want &want, const sptr<AAFwk::IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t userId = DEFAULT_INVAL_VALUE) override
    {
        connect->OnAbilityConnectDone(want.GetElement(), new (std::nothrow) MockFormProviderClient(), 0);
        return 0;
    }
    int DisconnectAbility(sptr<AAFwk::IAbilityConnection> connect) override
    {
        return 0;
    }
    sptr<AAFwk::IAbilityScheduler> AcquireDataAbility(
        const Uri &uri, bool tryBind, const sptr<IRemoteObject> &callerToken) override
    {
        return nullptr;
    }
    int ReleaseDataAbility(
        sptr<AAFwk::IAbilityScheduler> dataAbilityScheduler, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int AttachAbilityThread(
        const sptr<AAFwk::IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int AbilityTransitionDone(const sptr<IRemoteObject> &token, int state, const PacMap &saveData) override
    {
        return 0;
    }
    int ScheduleConnectAbilityDone(
        const sptr<IRemoteObject> &token, const sptr<IRemoteObject> &remoteObject) override
    {
        return 0;
    }
    int ScheduleDisconnectAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int ScheduleCommandAbilityDone(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }
    int ScheduleCommandAbilityWindowDone(
        const sptr<IRemoteObject> &token,
        const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd,
        AAFwk::AbilityCommand abilityCmd) override
    {
        return 0;
    }
    void DumpState(const std::string &args, std::vector<std::string> &state) override
    {
        return;
    }

    void DumpSysState(
        const std::string& args, std::vector<std::string>& state, bool isClient, bool isUserID, int UserID) override
    {
        return;
    }

    int StopServiceAbility(const AAFwk::Want &want, int32_t userId = DEFAULT_INVAL_VALUE,
        const sptr<IRemoteObject> &token = nullptr) override
    {
        return 0;
    }

    sptr<AAFwk::IWantSender> GetWantSender(
        const AAFwk::WantSenderInfo &wantSenderInfo, const sptr<IRemoteObject> &callerToken, int32_t uid) override
    {
        return nullptr;
    }
    int SendWantSender(sptr<AAFwk::IWantSender> target, AAFwk::SenderInfo &senderInfo) override
    {
        return 0;
    }
    void CancelWantSender(const sptr<AAFwk::IWantSender> &sender) override
    {
        return;
    }
    int GetPendingWantUid(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    int GetPendingWantUserId(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    std::string GetPendingWantBundleName(const sptr<AAFwk::IWantSender> &target) override
    {
        return "";
    }
    int GetPendingWantCode(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    int GetPendingWantType(const sptr<AAFwk::IWantSender> &target) override
    {
        return 0;
    }
    int32_t ReportDrawnCompleted(const sptr<IRemoteObject>& callerToken) override
    {
        return 0;
    }
    void RegisterCancelListener(
        const sptr<AAFwk::IWantSender> &sender, const sptr<AAFwk::IWantReceiver> &receiver) override
    {
        return;
    }
    void UnregisterCancelListener(
        const sptr<AAFwk::IWantSender> &sender, const sptr<AAFwk::IWantReceiver> &receiver) override
    {
        return;
    }
    int GetPendingRequestWant(const sptr<AAFwk::IWantSender> &target, std::shared_ptr<Want> &want) override
    {
        return 0;
    }

    int32_t GetMissionIdByToken(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    void GetAbilityTokenByCalleeObj(const sptr<IRemoteObject> &callStub, sptr<IRemoteObject> &token) override
    {
        return;
    }

    int KillProcess(const std::string &bundleName, const bool clreaPageStack = true, int32_t appIndex = 0) override
    {
        return 0;
    }
    int UninstallApp(const std::string &bundleName, int32_t uid) override
    {
        return 0;
    }
    int TerminateAbilityByRecordId(const int64_t recordId = -1)
    {
        return 0;
    }

    int StartAbility(
        const Want &want,
        const AbilityStartSetting &abilityStartSetting,
        const sptr<IRemoteObject> &callerToken,
        int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE) override
    {
        return startAbility_;
    }

    int GetWantSenderInfo(const sptr<IWantSender> &target, std::shared_ptr<WantSenderInfo> &info) override
    {
        return 0;
    }
    int LockMissionForCleanup(int32_t missionId) override
    {
        return 0;
    }
        int StartContinuation(const Want &want, const sptr<IRemoteObject> &abilityToken, int32_t status) override
    {
        return 0;
    }
    int NotifyContinuationResult(int32_t missionId, int32_t result) override
    {
        return 0;
    }
    int ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams) override
    {
        return 0;
    }
    int ContinueAbility(const std::string &deviceId, int32_t missionId, uint32_t versionCode) override
    {
        return 0;
    }
    void NotifyCompleteContinuation(const std::string &deviceId, int32_t sessionId, bool isSuccess) override
    {}

    int UnlockMissionForCleanup(int32_t missionId) override
    {
        return 0;
    }

    int RegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 0;
    }

    int UnRegisterMissionListener(const sptr<IMissionListener> &listener) override
    {
        return 0;
    }

    int GetMissionInfos(const std::string& deviceId, int32_t numMax,
        std::vector<MissionInfo> &missionInfos) override
    {
        return 0;
    }

    int GetMissionInfo(const std::string& deviceId, int32_t missionId,
        MissionInfo &missionInfo) override
    {
        return 0;
    }

    int CleanMission(int32_t missionId) override
    {
        return 0;
    }

    int CleanAllMissions() override
    {
        return 0;
    }
#ifdef SUPPORT_GRAPHICS
    void CompleteFirstFrameDrawing(const sptr<IRemoteObject> &abilityToken) override {}

    int SetMissionLabel(const sptr<IRemoteObject> &token,
        const std::string &lable) override
    {
        return 0;
    }

    int SetMissionIcon(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &icon) override
    {
        return 0;
    }
#endif
    int StartUserTest(const Want &want, const sptr<IRemoteObject> &observer) override
    {
        return 0;
    }

    int FinishUserTest(
        const std::string &msg, const int64_t &resultCode, const std::string &bundleName) override
    {
        return 0;
    }

    int GetTopAbility(sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int DelegatorDoAbilityForeground(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int DelegatorDoAbilityBackground(const sptr<IRemoteObject> &token) override
    {
        return 0;
    }

    int MoveMissionToFront(int32_t missionId) override
    {
        return 0;
    }
    int MoveMissionToFront(int32_t missionId, const StartOptions &startOptions) override
    {
        return 0;
    }
    int StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag) override
    {
        return 0;
    }
    int StopSyncRemoteMissions(const std::string& devId) override
    {
        return 0;
    }
    int RegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) override
    {
        return 0;
    }
    int UnRegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) override
    {
        return 0;
    }
    int GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info) override
    {
        return 0;
    }
    int GetExtensionRunningInfos(int upperLimit, std::vector<ExtensionRunningInfo> &info) override
    {
        return 0;
    }
    int GetProcessRunningInfos(std::vector<AppExecFwk::RunningProcessInfo> &info) override
    {
        return 0;
    }
    int SetAbilityController(const sptr<AppExecFwk::IAbilityController> &abilityController,
        bool imAStabilityTest) override
    {
        return 0;
    }
    bool IsRunningInStabilityTest() override
    {
        return true;
    }
    int StartUser(int userId, uint64_t displayId, sptr<IUserCallback> callback, bool isAppRecovery) override
    {
        return 0;
    }
    int StopUser(int userId, const sptr<IUserCallback> &callback) override
    {
        return 0;
    }
    int GetMissionSnapshot(const std::string& deviceId, int32_t missionId,
        MissionSnapshot& snapshot, bool isLowResolution) override
    {
        return 0;
    }
    int RegisterSnapshotHandler(const sptr<ISnapshotHandler>& handler) override
    {
        return 0;
    }
#ifdef SUPPORT_GRAPHICS
    int RegisterWindowManagerServiceHandler(const sptr<IWindowManagerServiceHandler>& handler,
        bool animationEnabled = true) override
    {
        return 0;
    }
#endif

    int StartAbilityByCall(const Want &want, const sptr<IAbilityConnection> &connect,
        const sptr<IRemoteObject> &callerToken, int32_t accountId = DEFAULT_INVAL_VALUE, bool isSilent = false,
        bool promotePriority = false) override
    {
        return startAbilityByCall_;
    }
    int ReleaseCall(
        const sptr<IAbilityConnection> &connect, const AppExecFwk::ElementName &element) override
    {
        return 0;
    }

    int DoAbilityForeground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 0;
    }

    int DoAbilityBackground(const sptr<IRemoteObject> &token, uint32_t flag) override
    {
        return 0;
    }

    #ifdef ABILITY_COMMAND_FOR_TEST
    int ForceTimeoutForTest(const std::string &abilityName, const std::string &state) override
    {
        return 0;
    }

    int BlockAmsService() override
    {
        return 0;
    }

    int BlockAppService() override
    {
        return 0;
    }

    int BlockAbility(int32_t abilityRecordId) override
    {
        return 0;
    }
    #endif
    int32_t IsValidMissionIds(const std::vector<int32_t>& missionIds, std::vector<MissionValidResult>& results)
    {
        return 0;
    }

    int32_t RegisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener)
    {
        return 0;
    }

    int32_t UnregisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener)
    {
        return 0;
    }

    int32_t AttachAppDebug(const std::string &bundleName, bool isDebugFromLocal)
    {
        return 0;
    }

    int32_t DetachAppDebug(const std::string &bundleName, bool isDebugFromLocal)
    {
        return 0;
    }

    int32_t ExecuteIntent(uint64_t key,  const sptr<IRemoteObject> &callerToken,
        const InsightIntentExecuteParam &param)
    {
        return 0;
    }

    int32_t ExecuteInsightIntentDone(const sptr<IRemoteObject> &token, uint64_t intentId,
        const InsightIntentExecuteResult &result)
    {
        return 0;
    }

    int32_t GetForegroundUIAbilities(std::vector<AppExecFwk::AbilityStateData> &list) override
    {
        return 0;
    }

    int StartAbilityWithSpecifyTokenId(const Want& want,
        const sptr<IRemoteObject>& callerToken,
        uint32_t specifyTokenId,
        int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE)
    {
        return startAbilityWithSpecifyTokenId_;
    }

    int StartAbilityOnlyUIAbility(const Want& want, const sptr<IRemoteObject>& callerToken,
        uint32_t specifyTokenId)
    {
        return startAbilityOnlyUIAbility_;
    }

    int32_t startAbility_ = 0;

    int32_t startAbilityByCall_ = 0;

    int32_t startAbilityWithSpecifyTokenId_ = 0;

    int32_t startAbilityOnlyUIAbility_ = 0;
private:
    Semaphore sem_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_ABILITY_MANAGER_H
