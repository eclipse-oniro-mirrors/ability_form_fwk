/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_DISTRIBUTED_SCHED_H
#define OHOS_MOCK_DISTRIBUTED_SCHED_H

#include "gmock/gmock.h"
#include "distributed_sched_interface.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "form_share_info.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission_info.h"
#include "mission/distributed_mission_info.h"
#endif

namespace OHOS {
namespace DistributedSchedule {
class DistributedSchedStub : public IRemoteStub<IDistributedSched> {
public:
    DistributedSchedStub();
    virtual ~DistributedSchedStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) override;

    int32_t StartRemoteShareFormInner(MessageParcel &data, MessageParcel &reply);
    bool EnforceInterfaceToken(MessageParcel &data);
    MOCK_METHOD2(StartRemoteShareForm, int32_t(const std::string&, const AppExecFwk::FormShareInfo&));
    using DistributedSchedFunc = int32_t(DistributedSchedStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, DistributedSchedFunc> localFuncsMap_;
};


class DistributedSchedService : public DistributedSchedStub {
public:
    DistributedSchedService() = default;
    virtual ~DistributedSchedService() = default;

    MOCK_METHOD5(SendResultFromRemote,
        int32_t(OHOS::AAFwk::Want&, int32_t, const CallerInfo&, const AccountInfo&, int32_t));

    int32_t StartRemoteAbility(const OHOS::AAFwk::Want &want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken, uint32_t specifyTokenId = 0) override
    {
        return 0;
    }
    int32_t StartAbilityFromRemote(const OHOS::AAFwk::Want &want,
        const OHOS::AppExecFwk::AbilityInfo &abilityInfo, int32_t requestCode, const CallerInfo &callerInfo,
        const AccountInfo &accountInfo) override
    {
        return 0;
    }
    int32_t ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject> &callback, const OHOS::AAFwk::WantParams &wantParams) override
    {
        return 0;
    }
    int32_t StartContinuation(const OHOS::AAFwk::Want &want, int32_t missionId, int32_t callerUid,
        int32_t status, uint32_t accessToken) override
    {
        return 0;
    }
    void NotifyCompleteContinuation(const std::u16string &devId, int32_t sessionId, bool isSuccess) override
    {
        return;
    }
    int32_t NotifyContinuationResultFromRemote(int32_t sessionId, bool isSuccess, const std::string dstInfo) override
    {
        return 0;
    }
    int32_t ConnectRemoteAbility(const OHOS::AAFwk::Want &want, const sptr<IRemoteObject> &connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken) override
    {
        return 0;
    }
    int32_t DisconnectRemoteAbility(const sptr<IRemoteObject> &connect, int32_t callerUid,
        uint32_t accessToken) override
    {
        return 0;
    }
    int32_t ConnectAbilityFromRemote(const OHOS::AAFwk::Want &want, const AppExecFwk::AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &connect, const CallerInfo &callerInfo, const AccountInfo &accountInfo) override
    {
        return 0;
    }
    int32_t DisconnectAbilityFromRemote(const sptr<IRemoteObject> &connect,
        int32_t uid, const std::string &sourceDeviceId) override
    {
        return 0;
    }
    int32_t NotifyProcessDiedFromRemote(const CallerInfo &callerInfo) override
    {
        return 0;
    }
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    int32_t GetMissionInfos(const std::string &deviceId, int32_t numMissions,
        std::vector<AAFwk::MissionInfo> &missionInfos) override
    {
        return 0;
    }
    int32_t StoreSnapshotInfo(const std::string &deviceId, int32_t missionId,
        const uint8_t* byteStream, size_t len) override
    {
        return 0;
    }
    int32_t RemoveSnapshotInfo(const std::string &deviceId, int32_t missionId) override
    {
        return 0;
    }
    int32_t NotifyMissionsChangedFromRemote(const std::vector<DstbMissionInfo> &missionInfos,
        const CallerInfo &callerInfo) override
    {
        return 0;
    }
    int32_t CheckSupportOsd(const std::string &deviceId) override
    {
        return 0;
    }
    void GetCachedOsdSwitch(std::vector<std::u16string> &deviceIds, std::vector<int32_t> &values) override
    {
        return 0;
    }
    int32_t GetOsdSwitchValueFromRemote() override
    {
        return 0;
    }
    int32_t UpdateOsdSwitchValueFromRemote(int32_t switchVal, const std::string &sourceDeviceId) override
    {
        return 0;
    }
    std::unique_ptr<Snapshot> GetRemoteSnapshotInfo(const std::u16string &deviceId, int32_t missionId) override
    {
        return 0;
    }
    int32_t GetRemoteMissionSnapshotInfo(const std::string &networkId, int32_t missionId,
        std::unique_ptr<AAFwk::MissionSnapshot> &missionSnapshot) override
    {
        return 0;
    }
    int32_t StartSyncRemoteMissions(const std::string &devId, bool fixConflict, int64_t tag) override
    {
        return 0;
    }
    int32_t StartSyncMissionsFromRemote(const CallerInfo &callerInfo,
        std::vector<DstbMissionInfo> &missionInfos) override
    {
        return 0;
    }
    int32_t StopSyncRemoteMissions(const std::string &devId) override
    {
        return 0;
    }
    int32_t StopSyncMissionsFromRemote(const CallerInfo &callerInfo) override
    {
        return 0;
    }
    int32_t RegisterMissionListener(const std::u16string &devId, const sptr<IRemoteObject> &obj) override
    {
        return 0;
    }
    int32_t UnRegisterMissionListener(const std::u16string &devId, const sptr<IRemoteObject> &obj) override
    {
        return 0;
    }
#endif
    int32_t StartRemoteAbilityByCall(const OHOS::AAFwk::Want &want, const sptr<IRemoteObject> &connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken) override
    {
        return 0;
    }
    int32_t ReleaseRemoteAbility(const sptr<IRemoteObject> &connect,
        const AppExecFwk::ElementName &element) override
    {
        return 0;
    }
    int32_t StartAbilityByCallFromRemote(const OHOS::AAFwk::Want &want, const sptr<IRemoteObject> &connect,
        const CallerInfo &callerInfo, const AccountInfo &accountInfo) override
    {
        return 0;
    }
    int32_t ReleaseAbilityFromRemote(const sptr<IRemoteObject> &connect, const AppExecFwk::ElementName &element,
        const CallerInfo &callerInfo) override
    {
        return 0;
    }
    int32_t NotifyStateChangedFromRemote(int32_t abilityState, int32_t missionId,
        const AppExecFwk::ElementName& element) override
    {
        return 0;
    }
    #ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    int32_t StartShareFormFromRemote(
        const std::string &remoteDeviceId, const FormShareInfo &formShareInfo) override
    {
        return 0;
    }
    #endif
    int32_t GetDistributedComponentList(std::vector<std::string> &distributedComponents) override
    {
        return 0;
    }
    int32_t StopRemoteExtensionAbility(
        const OHOS::AAFwk::Want& want, int32_t callerUid, uint32_t accessToken, int32_t extensionType) override;
    int32_t StopExtensionAbilityFromRemote(const OHOS::AAFwk::Want& want,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t extensionType) override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_SCHED_PROXY_H