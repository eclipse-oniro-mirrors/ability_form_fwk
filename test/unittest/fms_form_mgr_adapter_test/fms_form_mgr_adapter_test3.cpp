/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#define private public
#include "form_mgr/form_mgr_adapter.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "mock_ability_manager.h"
#include "mock_bundle_mgr.h"
#include "mock_form_data_mgr.h"
#include "mock_form_provider_client.h"
#include "mock_form_mgr_adapter_test.h"
#include "mock_want.h"
#include "mock_ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgReferee;

extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockGetFormRecordParams(bool mockRet);
extern void MockGetFormRecordParamsUid(bool mockRet);
extern void MockSceneAnimationCheck(OHOS::ErrCode mockRet);

namespace {
static const int64_t MAX_NUMBER_OF_JS = 0x20000000000000;
constexpr int32_t DEFAULT_CALLING_UID = 20000001;

class FmsFormMgrAdapterTest3 : public testing::Test {
public:
    FormItemInfo* formItemInfo_;
    sptr<IRemoteObject>* callerToken_;
    FormJsInfo* formJsInfo_;
    std::mutex formResultMutex_;
    std::map<int64_t, AddFormResultErrorCode> formIdMap_;
    void SetUp();
    void TearDown();
};

void FmsFormMgrAdapterTest3::SetUp()
{
    formItemInfo_ = new FormItemInfo();
    callerToken_ = new sptr<IRemoteObject>();
    formJsInfo_ = new FormJsInfo();
    formResultMutex_.lock();
    formIdMap_.clear();
    formResultMutex_.unlock();
}
void FmsFormMgrAdapterTest3::TearDown()
{
    delete formItemInfo_;
    formItemInfo_ = nullptr;
    delete callerToken_;
    callerToken_ = nullptr;
    delete formJsInfo_;
    formJsInfo_ = nullptr;
    formResultMutex_.lock();
    formIdMap_.clear();
    formResultMutex_.unlock();
}

/**
 * @tc.name: FormMgrAdapter_0246
 * @tc.desc: test CancelAddFormRequestTimeOutTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0246, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0246 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int result = ERR_APPEXECFWK_FORM_COMMON_CODE;
    const std::string queueName = "queue";
    formMgrAdapter.serialQueue_ = std::make_unique<FormSerialQueue>(queueName.c_str());
    formMgrAdapter.CancelAddFormRequestTimeOutTask(formId, result);
    EXPECT_EQ(formMgrAdapter.formIdMap_.find(formId), formMgrAdapter.formIdMap_.end());
    formMgrAdapter.formIdMap_[formId] = AddFormResultErrorCode::UNKNOWN;
    formMgrAdapter.CancelAddFormRequestTimeOutTask(formId, result);
    auto iter = formMgrAdapter.formIdMap_.find(formId);
    EXPECT_EQ(iter->second, AddFormResultErrorCode::FAILED);
    result = ERR_OK;
    formMgrAdapter.CancelAddFormRequestTimeOutTask(formId, result);
    iter = formMgrAdapter.formIdMap_.find(formId);
    EXPECT_EQ(iter->second, AddFormResultErrorCode::SUCCESS);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0246 end";
}

/**
 * @tc.name: FormMgrAdapter_0247
 * @tc.desc: test RemoveFormIdMapElement function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0247, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0247 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    formMgrAdapter.formIdMap_[formId] = AddFormResultErrorCode::UNKNOWN;
    formMgrAdapter.RemoveFormIdMapElement(formId);
    EXPECT_EQ(formMgrAdapter.formIdMap_.find(formId), formMgrAdapter.formIdMap_.end());
    GTEST_LOG_(INFO) << "FormMgrAdapter_0247 end";
}

/**
 * @tc.name: FormMgrAdapter_0248
 * @tc.desc: test StopRenderingForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0248, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0248 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::string compId;
    auto ret = formMgrAdapter.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formId = 1;
    ret = formMgrAdapter.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    compId = "compId";
    formId = 0;
    ret = formMgrAdapter.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formId = 1;
    ret = formMgrAdapter.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0248 end";
}

/**
 * @tc.name: FormMgrAdapter_0249
 * @tc.desc: test PaddingNotifyVisibleFormsMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0249, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0249 start";
    FormMgrAdapter formMgrAdapter;
    int32_t formVisibleType = 1;
    int64_t formId = 2;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::string specialFlag = "#";
    bool isVisibility = (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE));
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormInstance formInstance;
    FormDataMgr::GetInstance().GetFormInstanceById(matchedFormId, false, formInstance);
    std::string formHostName = formInstance.formHostName;
    std::vector<sptr<IRemoteObject>> formObserver;
    auto first = formHostName + specialFlag + std::to_string(isVisibility);
    formMgrAdapter.formObservers_[first] = formObserver;
    formMgrAdapter.PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
    EXPECT_FALSE(formInstanceMaps.empty());
    auto iter = formMgrAdapter.formObservers_.find(first);
    auto observer = formInstanceMaps.find(iter->first);
    auto sizeOne = observer->second.size();
    formMgrAdapter.PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
    iter = formMgrAdapter.formObservers_.find(first);
    observer = formInstanceMaps.find(iter->first);
    EXPECT_EQ(observer->second.size(), sizeOne + 1);
    formInstanceMaps.clear();
    std::string formAllHostName = "";
    first = formAllHostName + specialFlag + std::to_string(isVisibility);
    formMgrAdapter.formObservers_.clear();
    formMgrAdapter.formObservers_[first] = formObserver;
    auto mapSize = formInstanceMaps.size();
    formMgrAdapter.PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
    EXPECT_EQ(formInstanceMaps.size(), mapSize + 1);
    first = "first";
    formMgrAdapter.formObservers_.clear();
    formMgrAdapter.formObservers_[first] = formObserver;
    formMgrAdapter.PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
    EXPECT_EQ(formInstanceMaps.size(), mapSize + 1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0249 end";
}

/**
 * @tc.name: FormMgrAdapter_0250
 * @tc.desc: test HandlerNotifyWhetherVisibleForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0250, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0250 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {1};
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    int32_t formVisibleType = static_cast<int32_t>(FormVisibilityType::VISIBLE);
    std::string eventMapFirst = "eventMapFirst";
    eventMaps[eventMapFirst] = {0};
    std::string bundleName = "bundleName";
    std::vector<sptr<IRemoteObject>> formObserver;
    sptr<IRemoteObject> iRemoteObjectPtr = nullptr;
    formObserver.push_back(iRemoteObjectPtr);
    formMgrAdapter.formObservers_[bundleName] = formObserver;
    std::vector<FormInstance> formInstanceVector;
    formInstanceMaps[bundleName] = formInstanceVector;
    formMgrAdapter.HandlerNotifyWhetherVisibleForms(formIds,
        formInstanceMaps, eventMaps, formVisibleType, iRemoteObjectPtr);
    auto iter = eventMaps.find(eventMapFirst);
    auto ret = formMgrAdapter.HandleEventNotify(iter->first, iter->second, formVisibleType);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0250 end";
}

/**
 * @tc.name: FormMgrAdapter_0251
 * @tc.desc: test DumpHasFormVisible function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0251, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0251 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleInfo = "1_2";
    std::string formInfos = "test";
    auto ret = formMgrAdapter.DumpHasFormVisible(bundleInfo, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    bundleInfo = "1_2_3";
    ret = formMgrAdapter.DumpHasFormVisible(bundleInfo, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0251 end";
}

/**
 * @tc.name: FormMgrAdapter_0253
 * @tc.desc: test AllotFormBySpecificId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0253, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0253 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    auto ret = formMgrAdapter.AllotFormBySpecificId(info, callerToken, wantParams, formInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0253 end";
}

/**
 * @tc.name: FormMgrAdapter_0254
 * @tc.desc: test AcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0254, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0254 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    info.SetEnableForm(false);
    auto ret = formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0254 end";
}

/**
 * @tc.name: FormMgrAdapter_0255
 * @tc.desc: test SetFormItemModuleInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0255, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0255 start";
    FormMgrAdapter formMgrAdapter;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.hapPath = "/data/app/el1/bundle/public";
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfo.name = "Ability1";
    abilityInfo.isModuleJson = true;
    abilityInfo.moduleName = "moduleName";
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    FormInfo formInfo;
    formInfo.abilityName = "Ability1";
    FormItemInfo itemInfo;
    itemInfo.SetFormSrc("test");
    formMgrAdapter.SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    EXPECT_EQ(itemInfo.formSrc_, "test");
    EXPECT_EQ(itemInfo.abilityModuleName_, abilityInfo.moduleName);
    formInfo.abilityName = "Ability2";
    FormItemInfo itemInfo2;
    formMgrAdapter.SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
    EXPECT_NE(itemInfo2.abilityModuleName_, abilityInfo.moduleName);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0255 end";
}

/**
 * @tc.name: FormMgrAdapter_0256
 * @tc.desc: test ReleaseRenderer function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0256, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0256 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    std::string compId = "";
    auto ret = formMgrAdapter.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formId = 1;
    ret = formMgrAdapter.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formId = -1;
    compId = "compId";
    ret = formMgrAdapter.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formId = 1;
    compId = "compId";
    ret = formMgrAdapter.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0256 end";
}

/**
 * @tc.name: FormMgrAdapter_0257
 * @tc.desc: test RequestPublishFormToHost function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0257, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0257 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    EXPECT_EQ(ERR_OK, formMgrAdapter.QueryPublishFormToHost(want));
    EXPECT_EQ(ERR_OK, formMgrAdapter.RequestPublishFormToHost(want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0257 end";
}

/**
 * @tc.name: FormMgrAdapter_0258
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0258, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0258 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = MAX_NUMBER_OF_JS;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formMgrAdapter.RouterEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0258 end";
}

/**
 * @tc.name: FormMgrAdapter_0259
 * @tc.desc: test BackgroundEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0259, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0259 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want = {};
    want.SetUri("url");
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formMgrAdapter.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0259 end";
}

/**
 * @tc.name: FormMgrAdapter_0260
 * @tc.desc: test HandleUpdateFormFlag function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0260, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0260 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {1};
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formMgrAdapter.HandleUpdateFormFlag(formIds, callerToken, false, false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, ret);
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    ret = formMgrAdapter.HandleUpdateFormFlag(formIds, callerToken2, false, false);
    EXPECT_NE(ERR_APPEXECFWK_FORM_INVALID_PARAM, ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0260 end";
}

/**
 * @tc.name: FormMgrAdapter_0261
 * @tc.desc: test UpdateProviderInfoToHost function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0261, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0261 start";
    FormMgrAdapter formMgrAdapter;
    int64_t mFormId = 0;
    int32_t userId = 0;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t formVisibleType = Constants::FORM_VISIBLE;
    FormRecord formRecord;
    formRecord.needRefresh = true;
    formRecord.isTimerRefresh = true;
    auto ret = formMgrAdapter.UpdateProviderInfoToHost(mFormId, userId, callerToken, formVisibleType, formRecord);
    EXPECT_TRUE(ret);
    formVisibleType = Constants::FORM_INVISIBLE;
    ret = formMgrAdapter.UpdateProviderInfoToHost(mFormId, userId, callerToken, formVisibleType, formRecord);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0261 end";
}

/**
 * @tc.name: FormMgrAdapter_0262
 * @tc.desc: test GetFormsCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0262, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0262 start";
    FormMgrAdapter formMgrAdapter;
    bool isTempFormFlag = true;
    int32_t formCount = 1;
    auto ret = formMgrAdapter.GetFormsCount(isTempFormFlag, formCount);
    EXPECT_EQ(ERR_OK, ret);
    isTempFormFlag = false;
    ret = formMgrAdapter.GetFormsCount(isTempFormFlag, formCount);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0262 end";
}

/**
 * @tc.name: FormMgrAdapter_0263
 * @tc.desc: test RegisterAddObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0263, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0263 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = nullptr;
    formMgrAdapter.RegisterAddObserver(bundleName, callerToken);
    EXPECT_FALSE(formMgrAdapter.formObservers_.empty());
    auto ret = formMgrAdapter.RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, ret);
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    ret = formMgrAdapter.RegisterAddObserver(bundleName, callerToken2);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0263 end";
}

/**
 * @tc.name: FormMgrAdapter_0264
 * @tc.desc: test RegisterRemoveObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0264, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0264 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formMgrAdapter.RegisterAddObserver(bundleName, callerToken);
    EXPECT_FALSE(formMgrAdapter.formObservers_.empty());
    sptr<IRemoteObject> callerToken2 = nullptr;
    auto ret = formMgrAdapter.RegisterRemoveObserver(bundleName, callerToken2);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, ret);
    ret = formMgrAdapter.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ERR_OK, ret);
    ret = formMgrAdapter.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, ret);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0264 end";
}

/**
 * @tc.name: FormMgrAdapter_0265
 * @tc.desc: test SetDeathRecipient function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0265, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0265 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formMgrAdapter.SetDeathRecipient(callerToken, deathRecipient);
    EXPECT_TRUE(formMgrAdapter.deathRecipients_.empty());
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    formMgrAdapter.SetDeathRecipient(callerToken, deathRecipient);
    EXPECT_TRUE(formMgrAdapter.deathRecipients_.empty());
    GTEST_LOG_(INFO) << "FormMgrAdapter_0265 end";
}

/**
 * @tc.name: FormMgrAdapter_0266
 * @tc.desc: test CleanResource function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0266, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0266 start";
    FormMgrAdapter formMgrAdapter;
    wptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    auto object = remote.promote();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formMgrAdapter.deathRecipients_[object] = deathRecipient;
    formMgrAdapter.CleanResource(remote);
    EXPECT_TRUE(formMgrAdapter.deathRecipients_.empty());
    GTEST_LOG_(INFO) << "FormMgrAdapter_0266 end";
}

/**
 * @tc.name: FormMgrAdapter_0267
 * @tc.desc: test RegisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0267, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0267 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback = new (std::nothrow) MockFormProviderClient();
    auto ret = formMgrAdapter.RegisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0267 end";
}

/**
 * @tc.name: FormMgrAdapter_0268
 * @tc.desc: test UnregisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0268, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0268 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback = new (std::nothrow) MockFormProviderClient();
    auto ret = formMgrAdapter.UnregisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0268 end";
}

/**
 * @tc.name: FormMgrAdapter_0269
 * @tc.desc: test RegisterClickEventObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0269, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0269 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string formEventType = "";
    sptr<IRemoteObject> observer = nullptr;
    auto ret = formMgrAdapter.RegisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0269 end";
}

/**
 * @tc.name: FormMgrAdapter_0270
 * @tc.desc: test UnregisterClickEventObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0270, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0270 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string formEventType = "";
    sptr<IRemoteObject> observer = nullptr;
    auto ret = formMgrAdapter.UnregisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    sptr<IRemoteObject> observer2 = new (std::nothrow) MockFormProviderClient();
    ret = formMgrAdapter.UnregisterClickEventObserver(bundleName, formEventType, observer2);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0270 end";
}

/**
 * @tc.name: FormMgrAdapter_0271
 * @tc.desc: test IsFormRenderServiceCall function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0271, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0271 start";
    FormMgrAdapter formMgrAdapter;
    int callingUid = 0;
    EXPECT_FALSE(formMgrAdapter.IsFormRenderServiceCall(callingUid));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0271 end";
}

/**
 * @tc.name: FormMgrAdapter_0272
 * @tc.desc: test SetFormsRecyclable function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0272, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0272 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {0, 1};
    auto ret = formMgrAdapter.SetFormsRecyclable(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0272 end";
}

/**
 * @tc.name: FormMgrAdapter_0273
 * @tc.desc: test RecycleForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0273, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0273 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {0, 1};
    Want want;
    auto ret = formMgrAdapter.RecycleForms(formIds, want, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0273 end";
}

/**
 * @tc.name: FormMgrAdapter_0274
 * @tc.desc: test RecoverForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0274, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0274 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {0, 1};
    Want want;
    auto ret = formMgrAdapter.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockFormRecordIsDynamic(false);
    ret = formMgrAdapter.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0274 end";
}

/**
 * @tc.name: FormMgrAdapter_RecoverForms
 * @tc.desc: test RecoverForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_RecoverForms, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_RecoverForms start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds = {1};
    Want want = {};

    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockFormRecordIsDynamic(true);

    MockGetBoolParam(false);
    MockIsExistRecycleTask(true);
    EXPECT_EQ(formMgrAdapter.RecoverForms(formIds, want), ERR_OK);

    MockGetBoolParam(false);
    MockIsExistRecycleTask(false);
    EXPECT_EQ(formMgrAdapter.RecoverForms(formIds, want), ERR_APPEXECFWK_FORM_INVALID_PARAM);

    MockGetBoolParam(true);
    MockIsExistRecycleTask(true);
    EXPECT_EQ(formMgrAdapter.RecoverForms(formIds, want), ERR_OK);

    MockGetBoolParam(true);
    MockIsExistRecycleTask(false);
    EXPECT_EQ(formMgrAdapter.RecoverForms(formIds, want), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrAdapter_RecoverForms end";
}

 /**
 * @tc.name: FormMgrAdapter_0278_0
 * @tc.desc: test AllotForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0278_0, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0278_0 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    want.SetParam(Constants::KEY_DIRECT_CALL_INAPP, true);
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE, Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE);
    formItemInfo_->SetProviderBundleName("providerBundle");
    formItemInfo_->SetHostBundleName("providerBundle");
    ErrCode ret = formMgrAdapter.AllotForm(formId, want, *callerToken_, *formJsInfo_, *formItemInfo_);
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::UNKNOWN));
    formMgrAdapter.StartAbilityByFms(want);
    formMgrAdapter.IsForegroundApp();
    formMgrAdapter.GetAppMgr();
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0278_0 end";
}

/**
 * @tc.name: FormMgrAdapter_0275
 * @tc.desc: test AllotForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0275, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0275 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    // Set up Want parameters for share form
    want.SetParam(Constants::KEY_DIRECT_CALL_INAPP, true);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);

    // Set up FormItemInfo
    formItemInfo_->SetProviderBundleName("providerBundle");
    formItemInfo_->SetHostBundleName("hostBundle");
    formItemInfo_->SetTransparencyEnabled(false);

    // Call the method under test
    ErrCode ret = formMgrAdapter.AllotForm(formId, want, *callerToken_, *formJsInfo_, *formItemInfo_);

    // Verify the result
    EXPECT_EQ(ret, 2293761);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0275 end";
}

/**
 * @tc.name: FormMgrAdapter_0276
 * @tc.desc: test AllotForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0276, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0276 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 123;
    Want want;
    // Set up Want parameters for specific form
    want.SetParam(Constants::PARAM_FORM_MIGRATE_FORM_KEY, true);

    // Set up FormItemInfo
    formItemInfo_->SetProviderBundleName("providerBundle");
    formItemInfo_->SetHostBundleName("hostBundle");
    formItemInfo_->SetTransparencyEnabled(false);

    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(false);
    MockIPCSkeleton::obj = new MockIPCSkeleton();
    EXPECT_CALL(*(MockIPCSkeleton::obj), GetCallingUid()).WillRepeatedly(Return(DEFAULT_CALLING_UID));
    // Call the method under test
    formMgrAdapter.AllotForm(formId, want, *callerToken_, *formJsInfo_, *formItemInfo_);
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0276 end";
}

/**
 * @tc.name: FormMgrAdapter_0277
 * @tc.desc: test AllotForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0277, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0277 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 456;
    Want want;
    // Set up Want parameters for non-specific form
    want.SetParam(Constants::PARAM_FORM_MIGRATE_FORM_KEY, false);

    // Set up FormItemInfo
    formItemInfo_->SetProviderBundleName("providerBundle");
    formItemInfo_->SetHostBundleName("hostBundle");
    formItemInfo_->SetTransparencyEnabled(false);

    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(false);
    MockIPCSkeleton::obj = new MockIPCSkeleton();
    EXPECT_CALL(*(MockIPCSkeleton::obj), GetCallingUid()).WillRepeatedly(Return(DEFAULT_CALLING_UID));
    // Call the method under test
    formMgrAdapter.AllotForm(formId, want, *callerToken_, *formJsInfo_, *formItemInfo_);
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0277 end";
}

 /**
  * @tc.name: FormMgrAdapter_0278
  * @tc.desc: test AllotForm function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0278, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0278 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 0;
     Want want;
     // Set up Want parameters for temporary form
     want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

     // Set up FormItemInfo
     formItemInfo_->SetProviderBundleName("providerBundle");
     formItemInfo_->SetHostBundleName("hostBundle");
     formItemInfo_->SetTransparencyEnabled(false);

     // Call the method under test
     ErrCode ret = formMgrAdapter.AllotForm(formId, want, *callerToken_, *formJsInfo_, *formItemInfo_);

     // Verify the result
     EXPECT_EQ(ret, 2293761);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0278 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0279
  * @tc.desc: test CheckAddFormTaskTimeoutOrFailed function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0279, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0279 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 123;
     AddFormResultErrorCode expectedState = AddFormResultErrorCode::SUCCESS;
     formResultMutex_.lock();
     formIdMap_[formId] = AddFormResultErrorCode::SUCCESS;
     formResultMutex_.unlock();

     AddFormResultErrorCode formStates = AddFormResultErrorCode::UNKNOWN;
     formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId, formStates);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0279 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0280
  * @tc.desc: Test case for CheckAddFormTaskTimeoutOrFailed when form task is failed
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0280, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0280 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 456;
     formResultMutex_.lock();
     formIdMap_[formId] = AddFormResultErrorCode::FAILED;
     formResultMutex_.unlock();

     AddFormResultErrorCode formStates = AddFormResultErrorCode::UNKNOWN;
     ErrCode ret = formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId, formStates);

     EXPECT_EQ(ret, ERR_OK);
     // formStates should remain unchanged as it's only set for SUCCESS case
     EXPECT_NE(formStates, AddFormResultErrorCode::SUCCESS);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0280 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0281
  * @tc.desc: Test case for CheckAddFormTaskTimeoutOrFailed when form task is timed out
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0281, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0281 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 789;
     formResultMutex_.lock();
     formIdMap_[formId] = AddFormResultErrorCode::TIMEOUT;
     formResultMutex_.unlock();

     AddFormResultErrorCode formStates = AddFormResultErrorCode::UNKNOWN;
     ErrCode ret = formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId, formStates);

     EXPECT_EQ(ret, ERR_OK);
     // formStates should remain unchanged as it's only set for SUCCESS case
     EXPECT_NE(formStates, AddFormResultErrorCode::SUCCESS);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0281 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0282
  * @tc.desc: Test case for CheckAddFormTaskTimeoutOrFailed when form task is in unknown state
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0282, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0282 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 101;
     formResultMutex_.lock();
     formIdMap_[formId] = AddFormResultErrorCode::UNKNOWN;
     formResultMutex_.unlock();

     AddFormResultErrorCode formStates = AddFormResultErrorCode::UNKNOWN;
     ErrCode ret = formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId, formStates);

     EXPECT_EQ(ret, ERR_OK);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0282 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0283
  * @tc.desc: Test case for CheckAddFormTaskTimeoutOrFailed when form task does not exist
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0283, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0283 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 202;
     AddFormResultErrorCode formStates = AddFormResultErrorCode::UNKNOWN;
     ErrCode ret = formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId, formStates);

     EXPECT_EQ(ret, ERR_OK);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0283 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0284
  * @tc.desc: Test case for UpdateReUpdateFormMap when formId is added and some entries are expired
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0284, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0284 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 123;
     formMgrAdapter.UpdateReUpdateFormMap(formId);
     formMgrAdapter.SetReUpdateFormMap(formId);
     formMgrAdapter.UpdateReUpdateFormMap(formId);
     formMgrAdapter.SetReUpdateFormMap(formId);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0284 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0285
  * @tc.desc: Test case for SetVisibleChange
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0285, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0285 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 0;
     int32_t formVisibleType = 0;
     formMgrAdapter.SetVisibleChange(formId, formVisibleType);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0285 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0286
  * @tc.desc: Test case for SetVisibleChange
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0286, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0286 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t formVisibleType = Constants::FORM_VISIBLE;
     formMgrAdapter.SetVisibleChange(formId, formVisibleType);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0286 end";
 }

 /**
  * @tc.name: FormMgrAdapter_0287
  * @tc.desc: Test case for SetVisibleChange
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0287, TestSize.Level1)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0287 start";
     FormMgrAdapter formMgrAdapter;
     Want want;
     FormItemInfo formItemInfo;
     formMgrAdapter.GetFormConfigInfo(want, formItemInfo);
     FormInfo formInfo;
     FormItemInfo formConfigInfo;
     int formLocation = 0;
     formMgrAdapter.SetFormEnableAndLockState(formInfo, formConfigInfo, formLocation);
     formMgrAdapter.SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0287 end";
 }

/**
 * @tc.name: FormMgrAdapter_0296
 * @tc.desc: Verify PostVisibleNotify
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0296, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0296 start";
    std::shared_ptr<FormMgrAdapter> formTaskMgr = std::make_shared<FormMgrAdapter>();
    std::vector<int64_t> formIds;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    int32_t formVisibleType = 123;
    int32_t visibleNotifyDelay = 123;
    sptr<IRemoteObject> callerToken;
    formTaskMgr->PostVisibleNotify(formIds, formInstanceMaps, eventMaps,
        formVisibleType, visibleNotifyDelay, callerToken);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0296 end";
}
 /**
  * @tc.name:  FormMgrAdapter_0288
  * @tc.desc: test RequestOverflow function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0288, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0288 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = -1;
     int32_t uid = 1;
     OverflowInfo overflowInfo;
     bool isOverflow = true;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_INVALID_PARAM);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
         formMgrAdapter.RequestOverflow(formId, uid, overflowInfo, isOverflow));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0288 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0289
  * @tc.desc: test RequestOverflow function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0289, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0289 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     OverflowInfo overflowInfo;
     bool isOverflow = true;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
         formMgrAdapter.RequestOverflow(formId, uid, overflowInfo, isOverflow));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0289 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0290
  * @tc.desc: test RequestOverflow function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0290, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0290 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     OverflowInfo overflowInfo;
     bool isOverflow = true;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
         formMgrAdapter.RequestOverflow(formId, uid, overflowInfo, isOverflow));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0290 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0291
  * @tc.desc: test RequestOverflow function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0291, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0291 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     OverflowInfo overflowInfo;
     bool isOverflow = true;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED,
         formMgrAdapter.RequestOverflow(formId, uid, overflowInfo, isOverflow));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0291 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0292
  * @tc.desc: test ChangeSceneAnimationState function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0292, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0292 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = -1;
     int32_t uid = 1;
     int32_t state = 1;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_INVALID_PARAM);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
         formMgrAdapter.ChangeSceneAnimationState(formId, uid, state));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0292 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0293
  * @tc.desc: test ChangeSceneAnimationState function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0293, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0293 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     int32_t state = 1;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
         formMgrAdapter.ChangeSceneAnimationState(formId, uid, state));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0293 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0294
  * @tc.desc: test ChangeSceneAnimationState function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0294, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0294 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     int32_t state = 1;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
         formMgrAdapter.ChangeSceneAnimationState(formId, uid, state));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0294 end";
 }

 /**
  * @tc.name:  FormMgrAdapter_0295
  * @tc.desc: test ChangeSceneAnimationState function.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest3,  FormMgrAdapter_0295, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << " FormMgrAdapter_0295 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     int32_t uid = 1;
     int32_t state = 1;
     MockSceneAnimationCheck(ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED,
         formMgrAdapter.ChangeSceneAnimationState(formId, uid, state));
     GTEST_LOG_(INFO) << " FormMgrAdapter_0295 end";
 }

/**
 * @tc.name: FormMgrAdapter_0297
 * @tc.desc: test GetFormRect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0297, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0297 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    int32_t uid = 1;
    Rect rect;
    MockCallerCheck(ERR_APPEXECFWK_FORM_INVALID_PARAM);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.GetFormRect(formId, uid, rect));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0297 end";
}

/**
 * @tc.name: FormMgrAdapter_0298
 * @tc.desc: test GetFormRect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0298, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0298 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    Rect rect;
    MockCallerCheck(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
        formMgrAdapter.GetFormRect(formId, uid, rect));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0298 end";
}

/**
 * @tc.name: FormMgrAdapter_0299
 * @tc.desc: test GetFormRect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0299, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0299 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    Rect rect;
    MockCallerCheck(ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formMgrAdapter.GetFormRect(formId, uid, rect));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0299 end";
}

/**
 * @tc.name: FormMgrAdapter_0300
 * @tc.desc: test RegisterGetFormRectProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0300 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> observer = nullptr;
    auto ret = formMgrAdapter.RegisterGetFormRectProxy(observer);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0300 end";
}

/**
 * @tc.name: FormMgrAdapter_0301
 * @tc.desc: test UnregisterGetFormRectProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0301, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0301 start";
    FormMgrAdapter formMgrAdapter;
    auto ret = formMgrAdapter.UnregisterGetFormRectProxy();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0301 end";
}


/**
 * @tc.name: FormMgrAdapter_0302
 * @tc.desc: test GetFormRect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0302, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0302 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    Rect rect;
    MockCallerCheck(ERR_OK);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED,
        formMgrAdapter.GetFormRect(formId, uid, rect));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0302 end";
}

/**
 * @tc.name: FormMgrAdapter_0303
 * @tc.desc: test RegisterGetLiveFormStatusProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0303, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0303 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> observer = nullptr;
    auto ret = formMgrAdapter.RegisterGetLiveFormStatusProxy(observer);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0303 end";
}

/**
 * @tc.name: FormMgrAdapter_0304
 * @tc.desc: test UnregisterGetLiveFormStatusProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0304, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0304 start";
    FormMgrAdapter formMgrAdapter;
    auto ret = formMgrAdapter.UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0304 end";
}

/**
 * @tc.name: FormMgrAdapter_0305
 * @tc.desc: test GetLiveFormStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0305, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0305 start";
    FormMgrAdapter formMgrAdapter;
    std::unordered_map<std::string, std::string> liveFormStatusMap;
    formMgrAdapter.getLiveFormStatusCallerToken_ = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, formMgrAdapter.GetLiveFormStatus(liveFormStatusMap));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0305 end";
}

/**
 * @tc.name: FormMgrAdapter_CheckUpdateFormRecord
 * @tc.desc: test CheckUpdateFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_CheckUpdateFormRecord, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_CheckUpdateFormRecord start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormItemInfo formItemInfo;
    FormRecord formRecord;
    formRecord.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
    formMgrAdapter.CheckUpdateFormRecord(formId, formItemInfo, formRecord);
    EXPECT_EQ(LowMemoryRecycleStatus::NON_RECYCLABLE, formRecord.lowMemoryRecycleStatus);
    formRecord.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLABLE;
    formMgrAdapter.CheckUpdateFormRecord(formId, formItemInfo, formRecord);
    EXPECT_EQ(LowMemoryRecycleStatus::NON_RECYCLABLE, formRecord.lowMemoryRecycleStatus);
    GTEST_LOG_(INFO) << "FormMgrAdapter_CheckUpdateFormRecord end";
}

/**
 * @tc.name: FormMgrAdapter_SwitchLockForms
 * @tc.desc: test SwitchLockForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_SwitchLockForms, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_SwitchLockForms start";
    FormMgrAdapter formMgrAdapter;
    EXPECT_EQ(ERR_OK, formMgrAdapter.SwitchLockForms("", 1, false));
    GTEST_LOG_(INFO) << "FormMgrAdapter_SwitchLockForms end";
}

/**
 * @tc.name: FormMgrAdapter_0306
 * @tc.desc: test ReAcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0306, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0306 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    info.SetFormId(1);
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    formMgrAdapter.ReAcquireProviderFormInfoAsync(info, wantParams);
    formMgrAdapter.ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formMgrAdapter.ReAcquireProviderFormInfoAsync(info, wantParams));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0306 end";
}

/**
 * @tc.name: FormMgrAdapter_0307
 * @tc.desc: test CheckFormDueControl function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest3, FormMgrAdapter_0307, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0307 start";
    FormMgrAdapter formMgrAdapter;
    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = "test";
    EXPECT_FALSE(formMgrAdapter.CheckFormDueControl(formMajorInfo, true));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0307 end";
}
}