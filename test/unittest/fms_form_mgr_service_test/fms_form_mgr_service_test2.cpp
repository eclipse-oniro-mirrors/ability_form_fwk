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
#include <string>
#include <thread>

#include "access_token.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "data_center/form_data_mgr.h"
#include "common/event/form_event_util.h"
#include "form_mgr/form_mgr_service.h"
#include "tokenid_kit.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "accesstoken_kit.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "ability_info.h"
#include "bundle_mgr_interface.h"
#include "gmock/gmock.h"
#include "mock_ability_manager.h"
#include "mock_form_params.h"
#include "system_ability_definition.h"
#include "inner/mock_form_mgr_service.h"
#include "inner/mock_form_util.h"
#include "inner/mock_form_bms_helper.h"
#include "inner/mock_form_mgr_adapter.h"
#include "inner/mock_form_data_mgr.h"
#include "form_instance.h"
#include "template_form_detail_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AAFwk;

extern void MockCheckAcrossLocalAccountsPermission(bool mockRet);
extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockVerifyCallingPermission(bool mockRet);
extern void MockIsSystemAppByFullTokenID(bool mockRet);
extern void MockGetAbilityManager(sptr<AAFwk::IAbilityManager> abilityManager);
#ifdef THEME_MGR_ENABLE
extern void MockSetThemeManagerAddFormResult(int mockRet);
#endif

namespace {
const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";
const int32_t APP_600 = 600;
using BundleInfoMap = std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>>;
const std::string BUNDLE_NAME = "bundleName";
const std::string MODULE_NAME = "moduleName";
const std::string ABILITY_NAME = "abilityName";
const std::string FORM_NAME = "formName";

const BundleInfoMap CreateBundleFormInfoMapWithTemplateForm(bool isTemplateForm = false)
{
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap;
    std::shared_ptr<BundleFormInfo> bundleFormInfo = std::make_shared<BundleFormInfo>(BUNDLE_NAME);
    FormInfo formInfo;
    formInfo.bundleName = BUNDLE_NAME;
    formInfo.abilityName = ABILITY_NAME;
    formInfo.moduleName = MODULE_NAME;
    formInfo.name = FORM_NAME;
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 1;
    formInfo.scheduledUpdateTime = "06:06";
    formInfo.formVisibleNotify = true;
    formInfo.supportDimensions = {1, 2, 5, 7};
    formInfo.defaultDimension = 1;
    formInfo.supportShapes = {1};
    formInfo.isTemplateForm = isTemplateForm;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = 0;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    bundleFormInfoMap.emplace(BUNDLE_NAME, bundleFormInfo);
    return bundleFormInfoMap;
}

class MockBundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit MockBundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
    {}
    virtual ~MockBundleMgrProxy()
    {}

    MOCK_METHOD5(QueryAbilityInfo, bool(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &callBack));
    bool QueryAbilityInfo(const AAFwk::Want &want, AbilityInfo &abilityInfo) override
    {
        return true;
    }

    std::string GetAppType(const std::string &bundleName) override
    {
        return "system";
    }

    int GetUidByBundleName(const std::string &bundleName, const int userId) override
    {
        if (bundleName.compare("com.form.host.app600") == 0) {
            return APP_600;
        }
        return 0;
    }

    bool GetBundleNameForUid(const int uid, std::string &bundleName) override
    {
        bundleName = "com.form.service";
        return true;
    }

    int32_t GetNameForUid(const int uid, std::string &bundleName) override
    {
        return GetNameForUid_;
    };

    bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfo) override
    {
        return false;
    };
    bool GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfo) override
    {
        return false;
    };

    ErrCode GetBundlePackInfo(const std::string &bundleName, int32_t flags,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override
    {
        GTEST_LOG_(INFO) << "GetBundlePackInfo int32_t";
        return GetBundlePackInfo_;
    }

    ErrCode GetBundlePackInfo(const std::string &bundleName, const BundlePackFlag flag,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override
    {
        GTEST_LOG_(INFO) << "GetBundlePackInfo BundlePackFlag";
        return GetBundlePackInfo_;
    }

    bool SetModuleRemovable(
        const std::string &bundleName, const std::string &moduleName, bool isEnable) override
    {
        return setModuleRemovable_;
    }

    sptr<IBundleInstaller> GetBundleInstaller() override
    {
        return nullptr;
    }

    ErrCode GetBundlePackInfo_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    bool setModuleRemovable_ = false;
    int32_t GetNameForUid_ = ERR_OK;
};

class FmsFormMgrServiceTest2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormMgrServiceTest2::SetUpTestCase()
{}

void FmsFormMgrServiceTest2::TearDownTestCase()
{}

void FmsFormMgrServiceTest2::SetUp()
{}

void FmsFormMgrServiceTest2::TearDown()
{}

/**
 * @tc.number: FormMgrService_0081
 * @tc.name: test UpdateProxyForm function.
 * @tc.desc: Verify that the UpdateProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0081, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0081 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    const FormProviderData formBindingData;
    const std::vector<FormDataProxy> formDataProxies;
    ErrCode ret = formMgrService.UpdateProxyForm(formId, formBindingData, formDataProxies);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0081 end";
}

/**
 * @tc.number: FormMgrService_0082
 * @tc.name: test RegisterRemoveObserver function.
 * @tc.desc: Verify that the RegisterRemoveObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0082, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0082 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0082 end";
}

/**
 * @tc.number: FormMgrService_0083
 * @tc.name: test RequestPublishProxyForm function.
 * @tc.desc: Verify that the RequestPublishProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0083, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0083 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    const std::vector<FormDataProxy> formDataProxies;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0083 end";
}

/**
 * @tc.number: FormMgrService_0084
 * @tc.name: test RequestPublishProxyForm function.
 * @tc.desc: Verify that the RequestPublishProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0084, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0084 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    const std::vector<FormDataProxy> formDataProxies;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0084 end";
}


/**
 * @tc.number: FormMgrService_0085
 * @tc.name: test BackgroundEvent function.
 * @tc.desc: Verify that the BackgroundEvent interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0085, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0085 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    Want want;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    int ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockCheckInvalidForm(ERR_OK);
    ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0085 end";
}

/**
 * @tc.number: FormMgrService_0086
 * @tc.name: test RegisterFormRouterProxy function.
 * @tc.desc: Verify that the RegisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0086, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0086 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    int ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0086 end";
}

/**
 * @tc.number: FormMgrService_0087
 * @tc.name: test UnregisterFormRouterProxy function.
 * @tc.desc: Verify that the UnregisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0087, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0087 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    MockIsSACall(false);
    int ret = formMgrService.UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0087 end";
}

/**
 * @tc.number: FormMgrService_0088
 * @tc.name: test RegisterFormRouterProxy function.
 * @tc.desc: Verify that the RegisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0088, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0088 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();;
    int ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0088 end";
}

/**
 * @tc.number: FormMgrService_0089
 * @tc.name: test UnregisterFormRouterProxy function.
 * @tc.desc: Verify that the UnregisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0089, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0089 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    int ret = formMgrService.UnregisterFormRouterProxy(formIds);
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0089 end";
}

/**
 * @tc.number: FormMgrService_0090
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0090, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0090 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0090 end";
}

/**
 * @tc.number: FormMgrService_0091
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0091, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0091 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0091 end";
}

/**
 * @tc.number: FormMgrService_0092
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0092, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0092 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0092 end";
}

/**
 * @tc.number: FormMgrService_0093
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0093, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0093 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0093 end";
}

/**
 * @tc.number: FormMgrService_0094
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0094, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0094 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0094 end";
}

/**
 * @tc.number: FormMgrService_0095
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0095, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0095 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0095 end";
}

/**
 * @tc.number: FormMgrService_0096
 * @tc.name: test HasFormVisible function.
 * @tc.desc: Verify that the HasFormVisible interface is called normally and return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0096, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0096 start";
    FormMgrService formMgrService;
    uint32_t tokenId = 1;
    MockIsSACall(true);
    MockHasFormVisible(true);
    EXPECT_TRUE(formMgrService.HasFormVisible(tokenId));
    GTEST_LOG_(INFO) << "FormMgrService_0096 end";
}

/**
 * @tc.number: FormMgrService_0097
 * @tc.name: test HiDumpHasFormVisible function.
 * @tc.desc: Verify that the HiDumpHasFormVisible interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0097, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0097 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    formMgrService.HiDumpHasFormVisible(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0097 end";
}

/**
 * @tc.number: FormMgrService_0098
 * @tc.name: test StartAbility function.
 * @tc.desc: Verify that the StartAbility interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0098, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0098 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    FormMgrService formMgrService;
    std::string str = "aa";
    Want want;
    want.SetElementName("", "");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    const sptr<IRemoteObject> callerToken = nullptr;
    MockGetAbilityManager(new MockAbilityMgrService());
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);

    want.SetElementName("bundleName", "abilityName");
    MockGetAbilityManager(nullptr);
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockGetAbilityManager(new MockAbilityMgrService());
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_OK);
    MockIsSACall(false);

    GTEST_LOG_(INFO) << "FormMgrService_0098 end";
}

/**
 * @tc.number: FormMgrService_0099
 * @tc.name: test FormMgr HiDumpFormRunningFormInfos function.
 * @tc.desc: Verify that the HiDumpFormRunningFormInfos interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0099, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0099 start";
    FormMgrService formMgrService;
    std::string args;
    std::string runningFormInfo;
    formMgrService.HiDumpFormRunningFormInfos(args, runningFormInfo);
    GTEST_LOG_(INFO) << "FormMgrService_0099 end";
}

/**
 * @tc.number: FormMgrService_0100
 * @tc.name: test GetFormsInfoByFilter function.
 * @tc.desc: Verify that the GetFormsInfoByFilter interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0100 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormsInfoByFilter(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0100 end";
}

/**
 * @tc.number: FormMgrService_0101
 * @tc.name: test UpdateFormLocation function.
 * @tc.desc: Verify that the UpdateFormLocation interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0101, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0101 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    int32_t formLocation = 1;
    EXPECT_EQ(ERR_OK, formMgrService.UpdateFormLocation(formId, formLocation));
    GTEST_LOG_(INFO) << "FormMgrService_0101 end";
}

/**
 * @tc.number: FormMgrService_0102
 * @tc.name: test RegisterPublishFormInterceptor function.
 * @tc.desc: Verify that the RegisterPublishFormInterceptor interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0102 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = nullptr;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    FormBmsHelper::GetInstance().SetBundleManager(bundleManager);
    EXPECT_EQ(formMgrService.RegisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "FormMgrService_0102 end";
}

/**
 * @tc.number: FormMgrService_0103
 * @tc.name: test UnregisterPublishFormInterceptor function.
 * @tc.desc: Verify that the UnregisterPublishFormInterceptor interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0103 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = nullptr;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    FormBmsHelper::GetInstance().SetBundleManager(bundleManager);
    EXPECT_EQ(formMgrService.UnregisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "FormMgrService_0103 end";
}

/**
 * @tc.number: FormMgrService_0104
 * @tc.name: test HiDump functions.
 * @tc.desc: Verify that the HiDump interfaces are calling normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0104 start";
    FormMgrService formMgrService;
    std::string args;
    std::string formInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    formMgrService.HiDumpStorageFormInfos(args, formInfo);
    formMgrService.HiDumpTemporaryFormInfos(args, formInfo);
    formMgrService.HiDumpStaticBundleFormInfos(args, formInfo);
    formMgrService.HiDumpFormInfoByBundleName(args, formInfo);
    formMgrService.HiDumpHasFormVisible(args, formInfo);
    formMgrService.HiDumpFormInfoByFormId(args, formInfo);

    std::string args0 = "0";
    formMgrService.HiDumpFormInfoByFormId(args0, formInfo);
    std::string args1 = "1";
    formMgrService.HiDumpFormInfoByFormId(args1, formInfo);

    GTEST_LOG_(INFO) << "FormMgrService_0104 end";
}

/**
 * @tc.number: FormMgrService_0105
 * @tc.name: test GetCurrentDateTime function.
 * @tc.desc: Verify that the GetCurrentDateTime interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0105, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0105 start";
    FormMgrService formMgrService;
    EXPECT_NE(formMgrService.GetCurrentDateTime(), "");

    GTEST_LOG_(INFO) << "FormMgrService_0105 end";
}

/**
 * @tc.number: FormMgrService_0106
 * @tc.name: test GetCurrentDateTime function.
 * @tc.desc: Verify that the GetCurrentDateTime interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0106 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    Want want;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "FormMgrService_0106 end";
}

/**
 * @tc.number: FormMgrService_0107
 * @tc.name: test GetFormsCount function.
 * @tc.desc: Verify that the GetFormsCount interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0107, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0107 start";
    FormMgrService formMgrService;
    bool isTempFormFlag = true;
    int32_t formCount;
    EXPECT_EQ(formMgrService.GetFormsCount(isTempFormFlag, formCount), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0107 end";
}

/**
 * @tc.number: FormMgrService_0108
 * @tc.name: test GetFormsCount function.
 * @tc.desc: Verify that the GetFormsCount interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0108, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0108 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    int32_t formCount;
    EXPECT_EQ(formMgrService.GetHostFormsCount(bundleName, formCount), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0108 end";
}

/**
 * @tc.number: FormMgrService_0109
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0109, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0109 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    FormInstance formInstance;
    bool isUnusedInclude = false;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0109 end";
}

/**
 * @tc.number: FormMgrService_0110
 * @tc.name: test RegisterClickEventObserver function.
 * @tc.desc: Verify that the RegisterClickEventObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0110, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0110 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    const std::string bundleName = "";
    const std::string formEventType = "";

    ErrCode ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0110 end";
}

/**
 * @tc.number: FormMgrService_0111
 * @tc.name: test UnregisterClickEventObserver function.
 * @tc.desc: Verify that the UnregisterClickEventObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0111, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0111 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    const std::string bundleName = "";
    const std::string formEventType = "";

    ErrCode ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0111 end";
}

/**
 * @tc.number: FormMgrService_0112
 * @tc.name: test SetFormsRecyclable function.
 * @tc.desc: Verify that the SetFormsRecyclable interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0112, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0112 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    MockIsSACall(false);
    ErrCode ret = formMgrService.SetFormsRecyclable(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.SetFormsRecyclable(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrService_0112 end";
}

/**
 * @tc.number: FormMgrService_0113
 * @tc.name: test RecycleForms function.
 * @tc.desc: Verify that the RecycleForms interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0113, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0113 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    Want want;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RecycleForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RecycleForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrService_0113 end";
}


/**
 * @tc.number: FormMgrService_0114
 * @tc.name: test updateForm function.
 * @tc.desc: Verify that the UpdateForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0114, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0114 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    FormProviderData formProviderData;
    EXPECT_EQ(formMgrService.UpdateForm(formId, formProviderData), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0114 end";
}

/**
 * @tc.number: FormMgrService_0115
 * @tc.name: test DumpFormTimerByFormId function.
 * @tc.desc: Verify that the DumpFormTimerByFormId interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0115, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0115 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    std::string isTimingService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.DumpFormTimerByFormId(formId, isTimingService), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.DumpFormTimerByFormId(formId, isTimingService), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0115 end";
}

/**
 * @tc.number: FormMgrService_0116
 * @tc.name: test RecvFormShareInfoFromRemote function.
 * @tc.desc: Verify that the RecvFormShareInfoFromRemote interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0116, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0116 start";
    FormMgrService formMgrService;
    FormShareInfo formShareInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.RecvFormShareInfoFromRemote(formShareInfo), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.RecvFormShareInfoFromRemote(formShareInfo), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0116 end";
}

/**
 * @tc.number: FormMgrService_0117
 * @tc.name: test CreateForm function.
 * @tc.desc: Verify that the CreateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0117, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0117 start";
    FormMgrService formMgrService;
    Want want;
    RunningFormInfo runningFormInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CreateForm(want, runningFormInfo));

    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrService.CreateForm(want, runningFormInfo));
    GTEST_LOG_(INFO) << "FormMgrService_0117 end";
}

/**
 * @tc.number: FormMgrService_0118
 * @tc.name: test CreateForm function.
 * @tc.desc: Verify that the CreateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0118, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0118 start";
    FormMgrService formMgrService;
    Want want;
    want.SetParam(AppExecFwk::Constants::PARAM_THEME_KEY, true);
    RunningFormInfo runningFormInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(true);
#ifdef THEME_MGR_ENABLE
    GTEST_LOG_(INFO) << "FormMgrService_0118 THEME_MGR_ENABLE defined";
    MockSetThemeManagerAddFormResult(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.CreateForm(want, runningFormInfo));
#else
    GTEST_LOG_(INFO) << "FormMgrService_0118 THEME_MGR_ENABLE undefined";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED, formMgrService.CreateForm(want, runningFormInfo));
#endif

    GTEST_LOG_(INFO) << "FormMgrService_0118 end";
}

/**
 * @tc.number: FormMgrService_0119
 * @tc.name: test FormMgr HiDumpFormBlockedApps function.
 * @tc.desc: Verify that the HiDumpFormBlockedApps interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0119, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0119 start";
    FormMgrService formMgrService;
    std::string args;
    std::string blockAppInfo;
    formMgrService.HiDumpFormBlockedApps(args, blockAppInfo);
    GTEST_LOG_(INFO) << "FormMgrService_0119 end";
}

/**
 * @tc.number: FormMgrService_0120
 * @tc.name: test SetPublishFormResult function.
 * @tc.desc: Verify that the SetPublishFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0120, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0120 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(formMgrService.SetPublishFormResult(formId, result), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0120 end";
}

/**
 * @tc.number: FormMgrService_0121
 * @tc.name: test AcquireAddFormResult function.
 * @tc.desc: Verify that the AcquireAddFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0121, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0121 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    EXPECT_EQ(formMgrService.AcquireAddFormResult(formId), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0121 end";
}

/**
 * @tc.number: FormMgrService_0122
 * @tc.name: test OnSystemloadLevel function.
 * @tc.desc: Verify that the OnSystemloadLevel interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0122, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0122 start";
    FormMgrService formMgrService;
    int32_t level = 5;
    formMgrService.OnSystemloadLevel(level);
    GTEST_LOG_(INFO) << "FormMgrService_0122 end";
}

/**
 * @tc.number: FormMgrService_0123
 * @tc.name: test OnSystemloadLevel function.
 * @tc.desc: Verify that the OnSystemloadLevel interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0123, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0123 start";
    FormMgrService formMgrService;
    int32_t level = 1;
    formMgrService.OnSystemloadLevel(level);
    GTEST_LOG_(INFO) << "FormMgrService_0123 end";
}

/**
 * @tc.number: FormMgrService_0124
 * @tc.name: test BatchRefreshForms function.
 * @tc.desc: Verify that the BatchRefreshForms interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0124, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0124 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(ERR_OK, formMgrService.BatchRefreshForms(formRefreshType));
    GTEST_LOG_(INFO) << "FormMgrService_0124 end";
}

/**
 * @tc.number: FormMgrService_0125
 * @tc.name: test BatchRefreshForms function.
 * @tc.desc: Verify that the BatchRefreshForms interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0125, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0125 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.BatchRefreshForms(formRefreshType));
    GTEST_LOG_(INFO) << "FormMgrService_0125 end";
}

/**
 * @tc.number: FormMgrService_0126
 * @tc.name: test IsFormBundleForbidden function.
 * @tc.desc: Verify that the IsFormBundleForbidden interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0126, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0126 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    std::string bundleName = "";
    EXPECT_FALSE(formMgrService.IsFormBundleForbidden(bundleName));
    GTEST_LOG_(INFO) << "FormMgrService_0126 end";
}

/**
 * @tc.number: FormMgrService_0127
 * @tc.name: test EnableForms function.
 * @tc.desc: Verify that the EnableForms interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0127, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0127 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    MockEnableForms(ERR_OK);
    EXPECT_EQ(formMgrService.EnableForms(bundleName, userId, true), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.EnableForms(bundleName, userId, true), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0127 end";
}

/**
 * @tc.number: FormMgrService_0128
 * @tc.name: test RequestPublishFormWithSnapshot function.
 * @tc.desc: Verify that the RequestPublishFormWithSnapshot interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0128, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0128 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    std::string bundleName = "ohos.samples.FormApplication";
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, bundleName);
    MockIsSACall(false);
    ErrCode ret = formMgrService.RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0128 end";
}

/**
 * @tc.number: FormMgrService_0129
 * @tc.name: test GetFormsInfoByFilter function.
 * @tc.desc: Verify that the GetFormsInfoByFilter interface deny the caller Across Local Accounts Permission
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0129, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0129 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.GetFormsInfoByFilter(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0129 end";
}

/**
 * @tc.number: FormMgrService_0130
 * @tc.name: test GetFormsInfoByFilter function.
 * @tc.desc: Verify that the GetFormsInfoByFilter interface the caller is a system app
 *           and permit Across Local Accounts Permission, the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0130, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0130 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByFilter(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0130 end";
}

/**
 * @tc.number: FormMgrService_0132
 * @tc.name: test SubscribeSysEventReceiver function.
 * @tc.desc: Verify that the SubscribeSysEventReceiver
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0132, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0132 start";
    FormMgrService formMgrService;
    formMgrService.SubscribeSysEventReceiver();
    GTEST_LOG_(INFO) << "FormMgrService_0132 end";
}

/**
 * @tc.number: FormMgrService_0133
 * @tc.name: test FormMgrService function.
 * @tc.desc: Verify that the FormMgrService
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0133, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0133 start";
    FormMgrService* service = new FormMgrService();
    service->SubscribeSysEventReceiver();
    delete service;
    GTEST_LOG_(INFO) << "FormMgrService_0133 end";
}

/**
 * @tc.number: FormMgrService_0135
 * @tc.name: test IsSystemAppForm function.
 * @tc.desc: !formRecords.empty()
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0135, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0135 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    EXPECT_FALSE(formMgrService.IsSystemAppForm(bundleName));
    GTEST_LOG_(INFO) << "FormMgrService_0135 end";
}

/**
 * @tc.number: FormMgrService_0136
 * @tc.name: test IsSystemAppForm function.
 * @tc.desc: formRecords.empty()
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0136, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0136 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";

    EXPECT_FALSE(formMgrService.IsSystemAppForm(bundleName));
    GTEST_LOG_(INFO) << "FormMgrService_0136 end";
}

/**
 * @tc.number: FormMgrService_0137
 * @tc.name: test HasFormVisible function.
 * @tc.desc: formRecords.empty()
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0137, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0137 start";
    FormMgrService formMgrService;
    uint32_t tokenId = 1;
    MockIsSACall(false);
    EXPECT_FALSE(formMgrService.HasFormVisible(tokenId));
    GTEST_LOG_(INFO) << "FormMgrService_0137 end";
}

/**
 * @tc.number: FormMgrService_0138
 * @tc.name: test HasFormVisible function.
 * @tc.desc: formRecords.empty()
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0138, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0138 start";
    FormMgrService formMgrService;
    std::string abilityName = "abilityName";
    int64_t formId = 1;
    formMgrService.SubscribeSysEventReceiver();
    formMgrService.OnStop();
    formMgrService.SubscribeSysEventReceiver();
    RunningFormInfo formInfo;
    std::vector<RunningFormInfo> formInfos;
    Want want;
    formMgrService.StartAbilityByFms(want);
    std::vector<std::u16string> args;
    std::string result = "result";
    int fd = 1;
    formMgrService.Dump(fd, args);
    formMgrService.Dump(args, result);
    formMgrService.OpenFormEditAbility(abilityName, formId, true);
    formMgrService.OpenFormEditAbility(abilityName, formId, false);
    GTEST_LOG_(INFO) << "FormMgrService_0138 end";
}

/**
 * @tc.number: FormMgrService_0139
 * @tc.name: test RegisterPublishFormInterceptor function.
 * @tc.desc: Verify that the RegisterPublishFormInterceptor interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0139, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0139 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(formMgrService.RegisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    EXPECT_EQ(formMgrService.UnregisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    GTEST_LOG_(INFO) << "FormMgrService_0139 end";
}

// FormMgrService_0140-0179 in file fms_form_mgr_service_test.cpp

/**
 * @tc.number: FormMgrService_0180
 * @tc.name: test formMgrService function.
 * @tc.desc: Verify
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0180, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0180 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string abilityName = "abilityName";
    std::string bundleName = "bundleName";
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    float formViewScale = 1;
    FormLockInfo formLockInfo;
    formLockInfo.bundleName = "bundleName";
    formLockInfo.userId = 1;
    formLockInfo.lock = true;
    FormLockInfo formLockInfo1;
    std::vector<FormLockInfo> formLockInfos = {formLockInfo, formLockInfo1};
    MockIsSACall(false);
    formMgrService.LockForms(formLockInfos, LockChangeType::SWITCH_CHANGE);
    formMgrService.IsFormBundleProtected(bundleName, formId);
    formMgrService.IsFormBundleExempt(formId);
    formMgrService.NotifyFormLocked(formId, true);
    formMgrService.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    MockIsSACall(true);
    formMgrService.LockForms(formLockInfos, LockChangeType::SWITCH_CHANGE);
    formMgrService.LockForms(formLockInfos, LockChangeType::PROTECT_CHANGE);
    formMgrService.IsFormBundleProtected(bundleName, formId);
    formMgrService.IsFormBundleExempt(formId);
    formMgrService.NotifyFormLocked(formId, true);
    formMgrService.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    GTEST_LOG_(INFO) << "FormMgrService_0180 end";
}

/**
 * @tc.number: FormMgrService_0181
 * @tc.name: test RequestOverflow function.
 * @tc.desc: Verify that the RequestOverflow interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0181, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0181 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    EXPECT_EQ(formMgrService.RequestOverflow(formId, overflowInfo, isOverflow), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0181 end";
}

/**
 * @tc.number: FormMgrService_0182
 * @tc.name: test ChangeSceneAnimationState function.
 * @tc.desc: Verify that the ChangeSceneAnimationState interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0182, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0182 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    int32_t state = 1;
    EXPECT_EQ(formMgrService.ChangeSceneAnimationState(formId, state), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0182 end";
}

/**
 * @tc.number: FormMgrService_0184
 * @tc.name: test getFormRect function.
 * @tc.desc: Verify that the getFormRect interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_0184, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0184 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    Rect rect;
    EXPECT_EQ(formMgrService.GetFormRect(formId, rect), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0184 end";
}

/**
 * @tc.name: FormMgrService_ReloadForms_0001
 * @tc.desc: Verify ReloadForms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_ReloadForms_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_ReloadForms_0001 start";
    FormMgrService formMgrService;
    int32_t reloadNum = 0;
    std::string moduleName = "testModule";
    std::string abilityName = "testAbility";
    std::string formName = "testForm";
    ErrCode ret = formMgrService.ReloadForms(reloadNum, moduleName, abilityName, formName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY);
    GTEST_LOG_(INFO) << "FormMgrService_ReloadForms_0001 end";
}

/**
 * @tc.name: FormMgrService_ReloadAllForms_0001
 * @tc.desc: Verify ReloadForms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_ReloadAllForms_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_ReloadAllForms_0001 start";
    FormMgrService formMgrService;
    int32_t reloadNum = 0;
    ErrCode ret = formMgrService.ReloadAllForms(reloadNum);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY);
    GTEST_LOG_(INFO) << "FormMgrService_ReloadAllForms_0001 end";
}

/**
 * @tc.name: FormMgrService_IsFormDueControl_0001
 * @tc.desc: Verify IsFormDueControl
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_IsFormDueControl_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_IsFormDueControl_0001 start";
    FormMgrService formMgrService;
    FormMajorInfo formMajorInfo;
    bool ret = formMgrService.IsFormDueControl(formMajorInfo, true);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "FormMgrService_IsFormDueControl_0001 end";
}

/**
 * @tc.name: FormMgrService_SendNonTransparencyRatio_0001
 * @tc.desc: Verify SendNonTransparencyRatio
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_SendNonTransparencyRatio_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_SendNonTransparencyRatio_0001 start";
    FormMgrService formMgrService;
    int64_t formId = 10;
    int32_t ratio = 0;
    MockIsSACall(true);
    auto ret = formMgrService.SendNonTransparencyRatio(formId, ratio);
    EXPECT_EQ(ret, ERR_OK);

    MockIsSACall(false);
    ret = formMgrService.SendNonTransparencyRatio(formId, ratio);
    EXPECT_NE(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_SendNonTransparencyRatio_0001 end";
}

/**
 * @tc.name: FormMgrService_GetAllTemplateFormsInfo_0001
 * @tc.desc: Verify GetAllTemplateFormsInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetAllTemplateFormsInfo_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetAllTemplateFormsInfo_0001 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;

    MockIsSACall(false);
    MockCheckAcrossLocalAccountsPermission(false);
    // get empty template form info
    auto ret = formMgrService.GetAllTemplateFormsInfo(formInfos);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    // get no template form info cause add normal form
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm();
    ret = formMgrService.GetAllTemplateFormsInfo(formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    // get one template form info
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm(true);
    ret = formMgrService.GetAllTemplateFormsInfo(formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(1, formInfos.size());
    GTEST_LOG_(INFO) << "FormMgrService_GetAllTemplateFormsInfo_0001 end";
}

/**
 * @tc.name: FormMgrService_GetTemplateFormsInfoByApp_0001
 * @tc.desc: Verify GetTemplateFormsInfoByApp
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetTemplateFormsInfoByApp_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetTemplateFormsInfoByApp_0001 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;

    MockIsSACall(false);
    MockCheckAcrossLocalAccountsPermission(false);
    // get empty template form info
    auto ret = formMgrService.GetTemplateFormsInfoByApp(BUNDLE_NAME, formInfos);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    // get no template form info cause add normal form
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm();
    ret = formMgrService.GetTemplateFormsInfoByApp(BUNDLE_NAME, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    // get one template form info
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm(true);
    ret = formMgrService.GetTemplateFormsInfoByApp(BUNDLE_NAME, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(1, formInfos.size());
    GTEST_LOG_(INFO) << "FormMgrService_GetTemplateFormsInfoByApp_0001 end";
}

/**
 * @tc.name: FormMgrService_GetTemplateFormsInfoByModule_0001
 * @tc.desc: Verify GetTemplateFormsInfoByModule
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetTemplateFormsInfoByModule_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetTemplateFormsInfoByModule_0001 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockCheckAcrossLocalAccountsPermission(false);
    // get empty template form info
    auto ret = formMgrService.GetTemplateFormsInfoByModule(BUNDLE_NAME, MODULE_NAME, formInfos);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    // get no template form info cause add normal form
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm();
    ret = formMgrService.GetTemplateFormsInfoByModule(BUNDLE_NAME, MODULE_NAME, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(0, formInfos.size());

    // get one template form info
    FormInfoMgr::GetInstance().bundleFormInfoMap_ = CreateBundleFormInfoMapWithTemplateForm(true);
    ret = formMgrService.GetTemplateFormsInfoByModule(BUNDLE_NAME, MODULE_NAME, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(1, formInfos.size());
    GTEST_LOG_(INFO) << "FormMgrService_GetTemplateFormsInfoByModule_0001 end";
}

/**
 * @tc.name: FormMgrService_GetFormIdsByFormLocation_001
 * @tc.desc: Verify GetFormIdsByFormLocation with permission denied (system)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetFormIdsByFormLocation_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_001 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    FormMgrService formMgrService;
    int32_t formLocation = static_cast<int32_t>(Constants::FormLocation::DESKTOP);
    std::vector<std::string> formIds;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormIdsByFormLocation(formLocation, formIds));
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_001 end";
}

/**
 * @tc.name: FormMgrService_GetFormIdsByFormLocation_002
 * @tc.desc: Verify GetFormIdsByFormLocation with permission denied (bundle)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetFormIdsByFormLocation_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_002 start";
    MockIsSACall(true);
    MockVerifyCallingPermission(false);
    FormMgrService formMgrService;
    int32_t formLocation = static_cast<int32_t>(Constants::FormLocation::DESKTOP);
    std::vector<std::string> formIds;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE,
        formMgrService.GetFormIdsByFormLocation(formLocation, formIds));
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_002 end";
}

/**
 * @tc.name: FormMgrService_GetFormIdsByFormLocation_003
 * @tc.desc: Verify GetFormIdsByFormLocation with invalid location (< OTHER)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetFormIdsByFormLocation_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_003 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int32_t formLocation = static_cast<int32_t>(Constants::FormLocation::OTHER) - 1;
    std::vector<std::string> formIds;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_LOCATION_INVALID, formMgrService.GetFormIdsByFormLocation(formLocation, formIds));
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_003 end";
}

/**
 * @tc.name: FormMgrService_GetFormIdsByFormLocation_004
 * @tc.desc: Verify GetFormIdsByFormLocation with invalid location (FORM_LOCATION_END)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetFormIdsByFormLocation_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_004 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int32_t formLocation = static_cast<int32_t>(Constants::FormLocation::FORM_LOCATION_END);
    std::vector<std::string> formIds;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_LOCATION_INVALID, formMgrService.GetFormIdsByFormLocation(formLocation, formIds));
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_004 end";
}

/**
 * @tc.name: FormMgrService_GetFormIdsByFormLocation_005
 * @tc.desc: Verify GetFormIdsByFormLocation with DESKTOP location
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetFormIdsByFormLocation_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_005 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int32_t formLocation = static_cast<int32_t>(Constants::FormLocation::DESKTOP);
    std::vector<std::string> formIds;
    EXPECT_EQ(ERR_OK, formMgrService.GetFormIdsByFormLocation(formLocation, formIds));
    GTEST_LOG_(INFO) << "FormMgrService_GetFormIdsByFormLocation_005 end";
}

/**
 * @tc.number: FormMgrService_GetPublishedFormInfoById_0001
 * @tc.name: test GetPublishedFormInfoById success.
 * @tc.desc: Verify that GetPublishedFormInfoById returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetPublishedFormInfoById_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfoById_0001 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    RunningFormInfo formInfo;
    MockGetCallerBundleName(ERR_OK);
    MockFormDataMgrGetPublishedFormInfoById(ERR_OK);
    int32_t ret = formMgrService.GetPublishedFormInfoById(formId, formInfo);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfoById_0001 end";
}

/**
 * @tc.number: FormMgrService_GetPublishedFormInfoById_0002
 * @tc.name: test GetPublishedFormInfoById failed.
 * @tc.desc: Verify that GetPublishedFormInfoById returns error when GetCallerBundleName fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetPublishedFormInfoById_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfoById_0002 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    RunningFormInfo formInfo;
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    int32_t ret = formMgrService.GetPublishedFormInfoById(formId, formInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfoById_0002 end";
}

/**
 * @tc.number: FormMgrService_GetPublishedFormInfos_0001
 * @tc.name: test GetPublishedFormInfos success.
 * @tc.desc: Verify that GetPublishedFormInfos returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetPublishedFormInfos_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfos_0001 start";
    FormMgrService formMgrService;
    std::vector<RunningFormInfo> formInfos;
    MockGetCallerBundleName(ERR_OK);
    MockFormDataMgrGetPublishedFormInfos(ERR_OK);
    int32_t ret = formMgrService.GetPublishedFormInfos(formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfos_0001 end";
}

/**
 * @tc.number: FormMgrService_GetPublishedFormInfos_0002
 * @tc.name: test GetPublishedFormInfos failed.
 * @tc.desc: Verify that GetPublishedFormInfos returns error when GetCallerBundleName fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_GetPublishedFormInfos_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfos_0002 start";
    FormMgrService formMgrService;
    std::vector<RunningFormInfo> formInfos;
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    int32_t ret = formMgrService.GetPublishedFormInfos(formInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_GetPublishedFormInfos_0002 end";
}

/**
 * @tc.number: FormMgrService_StartAbilityByCrossBundle_0001
 * @tc.name: test StartAbilityByCrossBundle non-system app.
 * @tc.desc: Verify that StartAbilityByCrossBundle returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_StartAbilityByCrossBundle_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0001 start";
    FormMgrService formMgrService;
    Want want;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    int32_t ret = formMgrService.StartAbilityByCrossBundle(want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0001 end";
}

/**
 * @tc.number: FormMgrService_StartAbilityByCrossBundle_0002
 * @tc.name: test StartAbilityByCrossBundle permission denied.
 * @tc.desc: Verify that StartAbilityByCrossBundle returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_StartAbilityByCrossBundle_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0002 start";
    FormMgrService formMgrService;
    Want want;
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    int32_t ret = formMgrService.StartAbilityByCrossBundle(want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0002 end";
}

/**
 * @tc.number: FormMgrService_StartAbilityByCrossBundle_0003
 * @tc.name: test StartAbilityByCrossBundle PublishFormCrossBundleControl failed.
 * @tc.desc: Verify that StartAbilityByCrossBundle returns error when PublishFormCrossBundleControl fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_StartAbilityByCrossBundle_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0003 start";
    FormMgrService formMgrService;
    Want want;
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    want.SetParam(Constants::FORM_MANAGER_SHOW_SINGLE_FORM_KEY, true);
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    int32_t ret = formMgrService.StartAbilityByCrossBundle(want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME);
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0003 end";
}

/**
 * @tc.number: FormMgrService_StartAbilityByCrossBundle_0004
 * @tc.name: test StartAbilityByCrossBundle success.
 * @tc.desc: Verify that StartAbilityByCrossBundle returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_StartAbilityByCrossBundle_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0004 start";
    FormMgrService formMgrService;
    Want want;
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockFormMgrAdapterStartAbilityByFms(ERR_OK);
    int32_t ret = formMgrService.StartAbilityByCrossBundle(want);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_StartAbilityByCrossBundle_0004 end";
}

/**
 * @tc.number: FormMgrService_CheckAcrossLocalAccountsPermission_0001
 * @tc.name: test CheckAcrossLocalAccountsPermission same user.
 * @tc.desc: Verify that CheckAcrossLocalAccountsPermission returns true for same user.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_CheckAcrossLocalAccountsPermission_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_CheckAcrossLocalAccountsPermission_0001 start";
    FormMgrService formMgrService;
    MockGetCallerUserId(100);
    MockGetCurrentAccountIdRet(100);
    bool result = formMgrService.CheckAcrossLocalAccountsPermission();
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrService_CheckAcrossLocalAccountsPermission_0001 end";
}

/**
 * @tc.number: FormMgrService_CheckAcrossLocalAccountsPermission_0002
 * @tc.name: test CheckAcrossLocalAccountsPermission with permission.
 * @tc.desc: Verify that CheckAcrossLocalAccountsPermission returns true with permission.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_CheckAcrossLocalAccountsPermission_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_CheckAcrossLocalAccountsPermission_0002 start";
    FormMgrService formMgrService;
    MockGetCallerUserId(100);
    MockGetCurrentAccountIdRet(200);
    MockVerifyCallingPermission(true);
    bool result = formMgrService.CheckAcrossLocalAccountsPermission();
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrService_CheckAcrossLocalAccountsPermission_0002 end";
}

/**
 * @tc.number: FormMgrService_IsFormBundleDebugSignature_0001
 * @tc.name: test IsFormBundleDebugSignature permission denied.
 * @tc.desc: Verify that IsFormBundleDebugSignature returns false when permission denied.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_IsFormBundleDebugSignature_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0001 start";
    FormMgrService formMgrService;
    std::string bundleName = "com.example.test";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    bool result = formMgrService.IsFormBundleDebugSignature(bundleName);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0001 end";
}

/**
 * @tc.number: FormMgrService_IsFormBundleDebugSignature_0002
 * @tc.name: test IsFormBundleDebugSignature GetBundleInfo failed.
 * @tc.desc: Verify that IsFormBundleDebugSignature returns false when GetBundleInfo fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_IsFormBundleDebugSignature_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0002 start";
    FormMgrService formMgrService;
    std::string bundleName = "com.example.test";
    MockIsSACall(true);
    MockFormBmsHelperGetBundleInfoByFlags(false);
    bool result = formMgrService.IsFormBundleDebugSignature(bundleName);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0002 end";
}

/**
 * @tc.number: FormMgrService_IsFormBundleDebugSignature_0003
 * @tc.name: test IsFormBundleDebugSignature debug type.
 * @tc.desc: Verify that IsFormBundleDebugSignature returns true for debug type.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_IsFormBundleDebugSignature_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0003 start";
    FormMgrService formMgrService;
    std::string bundleName = "com.example.test";
    MockIsSACall(true);
    MockFormBmsHelperGetBundleInfoByFlags(true, "debug");
    bool result = formMgrService.IsFormBundleDebugSignature(bundleName);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0003 end";
}

/**
 * @tc.number: FormMgrService_IsFormBundleDebugSignature_0004
 * @tc.name: test IsFormBundleDebugSignature release type.
 * @tc.desc: Verify that IsFormBundleDebugSignature returns false for release type.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_IsFormBundleDebugSignature_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0004 start";
    FormMgrService formMgrService;
    std::string bundleName = "com.example.test";
    MockIsSACall(true);
    MockFormBmsHelperGetBundleInfoByFlags(true, "release");
    bool result = formMgrService.IsFormBundleDebugSignature(bundleName);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FormMgrService_IsFormBundleDebugSignature_0004 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0001
 * @tc.name: test OpenFormEditAbility GetBundleName failed.
 * @tc.desc: Verify that OpenFormEditAbility returns error when GetBundleName fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0001 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = true;
    MockFormBmsHelperGetBundleNameByUid(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0001 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0002
 * @tc.name: test OpenFormEditAbility GetRunningFormInfo failed.
 * @tc.desc: Verify that OpenFormEditAbility returns error when GetRunningFormInfo fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0002 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = true;
    MockFormBmsHelperGetBundleNameByUid(ERR_OK, "caller");
    MockFormDataMgrGetRunningFormInfosByFormId(ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0002 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0003
 * @tc.name: test OpenFormEditAbility BundleName mismatch.
 * @tc.desc: Verify that OpenFormEditAbility returns error when BundleName mismatches.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0003 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = true;
    MockFormBmsHelperGetBundleNameByUid(ERR_OK, "caller1");
    MockFormDataMgrGetRunningFormInfosByFormId(ERR_OK, "caller2");
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0003 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0004
 * @tc.name: test OpenFormEditAbility form invisible.
 * @tc.desc: Verify that OpenFormEditAbility returns error when form is invisible.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0004 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = true;
    MockFormBmsHelperGetBundleNameByUid(ERR_OK, "caller");
    MockFormDataMgrGetRunningFormInfosByFormId(ERR_OK, "caller", FormVisibilityType::INVISIBLE);
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_TRUST);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0004 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0005
 * @tc.name: test OpenFormEditAbility success isMainPage=true.
 * @tc.desc: Verify that OpenFormEditAbility returns success.
.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0005 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = true;
    MockFormBmsHelperGetBundleNameByUid(ERR_OK, "caller");
    MockFormDataMgrGetRunningFormInfosByFormId(ERR_OK, "caller", FormVisibilityType::VISIBLE);
    MockFormMgrAdapterStartAbilityByFms(ERR_OK);
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0005 end";
}

/**
 * @tc.number: FormMgrService_OpenFormEditAbility_0006
 * @tc.name: test OpenFormEditAbility success isMainPage=false.
 * @tc.desc: Verify that OpenFormEditAbility returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_OpenFormEditAbility_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0006 start";
    FormMgrService formMgrService;
    std::string abilityName = "EditAbility";
    int64_t formId = 1;
    bool isMainPage = false;
    MockFormBmsHelperGetBundleNameByUid(ERR_OK, "caller");
    MockFormDataMgrGetRunningFormInfosByFormId(ERR_OK, "caller", FormVisibilityType::VISIBLE);
    MockFormMgrAdapterStartAbilityByFms(ERR_OK);
    ErrCode ret = formMgrService.OpenFormEditAbility(abilityName, formId, isMainPage);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_OpenFormEditAbility_0006 end";
}

/**
 * @tc.number: FormMgrService_RegisterChangeSceneAnimationStateProxy_0001
 * @tc.name: test RegisterChangeSceneAnimationStateProxy non-system app.
 * @tc.desc: Verify that RegisterChangeSceneAnimationStateProxy returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterChangeSceneAnimationStateProxy_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterChangeSceneAnimationStateProxy_0001 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterChangeSceneAnimationStateProxy(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterChangeSceneAnimationStateProxy_0001 end";
}

/**
 * @tc.number: FormMgrService_RegisterChangeSceneAnimationStateProxy_0002
 * @tc.name: test RegisterChangeSceneAnimationStateProxy success.
 * @tc.desc: Verify that RegisterChangeSceneAnimationStateProxy returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterChangeSceneAnimationStateProxy_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterChangeSceneAnimationStateProxy_0002 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterRegisterChangeSceneAnimationStateProxy(ERR_OK);
    ErrCode ret = formMgrService.RegisterChangeSceneAnimationStateProxy(callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterChangeSceneAnimationStateProxy_0002 end";
}

/**
 * @tc.number: FormMgrService_RegisterOverflowProxy_0001
 * @tc.name: test RegisterOverflowProxy non-system app.
 * @tc.desc: Verify that RegisterOverflowProxy returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterOverflowProxy_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterOverflowProxy_0001 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterOverflowProxy(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterOverflowProxy_0001 end";
}

/**
 * @tc.number: FormMgrService_RegisterOverflowProxy_0002
 * @tc.name: test RegisterOverflowProxy success.
 * @tc.desc: Verify that RegisterOverflowProxy returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterOverflowProxy_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterOverflowProxy_0002 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterRegisterOverflowProxy(ERR_OK);
    ErrCode ret = formMgrService.RegisterOverflowProxy(callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterOverflowProxy_0002 end";
}

/**
 * @tc.number: FormMgrService_RegisterGetFormRectProxy_0001
 * @tc.name: test RegisterGetFormRectProxy non-system app.
 * @tc.desc: Verify that RegisterGetFormRectProxy returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterGetFormRectProxy_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetFormRectProxy_0001 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterGetFormRectProxy(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetFormRectProxy_0001 end";
}

/**
 * @tc.number: FormMgrService_RegisterGetFormRectProxy_0002
 * @tc.name: test RegisterGetFormRectProxy success.
 * @tc.desc: Verify that RegisterGetFormRectProxy returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterGetFormRectProxy_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetFormRectProxy_0002 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterRegisterGetFormRectProxy(ERR_OK);
    ErrCode ret = formMgrService.RegisterGetFormRectProxy(callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetFormRectProxy_0002 end";
}

/**
 * @tc.number: FormMgrService_RegisterGetLiveFormStatusProxy_0001
 * @tc.name: test RegisterGetLiveFormStatusProxy non-system app.
 * @tc.desc: Verify that RegisterGetLiveFormStatusProxy returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterGetLiveFormStatusProxy_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetLiveFormStatusProxy_0001 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterGetLiveFormStatusProxy(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetLiveFormStatusProxy_0001 end";
}

/**
 * @tc.number: FormMgrService_RegisterGetLiveFormStatusProxy_0002
 * @tc.name: test RegisterGetLiveFormStatusProxy success.
 * @tc.desc: Verify that RegisterGetLiveFormStatusProxy returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterGetLiveFormStatusProxy_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetLiveFormStatusProxy_0002 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterRegisterGetLiveFormStatusProxy(ERR_OK);
    ErrCode ret = formMgrService.RegisterGetLiveFormStatusProxy(callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterGetLiveFormStatusProxy_0002 end";
}

/**
 * @tc.number: FormMgrService_UnregisterGetLiveFormStatusProxy_0001
 * @tc.name: test UnristerGetLiveFormStatusProxy non-system app.
 * @tc.desc: Verify that UnregisterGetLiveFormStatusProxy returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterGetLiveFormStatusProxy_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterGetLiveFormStatusProxy_0001 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterGetLiveFormStatusProxy_0001 end";
}

/**
 * @tc.number: FormMgrService_UnregisterGetLiveFormStatusProxy_0002
 * @tc.name: test UnregisterGetLiveFormStatusProxy success.
 * @tc.desc: Verify that UnregisterGetLiveFormStatusProxy returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterGetLiveFormStatusProxy_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterGetLiveFormStatusProxy_0002 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterUnregisterGetLiveFormStatusProxy(ERR_OK);
    ErrCode ret = formMgrService.UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterGetLiveFormStatusProxy_0002 end";
}

/**
 * @tc.number: FormMgrService_UpdateFormSize_0001
 * @tc.name: test UpdateFormSize permission denied.
 * @tc.desc: Verify that UpdateFormSize returns permission denied.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UpdateFormSize_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UpdateFormSize_0001 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    float width = 100.0f;
    float height = 200.0f;
    float borderWidth = 10.0f;
    float formViewScale = 1.0f;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_UpdateFormSize_0001 end";
}

/**
 * @tc.number: FormMgrService_UpdateFormSize_0002
 * @tc.name: test UpdateFormSize success.
 * @tc.desc: Verify that UpdateFormSize returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UpdateFormSize_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UpdateFormSize_0002 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    float width = 100.0f;
    float height = 200.0f;
    float borderWidth = 10.0f;
    float formViewScale = 1.0f;
    MockIsSACall(true);
    (void)MockFormMgrAdapterUpdateFormSizeFloat(ERR_OK);
    ErrCode ret = formMgrService.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_UpdateFormSize_0002 end";
}

/**
 * @tc.number: FormMgrService_RegisterTemplateFormDetailInfoChange_0001
 * @tc.name: test RegisterTemplateFormDetailInfoChange non-system app.
 * @tc.desc: Verify that RegisterTemplateFormDetailInfoChangeChange returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterTemplateFormDetailInfoChange_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0001 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RegisterTemplateFormDetailInfoChange(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0001 end";
}

/**
 * @tc.number: FormMgrService_RegisterTemplateFormDetailInfoChange_0002
 * @tc.name: test RegisterTemplateFormDetailInfoChange cross account permission denied.
 * @tc.desc: Verify that RegisterTemplateFormDetailInfoChange returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterTemplateFormDetailInfoChange_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0002 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    ErrCode ret = formMgrService.RegisterTemplateFormDetailInfoChange(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0002 end";
}

/**
 * @tc.number: FormMgrService_RegisterTemplateFormDetailInfoChange_0003
 * @tc.name: test RegisterTemplateFormDetailInfoChange bundle permission denied.
 * @tc.desc: Verify that RegisterTemplateFormDetailInfoChange returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterTemplateFormDetailInfoChange_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0003 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockVerifyCallingPermission(false);
    ErrCode ret = formMgrService.RegisterTemplateFormDetailInfoChange(callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0003 end";
}

/**
 * @tc.number: FormMgrService_RegisterTemplateFormDetailInfoChange_0004
 * @tc.name: test RegisterTemplateFormDetailInfoChange success.
 * @tc.desc: Verify that RegisterTemplateFormDetailInfoChange returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_RegisterTemplateFormDetailInfoChange_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0004 start";
    FormMgrService formMgrService;
    sptr<IRemoteObject> callerToken = nullptr;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockVerifyCallingPermission(true);
    MockFormMgrAdapterRegisterTemplateFormDetailInfoChange(ERR_OK);
    ErrCode ret = formMgrService.RegisterTemplateFormDetailInfoChange(callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_RegisterTemplateFormDetailInfoChange_0004 end";
}

/**
 * @tc.number: FormMgrService_UnregisterTemplateFormDetailInfoChange_0001
 * @tc.name: test UnregisterTemplateFormDetailInfoChange non-system app.
 * @tc.desc: Verify that UnregisterTemplateFormDetailInfoChange returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterTemplateFormDetailInfoChange_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0001 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.UnregisterTemplateFormDetailInfoChange();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0001 end";
}

/**
 * @tc.number: FormMgrService_UnregisterTemplateFormDetailInfoChange_0002
 * @tc.name: test UnregisterTemplateFormDetailInfoChange cross account permission denied.
 * @tc.desc: Verify that UnregisterTemplateFormDetailInfoChange returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterTemplateFormDetailInfoChange_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0002 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    ErrCode ret = formMgrService.UnregisterTemplateFormDetailInfoChange();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0002 end";
}

/**
 * @tc.number: FormMgrService_UnregisterTemplateFormDetailInfoChange_0003
 * @tc.name: test UnregisterTemplateFormDetailInfoChange bundle permission denied.
 * @tc.desc: Verify that UnregisterTemplateFormDetailInfoChange returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterTemplateFormDetailInfoChange_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0003 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockVerifyCallingPermission(false);
    ErrCode ret = formMgrService.UnregisterTemplateFormDetailInfoChange();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0003 end";
}

/**
 * @tc.number: FormMgrService_UnregisterTemplateFormDetailInfoChange_0004
 * @tc.name: test UnregisterTemplateFormDetailInfoChange success.
 * @tc.desc: Verify that UnregisterTemplateFormDetailInfoChange returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterTemplateFormDetailInfoChange_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0004 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockVerifyCallingPermission(true);
    MockFormMgrAdapterUnregisterTemplateFormDetailInfoChange(ERR_OK);
    ErrCode ret = formMgrService.UnregisterTemplateFormDetailInfoChange();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterTemplateFormDetailInfoChange_0004 end";
}

/**
 * @tc.number: FormMgrService_UpdateTemplateFormDetailInfo_0001
 * @tc.name: test UpdateTemplateFormDetailInfo non-system app.
 * @tc.desc: Verify that UpdateTemplateFormDetailInfo returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UpdateTemplateFormDetailInfo_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UpdateTemplateFormDetailInfo_0001 start";
    FormMgrService formMgrService;
    std::vector<TemplateFormDetailInfo> templateFormInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.UpdateTemplateFormDetailInfo(templateFormInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_UpdateTemplateFormDetailInfo_0001 end";
}

/**
 * @tc.number: FormMgrService_UpdateTemplateFormDetailInfo_0002
 * @tc.name: test UpdateTemplateFormDetailInfo success.
 * @tc.desc: Verify that UpdateTemplateFormDetailInfo returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UpdateTemplateFormDetailInfo_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UpdateTemplateFormDetailInfo_0002 start";
    FormMgrService formMgrService;
    std::vector<TemplateFormDetailInfo> templateFormInfo;
    MockIsSystemAppByFullTokenID(true);
    MockFormMgrAdapterUpdateTemplateFormDetailInfo(ERR_OK);
    ErrCode ret = formMgrService.UpdateTemplateFormDetailInfo(templateFormInfo);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_UpdateTemplateFormDetailInfo_0002 end";
}

/**
 * @tc.number: FormMgrService_UnregisterPublishFormCrossBundleControl_0001
 * @tc.name: test UnregisterPublishFormCrossBundleControl non-system app.
 * @tc.desc: Verify that UnregisterPublishFormCrossBundleControl returns permission deny for non-system app.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterPublishFormCrossBundleControl_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0001 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.UnregisterPublishFormCrossBundleControl();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0001 end";
}

/**
 * @tc.number: FormMgrService_UnregisterPublishFormCrossBundleControl_0002
 * @tc.name: test UnregisterPublishFormCrossBundleControl permission denied.
 * @tc.desc: Verify that UnregisterPublishFormCrossBundleControl returns permission deny.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterPublishFormCrossBundleControl_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0002 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    ErrCode ret = formMgrService.UnregisterPublishFormCrossBundleControl();
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0002 end";
}

/**
 * @tc.number: FormMgrService_UnregisterPublishFormCrossBundleControl_0003
 * @tc.name: test UnregisterPublishFormCrossBundleControl success.
 * @tc.desc: Verify that UnregisterPublishFormCrossBundleControl returns success.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_UnregisterPublishFormCrossBundleControl_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0003 start";
    FormMgrService formMgrService;
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockFormMgrAdapterUnregisterPublishFormCrossBundleControl(ERR_OK);
    ErrCode ret = formMgrService.UnregisterPublishFormCrossBundleControl();
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_UnregisterPublishFormCrossBundleControl_0003 end";
}

/**
 * @tc.number: FormMgrService_PublishFormCrossBundleControl_0001
 * @tc.name: test PublishFormCrossBundleControl isShowSingleForm=false.
 * @tc.desc: Verify that PublishFormCrossBundleControl returns true when isShowSingleForm is false.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_PublishFormCrossBundleControl_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0001 start";
    FormMgrService formMgrService;
    Want want;
    bool result = formMgrService.PublishFormCrossBundleControl(want);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0001 end";
}

/**
 * @tc.number: FormMgrService_PublishFormCrossBundleControl_0002
 * @tc.name: test PublishFormCrossBundleControl GetCallerBundleName failed.
 * @tc.desc: Verify that PublishFormCrossBundleControl returns false when GetCallerBundleName fails.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_PublishFormCrossBundleControl_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0002 start";
    FormMgrService formMgrService;
    Want want;
    want.SetParam(Constants::FORM_MANAGER_SHOW_SINGLE_FORM_KEY, true);
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    bool result = formMgrService.PublishFormCrossBundleControl(want);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0002 end";
}

/**
 * @tc.number: FormMgrService_PublishFormCrossBundleControl_0003
 * @tc.name: test PublishFormCrossBundleControl success.
 * @tc.desc: Verify that PublishFormCrossBundleControl returns true.
 */
HWTEST_F(FmsFormMgrServiceTest2, FormMgrService_PublishFormCrossBundleControl_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0003 start";
    FormMgrService formMgrService;
    Want want;
    want.SetParam(Constants::FORM_MANAGER_SHOW_SINGLE_FORM_KEY, true);
    MockGetCallerBundleName(ERR_OK);
    MockFormMgrAdapterPublishFormCrossBundleControl(true);
    bool result = formMgrService.PublishFormCrossBundleControl(want);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrService_PublishFormCrossBundleControl_0003 end";
}
}
