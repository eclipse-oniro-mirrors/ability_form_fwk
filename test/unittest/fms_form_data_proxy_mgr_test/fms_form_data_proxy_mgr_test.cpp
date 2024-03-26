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

#include <gtest/gtest.h>
#include <map>
#include <string>
#include <thread>

#include "appexecfwk_errors.h"
#define private public
#include "form_data_proxy_mgr.h"
#include "form_item_info.h"
#undef private
#include "form_bms_helper.h"
#include "form_data_proxy_record.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_data_mgr.h"
#include "form_record.h"
#include "form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
    OHOS::ErrCode g_mockGetApplicationInfo = OHOS::ERR_OK;
}

void MockGetApplicationInfo(OHOS::ErrCode mockRet)
{
    g_mockGetApplicationInfo = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

ErrCode FormBmsHelper::GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo)
{
    return g_mockGetApplicationInfo;
}
} // namespace AppExecFwk
} // namespace OHOS

namespace {
const std::string FORM_BUNDLE_NAME = "com.form.service";
const std::string PARAM_MODULE_NAME = "com.form.app.test.ability";
const std::string FORM_ABILITY_NAME = "com.form.app.test.ability";
const std::string PARAM_FORM_NAME = "com.form.name.test";
const int32_t PARAM_FORM_DIMENSION_VALUE = 1;

class FmsFormDataProxyMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDataProxyMgrTest::SetUpTestCase()
{}

void FmsFormDataProxyMgrTest::TearDownTestCase()
{}

void FmsFormDataProxyMgrTest::SetUp()
{}

void FmsFormDataProxyMgrTest::TearDown()
{}

/**
 * @tc.name: FmsFormDataProxyMgrTest_001
 * @tc.desc: Verify functionName SubscribeFormData.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_001 start";
    FormRecord formRecord;
    int64_t formId = 1;
    AAFwk::Want want;
    std::vector<FormDataProxy> formDataProxies;
    uint32_t ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want);
    EXPECT_EQ(ret, ERR_OK);
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    int callingUid {0};
    // Set cache
    FormItemInfo record1;
    record1.SetFormId(formId);
    record1.SetProviderBundleName(FORM_BUNDLE_NAME);
    record1.SetModuleName(PARAM_MODULE_NAME);
    record1.SetAbilityName(FORM_ABILITY_NAME);
    record1.SetFormName(PARAM_FORM_NAME);
    record1.SetSpecificationId(PARAM_FORM_DIMENSION_VALUE);
    record1.SetTemporaryFlag(false);
    FormRecord formRecord2 = FormDataMgr::GetInstance().AllotFormRecord(record1, callingUid);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want);
    EXPECT_EQ(ret, ERR_OK);

    formRecord2.isDataProxy = true;
    FormDataMgr::GetInstance().UpdateFormRecord(formId, formRecord2);
    MockGetApplicationInfo(ERR_OK + 1);
    ret = FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_001 end";
}

/**
 * @tc.name: FmsFormDataProxyMgrTest_002
 * @tc.desc: Verify functionName ConsumeFormDataProxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataProxyMgrTest, FmsFormDataProxyMgrTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_002 start";
    int64_t formId = 1;
    std::vector<FormDataProxy> formDataProxies;

    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    FormDataProxyMgr::GetInstance().ProduceFormDataProxies(formId, formDataProxies);
    EXPECT_EQ(FormDataProxyMgr::GetInstance().formDataProxiesMap_.size(), 1);

    std::vector<FormDataProxy> getFormDataProxies;
    bool ret = FormDataProxyMgr::GetInstance().ConsumeFormDataProxies(formId, getFormDataProxies);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "FmsFormDataProxyMgrTest_002 end";
}
}