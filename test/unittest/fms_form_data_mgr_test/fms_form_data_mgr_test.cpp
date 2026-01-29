/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "mock_form_db_cache.h"
#include "appexecfwk_errors.h"
#define private public
#include "data_center/database/form_db_cache.h"
#include "data_center/form_data_mgr.h"
#undef private
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "mock_form_host_client.h"
#include "running_form_info.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
static const std::string FORM_HOST_BUNDLE_NAME = "com.form.provider.service";
static const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
static const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
static const std::string FORM_NAME = "formName";
const std::string FORM_BUNDLE_NAME = "formBundleName";
const int64_t FORM_ID_ONE = 1;
const int64_t FORM_ID_ZERO = 0;
const int64_t FORM_USER_UIDS_ZERO = 0;

extern void MockGetBundleNameByUid(ErrCode mockRet);
extern void MockGetAllFormInfo(int32_t mockRet);

namespace {
class FmsFormDataMgrTest : public testing::Test {
public:
    FmsFormDataMgrTest()
    {}
    ~FmsFormDataMgrTest()
    {}

    void SetUp();
    void TearDown();
    void InitFormItemInfo(int64_t formId, FormItemInfo &form_item_info, bool istemp = true);

protected:
    FormDataMgr formDataMgr_;
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_;
};

void FmsFormDataMgrTest::SetUp(void)
{
    // token
    token_ = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
}

void FmsFormDataMgrTest::TearDown(void)
{
    while (!formDataMgr_.formRecords_.empty()) {
        formDataMgr_.formRecords_.erase(formDataMgr_.formRecords_.begin());
    }
    if (!formDataMgr_.clientRecords_.empty()) {
        formDataMgr_.clientRecords_.erase(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end());
    }
    if (!formDataMgr_.tempForms_.empty()) {
        formDataMgr_.tempForms_.erase(formDataMgr_.tempForms_.begin(), formDataMgr_.tempForms_.end());
    }
    if (!FormDbCache::GetInstance().formDBInfos_.empty()) {
        FormDbCache::GetInstance().formDBInfos_.clear();
    }
    formDataMgr_.udidHash_ = 0;
}

void FmsFormDataMgrTest::InitFormItemInfo(int64_t formId, FormItemInfo &form_item_info, bool istemp)
{
    // create hapSourceDirs
    std::vector<std::string> hapSourceDirs;
    std::string hapSourceDir = "1/2/3";
    hapSourceDirs.emplace_back(hapSourceDir);

    // create form_item_info
    form_item_info.SetFormId(formId);
    form_item_info.SetTemporaryFlag(istemp);
    form_item_info.SetEnableUpdateFlag(true);
    form_item_info.SetUpdateDuration(Constants::MIN_CONFIG_DURATION);
    form_item_info.SetScheduledUpdateTime("10:30");
    form_item_info.SetHapSourceDirs(hapSourceDirs);
    std::string providerBundleName = "testBundle";
    providerBundleName.append(std::to_string(formId));
    form_item_info.SetProviderBundleName(providerBundleName);
    std::string abilityName = "testAbility";
    abilityName.append(std::to_string(formId));
    form_item_info.SetAbilityName(abilityName);
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_001
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_001 start";

    int64_t formId = 1;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_002
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      formRecords_ is include this formId.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_002 start";

    int64_t formId = 2;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);

    // create formRecords
    FormRecord record = formDataMgr_.CreateFormRecord(form_item_info, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_003
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      formRecords_ is not include this formId, then create formRecords.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_003 start";

    int64_t formId = 3;
    int64_t otherformId = 100;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);

    // create other FormItemInfo
    FormItemInfo otherFormItemInfo;
    InitFormItemInfo(otherformId, otherFormItemInfo);

    // create formRecords
    FormRecord record = formDataMgr_.CreateFormRecord(otherFormItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherformId, record);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_004
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      EnableUpdateFlag is true,
 *      SetUpdateDuration is not MAX_CONFIG_DURATION.(call ParseIntervalConfig)
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_004 start";

    int64_t formId = 4;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(Constants::MAX_CONFIG_DURATION);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_005
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      EnableUpdateFlag is true,
 *      SetUpdateDuration is between MIN_CONFIG_DURATION and MAX_CONFIG_DURATION.(call ParseIntervalConfig)
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_005 start";

    int64_t formId = 5;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(Constants::MAX_CONFIG_DURATION-2);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_005 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_006
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      SetUpdateDuration is 0.(call ParseAtTimerConfig)
 *      获取配置项scheduledUpdateTime_为empty
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_006 start";

    int64_t formId = 6;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(0);
    form_item_info.scheduledUpdateTime_.clear();

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_006 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_007
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      SetUpdateDuration is 0.(call ParseAtTimerConfig)
 *      Gets the configuration item scheduledUpdateTime_ an invalid value.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_007 start";

    int64_t formId = 7;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(0);
    form_item_info.SetScheduledUpdateTime("10:30:10");

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_007 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_008
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      SetUpdateDuration is 0.(call ParseAtTimerConfig)
 *      获取配置项scheduledUpdateTime_为无效值
 *      不存在hapSourceDirs_
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_008 start";

    int64_t formId = 8;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(0);
    form_item_info.SetScheduledUpdateTime("10:70");
    form_item_info.hapSourceDirs_.clear();

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_008 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormRecord_009
 * @tc.name: AllotFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      SetUpdateDuration is 0.(call ParseAtTimerConfig)
 *      获取配置项scheduledUpdateTime_为有效值
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormRecord_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_009 start";

    int64_t formId = 9;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetUpdateDuration(0);

    FormRecord recordResult = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    EXPECT_EQ(formId, recordResult.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormRecord_009 end";
}


/**
 * @tc.number: FmsFormDataMgrTest_AllotFormHostRecord_001
 * @tc.name: AllotFormHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      clientRecords_ is include token_.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormHostRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_001 start";

    int64_t formId = 1;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    EXPECT_EQ(true, formDataMgr_.AllotFormHostRecord(formItemInfo, token_, formId, callingUid));
    EXPECT_EQ(true, formDataMgr_.clientRecords_.begin()->forms_[formId]);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormHostRecord_002
 * @tc.name: AllotFormHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      clientRecords_ is not include token_.
 *      CreateHostRecord is OK.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormHostRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_002 start";

    int64_t formId = 2;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);

    EXPECT_EQ(true, formDataMgr_.AllotFormHostRecord(formItemInfo, token_, formId, callingUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AllotFormHostRecord_003
 * @tc.name: AllotFormHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      clientRecords_ is not include token_.
 *      CreateHostRecord is NG.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AllotFormHostRecord_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_003 start";

    int64_t formId = 3;
    int callingUid = 0;

    // create FormItemInfo
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);

    // set callerToken nullptr
    token_ = nullptr;

    EXPECT_EQ(false, formDataMgr_.AllotFormHostRecord(formItemInfo, token_, formId, callingUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AllotFormHostRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormInfo_001
 * @tc.name: CreateFormInfo
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormInfo_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormInfo_001 start";

    int64_t formId = 1;

    // create record
    FormRecord record;
    record.bundleName = FORM_HOST_BUNDLE_NAME;
    record.abilityName = FORM_PROVIDER_ABILITY_NAME;
    record.formName = FORM_NAME;
    record.formTempFlag = true;

    FormJsInfo formInfo;
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->CreateFormJsInfo(formId, record, formInfo);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormInfo_001 output=>bundleName:"<<formInfo.bundleName
    <<"abilityName:"<<formInfo.abilityName<<"formName:"<<formInfo.formName<<"formTempFlag:"<<formInfo.formTempFlag;
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormInfo_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CheckTempEnoughForm_001
 * @tc.name: CheckTempEnoughForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      tempForms_ is empty.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CheckTempEnoughForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckTempEnoughForm_001 start";

    EXPECT_EQ(ERR_OK, formDataMgr_.CheckTempEnoughForm());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckTempEnoughForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CheckTempEnoughForm_002
 * @tc.name: CheckTempEnoughForm
 * @tc.desc: Verify that the return value is correct.
* @tc.details:
 *      tempForms_'s size is over 256.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CheckTempEnoughForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckTempEnoughForm_002 start";

    for (int index = 0; index < Constants::MAX_TEMP_FORMS; index++) {
        formDataMgr_.tempForms_.emplace_back(index);
    }
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, formDataMgr_.CheckTempEnoughForm());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckTempEnoughForm_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CheckEnoughForm_001
 * @tc.name: CheckEnoughForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      formDBInfos_'s size is over 512.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CheckEnoughForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_001 start";

    int callingUid = 0;
    int32_t checkAllDBFormMaxSize = 2;

    // set formDbInfos size is over 512
    MockGetAllFormInfoSize(checkAllDBFormMaxSize, callingUid);

    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS, formDataMgr_.CheckEnoughForm(callingUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CheckEnoughForm_002
 * @tc.name: CheckEnoughForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      there is no formRecords.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CheckEnoughForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_002 start";

    int callingUid = 0;
    int32_t checkAllDBFormPreAPPSize = 1;

    MockGetAllFormInfoSize(checkAllDBFormPreAPPSize, callingUid);

    EXPECT_EQ(ERR_OK, formDataMgr_.CheckEnoughForm(callingUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CheckEnoughForm_003
 * @tc.name: CheckEnoughForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      there is 256 formDBInfos_ and their callingUid is -1.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CheckEnoughForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_003 start";

    int callingUid = -1;
    int32_t checkAllDBFormPreAPPSize = 1;

    // set formDbInfos size is over 256
    MockGetAllFormInfoSize(checkAllDBFormPreAPPSize, callingUid);

    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT, formDataMgr_.CheckEnoughForm(callingUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CheckEnoughForm_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteTempForm_001
 * @tc.name: DeleteTempForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       temp form is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteTempForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteTempForm_001 start";

    int64_t formId = 1;
    EXPECT_EQ(false, formDataMgr_.DeleteTempForm(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteTempForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteTempForm_002
 * @tc.name: DeleteTempForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       temp form is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteTempForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteTempForm_002 start";

    int64_t formId = 2;
    formDataMgr_.tempForms_.emplace_back(formId);

    EXPECT_EQ(true, formDataMgr_.DeleteTempForm(formId));
    EXPECT_EQ(true, formDataMgr_.tempForms_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteTempForm_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ModifyFormTempFlag_001
 * @tc.name: ModifyFormTempFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ModifyFormTempFlag_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ModifyFormTempFlag_001 start";

    int64_t formId = 1;
    bool formTempFlag = true;

    EXPECT_EQ(false, formDataMgr_.ModifyFormTempFlag(formId, formTempFlag));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ModifyFormTempFlag_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ModifyFormTempFlag_002
 * @tc.name: ModifyFormTempFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ModifyFormTempFlag_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ModifyFormTempFlag_002 start";

    int64_t formId = 2;
    bool formTempFlag = false;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(true, formDataMgr_.ModifyFormTempFlag(formId, formTempFlag));
    EXPECT_EQ(false, formDataMgr_.formRecords_[formId].formTempFlag);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ModifyFormTempFlag_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AddFormUserUid_001
 * @tc.name: AddFormUserUid
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AddFormUserUid_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AddFormUserUid_001 start";

    int64_t formId = 1;
    int formUserUid = 100;

    EXPECT_EQ(false, formDataMgr_.AddFormUserUid(formId, formUserUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AddFormUserUid_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AddFormUserUid_002
 * @tc.name: AddFormUserUid
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found, and add new formUserUid.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AddFormUserUid_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AddFormUserUid_002 start";

    int64_t formId = 2;
    int formUserUid = 100;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);
    EXPECT_EQ(true, formDataMgr_.AddFormUserUid(formId, formUserUid));
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AddFormUserUid_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormUserUid_001
 * @tc.name: DeleteFormUserUid
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormUserUid_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormUserUid_001 start";

    int64_t formId = 1;
    int32_t formUserUid = 100;

    EXPECT_EQ(false, formDataMgr_.DeleteFormUserUid(formId, formUserUid));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormUserUid_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormUserUid_002
 * @tc.name: DeleteFormUserUid
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found, and delete.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormUserUid_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormUserUid_002 start";

    int64_t formId = 2;
    int32_t formUserUid = 100;

    // create formRecords
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, formUserUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(true, formDataMgr_.DeleteFormUserUid(formId, formUserUid));

    // check formUserUids
    bool find = false;
    for (int uid : formDataMgr_.formRecords_[formId].formUserUids) {
        if (uid == formUserUid) {
            find = true;
        }
    }
    EXPECT_EQ(false, find);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormUserUid_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormRecord_001
 * @tc.name: UpdateFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_001 start";

    int64_t formId = 1;

    // create record
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);

    EXPECT_EQ(false, formDataMgr_.UpdateFormRecord(formId, record));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormRecord_002
 * @tc.name: UpdateFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_002 start";

    int64_t formId = 2;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    int callingUidModify = 1;
    FormRecord recordModify = formDataMgr_.CreateFormRecord(formItemInfo, callingUidModify);

    EXPECT_EQ(true, formDataMgr_.UpdateFormRecord(formId, recordModify));

    // check update form
    auto iter = std::find(formDataMgr_.formRecords_[formId].formUserUids.begin(),
    formDataMgr_.formRecords_[formId].formUserUids.end(), callingUidModify);
    if (iter != formDataMgr_.formRecords_[formId].formUserUids.end())
    {
        GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_002 find callingUidModify after update!";
    }

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormRecord_003
 * @tc.name: UpdateFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormRecord_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_003 start";
    int64_t formId = 1;
    FormRecord record;
    record.bundleName = "XXX";

    formDataMgr_.formRecords_.clear();
    formDataMgr_.formRecords_[formId] = record;
    formDataMgr_.UpdateFormRecord(formId, [](FormRecord &record) {
        record.bundleName = "bundleName";
    });
    EXPECT_EQ(formDataMgr_.formRecords_[formId].bundleName, "bundleName");
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormRecord_001
 * @tc.name: GetFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_001 start";

    int64_t formId = 1;
    FormRecord record;

    EXPECT_EQ(false, formDataMgr_.GetFormRecord(formId, record));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormRecord_002
 * @tc.name: GetFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_002 start";

    int64_t formId = 2;

    // create formRecords_
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    FormRecord recordOutput;
    EXPECT_EQ(true, formDataMgr_.GetFormRecord(formId, recordOutput));
    EXPECT_EQ(formId, recordOutput.formId);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_002 end";
}


/**
 * @tc.number: FmsFormDataMgrTest_GetFormRecord_2_001
 * @tc.name: GetFormRecord_2
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormRecord_2_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_2_001 start";

    std::string bundleName = "bundleName";
    std::vector<FormRecord> formInfos;

    EXPECT_EQ(false, formDataMgr_.GetFormRecord(bundleName, formInfos));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_2_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormRecord_2_002
 * @tc.name: GetFormRecord_2
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormRecord_2_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_2_002 start";

    std::string bundleName = "bundleName";
    std::vector<FormRecord> formInfos;

    // create formRecords_
    int64_t formId = 2;
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    formItemInfo.SetProviderBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(true, formDataMgr_.GetFormRecord(bundleName, formInfos));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormRecord_2_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HasFormUserUids_001
 * @tc.name: HasFormUserUids
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HasFormUserUids_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormUserUids_001 start";

    int64_t formId = 1;

    EXPECT_EQ(false, formDataMgr_.HasFormUserUids(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormUserUids_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HasFormUserUids_002
 * @tc.name: HasFormUserUids
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HasFormUserUids_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormUserUids_002 start";

    int64_t formId = 2;

    // create formRecords_
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(true, formDataMgr_.HasFormUserUids(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormUserUids_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormHostRecord_001
 * @tc.name: GetFormHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormHostRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRecord_001 start";

    int64_t formId = 1;
    std::vector<FormHostRecord> formHostRecords;

    formDataMgr_.GetFormHostRecord(formId, formHostRecords);
    EXPECT_EQ(true, formHostRecords.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormHostRecord_002
 * @tc.name: GetFormHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormHostRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRecord_002 start";

    int64_t formId = 2;
    std::vector<FormHostRecord> formHostRecords;

    // create clientRecords_
    FormHostRecord form_host_record;
    form_host_record.SetFormHostClient(token_);
    form_host_record.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(form_host_record);

    formDataMgr_.GetFormHostRecord(formId, formHostRecords);
    EXPECT_EQ(true, formHostRecords[0].forms_[formId]);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteHostRecord_001
 * @tc.name: DeleteHostRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteHostRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteHostRecord_001 start";

    int64_t formId = 1;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    EXPECT_EQ(true, formDataMgr_.DeleteHostRecord(token_, formId));
    EXPECT_EQ(false, formDataMgr_.clientRecords_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteHostRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CleanHostRemovedForms_001
 * @tc.name: CleanHostRemovedForms
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CleanHostRemovedForms_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanHostRemovedForms_001 start";

    std::vector<int64_t> removedFormIds;
    int64_t formId = 1;
    removedFormIds.emplace_back(formId);

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    formDataMgr_.CleanHostRemovedForms(removedFormIds);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanHostRemovedForms_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HandleHostDied_001
 * @tc.name: HandleHostDied
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ & tempForms_ & formRecords is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleHostDied_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_001 start";

    int64_t formId = 1;

    // create tempForms_
    formDataMgr_.tempForms_.emplace_back(formId);

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.HandleHostDied(token_);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HandleHostDied_002
 * @tc.name: HandleHostDied
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       tempForms_ is not match.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleHostDied_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_002 start";

    int64_t formId = 2;
    int64_t otherFormId = 3;

    // create tempForms_
    formDataMgr_.tempForms_.emplace_back(otherFormId);

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.HandleHostDied(token_);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HandleHostDied_003
 * @tc.name: HandleHostDied
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       remoteHost is not match, formRecords is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleHostDied_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_003 start";

    int64_t formId = 3;

    // create clientRecords_
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_2;
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_2);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    record.expectRecycled = true;
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.HandleHostDied(token_);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDied_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsEnableRefresh_001
 * @tc.name: IsEnableRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsEnableRefresh_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableRefresh_001 start";

    int64_t formId = 1;
    EXPECT_EQ(false, formDataMgr_.IsEnableRefresh(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsEnableRefresh_002
 * @tc.name: IsEnableRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsEnableRefresh_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableRefresh_002 start";

    int64_t formId = 2;

    // create clientRecords_
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_;
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    EXPECT_EQ(true, formDataMgr_.IsEnableRefresh(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableRefresh_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GenerateUdidHash_001
 * @tc.name: GenerateUdidHash
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       udidHash_ is not 0.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GenerateUdidHash_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GenerateUdidHash_001 start";

    formDataMgr_.udidHash_ = 1;
    EXPECT_EQ(true, formDataMgr_.GenerateUdidHash());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GenerateUdidHash_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GenerateUdidHash_002
 * @tc.name: GenerateUdidHash
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       udidHash_ is 0.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GenerateUdidHash_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GenerateUdidHash_002 start";

    formDataMgr_.udidHash_ = Constants::INVALID_UDID_HASH;
    EXPECT_EQ(true, formDataMgr_.GenerateUdidHash());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GenerateUdidHash_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetMatchedHostClient_001
 * @tc.name: GetMatchedHostClient
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetMatchedHostClient_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetMatchedHostClient_001 start";

    // create clientRecords_
    FormHostRecord formHostRecord;

    EXPECT_EQ(false, formDataMgr_.GetMatchedHostClient(token_, formHostRecord));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetMatchedHostClient_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetMatchedHostClient_002
 * @tc.name: GetMatchedHostClient
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetMatchedHostClient_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetMatchedHostClient_002 start";

    int64_t formId = 2;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    FormHostRecord formHostRecordOutput;

    EXPECT_EQ(true, formDataMgr_.GetMatchedHostClient(token_, formHostRecordOutput));
    EXPECT_EQ(true, formHostRecordOutput.forms_[formId]);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetMatchedHostClient_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetNeedRefresh_001
 * @tc.name: SetNeedRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetNeedRefresh_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetNeedRefresh_001 start";

    int64_t formId = 1;
    bool needRefresh = true;
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetNeedRefresh(formId, needRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetNeedRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetNeedRefresh_002
 * @tc.name: SetNeedRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetNeedRefresh_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetNeedRefresh_002 start";

    int64_t formId = 2;
    bool needRefresh = true;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetNeedRefresh(formId, needRefresh);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.needRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetNeedRefresh_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetCountTimerRefresh_001
 * @tc.name: SetCountTimerRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetCountTimerRefresh_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetCountTimerRefresh_001 start";

    int64_t formId = 1;
    bool countTimerRefresh = true;
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetCountTimerRefresh(formId, countTimerRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetCountTimerRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetCountTimerRefresh_002
 * @tc.name: SetCountTimerRefresh
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetCountTimerRefresh_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetCountTimerRefresh_002 start";

    int64_t formId = 2;
    bool countTimerRefresh = true;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetCountTimerRefresh(formId, countTimerRefresh);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.isCountTimerRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetCountTimerRefresh_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetUpdatedForm_001
 * @tc.name: GetUpdatedForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       targetForms is empty.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUpdatedForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_001 start";

    FormRecord record;
    record.bundleName = "";
    record.moduleName = "";
    record.abilityName = "";
    record.formName = "";
    record.specification = 0;

    std::vector<FormInfo> targetForms;
    FormInfo updatedForm;

    EXPECT_EQ(false, formDataMgr_.GetUpdatedForm(record, targetForms, updatedForm));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetUpdatedForm_002
 * @tc.name: GetUpdatedForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       targetForms is not empty. record is same as formInfo.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUpdatedForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_002 start";

    int32_t specification = 2;

    FormRecord record;
    record.bundleName = FORM_HOST_BUNDLE_NAME;
    record.moduleName = PARAM_PROVIDER_MODULE_NAME;
    record.abilityName = FORM_PROVIDER_ABILITY_NAME;
    record.formName = FORM_NAME;
    record.specification = specification;

    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    formInfo.supportDimensions.emplace_back(specification);
    targetForms.emplace_back(formInfo);

    FormInfo updatedForm;

    EXPECT_EQ(true, formDataMgr_.GetUpdatedForm(record, targetForms, updatedForm));
    EXPECT_EQ(FORM_HOST_BUNDLE_NAME, updatedForm.bundleName);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetUpdatedForm_003
 * @tc.name: GetUpdatedForm
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       targetForms is not empty. record is not same as formInfo.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUpdatedForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_003 start";

    int32_t specification = 3;

    FormRecord record;
    record.bundleName = "bundleName";
    record.moduleName = PARAM_PROVIDER_MODULE_NAME;
    record.abilityName = FORM_PROVIDER_ABILITY_NAME;
    record.formName = FORM_NAME;
    record.specification = specification;

    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    formInfo.supportDimensions.emplace_back(specification);
    targetForms.emplace_back(formInfo);

    FormInfo updatedForm;

    EXPECT_EQ(false, formDataMgr_.GetUpdatedForm(record, targetForms, updatedForm));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUpdatedForm_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetEnableUpdate_001
 * @tc.name: SetEnableUpdate
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetEnableUpdate_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetEnableUpdate_001 start";

    int64_t formId = 1;
    bool enableUpdate = true;

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetEnableUpdate(formId, enableUpdate);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetEnableUpdate_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetEnableUpdate_002
 * @tc.name: SetEnableUpdate
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetEnableUpdate_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetEnableUpdate_002 start";

    int64_t formId = 2;
    bool enableUpdate = true;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetEnableUpdate(formId, enableUpdate);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.isEnableUpdate);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetEnableUpdate_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetUpdateInfo_001
 * @tc.name: SetUpdateInfo
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetUpdateInfo_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetUpdateInfo_001 start";

    int64_t formId = 1;
    bool enableUpdate = true;
    long updateDuration = 100;
    int updateAtHour = 24;
    int updateAtMin = 59;
    std::vector<std::vector<int>> updateAtTimes;
    std::vector<int> newElement = {updateAtHour, updateAtMin};
    updateAtTimes.push_back(newElement);
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetUpdateInfo(formId, enableUpdate, updateDuration, updateAtHour, updateAtMin, updateAtTimes);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetUpdateInfo_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetUpdateInfo_002
 * @tc.name: SetUpdateInfo
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetUpdateInfo_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetUpdateInfo_002 start";

    int64_t formId = 1;
    bool enableUpdate = true;
    long updateDuration = 100;
    int updateAtHour = 24;
    int updateAtMin = 59;
    std::vector<std::vector<int>> updateAtTimes;
    std::vector<int> newElement = {updateAtHour, updateAtMin};
    updateAtTimes.push_back(newElement);
    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetUpdateInfo(formId, enableUpdate, updateDuration, updateAtHour, updateAtMin, updateAtTimes);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.isEnableUpdate);
    EXPECT_EQ(100, formDataMgr_.formRecords_.find(formId)->second.updateDuration);
    EXPECT_EQ(24, formDataMgr_.formRecords_.find(formId)->second.updateAtHour);
    EXPECT_EQ(59, formDataMgr_.formRecords_.find(formId)->second.updateAtMin);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetUpdateInfo_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CleanRemovedFormRecords_001
 * @tc.name: CleanRemovedFormRecords

 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       removedForm is matched with formRecords_.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CleanRemovedFormRecords_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedFormRecords_001 start";

    // create formRecords
    int callingUid = 0;
    int64_t formId = 1;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    std::string bundleName = FORM_HOST_BUNDLE_NAME;

    std::set<int64_t> removedForms;
    int64_t removedForm = formId;
    removedForms.emplace(removedForm);

    formDataMgr_.CleanRemovedFormRecords(bundleName, removedForms);
    EXPECT_EQ(true, formDataMgr_.formRecords_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedFormRecords_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CleanRemovedFormRecords_002
 * @tc.name: CleanRemovedFormRecords

 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       removedForm is not matched with formRecords_.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CleanRemovedFormRecords_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedFormRecords_002 start";

    // create formRecords
    int callingUid = 0;
    int64_t formId = 2;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    std::string bundleName = FORM_HOST_BUNDLE_NAME;

    std::set<int64_t> removedForms;
    int64_t removedForm = 100;
    removedForms.emplace(removedForm);

    formDataMgr_.CleanRemovedFormRecords(bundleName, removedForms);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedFormRecords_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CleanRemovedTempFormRecords_001
 * @tc.name: CleanRemovedTempFormRecords

 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      bundleName is matched with formRecords_, and it is temp.
 *      erase formRecords_ and tempForms_.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CleanRemovedTempFormRecords_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedTempFormRecords_001 start";

    int64_t formId = 1;
    std::string bundleName = FORM_HOST_BUNDLE_NAME;

    std::set<int64_t> removedForms;
    int64_t removedForm = formId;
    removedForms.emplace(removedForm);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    formItemInfo.SetProviderBundleName(bundleName);
    int32_t userId = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid, userId);
    formDataMgr_.formRecords_.emplace(formId, record);

    // create tempForms_
    formDataMgr_.tempForms_.emplace_back(formId);

    formDataMgr_.CleanRemovedTempFormRecords(bundleName, userId, removedForms);
    EXPECT_EQ(true, formDataMgr_.formRecords_.empty());
    EXPECT_EQ(true, formDataMgr_.tempForms_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedTempFormRecords_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CleanRemovedTempFormRecords_002
 * @tc.name: CleanRemovedTempFormRecords

 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      bundleName is not matched with formRecords_.
 *      erase none.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CleanRemovedTempFormRecords_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedTempFormRecords_002 start";

    int64_t formId = 2;
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    std::string otherBundleName = "bundleName";

    std::set<int64_t> removedForms;
    int64_t removedForm = formId;
    removedForms.emplace(removedForm);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    formItemInfo.SetProviderBundleName(otherBundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    // create tempForms_
    formDataMgr_.tempForms_.emplace_back(formId);

    formDataMgr_.CleanRemovedTempFormRecords(bundleName, Constants::DEFAULT_USER_ID, removedForms);
    EXPECT_EQ(false, formDataMgr_.formRecords_.empty());
    EXPECT_EQ(false, formDataMgr_.tempForms_.empty());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CleanRemovedTempFormRecords_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetReCreateFormRecordsByBundleName_001
 * @tc.name: GetReCreateFormRecordsByBundleName

 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetReCreateFormRecordsByBundleName_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetReCreateFormRecordsByBundleName_001 start";

    int64_t formId = 1;
    std::string bundleName = FORM_HOST_BUNDLE_NAME;

    std::set<int64_t> reCreateForms;
    int64_t reCreateForm = formId;
    reCreateForms.emplace(reCreateForm);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    formItemInfo.SetProviderBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.GetReCreateFormRecordsByBundleName(bundleName, reCreateForms);
    EXPECT_EQ(true, reCreateForms.count(formId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetReCreateFormRecordsByBundleName_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetFormCacheInited_001
 * @tc.name: SetFormCacheInited
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetFormCacheInited_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetFormCacheInited_001 start";

    int64_t formId = 1;
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetFormCacheInited(formId, true);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetFormCacheInited_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetFormCacheInited_002
 * @tc.name: SetFormCacheInited
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetFormCacheInited_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetFormCacheInited_002 start";

    int64_t formId = 2;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetFormCacheInited(formId, true);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.isInited);
    EXPECT_EQ(false, formDataMgr_.formRecords_.find(formId)->second.needRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetFormCacheInited_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetVersionUpgrade_001
 * @tc.name: SetVersionUpgrade
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is not found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetVersionUpgrade_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetVersionUpgrade_001 start";

    int64_t formId = 1;
    bool version = true;
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    formDataMgr->SetVersionUpgrade(formId, version);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetVersionUpgrade_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetVersionUpgrade_002
 * @tc.name: SetFormCacheInited
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords_ is found.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetVersionUpgrade_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetVersionUpgrade_002 start";

    int64_t formId = 2;
    bool versionUpgrade = true;

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    formDataMgr_.SetVersionUpgrade(formId, versionUpgrade);
    EXPECT_EQ(true, formDataMgr_.formRecords_.find(formId)->second.versionUpgrade);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetVersionUpgrade_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostNeedRefresh_001
 * @tc.name: UpdateHostNeedRefresh
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostNeedRefresh_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostNeedRefresh_001 start";

    int64_t formId = 1;
    bool needRefresh = true;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    formDataMgr_.UpdateHostNeedRefresh(formId, needRefresh);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostNeedRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostForm_001
 * @tc.name: UpdateHostForm
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostForm_001 start";

    int64_t formId = 1;
    FormRecord formRecord;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    EXPECT_EQ(true, formDataMgr_.UpdateHostForm(formId, formRecord));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_001
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is not exit.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_001 start";

    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false,
        refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_002
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords's VersionUpgrade is false.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_002 start";

    std::vector<int64_t> formIds;
    int64_t formId = 2;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    // SetNeedRefresh:true
    formHostRecord.SetNeedRefresh(formId, true);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);
    // versionUpgrade : false
    formDataMgr_.SetVersionUpgrade(formId, false);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_003
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords's VersionUpgrade is true.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_003 start";

    std::vector<int64_t> formIds;
    int64_t formId = 3;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    // SetNeedRefresh:true
    formHostRecord.SetNeedRefresh(formId, true);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);
    // versionUpgrade : true
    formDataMgr_.SetVersionUpgrade(formId, true);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_004
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_'s NeedRefresh is false.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_004 start";

    std::vector<int64_t> formIds;
    int64_t formId = 4;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    // SetNeedRefresh:false
    formHostRecord.SetNeedRefresh(formId, false);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_005
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       clientRecords_ is not include formId.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_005 start";

    std::vector<int64_t> formIds;
    int64_t formId = 5;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    int64_t otherformId = 500;
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(otherformId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_005 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_006
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       flag is false.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_006 start";

    std::vector<int64_t> formIds;
    int64_t formId = 6;
    formIds.emplace_back(formId);

    bool flag = false;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_006 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_007
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords's needRefresh is true.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_007 start";

    std::vector<int64_t> formIds;
    int64_t formId = 7;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    // needRefresh:true
    record.needRefresh = true;
    formDataMgr_.formRecords_.emplace(formId, record);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_007 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateHostFormFlag_008
 * @tc.name: UpdateHostFormFlag
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       formRecords is not include formId.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateHostFormFlag_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_008 start";

    std::vector<int64_t> formIds;
    int64_t formId = 8;
    formIds.emplace_back(formId);

    bool flag = true;

    std::vector<int64_t> refreshForms;

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    // create formRecords
    int64_t otherFormId = 800;
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(otherFormId, formItemInfo);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateHostFormFlag(formIds, token_, flag, false, refreshForms));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateHostFormFlag_008 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetTempFormRecord_001
 * @tc.name: GetTempFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is zero, return false.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetTempFormRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetTempFormRecord_001 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 0;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    std::vector<FormRecord> formInfos;
    EXPECT_EQ(false, formDataMgr_.GetTempFormRecord(formInfos));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetTempFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetTempFormRecord_002
 * @tc.name: GetTempFormRecord
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetTempFormRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetTempFormRecord_002 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 0;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(true);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    std::vector<FormRecord> formInfos;
    EXPECT_EQ(true, formDataMgr_.GetTempFormRecord(formInfos));
    EXPECT_EQ(1, formInfos.size());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetTempFormRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfos_001
 * @tc.name: GetRunningFormInfos
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfos_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfos_001 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "A";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    // create clientRecords_
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.SetHostBundleName(bundleName);
    formHostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);
    std::vector<FormHostRecord> formHostRecords;
    formDataMgr_.GetFormHostRecord(otherFormId, formHostRecords);
    std::string hostBundleName = formHostRecords.begin()->GetHostBundleName();
    EXPECT_EQ(bundleName, hostBundleName);
    EXPECT_EQ(1, formHostRecords.size());

    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_EQ(1, formDataMgr_.clientRecords_.size());
    bool isUnusedInclude = false;
    int32_t userId = 100;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRunningFormInfos(isUnusedInclude, runningFormInfos, userId));
    EXPECT_EQ(1, runningFormInfos.size());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfos_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfos_002
 * @tc.name: GetRunningFormInfos
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfos_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfos_002 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "A";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int32_t userId = 100;
    EXPECT_EQ(0, formDataMgr_.GetRunningFormInfos(isUnusedInclude, runningFormInfos, userId));
    EXPECT_EQ(0, runningFormInfos.size());

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfos_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfosByBundleName_001
 * @tc.name: GetRunningFormInfosByBundleName
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfosByBundleName_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_001 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "A";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.SetHostBundleName(bundleName);
    formHostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    EXPECT_EQ(0, runningFormInfos.size());
    int32_t userId = 100;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude,
        runningFormInfos, userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfosByBundleName_002
 * @tc.name: GetRunningFormInfosByBundleName
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfosByBundleName_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_002 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    MockGetBundleNameByUid(ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "A";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    EXPECT_EQ(0, runningFormInfos.size());
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,
        formDataMgr_.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos, userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfosByBundleName_003
 * @tc.name: GetRunningFormInfosByBundleName
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfosByBundleName_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_003 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    MockGetBundleNameByUid(ERR_OK);
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int32_t userId = 100;
    EXPECT_EQ(0, runningFormInfos.size());
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formDataMgr_.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos, userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRunningFormInfosByBundleName_004
 * @tc.name: GetRunningFormInfosByBundleName
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *       If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRunningFormInfosByBundleName_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_004 start";
    // Clean all formRecords
    formDataMgr_.formRecords_.clear();
    // create formRecord
    int64_t otherFormId = 800;
    int callingUid = 20000;
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "A";
    formItemInfo.SetHostBundleName(bundleName);
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    GTEST_LOG_(INFO) << "providerUserId = " << record.providerUserId;
    GTEST_LOG_(INFO) << "formTempFlag = " << record.formTempFlag;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formHostRecord.SetHostBundleName(bundleName);
    formHostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int32_t userId = 100;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos,
        userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRunningFormInfosByBundleName_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetConfigParamFormMap_001
 * @tc.name: GetConfigParamFormMap
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: If formConfigMap_ is empty.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetConfigParamFormMap_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_001 start";
    // create formRecord
    std::map<std::string, int32_t> configMap;
    formDataMgr_.SetConfigMap(configMap);
    const std::string key = "a";
    int32_t value = 0;
    formDataMgr_.GetConfigParamFormMap(key, value);
    EXPECT_EQ(configMap.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetConfigParamFormMap_002
 * @tc.name: GetConfigParamFormMap
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: If the value corresponding to the key is not found in the map.

 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetConfigParamFormMap_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_002 start";
    // create formRecord
    std::map<std::string, int32_t> configMap;
    std::string key = "a";
    std::string notFindkey = "b";
    int32_t value1 = 3;
    int32_t value2 = 0;
    configMap.emplace(key, value1);
    formDataMgr_.SetConfigMap(configMap);
    formDataMgr_.GetConfigParamFormMap(notFindkey, value2);
    EXPECT_NE(value1, value2);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetConfigParamFormMap_003
 * @tc.name: GetConfigParamFormMap
 * @tc.desc: Verify that the return value is correct.
 * @tc.details: If the value corresponding to the key is found in the map.

 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetConfigParamFormMap_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_003 start";
    // create formRecord
    std::map<std::string, int32_t> configMap;
    std::string key = "a";
    int32_t value1 = 3;
    int32_t value2 = 0;
    configMap.emplace(key, value1);
    formDataMgr_.SetConfigMap(configMap);
    formDataMgr_.GetConfigParamFormMap(key, value2);
    EXPECT_EQ(value1, value2);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetConfigParamFormMap_003 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetUnusedFormInstancesByFilter_0100
 * @tc.desc: Test GetUnusedFormInstancesByFilter by the size of formInstances.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUnusedFormInstancesByFilter_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUnusedFormInstancesByFilter_0100 start";
    FormDBInfo formDbInfo;
    formDbInfo.formId = FORM_ID_ONE;
    formDbInfo.formUserUids.emplace_back(0);
    formDbInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    FormDbCache::GetInstance().formDBInfos_.emplace_back(formDbInfo);
    MockGetBundleNameByUid(ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    MockGetAllFormInfo(0);
    FormInstancesFilter formInstancesFilter;
    formInstancesFilter.bundleName = FORM_HOST_BUNDLE_NAME;
    std::vector<FormInstance> formInstances;
    formDataMgr_.GetUnusedFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(formInstances.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUnusedFormInstancesByFilter_0100 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstancesByFilter_0100
 * @tc.desc: Test GetFormInstancesByFilter by bundleName of formInstancesFilter empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0100 start";
    FormInstancesFilter formInstancesFilter;
    formInstancesFilter.bundleName = "";
    std::vector<FormInstance> formInstances;
    auto res = formDataMgr_.GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(res, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0100 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstancesByFilter_0200
 * @tc.desc: Test GetFormInstancesByFilter by the size of formInstances.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0200 start";
    FormRecord formRecord;
    formRecord.bundleName = FORM_HOST_BUNDLE_NAME;
    formRecord.formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.emplace(1, formRecord);
    FormHostRecord formHostRecord;
    formHostRecord.AddForm(1);
    formDataMgr_.clientRecords_.push_back(formHostRecord);
    FormInstancesFilter formInstancesFilter;
    formInstancesFilter.bundleName = FORM_HOST_BUNDLE_NAME;
    formInstancesFilter.isUnusedIncluded = false;
    std::vector<FormInstance> formInstances;
    auto res = formDataMgr_.GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_NE(formInstances.size(), 0);
    EXPECT_EQ(res, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0200 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstancesByFilter_0300
 * @tc.desc: Test GetFormInstancesByFilter by the size of formInstances.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0300 start";
    FormRecord formRecord;
    formRecord.bundleName = FORM_BUNDLE_NAME;
    formRecord.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formDataMgr_.formRecords_.clear();
    formDataMgr_.formRecords_.emplace(FORM_ID_ONE, formRecord);
    FormInstancesFilter formInstancesFilter;
    formInstancesFilter.bundleName = FORM_HOST_BUNDLE_NAME;
    formInstancesFilter.isUnusedIncluded = false;
    formInstancesFilter.moduleName = PARAM_PROVIDER_MODULE_NAME;
    std::vector<FormInstance> formInstances;
    auto res = formDataMgr_.GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(formInstances.size(), 0);
    EXPECT_EQ(res, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0300 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstanceById_0100
 * @tc.desc: Test GetFormInstancesByFilter by the price of formId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0100 start";
    int64_t formId = FORM_ID_ZERO;
    bool isUnusedInclude = false;
    FormInstance formInstance;
    auto ret = formDataMgr_.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0100 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstanceById_0200
 * @tc.desc: Test GetFormInstancesByFilter by the price of formUsageState.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0200 start";
    int64_t formId = FORM_ID_ONE;
    FormRecord formRecord;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    FormHostRecord formHostRecord;
    formHostRecord.AddForm(formId);
    formDataMgr_.clientRecords_.push_back(formHostRecord);
    bool isUnusedInclude = false;
    FormInstance formInstance;
    auto res = formDataMgr_.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(formInstance.formUsageState, FormUsageState::USED);
    EXPECT_EQ(res, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0200 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstanceById_0300
 * @tc.desc: Verify that the return value when all condition inconformity.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0300 start";
    formDataMgr_.formRecords_.clear();
    int64_t formId = FORM_ID_ONE;
    bool isUnusedInclude = false;
    FormInstance formInstance;
    auto res = formDataMgr_.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(res, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0300 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_GetFormInstanceById_0400
 * @tc.desc: Verify that the return value when formUserUids is empty and isUnusedIncluded is ture.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0400 start";
    formDataMgr_.clientRecords_.clear();
    EXPECT_EQ(FormDbCache::GetInstance().formDBInfos_.size(), 0);
    FormDBInfo formDbInfo;
    formDbInfo.formId = FORM_ID_ONE;
    FormDbCache::GetInstance().formDBInfos_.emplace_back(formDbInfo);
    int64_t formId = FORM_ID_ONE;
    bool isUnusedInclude = true;
    FormInstance formInstance;
    auto res = formDataMgr_.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(res, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_0400 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetUnusedFormInfos_0100
 * @tc.desc: Verify that the runningFormInfos size.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUnusedFormInfos_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUnusedFormInfos_0100 start";
    FormDBInfo formDbInfo;
    formDbInfo.formId = 1;
    formDbInfo.formUserUids.emplace_back(FORM_USER_UIDS_ZERO);
    FormDbCache::GetInstance().formDBInfos_.emplace_back(formDbInfo);
    MockGetBundleNameByUid(ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    MockGetAllFormInfo(0);
    std::vector<RunningFormInfo> runningFormInfos;
    formDataMgr_.GetUnusedFormInfos(runningFormInfos);
    EXPECT_EQ(runningFormInfos.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUnusedFormInfos_0100 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_001
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_001 start";
    formDataMgr_.formRecords_.clear();
    FormInstancesFilter instancesFilter;
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_002
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_002 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_003
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_003 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(instancesFilter.bundleName);
    formItemInfo.SetHostBundleName(instancesFilter.bundleName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_004
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_004 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.demo";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_005
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_005 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetHostBundleName(bundleName);
    formItemInfo.SetProviderBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "entry";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_005 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_006
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_006 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "entry";
    instancesFilter.abilityName = "MainAbility";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_006 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_007
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_007 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "entry";
    instancesFilter.abilityName = "MainAbility";
    instancesFilter.formName = "FormAbility";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_007 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_008
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_008 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "testEntry";
    instancesFilter.abilityName = "MainAbility";
    instancesFilter.formName = "FormAbility";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_008 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_009
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_009 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "entry";
    instancesFilter.abilityName = "EntryAbility";
    instancesFilter.formName = "FormAbility";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_009 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstancesByFilter_0010
 * @tc.name: GetFormInstancesByFilter
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesByFilter_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0010 start";
    // create formRecord
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    record.formId = otherFormId;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    instancesFilter.bundleName = "com.example.text";
    instancesFilter.moduleName = "entry";
    instancesFilter.abilityName = "EntryAbility";
    instancesFilter.formName = "TestFormAbility";
    std::vector<FormInstance> formInstances;
    auto ret = formDataMgr_.GetFormInstancesByFilter(instancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstancesByFilter_0010 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstanceById_001
 * @tc.name: GetFormInstanceById
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesById_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_001 start";
    FormInstancesFilter instancesFilter;
    int64_t invalidFormId = -1;
    FormInstance formInstance;
    auto ret = formDataMgr_.GetFormInstanceById(invalidFormId, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstanceById_002
 * @tc.name: GetFormInstanceById
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_002 start";
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    hostRecord.AddForm(otherFormId);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    int64_t formId = 800;
    FormInstance formInstance;
    auto ret = formDataMgr_.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstanceById_003
 * @tc.name: GetFormInstanceById
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstancesById_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_003 start";
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    formDataMgr_.formRecords_.emplace(otherFormId, record);
    FormHostRecord hostRecord;
    hostRecord.AddForm(otherFormId);
    formDataMgr_.CreateHostRecord(formItemInfo, token_, 1000, hostRecord);
    formDataMgr_.clientRecords_.emplace_back(hostRecord);

    FormInstancesFilter instancesFilter;
    int64_t formId = 100;
    FormInstance formInstance;
    auto ret = formDataMgr_.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormInstanceById_004
 * @tc.name: GetFormInstanceById
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      If temp form count is greater than zero, return true, and the count is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormInstanceById_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_004 start";
    formDataMgr_.formRecords_.clear();
    FormItemInfo formItemInfo;
    formItemInfo.SetTemporaryFlag(false);
    std::string bundleName = "com.example.text";
    formItemInfo.SetProviderBundleName(bundleName);
    formItemInfo.SetHostBundleName(bundleName);
    std::string moduleName = "entry";
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName = "MainAbility";
    formItemInfo.SetAbilityName(abilityName);
    std::string formName = "FormAbility";
    formItemInfo.SetFormName(formName);
    int callingUid = 100;
    FormRecord record = formDataMgr_.CreateFormRecord(formItemInfo, callingUid);
    int64_t otherFormId = 800;
    formDataMgr_.formRecords_.emplace(otherFormId, record);

    FormInstancesFilter instancesFilter;
    int64_t formId = 800;
    FormInstance formInstance;
    auto ret = formDataMgr_.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormInstanceById_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_001
 * @tc.name: UpdateFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Add an element to an empty map, and add success.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_001 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    int expectDuration = formDataMgr_.GetFormCloudUpdateDuration(bundleName);
    EXPECT_EQ(expectDuration, duration);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_002
 * @tc.name: UpdateFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Add an existing element to a map, and the previous element was replaced.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_002 start";
    std::string bundleName = "bundleName";
    int duration = 0;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    duration = 1;
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    int expectDuration = formDataMgr_.GetFormCloudUpdateDuration(bundleName);
    EXPECT_EQ(expectDuration, duration);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormCloudUpdateDuration_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_001
 * @tc.name: RemoveFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Remove an element from the map, and remove success.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_001 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    EXPECT_EQ(formDataMgr_.formCloudUpdateDurationMap_.size(), 1);
    formDataMgr_.RemoveFormCloudUpdateDuration(bundleName);
    EXPECT_EQ(formDataMgr_.formCloudUpdateDurationMap_.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_002
 * @tc.name: RemoveFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Remove a non-existent element from the map, and no operation.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_002 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    EXPECT_EQ(formDataMgr_.formCloudUpdateDurationMap_.size(), 1);
    formDataMgr_.RemoveFormCloudUpdateDuration("");
    EXPECT_EQ(formDataMgr_.formCloudUpdateDurationMap_.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_RemoveFormCloudUpdateDuration_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormCloudUpdateDuration_001
 * @tc.name: GetFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Get an element from the map, and get success.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCloudUpdateDuration_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCloudUpdateDuration_001 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    int expectDuration = formDataMgr_.GetFormCloudUpdateDuration(bundleName);
    EXPECT_EQ(expectDuration, duration);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCloudUpdateDuration_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormCloudUpdateDuration_002
 * @tc.name: GetFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Get a non-existent element from the map, and result is 0.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCloudUpdateDuration_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCloudUpdateDuration_002 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    int expectDuration = formDataMgr_.GetFormCloudUpdateDuration("");
    EXPECT_EQ(expectDuration, 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCloudUpdateDuration_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HasFormCloudUpdateDuration_001
 * @tc.name: HasFormCloudUpdateDuration
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HasFormCloudUpdateDuration_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormCloudUpdateDuration_001 start";
    std::string bundleName = "bundleName";
    int duration = 1;
    formDataMgr_.formCloudUpdateDurationMap_.clear();
    formDataMgr_.UpdateFormCloudUpdateDuration(bundleName, duration);
    bool isHas = formDataMgr_.HasFormCloudUpdateDuration(bundleName);
    EXPECT_TRUE(isHas);
    isHas = formDataMgr_.HasFormCloudUpdateDuration("");
    EXPECT_FALSE(isHas);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HasFormCloudUpdateDuration_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_UpdateFormLocation_001
 * @tc.name: UpdateFormLocation
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormLocation_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormLocation_001 start";
    FormRecord record;
    record.formLocation = Constants::FormLocation::FORM_CENTER;
    int64_t formId = 1;
    int32_t formLocation = 1;
    formDataMgr_.formRecords_.emplace(formId, record);
    EXPECT_EQ(ERR_OK, formDataMgr_.UpdateFormLocation(formId, formLocation));
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormLocation_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetRecordsByFormType_001
 * @tc.name: GetRecordsByFormType
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetRecordsByFormType_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRecordsByFormType_001 start";
    FormRecord record1;
    int64_t formId = 1;
    record1.formBundleType = BundleType::APP;
    record1.formVisibleNotifyState = static_cast<int32_t>(FormVisibilityType::VISIBLE);
    formDataMgr_.formRecords_.emplace(formId, record1);

    FormRecord record2;
    formId = 2;
    record2.formBundleType = BundleType::ATOMIC_SERVICE;
    record2.formVisibleNotifyState = static_cast<int32_t>(FormVisibilityType::VISIBLE);
    formDataMgr_.formRecords_.emplace(formId, record2);

    FormRecord record3;
    formId = 3;
    record3.formBundleType = BundleType::ATOMIC_SERVICE;
    record3.formVisibleNotifyState = static_cast<int32_t>(FormVisibilityType::UNKNOWN);
    formDataMgr_.formRecords_.emplace(formId, record3);

    FormRecord record4;
    formId = 4;
    record4.formBundleType = BundleType::APP;
    record4.formVisibleNotifyState = static_cast<int32_t>(FormVisibilityType::INVISIBLE);
    formDataMgr_.formRecords_.emplace(formId, record4);

    FormRecord record5;
    formId = 5;
    record5.formBundleType = BundleType::ATOMIC_SERVICE;
    record5.formVisibleNotifyState = static_cast<int32_t>(FormVisibilityType::INVISIBLE);
    formDataMgr_.formRecords_.emplace(formId, record5);

    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    std::vector<FormRecord> visibleFormRecords1;
    std::vector<FormRecord> inVisibleFormRecords1;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRecordsByFormType(formRefreshType, visibleFormRecords1, inVisibleFormRecords1));
    EXPECT_EQ(2, visibleFormRecords1.size());
    EXPECT_EQ(3, inVisibleFormRecords1.size());

    formRefreshType = Constants::REFRESH_APP_FORM;
    std::vector<FormRecord> visibleFormRecords2;
    std::vector<FormRecord> inVisibleFormRecords2;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRecordsByFormType(formRefreshType, visibleFormRecords2, inVisibleFormRecords2));
    EXPECT_EQ(1, visibleFormRecords2.size());
    EXPECT_EQ(1, inVisibleFormRecords2.size());

    formRefreshType = Constants::REFRESH_ATOMIC_FORM;
    std::vector<FormRecord> visibleFormRecords3;
    std::vector<FormRecord> inVisibleFormRecords3;
    EXPECT_EQ(ERR_OK, formDataMgr_.GetRecordsByFormType(formRefreshType, visibleFormRecords3, inVisibleFormRecords3));
    EXPECT_EQ(1, visibleFormRecords3.size());
    EXPECT_EQ(2, inVisibleFormRecords3.size());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetRecordsByFormType_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_EnableForms_001
 * @tc.name: EnableForms
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_EnableForms_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_EnableForms_001 start";
    std::vector<FormRecord> formRecords;
    formDataMgr_.EnableForms(std::move(formRecords), true);
    formDataMgr_.EnableForms(std::move(formRecords), false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_EnableForms_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormIdsByUserId_001
 * @tc.name: GetFormIdsByUserId
 * @tc.desc: Verify that get all formIds by userId.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormIdsByUserId_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormIdsByUserId_001 start";
    FormRecord record;
    int64_t formId = 1;
    int formUserUid = 100;
    record.userId = formUserUid;

    formDataMgr_.formRecords_.emplace(formId, record);
    std::vector<int64_t> formIds;
    formDataMgr_.GetFormIdsByUserId(formUserUid, formIds);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormIdsByUserId_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormRecord_001
 * @tc.name: DeleteFormRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_001 start";
    int64_t formId = FORM_ID_ONE;
    bool result = formDataMgr_.DeleteFormRecord(formId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormRecord_002
 * @tc.name: DeleteFormRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_002 start";
    int64_t formId = FORM_ID_ONE;
    int callingUid = 0;
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    bool result = formDataMgr_.DeleteFormRecord(FORM_ID_ONE);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormRecord_003
 * @tc.name: DeleteFormRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_003 start";
    int64_t formId = FORM_ID_ONE;
    int callingUid = 0;
    FormItemInfo form_item_info;
    InitFormItemInfo(formId, form_item_info);
    form_item_info.SetFormLocation(Constants::FormLocation::SCREEN_LOCK);
    FormRecord record = formDataMgr_.AllotFormRecord(form_item_info, callingUid);
    bool result = formDataMgr_.DeleteFormRecord(FORM_ID_ONE);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateHostRecord_001
 * @tc.name: CreateHostRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateHostRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateHostRecord_001 start";
    FormItemInfo info;
    int callingUid = 0;
    FormHostRecord formHostRecord;
    bool result = formDataMgr_.CreateHostRecord(info, nullptr, callingUid, formHostRecord);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateHostRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ExistTempForm_001
 * @tc.name: ExistTempForm
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ExistTempForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ExistTempForm_001 start";
    int64_t formId = FORM_ID_ONE;
    bool result = formDataMgr_.ExistTempForm(formId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ExistTempForm_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsCallingUidValid_001
 * @tc.name: IsCallingUidValid
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsCallingUidValid_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_001 start";
    std::vector<int> formUserUids;
    bool result = formDataMgr_.IsCallingUidValid(formUserUids);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsCallingUidValid_002
 * @tc.name: IsCallingUidValid
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsCallingUidValid_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_002 start";
    std::vector<int> formUserUids;
    formUserUids.emplace_back(IPCSkeleton::GetCallingUid());
    bool result = formDataMgr_.IsCallingUidValid(formUserUids);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsCallingUidValid_003
 * @tc.name: IsCallingUidValid
 * @tc.desc: Verify that the return value is correct..
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsCallingUidValid_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_003 start";
    std::vector<int> formUserUids;
    int nullUserUid = 999;
    formUserUids.emplace_back(nullUserUid);
    bool result = formDataMgr_.IsCallingUidValid(formUserUids);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsCallingUidValid_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ExistFormRecord_001
 * @tc.name: ExistFormRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ExistFormRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ExistFormRecord_001 start";
    int64_t formId = FORM_ID_ONE;
    std::vector<int> formUserUids;
    formUserUids.emplace_back(formId);
    bool result = formDataMgr_.IsCallingUidValid(formUserUids);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ExistFormRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetFormHostRemoteObj_001
 * @tc.name: GetFormHostRemoteObj
 * @tc.desc: Test GetFormHostRemoteObj by the price of formId.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormHostRemoteObj_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRemoteObj_001 start";
    int64_t formId = FORM_ID_ONE;
    int callingUid = 0;
    FormItemInfo formItemInfo;
    InitFormItemInfo(formId, formItemInfo);
    FormHostRecord formHostRecord;
    formHostRecord.SetFormHostClient(token_);
    formDataMgr_.clientRecords_.emplace_back(formHostRecord);
    formDataMgr_.AllotFormHostRecord(formItemInfo, token_, formId, callingUid);
    std::vector<sptr<IRemoteObject>> formHostObjs;
    formDataMgr_.GetFormHostRemoteObj(formId, formHostObjs);
    bool result = formHostObjs.empty();
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormHostRemoteObj_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_HandleHostDiedForTempForms_001
 * @tc.name: HandleHostDiedForTempForms
 * @tc.desc: Get the temp forms from host and delete temp form in cache.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleHostDiedForTempForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDiedForTempForms_001 start";
    int64_t formId = FORM_ID_ONE;
    FormHostRecord record;
    record.forms_[formId] = true;
    std::vector<int64_t> recordTempForms;
    formDataMgr_.tempForms_.emplace_back(formId);
    formDataMgr_.HandleHostDiedForTempForms(record, recordTempForms);
    bool result = formDataMgr_.tempForms_.empty();
    EXPECT_EQ(result, true);
    result = recordTempForms.empty();
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleHostDiedForTempForms_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsEnableUpdate_001
 * @tc.name: IsEnableUpdate
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsEnableUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableUpdate_001 start";
    int64_t formId = FORM_ID_ONE;
    bool result = formDataMgr_.IsEnableUpdate(formId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableUpdate_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsEnableUpdate_002
 * @tc.name: IsEnableUpdate
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsEnableUpdate_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableUpdate_002 start";
    int64_t formId = FORM_ID_ONE;
    FormHostRecord record;
    record.enableUpdateMap_[formId] = true;
    formDataMgr_.clientRecords_.emplace_back(record);
    bool result = formDataMgr_.IsEnableUpdate(formId);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsEnableUpdate_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetUdidHash_001
 * @tc.name: GetUdidHash
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetUdidHash_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUdidHash_001 start";
    int64_t udidHash = 0;
    formDataMgr_.SetUdidHash(udidHash);
    EXPECT_EQ(0, formDataMgr_.udidHash_);
    int64_t result = formDataMgr_.GetUdidHash();
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetUdidHash_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetTimerRefresh_001
 * @tc.name: SetTimerRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetTimerRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetTimerRefresh_001 start";
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.erase(formId);
    formDataMgr_.SetTimerRefresh(formId, true);
    EXPECT_EQ(formDataMgr_.formRecords_.find(formId) == formDataMgr_.formRecords_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetTimerRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetTimerRefresh_002
 * @tc.name: SetTimerRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetTimerRefresh_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetTimerRefresh_002 start";
    FormRecord formRecord;
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.SetTimerRefresh(formId, true);
    auto itFormRecord = formDataMgr_.formRecords_.find(formId);
    EXPECT_EQ(itFormRecord->second.isTimerRefresh, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetTimerRefresh_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearHostDataByUId_001
 * @tc.name: ClearHostDataByUId
 * @tc.desc: Verify that the vector can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearHostDataByUId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearHostDataByUId_001 start";
    FormHostRecord formHostRecord;
    formHostRecord.callerUid_ = 1;
    formDataMgr_.clientRecords_.emplace_back(formHostRecord);
    formDataMgr_.ClearHostDataByUId(formHostRecord.callerUid_);
    bool result = true;
    for (auto itHostRecord : formDataMgr_.clientRecords_) {
        if (itHostRecord.GetCallerUid() == formHostRecord.callerUid_) {
            result = false;
        }
    }
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearHostDataByUId_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetNoHostTempForms_001
 * @tc.name: GetNoHostTempForms
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetNoHostTempForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_001 start";
    FormRecord formRecord;
    formRecord.formId = FORM_ID_ZERO;
    formRecord.formTempFlag = false;
    int64_t formRecordKey1 = FORM_ID_ZERO;
    formDataMgr_.formRecords_.emplace(formRecordKey1, formRecord);
    int64_t formRecordKey2 = FORM_ID_ONE;
    FormRecord record;
    record.formId = FORM_ID_ONE;
    record.formTempFlag = true;
    formDataMgr_.formRecords_.emplace(formRecordKey2, record);
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    int uid = FORM_USER_UIDS_ZERO;
    formDataMgr_.GetNoHostTempForms(uid, noHostTempFormsMap, foundFormsMap);
    EXPECT_EQ(foundFormsMap.find(formRecordKey1), foundFormsMap.end());
    EXPECT_NE(foundFormsMap.find(formRecordKey2), foundFormsMap.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetNoHostTempForms_002
 * @tc.name: GetNoHostTempForms
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetNoHostTempForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_002 start";
    int64_t formRecordKey = FORM_ID_ONE;
    FormRecord record;
    record.formId = FORM_ID_ONE;
    record.formTempFlag = true;
    record.formUserUids.push_back(FORM_USER_UIDS_ZERO);
    record.abilityName = "testAbility";
    record.bundleName = "testBundle";
    formDataMgr_.formRecords_.emplace(formRecordKey, record);
    FormIdKey formIdKey(record.bundleName, record.abilityName);
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    std::set<int64_t> vector;
    noHostTempFormsMap.emplace(formIdKey, vector);
    int uid = FORM_USER_UIDS_ZERO;
    formDataMgr_.GetNoHostTempForms(uid, noHostTempFormsMap, foundFormsMap);
    auto iter = noHostTempFormsMap.find(formIdKey);
    EXPECT_NE(iter->second.find(record.formId), iter->second.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_GetNoHostTempForms_003
 * @tc.name: GetNoHostTempForms
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetNoHostTempForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_003 start";
    formDataMgr_.formRecords_.clear();
    int64_t formRecordKey = FORM_ID_ONE;
    FormRecord record;
    record.formId = FORM_ID_ONE;
    record.formTempFlag = true;
    record.formUserUids.push_back(FORM_USER_UIDS_ZERO);
    record.abilityName = "testAbility2";
    record.bundleName = "testBundle2";
    formDataMgr_.formRecords_.emplace(formRecordKey, record);
    FormIdKey formIdKey(record.bundleName, record.abilityName);
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    int uid = FORM_USER_UIDS_ZERO;
    formDataMgr_.GetNoHostTempForms(uid, noHostTempFormsMap, foundFormsMap);
    auto iter = noHostTempFormsMap.find(formIdKey);
    EXPECT_NE(iter->second.find(record.formId), iter->second.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetNoHostTempForms_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseUpdateConfig_001
 * @tc.name: ParseUpdateConfig
 * @tc.desc: test ParseUpdateConfig function and updateDuration greater than zero.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseUpdateConfig_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseUpdateConfig_001 start";
    FormRecord record;
    FormItemInfo info;
    info.SetUpdateDuration(Constants::MIN_CONFIG_DURATION);
    formDataMgr_.ParseUpdateConfig(record, info);
    EXPECT_EQ(Constants::MIN_PERIOD, record.updateDuration);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseUpdateConfig_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseUpdateConfig_002
 * @tc.name: ParseUpdateConfig
 * @tc.desc: test ParseUpdateConfig function and updateDuration Not greater than zero.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseUpdateConfig_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseUpdateConfig_002 start";
    FormRecord record;
    FormItemInfo info;
    std::string scheduledUpdateTime = "10:30";
    info.SetScheduledUpdateTime(scheduledUpdateTime);
    info.updateDuration_ = 0;
    formDataMgr_.ParseUpdateConfig(record, info);
    EXPECT_EQ(record.updateAtHour, 10);
    EXPECT_EQ(record.updateAtMin, 30);
    EXPECT_EQ(record.isEnableUpdate, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseUpdateConfig_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseIntervalConfig_001
 * @tc.name: ParseIntervalConfig
 * @tc.desc: test ParseIntervalConfig function and configDuration Greater than MAX CONFIG DURATION.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseIntervalConfig_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseIntervalConfig_001 start";
    FormRecord record;
    int configDuration = 340;
    formDataMgr_.ParseIntervalConfig(record, configDuration);
    EXPECT_EQ(record.updateDuration, Constants::MAX_PERIOD);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseIntervalConfig_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseIntervalConfig_002
 * @tc.name: ParseIntervalConfig
 * @tc.desc: test ParseIntervalConfig function.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseIntervalConfig_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseIntervalConfig_002 start";
    FormRecord record;
    int configDuration = 20;
    formDataMgr_.ParseIntervalConfig(record, configDuration);
    EXPECT_EQ(record.updateDuration, configDuration * Constants::TIME_CONVERSION);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseIntervalConfig_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseAtTimerConfig_001
 * @tc.name: ParseAtTimerConfig
 * @tc.desc: test ParseIntervalConfig function and scheduledUpdateTime_ is empty.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseAtTimerConfig_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_001 start";
    FormRecord record;
    FormItemInfo info;
    formDataMgr_.ParseAtTimerConfig(record, info);
    EXPECT_EQ(record.isEnableUpdate, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseAtTimerConfig_002
 * @tc.name: ParseAtTimerConfig
 * @tc.desc: test ParseIntervalConfig function and scheduledUpdateTime string split size greater than 2.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseAtTimerConfig_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_002 start";
    FormRecord record;
    FormItemInfo info;
    std::string scheduledUpdateTime = "10:30:20";
    info.SetScheduledUpdateTime(scheduledUpdateTime);
    formDataMgr_.ParseAtTimerConfig(record, info);
    EXPECT_EQ(record.isEnableUpdate, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ParseAtTimerConfig_003
 * @tc.name: ParseAtTimerConfig
 * @tc.desc: test ParseIntervalConfig function and hour greater than 59.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ParseAtTimerConfig_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_003 start";
    FormRecord record;
    FormItemInfo info;
    std::string scheduledUpdateTime = "62:30";
    info.SetScheduledUpdateTime(scheduledUpdateTime);
    formDataMgr_.ParseAtTimerConfig(record, info);
    EXPECT_EQ(record.isEnableUpdate, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ParseAtTimerConfig_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsFormCached_001
 * @tc.name: IsFormCached
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsFormCached_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsFormCached_001 start";
    FormRecord record;
    record.versionUpgrade = true;
    bool result = formDataMgr_.IsFormCached(record);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsFormCached_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_IsFormCached_002
 * @tc.name: IsFormCached
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_IsFormCached_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsFormCached_002 start";
    FormRecord record;
    record.versionUpgrade = false;
    bool result = formDataMgr_.IsFormCached(record);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_IsFormCached_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormStateRecord_001
 * @tc.name: CreateFormStateRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormStateRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_001 start";
    std::string provider;
    FormItemInfo info;
    int callingUid = 0;
    bool result = formDataMgr_.CreateFormStateRecord(provider, info, nullptr, callingUid);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormStateRecord_002
 * @tc.name: CreateFormStateRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormStateRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_002 start";
    std::string provider = FORM_PROVIDER_ABILITY_NAME;
    FormItemInfo info;
    int callingUid = 0;
    FormHostRecord formHostRecord;
    bool result = formDataMgr_.CreateFormStateRecord(provider, info, token_, callingUid);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormStateRecord_003
 * @tc.name: CreateFormStateRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormStateRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_003 start";
    std::string provider = FORM_PROVIDER_ABILITY_NAME;
    FormItemInfo info;
    int callingUid = 0;
    FormHostRecord formHostRecord;
    formDataMgr_.formStateRecord_.emplace(provider, formHostRecord);
    bool result = formDataMgr_.CreateFormStateRecord(provider, info, nullptr, callingUid);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormStateRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormAcquireDataRecord_001
 * @tc.name: CreateFormAcquireDataRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormAcquireDataRecord_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_001 start";
    int64_t requestCode = 0;
    FormItemInfo info;
    int callingUid = 0;
    bool result = formDataMgr_.CreateFormAcquireDataRecord(requestCode, info, nullptr, callingUid);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormAcquireDataRecord_002
 * @tc.name: CreateFormAcquireDataRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormAcquireDataRecord_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_002 start";
    int64_t requestCode = 0;
    FormItemInfo info;
    int callingUid = 0;
    FormHostRecord formHostRecord;
    bool result = formDataMgr_.CreateFormAcquireDataRecord(requestCode, info, token_, callingUid);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_CreateFormAcquireDataRecord_003
 * @tc.name: CreateFormAcquireDataRecord
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_CreateFormAcquireDataRecord_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_003 start";
    int64_t requestCode = 0;
    FormItemInfo info;
    int callingUid = 0;
    FormHostRecord formHostRecord;
    formDataMgr_.formAcquireDataRecord_.emplace(requestCode, formHostRecord);
    bool result = formDataMgr_.CreateFormAcquireDataRecord(requestCode, info, nullptr, callingUid);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_CreateFormAcquireDataRecord_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AcquireFormDataBack_001
 * @tc.name: AcquireFormDataBack
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AcquireFormDataBack_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormDataBack_001 start";
    AAFwk::WantParams wantParams;
    int64_t requestCode = 0;
    auto result = formDataMgr_.AcquireFormDataBack(wantParams, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormDataBack_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AcquireFormDataBack_002
 * @tc.name: AcquireFormDataBack
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AcquireFormDataBack_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormDataBack_002 start";
    AAFwk::WantParams wantParams;
    int64_t requestCode = 0;
    FormHostRecord formHostRecord;
    formDataMgr_.formAcquireDataRecord_.emplace(requestCode, formHostRecord);
    auto result = formDataMgr_.AcquireFormDataBack(wantParams, requestCode);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormDataBack_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AcquireFormStateBack_001
 * @tc.name: AcquireFormStateBack
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AcquireFormStateBack_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormStateBack_001 start";
    AppExecFwk::FormState state = FormState::READY;
    std::string provider;
    Want want;
    auto result = formDataMgr_.AcquireFormStateBack(state, provider, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormStateBack_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_AcquireFormStateBack_002
 * @tc.name: AcquireFormStateBack
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_AcquireFormStateBack_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormStateBack_002 start";
    AppExecFwk::FormState state = AppExecFwk::FormState::READY;
    std::string provider = FORM_PROVIDER_ABILITY_NAME;
    FormHostRecord formHostRecord;
    formDataMgr_.formStateRecord_.emplace(provider, formHostRecord);
    Want want;
    auto result = formDataMgr_.AcquireFormStateBack(state, provider, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_AcquireFormStateBack_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_NotifyFormsVisible_001
 * @tc.name: NotifyFormsVisible
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_NotifyFormsVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_NotifyFormsVisible_001 start";
    std::vector<int64_t> formIds;
    bool isVisible;
    int32_t userId = 100;
    auto result = formDataMgr_.NotifyFormsVisible(formIds, true, nullptr, userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_NotifyFormsVisible_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_NotifyFormsVisible_002
 * @tc.name: NotifyFormsVisible
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_NotifyFormsVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_NotifyFormsVisible_002 start";
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID_ZERO);
    FormHostRecord record;
    formDataMgr_.clientRecords_.emplace_back(record);
    int32_t userId = 100;
    auto result = formDataMgr_.NotifyFormsVisible(formIds, true, token_, userId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_NotifyFormsVisible_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetRecordVisible_001
 * @tc.name: SetRecordVisible
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetRecordVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetRecordVisible_001 start";
    int64_t matchedFormId = FORM_ID_ZERO;
    auto result = formDataMgr_.SetRecordVisible(matchedFormId, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetRecordVisible_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetRecordVisible_002
 * @tc.name: SetRecordVisible
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetRecordVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetRecordVisible_002 start";
    int64_t matchedFormId = FORM_ID_ZERO;
    FormRecord formRecord;
    formDataMgr_.formRecords_.emplace(matchedFormId, formRecord);
    auto result = formDataMgr_.SetRecordVisible(matchedFormId, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetRecordVisible_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteFormsByUserId_001
 * @tc.name: DeleteFormsByUserId
 * @tc.desc: Verify that the vector can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteFormsByUserId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormsByUserId_001 start";
    int64_t usrId = FORM_ID_ONE;
    FormRecord formRecord;
    formRecord.formTempFlag = true;
    formRecord.providerUserId = FORM_ID_ONE;
    formRecord.formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.emplace(usrId, formRecord);
    std::vector<int64_t> removedFormIds;
    formDataMgr_.DeleteFormsByUserId(usrId, removedFormIds);
    EXPECT_NE(std::find(removedFormIds.begin(), removedFormIds.end(), formRecord.formId), removedFormIds.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteFormsByUserId_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearFormRecords_001
 * @tc.name: ClearFormRecords
 * @tc.desc: Verify that the vector and map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearFormRecords_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearFormRecords_001 start";
    int64_t formId = FORM_ID_ONE;
    FormRecord formRecord;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.tempForms_.emplace_back(formId);
    EXPECT_EQ(formDataMgr_.formRecords_.empty(), false);
    EXPECT_EQ(formDataMgr_.tempForms_.empty(), false);
    formDataMgr_.ClearFormRecords();
    EXPECT_EQ(formDataMgr_.formRecords_.empty(), true);
    EXPECT_EQ(formDataMgr_.tempForms_.empty(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearFormRecords_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteInvalidTempForms_001
 * @tc.name: DeleteInvalidTempForms
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteInvalidTempForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteInvalidTempForms_001 start";
    int32_t userId = 1;
    int32_t callingUid = 0;
    std::set<int64_t> matchedFormIds;
    std::map<int64_t, bool> removedFormsMap;
    auto result = formDataMgr_.DeleteInvalidTempForms(userId, callingUid, matchedFormIds, removedFormsMap);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteInvalidTempForms_001 end";
}

/**
* @tc.number: FmsFormDataMgrTest_GetFormCanUpdate_001
* @tc.name: GetFormCanUpdate
* @tc.desc: Verify that the return value is correct.
* @tc.details: If the value corresponding to the key is not found in the map.

*/
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCanUpdate_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_001 start";
    int64_t formId = FORM_ID_ZERO;
    formDataMgr_.DeleteFormVisible(formId);
    bool value = formDataMgr_.GetFormCanUpdate(formId);
    EXPECT_EQ(value, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_001 end";
}

/**
* @tc.number: FmsFormDataMgrTest_GetFormCanUpdate_002
* @tc.name: GetFormCanUpdate
* @tc.desc: Verify that the return value is correct.
* @tc.details: If the value corresponding to the key is found in the map.
*/
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCanUpdate_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_002 start";
    int64_t formId = FORM_ID_ZERO;
    formDataMgr_.SetFormVisible(formId, true);
    bool value = formDataMgr_.GetFormCanUpdate(formId);
    EXPECT_EQ(value, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetHostRefresh_001
 * @tc.name: SetHostRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetHostRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_001 start";
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.erase(formId);
    formDataMgr_.SetHostRefresh(formId, true);
    EXPECT_EQ(formDataMgr_.formRecords_.find(formId) == formDataMgr_.formRecords_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetHostRefresh_002
 * @tc.name: SetHostRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetHostRefresh_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_002 start";
    FormRecord formRecord;
    int64_t formId = FORM_ID_ONE;
    formRecord.formId = formId;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.SetHostRefresh(formId, true);
    auto itFormRecord = formDataMgr_.formRecords_.find(formId);
    EXPECT_EQ(itFormRecord->second.isHostRefresh, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearWantCache_001
 * @tc.name: ClearWantCache
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearWantCache_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_001 start";
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.erase(formId);
    formDataMgr_.ClearWantCache(formId);
    EXPECT_EQ(formDataMgr_.formRecords_.find(formId) == formDataMgr_.formRecords_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearWantCache_002
 * @tc.name: ClearWantCache
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearWantCache_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_002 start";
    Want want;
    FormRecord formRecord;
    int64_t formId = FORM_ID_ONE;
    formRecord.formId = formId;
    formRecord.wantCacheMap[formId] = want;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.ClearWantCache(formId);
    auto itFormRecord = formDataMgr_.formRecords_.find(formId);
    EXPECT_EQ(itFormRecord->second.wantCacheMap.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_001
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_001 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    formDataMgr_.RecycleAllRecyclableForms();

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_001 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_002
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_002 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    Want want;
    std::vector<int64_t> formIds = {formId1};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    formIds = {formId2};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_003
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_003 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    // init record
    int callingUid1 = 100;
    int callingUid2 = 102;
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    std::vector<int32_t> conditionUpdate1 = {1, 2};
    record1.conditionUpdate = conditionUpdate1;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);

    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    RunningFormInfo runningFormInfo;
    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, formId1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, -1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId2), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId1, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId1),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId1), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, -1), ERR_OK);
    EXPECT_TRUE(runningFormInfos.size() > 0);
    runningFormInfos.clear();
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_TRUE(runningFormInfos.size() == 0);

    std::vector<FormRecord> formInfos;
    EXPECT_TRUE(formDataMgr_.GetFormRecordByCondition(2, formInfos));
    EXPECT_TRUE(formInfos.size() > 0);
    formInfos.clear();
    EXPECT_FALSE(formDataMgr_.GetFormRecordByCondition(3, formInfos));
    EXPECT_TRUE(formInfos.size() == 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_004
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_004 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    // init MockFormHostClient token_temp
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_temp = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_temp, callingUid2);
    formHostRecord2.SetFormHostClient(token_temp);
    formHostRecord2.callerUid_ = callingUid2;

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_temp, callingUid3);
    formHostRecord3.AddForm(formId3);
    formHostRecord3.SetFormHostClient(token_temp);
    formHostRecord3.callerUid_ = callingUid3;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId3](const FormHostRecord record) { return record.Contains(formId3); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_005
 * @tc.name: GetNoHostInvalidTempForms
 * @tc.desc: Cover every branch of GetNoHostInvalidTempForms.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_005  start";
    // init formRecord
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUidTemp = 105;
    int formId1 = 1;
    int providerUserId1 = 11;
    int formId2 = 2;
    int providerUserId2 = 12;

    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1, false);
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.providerUserId = providerUserId1;
    formDataMgr_.formRecords_.emplace(formId1, record1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    record2.providerUserId = providerUserId2;
    formDataMgr_.formRecords_.emplace(formId2, record2);

    std::set<int64_t> matchedFormIds = {formId1};
    std::map<int64_t, bool> foundFormsMap{};
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap{};

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid1, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0);

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUidTemp);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0 && foundFormsMap.size() == 1);

    matchedFormIds = {formId2};
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_005 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_006
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_006 start";
    // init formID & callingUid
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    int callingUid4 = 104;
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int formId4 = 4;
    // init MockFormHostClient token_temp
    std::string configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    formItemInfo1.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo1.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    formItemInfo2.SetUpdateDuration(0);
    configAtMultiTime = "00:00:00,00:00";
    formItemInfo2.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    formItemInfo3.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo3.SetMultiScheduledUpdateTime(configAtMultiTime);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    FormRecord record3 = formDataMgr_.CreateFormRecord(formItemInfo3, callingUid3, formId3);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_006 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_007
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_007 start";
    // init formID
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, 100);

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, 102);
    formHostRecord2.callerUid_ = 102;
    formHostRecord2.AddForm(formId2);

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_, 103);
    formHostRecord3.AddForm(formId3);

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    std::vector<int64_t> updateFormIds = {formId2};
    formDataMgr_.UpdateHostForms(updateFormIds);

    std::map<int64_t, bool> removedFormsMap;
    removedFormsMap.emplace(formId3, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    removedFormsMap.emplace(formId2, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_007 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_008
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_008 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLABLE;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    formDataMgr_.RecycleAllRecyclableForms();

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_008 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_009
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_009 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    Want want;
    std::vector<int64_t> formIds = {formId1};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    formIds = {formId2};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_009 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_010
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_010 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    // init record
    int callingUid1 = 100;
    int callingUid2 = 102;
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    std::vector<int32_t> conditionUpdate1 = {1, 2};
    record1.conditionUpdate = conditionUpdate1;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);

    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    RunningFormInfo runningFormInfo;
    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, formId1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, -1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId2), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId1, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId1),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId1), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, -1), ERR_OK);
    EXPECT_TRUE(runningFormInfos.size() > 0);
    runningFormInfos.clear();
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_TRUE(runningFormInfos.size() == 0);

    std::vector<FormRecord> formInfos;
    EXPECT_TRUE(formDataMgr_.GetFormRecordByCondition(2, formInfos));
    EXPECT_TRUE(formInfos.size() > 0);
    formInfos.clear();
    EXPECT_FALSE(formDataMgr_.GetFormRecordByCondition(3, formInfos));
    EXPECT_TRUE(formInfos.size() == 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_010 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_011
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_011 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    // init MockFormHostClient token_temp
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_temp = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_temp, callingUid2);
    formHostRecord2.SetFormHostClient(token_temp);
    formHostRecord2.callerUid_ = callingUid2;

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_temp, callingUid3);
    formHostRecord3.AddForm(formId3);
    formHostRecord3.SetFormHostClient(token_temp);
    formHostRecord3.callerUid_ = callingUid3;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId3](const FormHostRecord record) { return record.Contains(formId3); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_011 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_012
 * @tc.name: GetNoHostInvalidTempForms
 * @tc.desc: Cover every branch of GetNoHostInvalidTempForms.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_012  start";
    // init formRecord
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUidTemp = 105;
    int formId1 = 1;
    int providerUserId1 = 11;
    int formId2 = 2;
    int providerUserId2 = 12;

    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1, false);
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.providerUserId = providerUserId1;
    formDataMgr_.formRecords_.emplace(formId1, record1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    record2.providerUserId = providerUserId2;
    formDataMgr_.formRecords_.emplace(formId2, record2);

    std::set<int64_t> matchedFormIds = {formId1};
    std::map<int64_t, bool> foundFormsMap{};
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap{};

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid1, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0);

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUidTemp);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0 && foundFormsMap.size() == 1);

    matchedFormIds = {formId2};
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_012 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_013
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_013 start";
    // init formID & callingUid
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    int callingUid4 = 104;
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int formId4 = 4;
    // init MockFormHostClient token_temp
    std::string configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    formItemInfo1.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo1.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    formItemInfo2.SetUpdateDuration(0);
    configAtMultiTime = "00:00:00,00:00";
    formItemInfo2.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    formItemInfo3.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo3.SetMultiScheduledUpdateTime(configAtMultiTime);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    FormRecord record3 = formDataMgr_.CreateFormRecord(formItemInfo3, callingUid3, formId3);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_013 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_014
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_014 start";
    // init formID
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, 100);

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, 102);
    formHostRecord2.callerUid_ = 102;
    formHostRecord2.AddForm(formId2);

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_, 103);
    formHostRecord3.AddForm(formId3);

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    std::vector<int64_t> updateFormIds = {formId2};
    formDataMgr_.UpdateHostForms(updateFormIds);

    std::map<int64_t, bool> removedFormsMap;
    removedFormsMap.emplace(formId3, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    removedFormsMap.emplace(formId2, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_014 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_001
 * @tc.desc: Verify PostDelayRecheckWhetherNeedCleanFormHostTask
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_001 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    int callerUid = 1;
    sptr<IRemoteObject> remoteObjectOfHost = new (std::nothrow) MockFormProviderClient();
    formDataMgr->PostDelayRecheckWhetherNeedCleanFormHostTask(callerUid, remoteObjectOfHost);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormAbilityInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_001 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    FormRecord formRecord;
    formRecord.bundleName = "testBundle";
    FormRecord newRecord = formDataMgr->GetFormAbilityInfo(formRecord);
    EXPECT_EQ(formRecord.bundleName, newRecord.bundleName);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormRecordSetIsExistRecycleTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_001 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    int64_t formId = 123;
    bool isExistRecycleTask = true;
    auto result = formDataMgr->UpdateFormRecordSetIsExistRecycleTask(formId, isExistRecycleTask);
    EXPECT_FALSE(result);

    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isExistRecycleTask = isExistRecycleTask;
    formDataMgr->formRecords_.clear();
    formDataMgr->formRecords_.emplace(formId, formRecord);
    result = formDataMgr->UpdateFormRecordSetIsExistRecycleTask(formId, isExistRecycleTask);
    EXPECT_TRUE(result);
    EXPECT_EQ(formDataMgr->formRecords_[formId].isExistRecycleTask, isExistRecycleTask);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_001 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    int64_t formId = FORM_ID_ZERO;
    formDataMgr->SetFormVisible(formId, true);
    bool formIsVisible = formDataMgr->GetFormVisible(FORM_ID_ZERO);
    EXPECT_TRUE(formIsVisible);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_002 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    int64_t formId = FORM_ID_ZERO;
    formDataMgr->SetFormVisible(formId, false);
    bool formIsVisible = formDataMgr->GetFormVisible(FORM_ID_ZERO);
    EXPECT_FALSE(formIsVisible);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_002 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetExpectRecycledStatus_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_001 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord;
    formRecord.formId = FORM_ID_ZERO;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord);
    formDataMgr->SetExpectRecycledStatus(FORM_ID_ZERO, true);
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ZERO));

    formDataMgr->SetExpectRecycledStatus(100, true);
    EXPECT_FALSE(formDataMgr->IsExpectRecycled(100));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetExpectRecycledStatus_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_002 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord0;
    formRecord0.formId = FORM_ID_ZERO;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord0);
    FormRecord formRecord1;
    formRecord1.formId = FORM_ID_ONE;
    formDataMgr->formRecords_.emplace(FORM_ID_ONE, formRecord1);

    formDataMgr->SetExpectRecycledStatus({FORM_ID_ZERO, FORM_ID_ONE}, true);
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ZERO));
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ONE));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearFormRecords_002
 * @tc.name: ClearFormRecords
 * @tc.desc: Verify that the vector and map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearFormRecords_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearFormRecords_002 start";
    int64_t formId = FORM_ID_ONE;
    FormRecord formRecord;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.tempForms_.emplace_back(formId);
    EXPECT_EQ(formDataMgr_.formRecords_.empty(), false);
    EXPECT_EQ(formDataMgr_.tempForms_.empty(), false);
    formDataMgr_.ClearFormRecords();
    EXPECT_EQ(formDataMgr_.formRecords_.empty(), true);
    EXPECT_EQ(formDataMgr_.tempForms_.empty(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearFormRecords_002 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_DeleteInvalidTempForms_002
 * @tc.name: DeleteInvalidTempForms
 * @tc.desc: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_DeleteInvalidTempForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteInvalidTempForms_002 start";
    int32_t userId = 1;
    int32_t callingUid = 0;
    std::set<int64_t> matchedFormIds;
    std::map<int64_t, bool> removedFormsMap;
    auto result = formDataMgr_.DeleteInvalidTempForms(userId, callingUid, matchedFormIds, removedFormsMap);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_DeleteInvalidTempForms_002 end";
}

/**
* @tc.number: FmsFormDataMgrTest_GetFormCanUpdate_003
* @tc.name: GetFormCanUpdate
* @tc.desc: Verify that the return value is correct.
* @tc.details: If the value corresponding to the key is not found in the map.

*/
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCanUpdate_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_003 start";
    int64_t formId = FORM_ID_ZERO;
    formDataMgr_.DeleteFormVisible(formId);
    bool value = formDataMgr_.GetFormCanUpdate(formId);
    EXPECT_EQ(value, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_003 end";
}

/**
* @tc.number: FmsFormDataMgrTest_GetFormCanUpdate_004
* @tc.name: GetFormCanUpdate
* @tc.desc: Verify that the return value is correct.
* @tc.details: If the value corresponding to the key is found in the map.
*/
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormCanUpdate_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_004 start";
    int64_t formId = FORM_ID_ZERO;
    formDataMgr_.SetFormVisible(formId, true);
    bool value = formDataMgr_.GetFormCanUpdate(formId);
    EXPECT_EQ(value, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormCanUpdate_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetHostRefresh_003
 * @tc.name: SetHostRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetHostRefresh_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_003 start";
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.erase(formId);
    formDataMgr_.SetHostRefresh(formId, true);
    EXPECT_EQ(formDataMgr_.formRecords_.find(formId) == formDataMgr_.formRecords_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_SetHostRefresh_004
 * @tc.name: SetHostRefresh
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetHostRefresh_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_004 start";
    FormRecord formRecord;
    int64_t formId = FORM_ID_ONE;
    formRecord.formId = formId;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.SetHostRefresh(formId, true);
    auto itFormRecord = formDataMgr_.formRecords_.find(formId);
    EXPECT_EQ(itFormRecord->second.isHostRefresh, true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetHostRefresh_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearWantCache_003
 * @tc.name: ClearWantCache
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearWantCache_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_003 start";
    int64_t formId = FORM_ID_ONE;
    formDataMgr_.formRecords_.erase(formId);
    formDataMgr_.ClearWantCache(formId);
    EXPECT_EQ(formDataMgr_.formRecords_.find(formId) == formDataMgr_.formRecords_.end(), true);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_003 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_ClearWantCache_004
 * @tc.name: ClearWantCache
 * @tc.desc: Verify that the map can be operated normally.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_ClearWantCache_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_004 start";
    Want want;
    FormRecord formRecord;
    int64_t formId = FORM_ID_ONE;
    formRecord.formId = formId;
    formRecord.wantCacheMap[formId] = want;
    formDataMgr_.formRecords_.emplace(formId, formRecord);
    formDataMgr_.ClearWantCache(formId);
    auto itFormRecord = formDataMgr_.formRecords_.find(formId);
    EXPECT_EQ(itFormRecord->second.wantCacheMap.size(), 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_ClearWantCache_004 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_015
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_015 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    formDataMgr_.RecycleAllRecyclableForms();

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_015 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_016
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_016 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    Want want;
    std::vector<int64_t> formIds = {formId1};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    formIds = {formId2};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_016 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_017
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_017 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    // init record
    int callingUid1 = 100;
    int callingUid2 = 102;
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    std::vector<int32_t> conditionUpdate1 = {1, 2};
    record1.conditionUpdate = conditionUpdate1;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);

    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    RunningFormInfo runningFormInfo;
    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, formId1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, -1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId2), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId1, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId1),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId1), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, -1), ERR_OK);
    EXPECT_TRUE(runningFormInfos.size() > 0);
    runningFormInfos.clear();
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_TRUE(runningFormInfos.size() == 0);

    std::vector<FormRecord> formInfos;
    EXPECT_TRUE(formDataMgr_.GetFormRecordByCondition(2, formInfos));
    EXPECT_TRUE(formInfos.size() > 0);
    formInfos.clear();
    EXPECT_FALSE(formDataMgr_.GetFormRecordByCondition(3, formInfos));
    EXPECT_TRUE(formInfos.size() == 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_017 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_018
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_018 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    // init MockFormHostClient token_temp
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_temp = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_temp, callingUid2);
    formHostRecord2.SetFormHostClient(token_temp);
    formHostRecord2.callerUid_ = callingUid2;

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_temp, callingUid3);
    formHostRecord3.AddForm(formId3);
    formHostRecord3.SetFormHostClient(token_temp);
    formHostRecord3.callerUid_ = callingUid3;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId3](const FormHostRecord record) { return record.Contains(formId3); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_018 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_019
 * @tc.name: GetNoHostInvalidTempForms
 * @tc.desc: Cover every branch of GetNoHostInvalidTempForms.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_019  start";
    // init formRecord
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUidTemp = 105;
    int formId1 = 1;
    int providerUserId1 = 11;
    int formId2 = 2;
    int providerUserId2 = 12;

    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1, false);
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.providerUserId = providerUserId1;
    formDataMgr_.formRecords_.emplace(formId1, record1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    record2.providerUserId = providerUserId2;
    formDataMgr_.formRecords_.emplace(formId2, record2);

    std::set<int64_t> matchedFormIds = {formId1};
    std::map<int64_t, bool> foundFormsMap{};
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap{};

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid1, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0);

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUidTemp);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0 && foundFormsMap.size() == 1);

    matchedFormIds = {formId2};
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_019 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_020
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_020 start";
    // init formID & callingUid
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    int callingUid4 = 104;
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int formId4 = 4;
    // init MockFormHostClient token_temp
    std::string configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    formItemInfo1.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo1.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    formItemInfo2.SetUpdateDuration(0);
    configAtMultiTime = "00:00:00,00:00";
    formItemInfo2.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    formItemInfo3.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo3.SetMultiScheduledUpdateTime(configAtMultiTime);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    FormRecord record3 = formDataMgr_.CreateFormRecord(formItemInfo3, callingUid3, formId3);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_020 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_021
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_021 start";
    // init formID
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, 100);

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, 102);
    formHostRecord2.callerUid_ = 102;
    formHostRecord2.AddForm(formId2);

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_, 103);
    formHostRecord3.AddForm(formId3);

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    std::vector<int64_t> updateFormIds = {formId2};
    formDataMgr_.UpdateHostForms(updateFormIds);

    std::map<int64_t, bool> removedFormsMap;
    removedFormsMap.emplace(formId3, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    removedFormsMap.emplace(formId2, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_021 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_022
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_022 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLABLE;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    formDataMgr_.RecycleAllRecyclableForms();

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_022 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_023
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_023 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int callingUid1 = 100;
    int callingUid2 = 102;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);

    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, callingUid2);
    formHostRecord2.AddForm(formId2);
    formHostRecord2.callerUid_ = callingUid2;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);

    Want want;
    std::vector<int64_t> formIds = {formId1};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    formIds = {formId2};
    formDataMgr_.RecycleForms(formIds, callingUid2, want);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_023 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_024
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_024 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    // init record
    int callingUid1 = 100;
    int callingUid2 = 102;
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    std::vector<int32_t> conditionUpdate1 = {1, 2};
    record1.conditionUpdate = conditionUpdate1;
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);

    formDataMgr_.formRecords_.emplace(formId1, record1);
    formDataMgr_.formRecords_.emplace(formId2, record2);

    RunningFormInfo runningFormInfo;
    std::vector<RunningFormInfo> runningFormInfos;
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, formId1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle1", runningFormInfo, formId1, -1), ERR_OK);
    EXPECT_EQ(runningFormInfo.formId, formId1);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId2), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId1, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfoById("testBundle2", runningFormInfo, formId2, formId1),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId1), ERR_OK);
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, -1), ERR_OK);
    EXPECT_TRUE(runningFormInfos.size() > 0);
    runningFormInfos.clear();
    EXPECT_EQ(formDataMgr_.GetPublishedFormInfos("testBundle1", runningFormInfos, formId2),
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_TRUE(runningFormInfos.size() == 0);

    std::vector<FormRecord> formInfos;
    EXPECT_TRUE(formDataMgr_.GetFormRecordByCondition(2, formInfos));
    EXPECT_TRUE(formInfos.size() > 0);
    formInfos.clear();
    EXPECT_FALSE(formDataMgr_.GetFormRecordByCondition(3, formInfos));
    EXPECT_TRUE(formInfos.size() == 0);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_024 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_025
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_025 start";
    // init formID & callingUid
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    // init MockFormHostClient token_temp
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_temp = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, callingUid1);
    formHostRecord1.AddForm(formId1);
    formHostRecord1.callerUid_ = callingUid1;

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_temp, callingUid2);
    formHostRecord2.SetFormHostClient(token_temp);
    formHostRecord2.callerUid_ = callingUid2;

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_temp, callingUid3);
    formHostRecord3.AddForm(formId3);
    formHostRecord3.SetFormHostClient(token_temp);
    formHostRecord3.callerUid_ = callingUid3;

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    formDataMgr_.RecheckWhetherNeedCleanFormHost(token_temp);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId3](const FormHostRecord record) { return record.Contains(formId3); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_025 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_026
 * @tc.name: GetNoHostInvalidTempForms
 * @tc.desc: Cover every branch of GetNoHostInvalidTempForms.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_026  start";
    // init formRecord
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUidTemp = 105;
    int formId1 = 1;
    int providerUserId1 = 11;
    int formId2 = 2;
    int providerUserId2 = 12;

    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1, false);
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    record1.providerUserId = providerUserId1;
    formDataMgr_.formRecords_.emplace(formId1, record1);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    record2.providerUserId = providerUserId2;
    formDataMgr_.formRecords_.emplace(formId2, record2);

    std::set<int64_t> matchedFormIds = {formId1};
    std::map<int64_t, bool> foundFormsMap{};
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap{};

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid1, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0);

    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() == 0 && noHostTempFormsMap.size() == 1);

    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUid2);
    formDataMgr_.formRecords_[formId2].formUserUids.emplace_back(callingUidTemp);
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    EXPECT_TRUE(formDataMgr_.formRecords_[formId2].formUserUids.size() > 0 && foundFormsMap.size() == 1);

    matchedFormIds = {formId2};
    formDataMgr_.GetNoHostInvalidTempForms(
        providerUserId2, callingUid2, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_026 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_027
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_027 start";
    // init formID & callingUid
    int callingUid1 = 100;
    int callingUid2 = 102;
    int callingUid3 = 103;
    int callingUid4 = 104;
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;
    int formId4 = 4;
    // init MockFormHostClient token_temp
    std::string configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    formItemInfo1.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo1.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    formItemInfo2.SetUpdateDuration(0);
    configAtMultiTime = "00:00:00,00:00";
    formItemInfo2.SetMultiScheduledUpdateTime(configAtMultiTime);

    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    formItemInfo3.SetUpdateDuration(0);
    configAtMultiTime = "00:-1,00:60,-1:00,25:00";
    formItemInfo3.SetMultiScheduledUpdateTime(configAtMultiTime);

    // init record
    FormRecord record1 = formDataMgr_.CreateFormRecord(formItemInfo1, callingUid1, formId1);
    FormRecord record2 = formDataMgr_.CreateFormRecord(formItemInfo2, callingUid2, formId2);
    FormRecord record3 = formDataMgr_.CreateFormRecord(formItemInfo3, callingUid3, formId3);

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_027 end";
}

/**
 * @tc.number: FmsFormDataMgrTest_Coverage_028
 * @tc.name: Coverage
 * @tc.desc: Increase branch coverage.
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_Coverage_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_028 start";
    // init formID
    int formId1 = 1;
    int formId2 = 2;
    int formId3 = 3;

    // init FormItemInfo
    FormItemInfo formItemInfo1;
    InitFormItemInfo(formId1, formItemInfo1);
    FormItemInfo formItemInfo2;
    InitFormItemInfo(formId2, formItemInfo2);
    FormItemInfo formItemInfo3;
    InitFormItemInfo(formId3, formItemInfo3);
    // init clientRecords
    FormHostRecord formHostRecord1;
    formHostRecord1.CreateRecord(formItemInfo1, token_, 100);

    FormHostRecord formHostRecord2;
    formHostRecord2.CreateRecord(formItemInfo2, token_, 102);
    formHostRecord2.callerUid_ = 102;
    formHostRecord2.AddForm(formId2);

    FormHostRecord formHostRecord3;
    formHostRecord3.CreateRecord(formItemInfo3, token_, 103);
    formHostRecord3.AddForm(formId3);

    formDataMgr_.clientRecords_.push_back(formHostRecord1);
    formDataMgr_.clientRecords_.push_back(formHostRecord2);
    formDataMgr_.clientRecords_.push_back(formHostRecord3);

    std::vector<int64_t> updateFormIds = {formId2};
    formDataMgr_.UpdateHostForms(updateFormIds);

    std::map<int64_t, bool> removedFormsMap;
    removedFormsMap.emplace(formId3, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_NE(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    removedFormsMap.emplace(formId2, false);
    formDataMgr_.ClearHostDataByInvalidForms(102, removedFormsMap);
    EXPECT_EQ(
        std::find_if(formDataMgr_.clientRecords_.begin(), formDataMgr_.clientRecords_.end(),
            [formId2](const FormHostRecord record) { return record.Contains(formId2); }),
        formDataMgr_.clientRecords_.end());
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_Coverage_028 end";
}

/**
 * @tc.name: FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_003
 * @tc.desc: Verify PostDelayRecheckWhetherNeedCleanFormHostTask
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_003 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    int callerUid = 1;
    sptr<IRemoteObject> remoteObjectOfHost = new (std::nothrow) MockFormProviderClient();
    formDataMgr->PostDelayRecheckWhetherNeedCleanFormHostTask(callerUid, remoteObjectOfHost);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_PostDelayRecheckWhetherNeedCleanFormHostTask_003 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormAbilityInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_002 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    FormRecord formRecord;
    formRecord.bundleName = "testBundle";
    FormRecord newRecord = formDataMgr->GetFormAbilityInfo(formRecord);
    EXPECT_EQ(formRecord.bundleName, newRecord.bundleName);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormAbilityInfo_002 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_UpdateFormRecordSetIsExistRecycleTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecordSetIsExistRecycleTask_002 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    ASSERT_NE(nullptr, formDataMgr);
    int64_t formId = 123;
    bool isExistRecycleTask = true;
    auto result = formDataMgr->UpdateFormRecordSetIsExistRecycleTask(formId, isExistRecycleTask);
    EXPECT_FALSE(result);

    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isExistRecycleTask = isExistRecycleTask;
    formDataMgr->formRecords_.clear();
    formDataMgr->formRecords_.emplace(formId, formRecord);
    result = formDataMgr->UpdateFormRecordSetIsExistRecycleTask(formId, isExistRecycleTask);
    EXPECT_TRUE(result);
    EXPECT_EQ(formDataMgr->formRecords_[formId].isExistRecycleTask, isExistRecycleTask);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_UpdateFormRecordSetIsExistRecycleTask_002 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormVisible_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_003 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    int64_t formId = FORM_ID_ZERO;
    formDataMgr->SetFormVisible(formId, true);
    bool formIsVisible = formDataMgr->GetFormVisible(FORM_ID_ZERO);
    EXPECT_TRUE(formIsVisible);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_003 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetFormVisible_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_004 start";
    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    int64_t formId = FORM_ID_ZERO;
    formDataMgr->SetFormVisible(formId, false);
    bool formIsVisible = formDataMgr->GetFormVisible(FORM_ID_ZERO);
    EXPECT_FALSE(formIsVisible);
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetFormVisible_004 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetExpectRecycledStatus_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_003 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord;
    formRecord.formId = FORM_ID_ZERO;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord);
    formDataMgr->SetExpectRecycledStatus(FORM_ID_ZERO, true);
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ZERO));

    formDataMgr->SetExpectRecycledStatus(100, true);
    EXPECT_FALSE(formDataMgr->IsExpectRecycled(100));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_003 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_SetExpectRecycledStatus_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_004 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord0;
    formRecord0.formId = FORM_ID_ZERO;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord0);
    FormRecord formRecord1;
    formRecord1.formId = FORM_ID_ONE;
    formDataMgr->formRecords_.emplace(FORM_ID_ONE, formRecord1);

    formDataMgr->SetExpectRecycledStatus({FORM_ID_ZERO, FORM_ID_ONE}, true);
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ZERO));
    EXPECT_TRUE(formDataMgr->IsExpectRecycled(FORM_ID_ONE));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_SetExpectRecycledStatus_004 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetAddfinishAndSetUpdateFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetAddfinishAndSetUpdateFlag_001 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord0;
    formRecord0.formId = FORM_ID_ZERO;
    formRecord0.addFormFinish = false;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord0);
    FormRecord formRecord1;
    formRecord1.formId = FORM_ID_ONE;
    formRecord1.addFormFinish = true;
    formDataMgr->formRecords_.emplace(FORM_ID_ONE, formRecord1);

    formDataMgr->SetExpectRecycledStatus({FORM_ID_ZERO, FORM_ID_ONE}, true);
    EXPECT_FALSE(formDataMgr->GetAddfinishAndSetUpdateFlag(20251230));
    EXPECT_TRUE(formDataMgr->GetAddfinishAndSetUpdateFlag(FORM_ID_ONE));
    EXPECT_FALSE(formDataMgr->GetAddfinishAndSetUpdateFlag(FORM_ID_ZERO));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetAddfinishAndSetUpdateFlag_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_GetIsNeedUpdateOnAddFinish_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetIsNeedUpdateOnAddFinish_001 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord;
    formRecord.formId = FORM_ID_ZERO;
    formRecord.addFormFinish = false;
    formRecord.isNeedUpdateFormOnAddFormFinish = true;
    formDataMgr->formRecords_.emplace(FORM_ID_ZERO, formRecord);
    FormRecord formRecord1;
    EXPECT_FALSE(formDataMgr->GetIsNeedUpdateOnAddFinish(20251230, formRecord1));
    EXPECT_TRUE(formDataMgr->GetIsNeedUpdateOnAddFinish(FORM_ID_ZERO, formRecord1));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_GetIsNeedUpdateOnAddFinish_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleFormAddObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleFormAddObserver_001 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    std::string hostBundleName = "testBundleName";
    int64_t formId = -1;
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formDataMgr->HandleFormAddObserver(hostBundleName, formId, userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleFormAddObserver_001 end";
}

HWTEST_F(FmsFormDataMgrTest, FmsFormDataMgrTest_HandleFormAddObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleFormAddObserver_002 start";

    std::shared_ptr<FormDataMgr> formDataMgr = std::make_shared<FormDataMgr>();
    FormRecord formRecord;
    formRecord.formId = FORM_ID_ONE;
    formRecord.providerUserId = 100;
    FormHostRecord formHostRecord;
    formHostRecord.AddForm(FORM_ID_ONE);
    formDataMgr->clientRecords_.push_back(formHostRecord);
    formDataMgr->formRecords_.emplace(FORM_ID_ONE, formRecord);
    std::string hostBundleName = "testBundleName";
    int32_t userId = 100;
    EXPECT_EQ(ERR_OK, formDataMgr->HandleFormAddObserver(hostBundleName, FORM_ID_ONE, userId));

    GTEST_LOG_(INFO) << "FmsFormDataMgrTest_HandleFormAddObserver_002 end";
}
}
