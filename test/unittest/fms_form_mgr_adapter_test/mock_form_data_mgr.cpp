/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_data_mgr.h"
#include "form_mgr_errors.h"

namespace {
    bool g_mockExistTempFormRet = true;
    bool g_mockExistFormRecordRet = true;
    bool g_mockGetMatchedHostClientRet = true;
    bool g_mockGetFormRecordRet = true;
    bool g_mockDeleteFormRecordRet = true;
    bool g_mockAllotFormHostRecordRet = true;
    bool g_mockGenerateFormIdRet = true;
    bool g_mockGetRequestPublishFormInfoRet = true;
}

void MockExistTempForm(bool mockRet)
{
    g_mockExistTempFormRet = mockRet;
}

void MockExistFormRecord(bool mockRet)
{
    g_mockExistFormRecordRet = mockRet;
}

void MockGetMatchedHostClient(bool mockRet)
{
    g_mockGetMatchedHostClientRet = mockRet;
}

void MockGetFormRecord(bool mockRet)
{
    g_mockGetFormRecordRet = mockRet;
}

void MockDeleteFormRecord(bool mockRet)
{
    g_mockDeleteFormRecordRet = mockRet;
}

void MockAllotFormHostRecord(bool mockRet)
{
    g_mockAllotFormHostRecordRet = mockRet;
}

void MockGenerateFormId(bool mockRet)
{
    g_mockGenerateFormIdRet = mockRet;
}

void MockGetRequestPublishFormInfo(bool mockRet)
{
    g_mockGetRequestPublishFormInfoRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{}

FormDataMgr::~FormDataMgr()
{}

bool FormDataMgr::ExistTempForm(const int64_t formId) const
{
    return g_mockExistTempFormRet;
}

bool FormDataMgr::ExistFormRecord(const int64_t formId) const
{
    return g_mockExistFormRecordRet;
}

bool FormDataMgr::GetMatchedHostClient(const sptr<IRemoteObject> &callerToken, FormHostRecord &formHostRecord) const
{
    return g_mockGetMatchedHostClientRet;
}

bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    return g_mockGetFormRecordRet;
}

bool FormDataMgr::DeleteFormRecord(const int64_t formId)
{
    return g_mockDeleteFormRecordRet;
}

bool FormDataMgr::AllotFormHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const int64_t formId, const int callingUid)
{
    return g_mockAllotFormHostRecordRet;
}

int64_t FormDataMgr::GenerateFormId()
{
    if (true == g_mockGenerateFormIdRet) {
        return -1;
    }
    return 1;
    
}

ErrCode FormDataMgr::GetRequestPublishFormInfo(int64_t formId, Want &want,
                                               std::unique_ptr<FormProviderData> &formProviderData)
{
    if (true == g_mockGetRequestPublishFormInfoRet) {
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
