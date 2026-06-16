/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "forminfomgrthree_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

void CreateFormInfo(FuzzedDataProvider *fdp, FormInfo &formInfo)
{
    formInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.versionCode = fdp->ConsumeIntegral<uint32_t>();
    formInfo.isDynamic = fdp->ConsumeBool();
    formInfo.transparencyEnabled = fdp->ConsumeBool();
}

void CreateFormInfoFilter(FuzzedDataProvider *fdp, FormInfoFilter &filter)
{
    filter.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
}

void TestGetFormsInfoByFilter(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    FormInfoFilter filter;
    CreateFormInfoFilter(fdp, filter);
    
    std::vector<FormInfo> formInfos;
    formInfoMgr.GetFormsInfoByFilter(filter, formInfos);
}

void TestGetFormsInfoByBundle(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    
    std::vector<FormInfo> formInfos;
    formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos, userId);
    
    std::vector<FormInfo> templateFormInfos;
    formInfoMgr.GetTemplateFormsInfoByBundle(bundleName, templateFormInfos, userId);
}

void TestGetTemplateFormsInfoByBundle(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    
    std::vector<FormInfo> formInfos;
    formInfoMgr.GetTemplateFormsInfoByBundle(bundleName, formInfos, userId);
}

void TestGetFormsInfoByRecord(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    FormRecord formRecord;
    formRecord.formId = fdp->ConsumeIntegral<int64_t>();
    formRecord.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formRecord.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formRecord.formTempFlag = fdp->ConsumeBool();
    
    FormInfo formInfo;
    formInfoMgr.GetFormsInfoByRecord(formRecord, formInfo);
}

void TestAddDynamicFormInfo(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    FormInfo formInfo;
    CreateFormInfo(fdp, formInfo);
    
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    formInfoMgr.AddDynamicFormInfo(formInfo, userId);
}

void TestRemoveDynamicFormInfo(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    
    formInfoMgr.RemoveDynamicFormInfo(bundleName, moduleName, formName, userId);
}

void TestRemoveAllDynamicFormsInfo(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    
    formInfoMgr.RemoveAllDynamicFormsInfo(bundleName, userId);
}

void TestReloadFormInfos(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    formInfoMgr.ReloadFormInfos(userId);
}

void TestGetFormsInfoByFilterEdgeCases(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    FormInfoFilter filter;
    filter.bundleName = "";
    filter.moduleName = "";
    
    std::vector<FormInfo> formInfos;
    formInfoMgr.GetFormsInfoByFilter(filter, formInfos);
    
    filter.bundleName = "test_bundle";
    filter.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.GetFormsInfoByFilter(filter, formInfos);
}

void TestGetFormsInfoByBundleEdgeCases(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::vector<FormInfo> formInfos;
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.GetFormsInfoByBundle("", formInfos, 0);
    formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos, -1);
    formInfoMgr.GetFormsInfoByBundle("", formInfos, INT32_MAX);
}

void TestAddDynamicFormInfoEdgeCases(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    FormInfo formInfo;
    CreateFormInfo(fdp, formInfo);
    
    formInfoMgr.AddDynamicFormInfo(formInfo, 0);
    formInfoMgr.AddDynamicFormInfo(formInfo, -1);
    formInfoMgr.AddDynamicFormInfo(formInfo, INT32_MAX);
}

void TestRemoveDynamicFormInfoEdgeCases(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.RemoveDynamicFormInfo("", "", "", 0);
    formInfoMgr.RemoveDynamicFormInfo("bundle", moduleName, "form", 0);
    formInfoMgr.RemoveDynamicFormInfo("bundle", moduleName, "form", -1);
}

void TestRemoveAllDynamicFormsInfoEdgeCases(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.RemoveAllDynamicFormsInfo("", 0);
    formInfoMgr.RemoveAllDynamicFormsInfo("", -1);
    formInfoMgr.RemoveAllDynamicFormsInfo(bundleName, INT32_MAX);
}

void TestReloadFormInfosEdgeCases()
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    
    formInfoMgr.ReloadFormInfos(0);
    formInfoMgr.ReloadFormInfos(-1);
    formInfoMgr.ReloadFormInfos(INT32_MAX);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();

    switch (testType % 16) {
        case 0:
            TestGetFormsInfoByFilter(fdp);
            break;
        case 1:
            TestGetFormsInfoByBundle(fdp);
            break;
        case 2:
            TestGetTemplateFormsInfoByBundle(fdp);
            break;
        case 3:
            TestGetFormsInfoByRecord(fdp);
            break;
        case 4:
            TestAddDynamicFormInfo(fdp);
            break;
        case 5:
            TestRemoveDynamicFormInfo(fdp);
            break;
        case 6:
            TestRemoveAllDynamicFormsInfo(fdp);
            break;
        case 7:
            TestReloadFormInfos(fdp);
            break;
        case 8:
            TestGetFormsInfoByFilterEdgeCases(fdp);
            break;
        case 9:
            TestGetFormsInfoByBundleEdgeCases(fdp);
            break;
        case 10:
            TestAddDynamicFormInfoEdgeCases(fdp);
            break;
        case 11:
            TestRemoveDynamicFormInfoEdgeCases(fdp);
            break;
        case 12:
            TestRemoveAllDynamicFormsInfoEdgeCases(fdp);
            break;
        case 13:
            TestReloadFormInfosEdgeCases();
            break;
        default:
            TestGetFormsInfoByFilter(fdp);
            break;
    }

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
