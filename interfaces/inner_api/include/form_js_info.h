/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_JS_INFO_H
#define OHOS_FORM_FWK_FORM_JS_INFO_H

#include <string>
#include "form_ashmem.h"
#include "form_constants.h"
#include "form_provider_data.h"
#include "form_info_base.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @struct FormJsInfo
 * Defines form js info.
 */
struct FormJsInfo : public Parcelable {
    static constexpr int IMAGE_DATA_THRESHOLD = 128;
    static constexpr int BIG_DATA = 32 * 1024;
    int64_t formId;
    std::string formName;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;
    std::map<std::string, std::string> modulePkgNameMap;
    bool formTempFlag = false;
    std::string jsFormCodePath;
    std::string formData;
    std::map<std::string, sptr<FormAshmem>> imageDataMap;
    FormProviderData formProviderData;
    std::string formSrc;
    FormWindow formWindow;
    uint32_t versionCode = 0;
    std::string versionName;
    uint32_t compatibleVersion = 0;
    FormType type = FormType::JS;
    FormType uiSyntax = FormType::JS;
    bool isDynamic = true;
    bool transparencyEnabled = false;
    std::string templateFormImperativeFwk = Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NONE;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static FormJsInfo *Unmarshalling(Parcel &parcel);
    bool WriteFormData(Parcel &parcel) const;
    bool WriteObjects(Parcel &parcel) const;
    bool WriteImageData(Parcel &parcel) const;
    void ReadImageData(Parcel &parcel);
    bool ConvertRawImageData();
    bool WritePkgNameMap(Parcel &parcel) const;
    void ReadPkgNameMap(Parcel &parcel);
    FormJsInfo CopyFormJsInfoWithoutFormData() const;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_JS_INFO_H