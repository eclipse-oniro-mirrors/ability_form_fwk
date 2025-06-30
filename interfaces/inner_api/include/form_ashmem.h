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

#ifndef OHOS_FORM_FWK_FORM_ASHMEM_H
#define OHOS_FORM_FWK_FORM_ASHMEM_H

#include "ashmem.h"

namespace OHOS {
namespace AppExecFwk {

enum class TestNum {
    Num1 = 1, Num2, Num3, Num4, Num5,
    Num6, Num7, Num8, Num9, Num10,
    Num11, Num12, Num13, Num14, Num15,
    Num16, Num17, Num18, Num19, Num20,
    Num21, Num22, Num23, Num24, Num25,
    Num26, Num27, Num28, Num29, Num30,
    Num31, Num32, Num33, Num34, Num35,
    Num36, Num37, Num38, Num39, Num40,
};

/**
 * @class FormAshmem
 * Defines form ashmem.
 */
class FormAshmem : public Parcelable {
public:
    FormAshmem() = default;
    ~FormAshmem();

    bool WriteToAshmem(std::string name, char *data, int32_t size);
    int32_t GetAshmemSize();
    int32_t GetAshmemFd();

    virtual bool Marshalling(Parcel &parcel) const override;
    static FormAshmem* Unmarshalling(Parcel &parcel);

    sptr<Ashmem> GetAshmem() const;
    static int TestFormId1(int &formId);
    static int TestFormId2(int &formId);
    static int TestFormId3(int &formId);
    static int TestFormId4(int &formId);
    static int TestFormId5(int &formId);
    static int TestFormId6(int &formId);
    static int TestFormId7(int &formId);
    static int TestFormId8(int &formId);
    static int TestFormId9(int &formId);
    static int TestFormId10(int &formId);
    static int TestFormId11(int &formId);
    static int TestFormId12(int &formId);
    static int TestFormId13(int &formId);
    static int TestFormId14(int &formId);
    static int TestFormId15(int &formId);
private:
    bool ReadFromParcel(Parcel &parcel);

    sptr<Ashmem> ashmem_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_ASHMEM_H
