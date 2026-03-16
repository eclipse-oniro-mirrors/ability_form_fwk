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

#ifndef INNER_MOCK_FORM_MGR_ADAPTER_H
#define INNER_MOCK_FORM_MGR_ADAPTER_H

#include "form_constants.h"
#include "iremote_object.h"
#include "template_form_detail_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

void MockFormMgrAdapterStartAbilityByFms(int mockRet);
void MockFormMgrAdapterRegisterChangeSceneAnimationStateProxy(int mockRet);
void MockFormMgrAdapterRegisterOverflowProxy(int mockRet);
void MockFormMgrAdapterRegisterGetFormRectProxy(int mockRet);
void MockFormMgrAdapterRegisterGetLiveFormStatusProxy(int mockRet);
void MockFormMgrAdapterUnregisterGetLiveFormStatusProxy(int mockRet);
void MockFormMgrAdapterUpdateFormSizeFloat(int mockRet);
void MockFormMgrAdapterRegisterTemplateFormDetailInfoChange(int mockRet);
void MockFormMgrAdapterUnregisterTemplateFormDetailInfoChange(int mockRet);
void MockFormMgrAdapterUpdateTemplateFormDetailInfo(int mockRet);
void MockFormMgrAdapterUnregisterPublishFormCrossBundleControl(int mockRet);
void MockFormMgrAdapterPublishFormCrossBundleControl(bool mockRet);
void MockHasFormVisible(bool mockRet);
void MockEnableForms(int mockRet);

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // INNER_MOCK_FORM_MGR_ADAPTER_H
