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

class FormExtensionAbility {
    onAddForm(want) {
        console.log('FormExtension onAddForm, want:' + want.abilityName);
        return {
            data: ""
        };
    }

    onCastToNormalForm(formId) {
        console.log('FormExtension onCastToNormalForm, formId:' + formId);
    }

    onUpdateForm(formId) {
        console.log('FormExtension onUpdateForm, formId:' + formId);
    }

    onChangeFormVisibility(newStatus) {
        console.log('FormExtension onChangeFormVisibility, newStatus:' + newStatus);
    }

    onFormEvent(formId, message) {
        console.log('FormExtension onFormEvent, formId:' + formId + ", message:" + message);
    }

    onRemoveForm(formId) {
        console.log('FormExtension onRemoveForm, formId:' + formId);
    }

    onConfigurationUpdate(newConfig) {
        console.log('FormExtension onConfigurationUpdate');
    }

    onShareForm(formId) {
        console.log('FormExtension onShareForm, formId:' + formId);
    }
}

export default FormExtensionAbility
