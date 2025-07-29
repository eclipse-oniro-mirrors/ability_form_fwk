/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { BusinessError, AsyncCallback } from '@ohos.base';
import formBindingData from '@ohos.app.form.formBindingData';
import formInfo from '@ohos.app.form.formInfo';
import Want from '@ohos.app.ability.Want';

export namespace formProvider {

  loadLibrary("formProvider_ani.z");

  native function setFormNextRefreshTime_inner(formId: string, minute: int): void;
  native function updateForm_inner(formId: string, dataObjStr: string, proxies?: Array<formBindingData.ProxyData>): void;
  native function getFormsInfo_inner(filter?: formInfo.FormInfoFilter): Array<formInfo.FormInfo>;
  native function openFormEditAbility_inner(abilityName: string, formId: string, isMainPage: boolean): void;
  native function openFormManager_inner(want: Want): void;
  native function isRequestPublishFormSupported_inner(): boolean;

  const INVALID_PARAM_ERROR_CODE = 401;

  export function setFormNextRefreshTimeReturnsPromise(formId: string, minute: int): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid!')));
      } else if (minute < 0) {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('minute param cannot be negative!')));
      }
      setFormNextRefreshTime_inner(formId, minute);
      resolve(undefined);
    });
  }

  export function setFormNextRefreshTimeWithCallback(formId: string, minute: int,
    callback: AsyncCallback<void>): void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid!')), undefined);
      return;
    } else if (minute < 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('minute param cannot be negative!')), undefined);
      return;
    }
    taskpool.execute(() => setFormNextRefreshTime_inner(formId, minute)).then(() => {
      callback(null, undefined);
    }).catch((e: NullishType) => {
      callback(e as BusinessError, undefined);
    });
  }

  overload setFormNextRefreshTime { setFormNextRefreshTimeReturnsPromise, setFormNextRefreshTimeWithCallback }

  export function updateForm(formId: string, formBindingData: formBindingData.FormBindingData): Promise<void> {
    let dataObjStr: string = JSON.stringify(formBindingData.data);
    return new Promise<void>((resolve, reject) => {
      if(formId == "") {
        return reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid!')));
      }
      updateForm_inner(formId, dataObjStr, formBindingData.proxies);
      resolve(undefined);
    });
  }

  export function updateForm(formId: string, formBindingData: formBindingData.FormBindingData, callback: AsyncCallback<void>): void {
    if(formId == "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid!')), undefined);
      return;
    }
    let dataObjStr: string = JSON.stringify(formBindingData.data);
    taskpool.execute(() => updateForm_inner(formId, dataObjStr, formBindingData.proxies)).then(() => {
      callback(null, undefined);
    }).catch((e: NullishType) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function getFormsInfo(filter: formInfo.FormInfoFilter, callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    taskpool.execute(() => getFormsInfo_inner(filter)).then((e: NullishType) => {
      let infoArr: Array<formInfo.FormInfo> = e as Array<formInfo.FormInfo>;
      callback(null, infoArr);
    }).catch((e: NullishType) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function getFormsInfo(callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    taskpool.execute(() => getFormsInfo_inner()).then((e: NullishType) => {
      let infoArr: Array<formInfo.FormInfo> = e as Array<formInfo.FormInfo>;
      callback(null, infoArr);
    }).catch((e: NullishType) => {
      callback(e as BusinessError, undefined);
    });
  }

  export function getFormsInfo(filter?: formInfo.FormInfoFilter): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>((resolve, reject) => {
      let arr: Array<formInfo.FormInfo> = getFormsInfo_inner(filter);
      resolve(arr);
    });
  }

  export function openFormEditAbility(abilityName: string, formId: string, isMainPage?: boolean): void {
    if(abilityName == "") {
      throw new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('abilityName param invalid!'));
    } else if (formId == "") {
      throw new BusinessError(INVALID_PARAM_ERROR_CODE, new Error('formId param invalid!'));
    }

    if (isMainPage == undefined) {
      isMainPage = true;
    }

    openFormEditAbility_inner(abilityName, formId, isMainPage);
  }

  export function openFormManager(want: Want): void {
    openFormManager_inner(want);
  }

  export function isRequestPublishFormSupported(callback: AsyncCallback<boolean>): void {
    taskpool.execute(() => {
      return isRequestPublishFormSupported_inner();
    }).then((e: NullishType) => {
      callback(new BusinessError, e as boolean);
    });
  }

  export function isRequestPublishFormSupported(): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      let supported = isRequestPublishFormSupported_inner();
      resolve(supported);
    });
  }
}
