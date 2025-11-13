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
import UIAbilityContext from 'application.UIAbilityContext';

class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => { }

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export namespace formProvider {

  loadLibrary("formProvider_ani.z");

  native function setFormNextRefreshTimeInner(formId: string, minute: int, callback: AsyncCallbackWrapper<void>): void;
  native function updateFormInner(formId: string, dataObjStr: string, callback: AsyncCallbackWrapper<void>, proxies?: Array<formBindingData.ProxyData>): void;
  native function getFormsInfoInner(callback: AsyncCallbackWrapper<Array<formInfo.FormInfo>>, filter?: formInfo.FormInfoFilter): void;
  native function openFormEditAbilityInner(abilityName: string, formId: string, isMainPage: boolean): void;
  native function openFormManagerInner(want: Want): void;
  native function requestPublishFormInner(want: Want, callback: AsyncCallbackWrapper<string>, withFormBindingData: boolean, dataObjStr?: string, proxies?: Array<formBindingData.ProxyData>): void;
  native function isRequestPublishFormSupportedInner(callback: AsyncCallbackWrapper<boolean>): void;
  native function getPublishedFormInfosInner(callback: AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>): void;
  native function getPublishedFormInfoByIdInner(formId: string, callback: AsyncCallbackWrapper<formInfo.RunningFormInfo>): void;
  native function nativeGetFormRect(formId: string, callback: AsyncCallbackWrapper<formInfo.Rect>): void;
  native function nativeCancelOverflow(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function nativeRequestOverflow(formId: string, overflowInfo: formInfo.OverflowInfo, callback: AsyncCallbackWrapper<void>): void;
  native function nativeDeactivateSceneAnimation(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function nativeActivateSceneAnimation(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function nativeOpenFormManagerCrossBundle(want: Want): void;
  native function checkFormIDParam(formId: string): void;
  native function checkOverflowInfoParam(overflowInfo: formInfo.OverflowInfo): void;
  native function nativeReloadForms(context: UIAbilityContext, moduleName: string, abilityName: string, formName: string, callback: AsyncCallbackWrapper<int>): void;
  native function nativeReloadAllForms(context: UIAbilityContext, callback: AsyncCallbackWrapper<int>): void;

  const ERR_OK = 0;
  const INVALID_PARAM_ERROR_CODE = 401;
  const INVALID_PARAM_MESSAGE_ETS = "Parameter error. Possible causes: 1.Mandatory parameters are left unspecified;"
    + " 2.Incorrect parameter types;"
    + " 3.Parameter verification failed.";

  function getFormInfoInstance(): formInfo.FormInfo {
    let emptyInstance: formInfo.FormInfo = {
      bundleName: '',
      moduleName: '',
      abilityName: '',
      name: '',
      displayName: '',
      displayNameId: 0,
      description: '',
      descriptionId: 0,
      type: formInfo.FormType.JS,
      jsComponentName: '',
      isDefault: false,
      updateEnabled: false,
      formVisibleNotify: false,
      scheduledUpdateTime: '',
      formConfigAbility: '',
      updateDuration: 0,
      defaultDimension: 0,
      supportDimensions: {},
      customizeData: {},
      isDynamic: false,
      transparencyEnabled: false,
      supportedShapes: {}
    }
    return emptyInstance;
  }

  function setFormNextRefreshTime(formId: string, minute: int): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if ((formId === "") || (minute < 0)) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        setFormNextRefreshTimeInner(formId, minute, call);
      });
    });
  }

  function setFormNextRefreshTime(formId: string, minute: int,
    callback: AsyncCallback<void>): void {
    if (formId === "" || (minute < 0)) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      setFormNextRefreshTimeInner(formId, minute, call);
    });
  }
  
  export function setFormNextRefreshTimeReturnsPromise(formId: string, minute: int): Promise<void> {
    return setFormNextRefreshTime(formId, minute);
  }

  export function setFormNextRefreshTimeWithCallback(formId: string, minute: int, callback: AsyncCallback<void>): void {
    setFormNextRefreshTime(formId, minute, callback);
  }

  export function updateForm(formId: string, formBindingData: formBindingData.FormBindingData): Promise<void> {
    let dataObjStr: string = JSON.stringify(formBindingData.data);
    return new Promise<void>((resolve, reject): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        updateFormInner(formId, dataObjStr, call, formBindingData.proxies);
      });
    });
  }

  export function updateForm(formId: string, formBindingData: formBindingData.FormBindingData, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let dataObjStr: string = JSON.stringify(formBindingData.data);
    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      updateFormInner(formId, dataObjStr, call, formBindingData.proxies);
    });
  }

export function getPublishedFormInfos(): Promise<Array<formInfo.FormInfo>> {
  return new Promise<Array<formInfo.FormInfo>>((resolve, reject): void => {
    let call = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>((err, data) => {
      if (err && err.code !== ERR_OK) {
        reject(err);
        return;
      }
      const parsedResult: Array<formInfo.FormInfo> = [];
      if (!data || data.length === 0) {
        resolve(parsedResult);
        return;
      }
      for (let i = 0; i < data.length; i++) {
        const info = getFormInfoInstance();
        info.name = data[i].formName;
        info.bundleName = data[i].bundleName;
        info.moduleName = data[i].moduleName;
        info.abilityName = data[i].abilityName;
        info.description = data[i].formDescription;
        info.defaultDimension = data[i].dimension;
        parsedResult.push(info);
      }
      resolve(parsedResult);
    });
    taskpool.execute((): void => {
      getPublishedFormInfosInner(call);
    });
  });
}

export function getPublishedFormInfoById(formId: string): Promise<formInfo.FormInfo> {
  return new Promise<formInfo.FormInfo>((resolve, reject: (err: BusinessError) => void): void => {
    let call = new AsyncCallbackWrapper<formInfo.RunningFormInfo>((err, data) => {
      if (err && err.code !== ERR_OK) {
        reject(err);
        return;
      }
      const parsedResult: formInfo.FormInfo = getFormInfoInstance();
      if (data) {
        parsedResult.name = data.formName;
        parsedResult.bundleName = data.bundleName;
        parsedResult.moduleName = data.moduleName;
        parsedResult.abilityName = data.abilityName;
        parsedResult.description = data.formDescription;
        parsedResult.defaultDimension = data.dimension;
      }
      resolve(parsedResult);
    });
    taskpool.execute((): void => {
      getPublishedFormInfoByIdInner(formId, call);
    });
  });
}

  export function getPublishedRunningFormInfos(): Promise<Array<formInfo.RunningFormInfo>> {
    return new Promise<Array<formInfo.RunningFormInfo>>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as Array<formInfo.RunningFormInfo>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        getPublishedFormInfosInner(call);
      });
    });
  }

  export function getPublishedRunningFormInfoById(formId: string): Promise<formInfo.RunningFormInfo> {
    return new Promise<formInfo.RunningFormInfo>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<formInfo.RunningFormInfo>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as formInfo.RunningFormInfo);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        getPublishedFormInfoByIdInner(formId, call);
      });
    });
  }

  export function getFormsInfo(filter: formInfo.FormInfoFilter,
    callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    if (filter === null || filter === undefined) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(callback);
    taskpool.execute((): void => {
      getFormsInfoInner(call, filter);
    });
  }

  export function getFormsInfo(callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(callback);
    taskpool.execute((): void => {
      getFormsInfoInner(call);
    });
  }

  export function getFormsInfo(filter?: formInfo.FormInfoFilter): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as Array<formInfo.FormInfo>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        getFormsInfoInner(call, filter);
      });
    });
  }

  export function openFormEditAbility(abilityName: string, formId: string, isMainPage?: boolean): void {
    if (abilityName === "" || (formId === "")) {
      throw new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS));
    }

    if (isMainPage == undefined) {
      isMainPage = true;
    }

    openFormEditAbilityInner(abilityName, formId, isMainPage);
  }

  export function openFormManager(want: Want): void {
    openFormManagerInner(want);
  }

  export function requestPublishForm(want: Want, callback: AsyncCallback<string>): void {
    let call = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void => {
      requestPublishFormInner(want, call, false, undefined, undefined);
    });
  }

  export function requestPublishForm(want: Want, formBindingData: formBindingData.FormBindingData,
    callback: AsyncCallback<string>): void {
    let dataStr: string = JSON.stringify(formBindingData.data);
    let call = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void => {
      requestPublishFormInner(want, call, true, dataStr, formBindingData?.proxies);
    });
  }

  export function requestPublishForm(want: Want, formBindingData?: formBindingData.FormBindingData): Promise<string> {
    let dataStr: string = formBindingData ? JSON.stringify(formBindingData.data) : "";
    let withFormBindingData: boolean = formBindingData ? true : false;
    return new Promise<string>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<string>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as string);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        requestPublishFormInner(want, call, withFormBindingData, dataStr, formBindingData?.proxies);
      });
    });
  }

  export function isRequestPublishFormSupported(callback: AsyncCallback<boolean>): void {
    let call = new AsyncCallbackWrapper<boolean>(callback);
    taskpool.execute((): void => {
      isRequestPublishFormSupportedInner(call);
    });
  }

  export function isRequestPublishFormSupported(): Promise<boolean> {
    return new Promise<boolean>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<boolean>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as boolean);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        isRequestPublishFormSupportedInner(call);
      });
    });
  }

  export function getFormRect(formId: string): Promise<formInfo.Rect> {
    checkFormIDParam(formId);
    let getRectFormPromise: Promise<formInfo.Rect> =
      new Promise<formInfo.Rect>((resolve: (data: formInfo.Rect) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<formInfo.Rect>((err: BusinessError | null, data: formInfo.Rect | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as formInfo.Rect);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeGetFormRect(formId, myCall);
        });
      });
    return getRectFormPromise;
  }

  export function cancelOverflow(formId: string): Promise<void> {
    checkFormIDParam(formId);
    let requestFormPromise: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeCancelOverflow(formId, myCall);
        });
      });
    return requestFormPromise;
  }

  export function requestOverflow(formId: string, overflowInfo: formInfo.OverflowInfo): Promise<void> {
    checkFormIDParam(formId);
    checkOverflowInfoParam(overflowInfo);
    let requestFormPromise: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeRequestOverflow(formId, overflowInfo, myCall);
        });
      });
    return requestFormPromise;
  }

  export function deactivateSceneAnimation(formId: string): Promise<void> {
    checkFormIDParam(formId);
    let deactivateFormPromise: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeDeactivateSceneAnimation(formId, myCall);
        });
      });
    return deactivateFormPromise;
  }

  export function activateSceneAnimation(formId: string): Promise<void> {
    checkFormIDParam(formId);
    let activateFormPromise: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeActivateSceneAnimation(formId, myCall);
        });
      });
    return activateFormPromise;
  }

  export function openFormManagerCrossBundle(want: Want): void {
    nativeOpenFormManagerCrossBundle(want);
  }

  export function reloadForms(context: UIAbilityContext, moduleName: string, abilityName: string,
    formName: string): Promise<int> {
    let reloadFormsPromise: Promise<int> =
      new Promise<int>((resolve: (data: int) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<int>((err: BusinessError | null, data: int | undefined) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data as int);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeReloadForms(context, moduleName, abilityName, formName, myCall);
        });
      });
    return reloadFormsPromise;
  }

  export function reloadAllForms(context: UIAbilityContext): Promise<int> {
    let reloadAllFormsPromise: Promise<int> =
      new Promise<int>((resolve: (data: int) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<int>((err: BusinessError | null, data: int | undefined) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data as int);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          nativeReloadAllForms(context, myCall);
        });
      });
    return reloadAllFormsPromise;
  }
}