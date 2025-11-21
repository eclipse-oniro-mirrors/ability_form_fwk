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

import { Callback, AsyncCallback, BusinessError } from '@ohos.base';
import Want from '@ohos.app.ability.Want';
import formInfo from '@ohos.app.form.formInfo';

export class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => { }

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export class CallbackWrapper<T> {
  private myFun_: Callback<T> = (data: T) => { }

  constructor(myFun: Callback<T>) {
    this.myFun_ = myFun;
  }

  invoke(data: T): void {
    this.myFun_(data);
  }

  isEqual(callback: Callback<T>): boolean {
    return (this.myFun_ === callback);
  }
}

export default namespace formHost {

  let callbackArray: CallbackWrapper<string>[] = [];

  loadLibrary("formHost_ani.z");

  native function acquireFormStateInner(want: Want,
    callback: AsyncCallbackWrapper<formInfo.FormStateInfo>): void;
  native function acquireFormDataInner(formId: string, callback: AsyncCallbackWrapper<Record<string, Object>>): void;
  native function shareFormInner(formId: string, deviceId: string, callback: AsyncCallbackWrapper<void>): void;
  native function addFormInner(want: Want, callback: AsyncCallbackWrapper<formInfo.RunningFormInfo>): void;
  native function deleteFormInner(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function deleteInvalidFormsInner(formIds: Array<string>, callback: AsyncCallbackWrapper<int>): void;
  native function isSystemReadyInner(callback: AsyncCallbackWrapper<void>): void;
  native function getAllFormsInfoInner(callback: AsyncCallbackWrapper<Array<formInfo.FormInfo>>): void;
  native function getFormsInfoByFilterInner(filter: formInfo.FormInfoFilter,
      callback: AsyncCallbackWrapper<Array<formInfo.FormInfo>>): void;
  native function getFormsInfoInner(bundleName: string, moduleName: string,
        callback: AsyncCallbackWrapper<Array<formInfo.FormInfo>>): void;
  native function notifyFormsEnableUpdateInner(formIds: Array<string>, isEnableUpdate: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function notifyFormsVisibleInner(formIds: Array<string>, isVisible: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function releaseFormInner(formId: string, isReleaseCache: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function requestFormInner(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function requestFormWithParamsInner(formId: string, wantParams: Record<string, Object>, callback: AsyncCallbackWrapper<void>): void;
  native function castToNormalFormInner(formId: string, callback: AsyncCallbackWrapper<void>): void;
  native function notifyVisibleFormsInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  native function notifyInvisibleFormsInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  native function notifyFormsPrivacyProtectedInner(formIds: Array<string>, isProtected: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function setFormUpdateInner(formIds: Array<string>, isEnable: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function updateFormLocation(formId: string, location: formInfo.FormLocation): void;
  native function updateFormLockedStateInner(formId: string, isLocked: boolean, callback: AsyncCallbackWrapper<void>): void;
  native function setFormsRecyclableInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  native function setPublishFormResult(formId: string, result: formInfo.PublishFormResult): void;
  native function recycleFormsInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  native function recoverFormsInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  native function registerFormObserverInner(callback: CallbackWrapper<string>): void;
  native function unRegisterFormObserverInner(callback?: CallbackWrapper<string>): void;
  native function setRouterProxyInner(formIds: Array<string>, proxy: CallbackWrapper<Want>, callback: AsyncCallbackWrapper<void>): void;
  native function clearRouterProxyInner(formIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;
  export native function nativeOnFormOverflow(callback: CallbackWrapper<formInfo.OverflowRequest>): void;
  export native function nativeOffFormOverflow(callback?: CallbackWrapper<formInfo.OverflowRequest>): void;
  export native function nativeOnChangeSceneAnimationState(callback: CallbackWrapper<formInfo.ChangeSceneAnimationStateRequest>): void;
  export native function nativeOffChangeSceneAnimationState(callback?: CallbackWrapper<formInfo.ChangeSceneAnimationStateRequest>): void;
  export native function nativeOnGetFormRect(callback: GetFormRectInfoCallbackWrapper): void;
  export native function nativeOffGetFormRect(callback?: GetFormRectInfoCallbackWrapper): void;
  export native function nativeOnGetLiveFormStatus(callback: GetLiveFormStatusCallbackWrapper): void;
  export native function nativeOffGetLiveFormStatus(callback?: GetLiveFormStatusCallbackWrapper): void;

  const ERR_OK = 0;
  const INVALID_PARAM_ERROR_CODE = 401;
  const INVALID_PARAM_MESSAGE_ETS = "Parameter error. Possible causes: 1.Mandatory parameters are left unspecified;"
    + " 2.Incorrect parameter types;"
    + " 3.Parameter verification failed.";

  export function acquireFormState(want: Want, callback: AsyncCallback<formInfo.FormStateInfo>): void {
    if (want === undefined || want === null) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let callbackWrap = new AsyncCallbackWrapper<formInfo.FormStateInfo>(callback);
    taskpool.execute((): void => {
      acquireFormStateInner(want, callbackWrap);
    });
  }

  export function acquireFormState(want: Want): Promise<formInfo.FormStateInfo> {
    return new Promise<formInfo.FormStateInfo>((resolve: (data: formInfo.FormStateInfo) => void,
      reject: (err: BusinessError) => void): void => {
      if (want === null || want === undefined) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<formInfo.FormStateInfo>(
        (err: BusinessError | null, data: formInfo.FormStateInfo | undefined) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data as formInfo.FormStateInfo);
          } else {
            reject(err);
          }
        });
      acquireFormStateInner(want, call);
    });
  }

  export function shareForm(formId: string, deviceId: string, callback: AsyncCallback<void>): void {
    if ((formId === "") || (deviceId === "")) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      shareFormInner(formId, deviceId, myCall);
    });
  }

  export function shareForm(formId: string, deviceId: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if ((formId === "") || (deviceId === "")) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>((err) => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        shareFormInner(formId, deviceId, call);
      });
    });
  }

  export function acquireFormData(formId: string, callback: AsyncCallback<Record<string, Object>>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let myCall = new AsyncCallbackWrapper<Record<string, Object>>(callback);
    taskpool.execute((): void => {
      acquireFormDataInner(formId, myCall);
    })
  }

  export function acquireFormData(formId: string): Promise<Record<string, Object>> {
    return new Promise<Record<string, Object>>((resolve: (data: Record<string, Object>) => void,
      reject: (err: BusinessError) => void): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<Record<string, Object>>((err, data) => {
        if (err == null || err.code == ERR_OK) {
          resolve(data as Record<string, Object>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        acquireFormDataInner(formId, call);
      });
    });
  }

  export function addForm(want: Want): Promise<formInfo.RunningFormInfo> {
    return new Promise<formInfo.RunningFormInfo>((resolve: (data: formInfo.RunningFormInfo) => void,
      reject: (err: BusinessError) => void): void => {
      if (want === undefined) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<formInfo.RunningFormInfo>(
        (err: BusinessError | null, data: formInfo.RunningFormInfo | undefined) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data as formInfo.RunningFormInfo);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        addFormInner(want, call);
      });
    });

  }

  export function deleteForm(formId: string, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => { deleteFormInner(formId, call); })
  }

  export function deleteForm(formId: string): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            data = undefined
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        deleteFormInner(formId, call);
      });
    });

  }

  export function deleteInvalidForms(formIds: Array<string>): Promise<int> {
    return new Promise<int>((resolve: (data: int) => void,
      reject: (err: BusinessError) => void): void => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<int>(
        (err: BusinessError | null, data: int | undefined) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data as int);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        deleteInvalidFormsInner(formIds, call);
      });
    });
  }

  export function deleteInvalidForms(formIds: Array<string>, callback: AsyncCallback<int>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<int>(callback);

    taskpool.execute((): void => {
      deleteInvalidFormsInner(formIds, call);
    });
  }

  export function disableFormsUpdate(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);

    taskpool.execute((): void => {
      setFormUpdateInner(formIds, false, call);
    });
  }

  export function disableFormsUpdate(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        setFormUpdateInner(formIds, false, call);
      });
    });
  }

  export function enableFormsUpdate(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);

    taskpool.execute((): void => {
      setFormUpdateInner(formIds, true, call);
    });

  }

  export function enableFormsUpdate(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        setFormUpdateInner(formIds, false, call);
      });
    });
  }

  export function getAllFormsInfo(): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>(
      (resolve: (data: Array<formInfo.FormInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(
          (err: BusinessError | null, data: Array<formInfo.FormInfo> | undefined) => {
            if (err == null || err.code == ERR_OK) {
              resolve(data as Array<formInfo.FormInfo>);
            } else {
              reject(err);
            }
          });
        taskpool.execute((): void => {
          getAllFormsInfoInner(call);
        });
      });

  }

  export function getAllFormsInfo(callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(callback);
    taskpool.execute((): void => {
      getAllFormsInfoInner(call);
    })
  }

  export function getFormsInfo(filter: formInfo.FormInfoFilter): Promise<Array<formInfo.FormInfo>> {
    return new Promise<Array<formInfo.FormInfo>>(
      (resolve: (data: Array<formInfo.FormInfo>) => void,
        reject: (err: BusinessError) => void): void => {

        let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(
          (err: BusinessError | null, data: Array<formInfo.FormInfo> | undefined) => {
            if (err == null || err.code == ERR_OK) {
              resolve(data as Array<formInfo.FormInfo>);
            } else {
              reject(err);
            }
          });
        taskpool.execute((): void => {
          getFormsInfoByFilterInner(filter, call);
        });
      });
  }

  export function getFormsInfo(bundleName: string, moduleName: string, callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    if ((bundleName === "") || (moduleName === "")) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(callback);
    taskpool.execute((): void => {
      getFormsInfoInner(bundleName, moduleName, call);
    })
  }

  export function getFormsInfo(bundleName: string, moduleName?: string): Promise<Array<formInfo.FormInfo>> {
    let tempModule: string = "";
    if (moduleName != undefined) {
      tempModule = moduleName;
    }

    return new Promise<Array<formInfo.FormInfo>>(
      (resolve: (data: Array<formInfo.FormInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        if (bundleName === "") {
          reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
          return;
        }
        let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(
          (err: BusinessError | null, data: Array<formInfo.FormInfo> | undefined) => {
            if (err == null || err.code == ERR_OK) {
              resolve(data as Array<formInfo.FormInfo>);
            } else {
              reject(err);
            }
          });
        taskpool.execute((): void => {
          getFormsInfoInner(bundleName, tempModule, call);
        });
      });

  }

  export function getFormsInfo(bundleName: string, callback: AsyncCallback<Array<formInfo.FormInfo>>): void {
    if (bundleName.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let emptyString: string = "";
    let call = new AsyncCallbackWrapper<Array<formInfo.FormInfo>>(callback);

    taskpool.execute((): void => {
      getFormsInfoInner(bundleName, emptyString, call);
    })
  }

  export function isSystemReady(): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        isSystemReadyInner(call);
      });
    });

  }

  export function isSystemReady(callback: AsyncCallback<void>): void {
    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => { isSystemReadyInner(call); })
  }

  export function notifyFormsEnableUpdate(formIds: Array<string>, isEnableUpdate: boolean,
    callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let callbackWrap = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      notifyFormsEnableUpdateInner(formIds, isEnableUpdate, callbackWrap);
    });
  }

  export function notifyFormsEnableUpdate(formIds: Array<string>, isEnableUpdate: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let callbackWrap = new AsyncCallbackWrapper<void>((err) => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        notifyFormsEnableUpdateInner(formIds, isEnableUpdate, callbackWrap);
      });
    });
  }

  export function notifyFormsVisible(formIds: Array<string>, isVisible: boolean, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let callbackWrap = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      notifyFormsVisibleInner(formIds, isVisible, callbackWrap);
    });
  }

  export function notifyFormsVisible(formIds: Array<string>, isVisible: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let callbackWrap = new AsyncCallbackWrapper<void>((err) => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        notifyFormsVisibleInner(formIds, isVisible, callbackWrap);
      });
    });
  }

  export function notifyFormsPrivacyProtected(formIds: Array<string>, isProtected: boolean,
    callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let callbackWrap = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      notifyFormsPrivacyProtectedInner(formIds, isProtected, callbackWrap);
    });
  }

  export function notifyFormsPrivacyProtected(formIds: Array<string>, isProtected: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let callbackWrap = new AsyncCallbackWrapper<void>((err) => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        notifyFormsPrivacyProtectedInner(formIds, isProtected, callbackWrap);
      });
    });
  }

  export function releaseForm(formId: string, isReleaseCache?: boolean): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        if (isReleaseCache == undefined) {
          releaseFormInner(formId, false, call);
        } else {
          releaseFormInner(formId, isReleaseCache, call);
        }
      });
    });

  }

  export function releaseForm(formId: string, isReleaseCache: boolean, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);

    taskpool.execute((): void => { releaseFormInner(formId, isReleaseCache, call); });
  }

  export function releaseForm(formId: string, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);

    taskpool.execute((): void => { releaseFormInner(formId, true, call); });
  }

  export function requestForm(formId: string): Promise<void> {

    return new Promise<void>((resolve, reject): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {
        requestFormInner(formId, call);
      });
    });
  }

  export function requestForm(formId: string, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }
    let call = new AsyncCallbackWrapper<void>(callback);

    taskpool.execute((): void => { requestFormInner(formId, call); })
  }

  export function requestFormWithParams(formId: string, wantParams?: Record<string, Object>): Promise<void> {

    return new Promise<void>((resolve, reject): void => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }
      let call = new AsyncCallbackWrapper<void>(
        (err, data) => {
          if (err == null || err.code == ERR_OK) {
            resolve(data);
          } else {
            reject(err);
          }
        });
      taskpool.execute((): void => {

        let _wantParams: Record<string, Object> = {};
        if (wantParams) {
          _wantParams = wantParams;
        }
        requestFormWithParamsInner(formId, _wantParams, call);
      });
    });
  }

  export function castToNormalForm(formId: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        castToNormalFormInner(formId, call);
      });
    });
  }

  export function castToNormalForm(formId: string, callback: AsyncCallback<void>): void {
    if (formId === "") {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      castToNormalFormInner(formId, call);
    });
  }

  export function notifyVisibleForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        notifyVisibleFormsInner(formIds, call);
      });
    });
  }

  export function notifyVisibleForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      notifyVisibleFormsInner(formIds, call);
    });
  }

  export function notifyInvisibleForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        notifyInvisibleFormsInner(formIds, call);
      });
    });
  }

  export function notifyInvisibleForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      notifyInvisibleFormsInner(formIds, call);
    });
  }

  export function setFormsRecyclable(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        setFormsRecyclableInner(formIds, call);
      });
    });
  }

  export function setFormsRecyclable(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      setFormsRecyclableInner(formIds, call);
    });
  }

  export function updateFormLockedState(formId: string, isLocked: boolean): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formId === "") {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let callbackWrap = new AsyncCallbackWrapper<void>((err) => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        updateFormLockedStateInner(formId, isLocked, callbackWrap);
      });
    });
  }

  export function recycleForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        recycleFormsInner(formIds, call);
      });
    });
  }

  export function recoverForms(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => {
        recoverFormsInner(formIds, call);
      });
    });
  }

  export function recoverForms(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      recoverFormsInner(formIds, call);
    });
  }

  export function onFormUninstall(callback: Callback<string>): void {
    if(!hasCallback(callback)){
      let callbackWrap = createCallbackWrapper(callback);
        registerFormObserverInner(callbackWrap);
    }
  }

  export function offFormUninstall(callback?: Callback<string>): void {
      if (callback) {
        let callbackWrap = createCallbackWrapper(callback);
        unRegisterFormObserverInner(callbackWrap);
      } else {
        unRegisterFormObserverInner();
      }
  }

  export function setRouterProxy(formIds: Array<string>, proxy: Callback<Want>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      let callbackWrapper = new CallbackWrapper<Want>(proxy);
      taskpool.execute((): void => {
        setRouterProxyInner(formIds, callbackWrapper, call);
      });
    });
  }

  export function setRouterProxy(formIds: Array<string>, proxy: Callback<Want>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    let callbackWrapper = new CallbackWrapper<Want>(proxy);
    taskpool.execute((): void => {
      setRouterProxyInner(formIds, callbackWrapper, call);
    });
  }

  export function clearRouterProxy(formIds: Array<string>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (formIds.length === 0) {
        reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
        return;
      }

      let call = new AsyncCallbackWrapper<void>(err => {
        if (err == null || err.code == ERR_OK) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });

      taskpool.execute((): void => { clearRouterProxyInner(formIds, call); });
    });
  }

  export function clearRouterProxy(formIds: Array<string>, callback: AsyncCallback<void>): void {
    if (formIds.length === 0) {
      callback(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)), undefined);
      return;
    }

    let call = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => { clearRouterProxyInner(formIds, call); });
  }

  function hasCallback(callback: Callback<string>): boolean {
    for (let num of callbackArray) {
      if (num.isEqual(callback)) {
        return true;
      }
    }
    return false;
  }

  function createCallbackWrapper(callback: Callback<string>): CallbackWrapper<string> {
    for (let element of callbackArray) {
      if(element.isEqual(callback)){
        return element;
      }
    }
    let calbackWrapper: CallbackWrapper<string> = new CallbackWrapper<string>(callback);
    callbackArray.push(calbackWrapper)
    return calbackWrapper;
  }

  function onFormOverflow(callback: Callback<formInfo.OverflowRequest>): void {
    let myCall = new CallbackWrapper<formInfo.OverflowRequest>(callback);
    formHost.nativeOnFormOverflow(myCall);
  }

  function onChangeSceneAnimationState(callback: Callback<formInfo.ChangeSceneAnimationStateRequest>): void {
    let myCall = new CallbackWrapper<formInfo.ChangeSceneAnimationStateRequest>(callback);
    formHost.nativeOnChangeSceneAnimationState(myCall);
  }

  function offFormOverflow(callback?: Callback<formInfo.OverflowRequest>): void {
    let myCall: CallbackWrapper<formInfo.OverflowRequest> | undefined = undefined;
    if (callback) {
      myCall = new CallbackWrapper<formInfo.OverflowRequest>(callback);
    }
    formHost.nativeOffFormOverflow(myCall);
  }

  function offChangeSceneAnimationState(callback?: Callback<formInfo.ChangeSceneAnimationStateRequest>): void {
    let myCall: CallbackWrapper<formInfo.ChangeSceneAnimationStateRequest> | undefined = undefined;
    if (callback) {
      myCall = new CallbackWrapper<formInfo.ChangeSceneAnimationStateRequest>(callback);
    }
    formHost.nativeOffChangeSceneAnimationState(myCall);
  }

  function onGetFormRect(callback: formInfo.GetFormRectInfoCallback): void {
    let myCall = new GetFormRectInfoCallbackWrapper(callback);
    formHost.nativeOnGetFormRect(myCall);
  }

  function offGetFormRect(callback?: formInfo.GetFormRectInfoCallback): void {
    let myCall: GetFormRectInfoCallbackWrapper | undefined = undefined;
    if (callback) {
      myCall = new GetFormRectInfoCallbackWrapper(callback);
    }
    formHost.nativeOffGetFormRect(myCall);
  }

  function on(type: 'getLiveFormStatus', callback: formInfo.GetLiveFormStatusCallback): void {
    let myCall = new GetLiveFormStatusCallbackWrapper(callback);
    formHost.nativeOnGetLiveFormStatus(myCall);
  }

  function off(type: 'getLiveFormStatus', callback?: formInfo.GetLiveFormStatusCallback): void {
    let myCall: GetLiveFormStatusCallbackWrapper | undefined = undefined;
    if (callback) {
      myCall = new GetLiveFormStatusCallbackWrapper(callback);
    }
    formHost.nativeOffGetLiveFormStatus(myCall);
  }

  class GetFormRectInfoCallbackWrapper {
    private liveFormInterfaceParam: long;

    native nativePromiseCallback(realRect: formInfo.Rect): void;

    private checkPromise(obj: Any): boolean {
      if (obj instanceof Promise) {
        return true;
      }
      return false;
    }

    private callPromise(p: Promise<formInfo.Rect>): void {
      let rectObj: formInfo.Rect = await p;
      this.nativePromiseCallback(rectObj);
    }

    private formRectCallback: formInfo.GetFormRectInfoCallback = (formId: string): Promise<formInfo.Rect> => {
      return new Promise<formInfo.Rect>((resolve: (rect: formInfo.Rect) => void,
        reject: (rect: formInfo.Rect) => void): void => {
      });
    }

    constructor(myFun: formInfo.GetFormRectInfoCallback) {
      this.formRectCallback = myFun;
    }

    invoke(formId: string): Promise<formInfo.Rect> {
      return this.formRectCallback(formId);
    }
  }

  class GetLiveFormStatusCallbackWrapper {
    private liveFormStatusCallback: formInfo.GetLiveFormStatusCallback = (): Record<string, string> => { }

    constructor(callback: formInfo.GetLiveFormStatusCallback) {
      this.liveFormStatusCallback = callback;
    }

    invoke(): Record<string, string> {
      return this.liveFormStatusCallback();
    }
  }
}