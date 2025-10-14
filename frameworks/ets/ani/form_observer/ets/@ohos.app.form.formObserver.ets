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

import { BusinessError, AsyncCallback, Callback } from '@ohos.base';
import formInfo from '@ohos.app.form.formInfo';

class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

class CallbackWrapper<T> {
  private myFun_: Callback<T> = (data: T) => {}

  constructor(myFun: Callback<T>) {
    this.myFun_ = myFun;
  }

  invoke(data: T): void {
    this.myFun_(data);
  }
}

export default namespace formObserver {
  loadLibrary("formobserver_ani.z")
  export native function nativeGetRunningFormInfoById(formId: string, isUnusedIncluded: boolean, callback: AsyncCallbackWrapper<formInfo.RunningFormInfo>): void;
  export native function nativeGetRunningFormInfos(hostBundleName: string, isUnusedIncluded: boolean, callback: AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>): void;
  export native function nativeGetRunningFormInfosNotBundlename(isUnusedIncluded: boolean, callback: AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>): void;
  export native function nativeGetRunningFormInfosByFilter(formProviderFilter: formInfo.FormProviderFilter, callback: AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>): void;
  export native function nativeOn(type: string, observerCallback: CallbackWrapper<formInfo.RunningFormInfo>, hostBundleName: string): void;
  export native function nativeOnArray(type: string, observerCallback: CallbackWrapper<Array<formInfo.RunningFormInfo>>, hostBundleName?: string): void;
  export native function nativeOff(type: string, hostBundleName?: string, observerCallback?: CallbackWrapper<formInfo.RunningFormInfo>): void;
  export native function nativeOffArray(type: string, hostBundleName?: string, observerCallback?: CallbackWrapper<Array<formInfo.RunningFormInfo>>): void;
  export native function checkFormIDParam(formId: string): void;
  export native function checkHostBundleNameParam(hostBundleName: string): void;
  export native function checkformProviderFilterParam(formProviderFilter: formInfo.FormProviderFilter): void;

  export function getRunningFormInfoById(formId: string): Promise<formInfo.RunningFormInfo> {
    checkFormIDParam(formId);
    let getRunningInfoFormPromise: Promise<formInfo.RunningFormInfo> =
      new Promise<formInfo.RunningFormInfo>((resolve: (data: formInfo.RunningFormInfo) => void,
        reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<formInfo.RunningFormInfo>((err: BusinessError | null,
          data: formInfo.RunningFormInfo | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as formInfo.RunningFormInfo);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          let isUnusedIncluded: boolean = false;
          formObserver.nativeGetRunningFormInfoById(formId, isUnusedIncluded, myCall);
        });
      });
    return getRunningInfoFormPromise;
  }

  export function getRunningFormInfoById(formId: string, isUnusedIncluded: boolean): Promise<formInfo.RunningFormInfo> {
    checkFormIDParam(formId);
    let getRunningInfoFormPromise: Promise<formInfo.RunningFormInfo> =
      new Promise<formInfo.RunningFormInfo>((resolve: (data: formInfo.RunningFormInfo) => void,
        reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<formInfo.RunningFormInfo>((err: BusinessError | null,
          data: formInfo.RunningFormInfo | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as formInfo.RunningFormInfo);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          formObserver.nativeGetRunningFormInfoById(formId, isUnusedIncluded, myCall);
        });
      });
    return getRunningInfoFormPromise;
  }

  export function getRunningFormInfoById(formId: string,
    callback: AsyncCallback<formInfo.RunningFormInfo, void>): void {
    checkFormIDParam(formId);
    let isUnusedIncluded: boolean = false;
    let myCall = new AsyncCallbackWrapper<formInfo.RunningFormInfo>(callback);
    taskpool.execute((): void => {
      formObserver.nativeGetRunningFormInfoById(formId, isUnusedIncluded, myCall);
    });
  }

  export function getRunningFormInfoById(formId: string, isUnusedIncluded: boolean,
    callback: AsyncCallback<formInfo.RunningFormInfo, void>): void {
    checkFormIDParam(formId);
    let myCall = new AsyncCallbackWrapper<formInfo.RunningFormInfo>(callback);
    taskpool.execute((): void => {
      formObserver.nativeGetRunningFormInfoById(formId, isUnusedIncluded, myCall);
    });
  }

  export function getRunningFormInfos(callback: AsyncCallback<Array<formInfo.RunningFormInfo>>,
    hostBundleName?: string): void {
    if (hostBundleName != null) {
      formObserver.checkHostBundleNameParam(hostBundleName);
    }
    let isUnusedIncluded: boolean = false;
    let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>(callback);
    taskpool.execute((): void => {
      if (hostBundleName == null) {
        formObserver.nativeGetRunningFormInfosNotBundlename(isUnusedIncluded, myCall)
      } else {
        formObserver.nativeGetRunningFormInfos(hostBundleName, isUnusedIncluded, myCall)
      }
    });
  }

  export function getRunningFormInfos(callback: AsyncCallback<Array<formInfo.RunningFormInfo>>,
    isUnusedIncluded: boolean, hostBundleName?: string): void {
    if (hostBundleName != null) {
      formObserver.checkHostBundleNameParam(hostBundleName);
    }
    let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>(callback);
    taskpool.execute((): void => {
      if (hostBundleName == null) {
        formObserver.nativeGetRunningFormInfosNotBundlename(isUnusedIncluded, myCall)
      } else {
        formObserver.nativeGetRunningFormInfos(hostBundleName, isUnusedIncluded, myCall)
      }
    });
  }

  export function getRunningFormInfos(hostBundleName?: string): Promise<Array<formInfo.RunningFormInfo>> {
    if (hostBundleName != null) {
      formObserver.checkHostBundleNameParam(hostBundleName);
    }
    let getRunningInfoFormPromise: Promise<Array<formInfo.RunningFormInfo>> =
      new Promise<Array<formInfo.RunningFormInfo>>((resolve: (data: Array<formInfo.RunningFormInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>((err: BusinessError | null,
          data: Array<formInfo.RunningFormInfo> | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Array<formInfo.RunningFormInfo>);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          let isUnusedIncluded: boolean = false;
          if (hostBundleName == null) {
            formObserver.nativeGetRunningFormInfosNotBundlename(isUnusedIncluded, myCall)
          } else {
            formObserver.nativeGetRunningFormInfos(hostBundleName, isUnusedIncluded, myCall)
          }
        });
      });
    return getRunningInfoFormPromise;
  }

  export function getRunningFormInfos(isUnusedIncluded: boolean,
    hostBundleName?: string): Promise<Array<formInfo.RunningFormInfo>> {
    if (hostBundleName != null) {
      formObserver.checkHostBundleNameParam(hostBundleName);
    }
    let getRunningInfoFormPromise: Promise<Array<formInfo.RunningFormInfo>> =
      new Promise<Array<formInfo.RunningFormInfo>>((resolve: (data: Array<formInfo.RunningFormInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>((err: BusinessError | null,
          data: Array<formInfo.RunningFormInfo> | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Array<formInfo.RunningFormInfo>);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          if (hostBundleName == null) {
            formObserver.nativeGetRunningFormInfosNotBundlename(isUnusedIncluded, myCall)
          } else {
            formObserver.nativeGetRunningFormInfos(hostBundleName, isUnusedIncluded, myCall)
          }
        });
      });
    return getRunningInfoFormPromise;
  }

  export function getRunningFormInfosByFilter(formProviderFilter: formInfo.FormProviderFilter): Promise<Array<formInfo.RunningFormInfo>> {
    formObserver.checkformProviderFilterParam(formProviderFilter);
    let getRunningInfoFormPromise: Promise<Array<formInfo.RunningFormInfo>> =
      new Promise<Array<formInfo.RunningFormInfo>>((resolve: (data: Array<formInfo.RunningFormInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>((err: BusinessError | null,
          data: Array<formInfo.RunningFormInfo> | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Array<formInfo.RunningFormInfo>);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          formObserver.nativeGetRunningFormInfosByFilter(formProviderFilter, myCall);
        });
      });
    return getRunningInfoFormPromise;
  }

  export function getRunningFormInfosByFilter(formProviderFilter: formInfo.FormProviderFilter,
    callback: AsyncCallback<Array<formInfo.RunningFormInfo>>): void {
    formObserver.checkformProviderFilterParam(formProviderFilter);
    let myCall = new AsyncCallbackWrapper<Array<formInfo.RunningFormInfo>>(callback);
    taskpool.execute((): void => {
      formObserver.nativeGetRunningFormInfosByFilter(formProviderFilter, myCall);
    });
  }

  export function onNotifyVisible(observerCallback: Callback<Array<formInfo.RunningFormInfo>>): void {
    let myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
    formObserver.nativeOnArray('notifyVisible', myCall, undefined);
  }

  export function onNotifyInvisible(observerCallback: Callback<Array<formInfo.RunningFormInfo>>): void {
    let myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
    formObserver.nativeOnArray('notifyInvisible', myCall, undefined);
  }

  export function onFormAdd(observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('formAdd', myCall, '');
  }

  export function onFormAdd(hostBundleName: string, observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('formAdd', myCall, hostBundleName);
  }

  export function onFormRemove(observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('formRemove', myCall, '');
  }

  export function onFormRemove(hostBundleName: string, observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('formRemove', myCall, hostBundleName);
  }

  export function onNotifyVisible(hostBundleName: string,
    observerCallback: Callback<Array<formInfo.RunningFormInfo>>): void {
    let myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
    formObserver.nativeOnArray('notifyVisible', myCall, hostBundleName);
  }

  function onNotifyInvisible(hostBundleName: string,
    observerCallback: Callback<Array<formInfo.RunningFormInfo>>): void {
    let myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
    formObserver.nativeOnArray('notifyInvisible', myCall, hostBundleName);
  }

  function onCall(observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('call', myCall, '');
  }

  function onCall(hostBundleName: string, observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('call', myCall, hostBundleName);
  }

  function onMessage(observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('message', myCall, '');
  }

  function onMessage(hostBundleName: string, observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('message', myCall, hostBundleName);
  }

  function onRouter(observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('router', myCall, '');
  }

  function onRouter(hostBundleName: string, observerCallback: Callback<formInfo.RunningFormInfo>): void {
    let myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    formObserver.nativeOn('router', myCall, hostBundleName);
  }

  function offNotifyVisible(hostBundleName?: string,
    observerCallback?: Callback<Array<formInfo.RunningFormInfo>>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<Array<formInfo.RunningFormInfo>> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
      formObserver.nativeOffArray('notifyVisible', boundleName, myCall);
    }
  }

  function offNotifyInvisible(hostBundleName?: string,
    observerCallback?: Callback<Array<formInfo.RunningFormInfo>>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<Array<formInfo.RunningFormInfo>> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<Array<formInfo.RunningFormInfo>>(observerCallback);
      formObserver.nativeOffArray('notifyInvisible', boundleName, myCall);
    }
  }

  function offFormAdd(hostBundleName?: string, observerCallback?: Callback<formInfo.RunningFormInfo>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<formInfo.RunningFormInfo> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    }
    formObserver.nativeOff('formAdd', boundleName, myCall);
  }

  function offFormRemove(hostBundleName?: string, observerCallback?: Callback<formInfo.RunningFormInfo>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<formInfo.RunningFormInfo> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    }
    formObserver.nativeOff('formRemove', boundleName, myCall);
  }

  function offCall(hostBundleName?: string, observerCallback?: Callback<formInfo.RunningFormInfo>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<formInfo.RunningFormInfo> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    }
    formObserver.nativeOff('call', boundleName, myCall);
  }

  function offMessage(hostBundleName?: string, observerCallback?: Callback<formInfo.RunningFormInfo>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<formInfo.RunningFormInfo> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    }
    formObserver.nativeOff('message', boundleName, myCall);
  }

  function offRouter(hostBundleName?: string, observerCallback?: Callback<formInfo.RunningFormInfo>): void {
    let boundleName: string | undefined = undefined;
    if (hostBundleName) {
      boundleName = hostBundleName;
    }
    let myCall: CallbackWrapper<formInfo.RunningFormInfo> | undefined = undefined;
    if (observerCallback) {
      myCall = new CallbackWrapper<formInfo.RunningFormInfo>(observerCallback);
    }
    formObserver.nativeOff('router', boundleName, myCall);
  }
}