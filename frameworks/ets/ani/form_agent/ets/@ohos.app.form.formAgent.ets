/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
import Want from '@ohos.app.ability.Want';
import formBindingData from '@ohos.app.form.formBindingData';
import formInfo from '@ohos.app.form.formInfo';

export default class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export namespace formAgent {
  const ERR_OK: int = 0;
  const INVALID_PARAM_ERROR_CODE: int = 401;
  const INVALID_PARAM_MESSAGE_ETS: string = "Parameter error. Possible causes: 1.Mandatory parameters are left unspecified;"
    + " 2.Incorrect parameter types;"
    + " 3.Parameter verification failed.";

  loadLibrary("form_agent_ani.z")

  export native function nativeRequestPublishForm(want: Want, callback: AsyncCallbackWrapper<string>): void;
  export native function nativeUpdateFormCrossBundle(formId: string, dataObjStr: string,
    callback: AsyncCallbackWrapper<void>): void;
  export native function nativeGetAvailableFormHostServices(
    callback: AsyncCallbackWrapper<Array<formInfo.PeerFormHostServiceInfo>>): void;
  export native function nativeRequestPublishFormCrossDevice(
    peerServiceInfo: formInfo.PeerFormHostServiceInfo, want: Want,
    formBindingDataStr: string, callback: AsyncCallbackWrapper<formInfo.PublishFormCrossDeviceResult>): void;
  export native function checkWantParam(want: Want): void;

  export function requestPublishForm(want: Want, callback: AsyncCallback<string>): void {
    checkWantParam(want);
    let myCall = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void => {
      formAgent.nativeRequestPublishForm(want, myCall);
    });
  }

  export function requestPublishForm(want: Want): Promise<string> {
    checkWantParam(want);
    let publishFormPromise: Promise<string> =
      new Promise<string>((resolve: (data: string) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<string>((err: BusinessError | null, data: string | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as string);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          formAgent.nativeRequestPublishForm(want, myCall);
        });
      });
    return publishFormPromise;
  }

  export function updateFormCrossBundle(formId: string, bindingData: formBindingData.FormBindingData): Promise<void> {
    let dataObjStr: string = JSON.stringify(bindingData.data);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err === null || err.code === 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        try {
          formAgent.nativeUpdateFormCrossBundle(formId, dataObjStr, myCall);
        } catch (exception) {
          let err = exception as BusinessError;
          myCall.invoke(err, undefined);
        }
      });
    });
  }

  export function getAvailableFormHostServices(): Promise<Array<formInfo.PeerFormHostServiceInfo>> {
    return new Promise<Array<formInfo.PeerFormHostServiceInfo>>(
      (resolve: (data: Array<formInfo.PeerFormHostServiceInfo>) => void,
        reject: (err: BusinessError) => void): void => {
        let call = new AsyncCallbackWrapper<Array<formInfo.PeerFormHostServiceInfo>>(
          (err: BusinessError | null, data: Array<formInfo.PeerFormHostServiceInfo> | undefined) => {
            if (err == null || err.code == 0) {
              resolve(data as Array<formInfo.PeerFormHostServiceInfo>);
            } else {
              reject(err);
            }
          });
        taskpool.execute((): void => {
          formAgent.nativeGetAvailableFormHostServices(call);
        });
      });
  }

  export function requestPublishFormCrossDevice(peerServiceInfo: formInfo.PeerFormHostServiceInfo,
    want: Want, formBindingData?: formBindingData.FormBindingData): Promise<formInfo.PublishFormCrossDeviceResult> {
    return new Promise<formInfo.PublishFormCrossDeviceResult>(
      (resolve: (data: formInfo.PublishFormCrossDeviceResult) => void,
        reject: (err: BusinessError) => void): void => {
        if (peerServiceInfo === undefined || peerServiceInfo === null) {
          reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
          return;
        }
        if (want === undefined || want === null) {
          reject(new BusinessError(INVALID_PARAM_ERROR_CODE, new Error(INVALID_PARAM_MESSAGE_ETS)));
          return;
        }
        let formBindingDataStr: string = formBindingData ? JSON.stringify(formBindingData.data) : "";
        let call = new AsyncCallbackWrapper<formInfo.PublishFormCrossDeviceResult>(
          (err: BusinessError | null, data: formInfo.PublishFormCrossDeviceResult | undefined) => {
            if (err == null || err.code == 0) {
              resolve(data as formInfo.PublishFormCrossDeviceResult);
            } else {
              reject(err);
            }
          });
        taskpool.execute((): void => {
          formAgent.nativeRequestPublishFormCrossDevice(peerServiceInfo, want, formBindingDataStr, call);
        });
      });
  }
}
