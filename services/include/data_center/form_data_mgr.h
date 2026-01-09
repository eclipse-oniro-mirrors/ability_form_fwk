/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_FORM_DATA_MGR_H
#define OHOS_FORM_FWK_FORM_FORM_DATA_MGR_H

#include <map>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <singleton.h>
#include <string>

#include "bundle_pack_info.h"
#include "form_constants.h"
#include "form_host/form_host_record.h"
#include "common/util/form_id_key.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "data_center/form_info/form_item_info.h"
#include "form_js_info.h"
#include "data_center/form_record/form_record.h"
#include "form_state_info.h"
#include "iremote_object.h"
#include "libxml/parser.h"
#include "libxml/tree.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {
using Want = AAFwk::Want;

/**
 * @class FormDataMgr
 * form data manager.
 */
class FormDataMgr final : public DelayedRefSingleton<FormDataMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormDataMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormDataMgr);
    /**
     * @brief Allot form info by item info.
     * @param formInfo Form item info.
     * @param callingUid The UID of the proxy.
     * @param userId User ID.
     * @return Returns form record.
     */
    FormRecord AllotFormRecord(const FormItemInfo &formInfo, const int callingUid,
        const int32_t userId = Constants::DEFAULT_USER_ID);
    /**
     * @brief Create form js info by form record.
     * @param formId The Id of the form.
     * @param record Form record.
     * @param formInfo Js info.
     */
    void CreateFormJsInfo(const int64_t formId, const FormRecord &record, FormJsInfo &formInfo);

    /**
     * @brief Create form js info by form record.
     * @param formId The Id of the form.
     * @param record Form record.
     * @param formProviderData The form data.
     * @param formInfo Js info.
     */
    void CreateFormJsInfo(const int64_t formId, const FormRecord &record, const FormProviderData &formProviderData,
        FormJsInfo &formInfo);
    /**
     * @brief Delete form js info by form record.
     * @param formId The Id of the form.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteFormRecord(const int64_t formId);
    /**
     * @brief Clean removed forms for host.
     * @param removedFormIds The id list of the forms.
     */
    void CleanHostRemovedForms(const std::vector<int64_t> &removedFormIds);
    /**
     * @brief Allot form host record by caller token.
     * @param info The form item info.
     * @param callerToken callerToken
     * @param formId The Id of the form.
     * @param callingUid The UID of the proxy.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool AllotFormHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const int64_t formId, const int callingUid);
    /**
     * @brief Check temp form count is max.
     * @return Returns ERR_OK if the temp form not reached; returns ERR_MAX_SYSTEM_TEMP_FORMS is reached.
     */
    int CheckTempEnoughForm() const;
    /**
     * @brief Check form count is max.
     * @param currentUserId The current userId.
     * @param callingUid The UID of the proxy.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    int CheckEnoughForm(const int callingUid, const int32_t currentUserId = Constants::DEFAULT_USER_ID) const;
    /**
     * @brief Delete temp form.
     * @param formId The Id of the form.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteTempForm(const int64_t formId);
    /**
     * @brief Check temp form is exist.
     * @param formId The Id of the form.
     * @return Returns true if the temp form is exist; returns false is not exist.
     */
    bool ExistTempForm(const int64_t formId) const;
    /**
     * @brief Modify form temp flag by formId.
     * @param formId The Id of the form.
     * @param formTempFlag The form temp flag.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool ModifyFormTempFlag(const int64_t formId, const bool formTempFlag);
    /**
     * @brief Add form user uid from form record.
     * @param formId The Id of the form.
     * @param formUserUid The form user uid.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool AddFormUserUid(const int64_t formId, const int formUserUid);
    /**
     * @brief Delete form user uid from form record.
     * @param formId The Id of the form.
     * @param uid calling user id.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteFormUserUid(const int64_t formId, const int uid);
    /**
     * @brief Update form record.
     * @param formId The Id of the form.
     * @param formRecord The form record.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UpdateFormRecord(const int64_t formId, const FormRecord &formRecord);
    /**
     * @brief Get form record.
     * @param formId The Id of the form.
     * @param formRecord The form record.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormRecord(const int64_t formId, FormRecord &formRecord) const;
    /**
     * @brief Get form record.
     * @param bundleName Bundle name.
     * @param formInfos The form record list.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormRecord(const std::string &bundleName, std::vector<FormRecord> &formInfos,
        int32_t userId = Constants::INVALID_USER_ID) const;
    /**
     * @brief DataProxy if Ignore Visibility.
     * @param formId The Id of the form.
     * @return Returns true if DataProxy Update, others on false.
     */
    bool IsDataProxyIgnoreFormVisibility(const int64_t formId) const;
    /**
     * @brief Reset dataProxy update flag.
     * @param formId The Id of the form.
     */
    void ResetDataProxyUpdate (const int64_t formId);
    /**
     * @brief set dataProxy update.
     * @param formId The Id of the form.
     */
    void SetDataProxyUpdate(const int64_t formId);
    /**
     * @brief Get published form record by formId.
     * @param bundleName Bundle name.
     * @param formInfo The form record.
     * @param formId The Id of the form.
     * @param userId User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetPublishedFormInfoById(const std::string &bundleName, RunningFormInfo &formInfo,
        const int64_t &formId, int32_t userId = Constants::INVALID_USER_ID) const;
    /**
     * @brief Get published form records.
     * @param bundleName Bundle name.
     * @param formInfos The form record list.
     * @param userId User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetPublishedFormInfos(const std::string &bundleName, std::vector<RunningFormInfo> &formInfos,
        int32_t userId = Constants::INVALID_USER_ID) const;

    /**
     * @param conditionType refresh type.
     * @param formInfos The form record list.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormRecordByCondition(int32_t conditionType, std::vector<FormRecord> &formInfos) const;
    /**
     * @brief Get temporary form record.
     * @param formTempRecords The temp form record.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetTempFormRecord(std::vector<FormRecord> &formTempRecords);
    /**
     * @brief Check form record is exist.
     * @param formId The Id of the form.
     * @return Returns true if the form record is exist; returns false is not exist.
     */
    bool ExistFormRecord(const int64_t formId) const;
    /**
     * @brief Has form user uids in form record.
     * @param formId The Id of the form.
     * @return Returns true if this form has form user uids; returns false is not has.
     */
    bool HasFormUserUids(const int64_t formId) const;
    /**
     * @brief Get form host record.
     * @param formId The id of the form.
     * @param formHostRecords The form host records.
     */
    void GetFormHostRecord(const int64_t formId, std::vector<FormHostRecord> &formHostRecords) const;

    /**
     * @brief Get form host remote object.
     * @param formId The id of the form.
     * @param formHostObjs The form host remote object.
     */
    void GetFormHostRemoteObj(const int64_t formId, std::vector<sptr<IRemoteObject>> &formHostObjs) const;
    /**
     * @brief Delete form host record.
     * @param callerToken The client stub of the form host record.
     * @param formId The id of the form.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteHostRecord(const sptr<IRemoteObject> &callerToken, const int64_t formId);
    /**
     * @brief Handle form host died.
     * @param remoteHost Form host proxy object.
     */
    void HandleHostDied(const sptr<IRemoteObject> &remoteHost);
    /**
     * @brief Refresh enable or not.
     * @param formId The Id of the form.
     * @return true on enable, false on disable.
     */
    bool IsEnableRefresh(int64_t formId);
    /**
     * @brief update enable or not.
     * @param formId The Id of the form.
     * @return true on enable, false on disable.
     */
    bool IsEnableUpdate(int64_t formId);
    /**
     * @brief Check calling uid is valid.
     * @param formUserUids The form user uids.
     * @return Returns true if this user uid is valid; returns false otherwise.
     */
    bool IsCallingUidValid(const std::vector<int> &formUserUids) const;
    /**
     * @brief Generate udid.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GenerateUdidHash();
    /**
     * @brief Padding udid hash.
     * @param formId The form id.
     * @return Padded form id.
     */
    int64_t PaddingUdidHash(int64_t formId);
    /**
     * @brief Generate form id.
     * @return form id.
     */
    int64_t GenerateFormId();
    /**
     * @brief Get udid.
     * @return udid.
     */
    int64_t GetUdidHash() const;
    /**
     * @brief Set udid.
     * @param udidHash udid.
     */
    void SetUdidHash(const int64_t udidHash);

    /**
     * @brief Get the matched form host record by client stub.
     *
     * @param callerToken The client stub of the form host record.
     * @param formHostRecord The form host record.
     * @return Returns true if this function is successfully called, returns false otherwise.
     */
    bool GetMatchedHostClient(const sptr<IRemoteObject> &callerToken, FormHostRecord &formHostRecord) const;

    /**
     * @brief Set needRefresh for FormRecord.
     * @param formId The Id of the form.
     * @param needRefresh true or false.
     */
    void SetNeedRefresh(const int64_t formId, const bool needRefresh);

    /**
     * @brief Set refreshType for FormRecord.
     * @param formId The Id of the form.
     * @param needRefresh true or false.
     */
    void SetRefreshType(const int64_t formId, const int refreshType);

    /**
     * @brief Get refreshType for FormRecord.
     * @param formId The Id of the form.
     * @param refreshType the form refresh type.
     */
    void GetRefreshType(const int64_t formId, int &refreshType);

    /**
     * @brief Set needAddForm for FormRecord.
     * @param formId The Id of the form.
     * @param needAddForm true or false.
     */
    void SetNeedAddForm(const int64_t formId, const bool needAddForm);

    /**
     * @brief Set isCountTimerRefresh for FormRecord.
     * @param formId The Id of the form.
     * @param countTimerRefresh true or false.
     */
    void SetCountTimerRefresh(const int64_t formId, const bool countTimerRefresh);

    /**
     * @brief Set timerRefresh for FormRecord.
     * @param formId The Id of the form.
     * @param timerRefresh true or false.
     */
    void SetTimerRefresh(const int64_t formId, const bool timerRefresh);

    /**
    * @brief Set isHostRefresh for FormRecord.
    * @param formId The Id of the form.
    * @param hostRefresh true or false.
    */
    void SetHostRefresh(const int64_t formId, const bool hostRefresh);

    /**
    * @brief Clear want cache for FormRecord.
    * @param formId The Id of the form.
    */
    void ClearWantCache(const int64_t formId);

    /**
    * @brief Clear host refresh flag.
    * @param formId The Id of the form.
    */
    void ClearHostRefreshFlag(const int64_t formId);

    /**
     * @brief Get updated form info.
     * @param record FormRecord.
     * @param targetForms Target forms.
     * @param updatedForm Updated form info.
     * @return Returns true on success, false on failure.
     */
    bool GetUpdatedForm(const FormRecord &record, const std::vector<FormInfo> &targetForms, FormInfo &updatedForm);
    /**
     * @brief Set isEnableUpdate for FormRecord.
     * @param formId The Id of the form.
     * @param enableUpdate true or false.
     */
    void SetEnableUpdate(const int64_t formId, const bool enableUpdate);
    /**
     * @brief Set update info for FormRecord.
     * @param formId The Id of the form.
     * @param enableUpdate true or false.
     * @param updateDuration Update duration.
     * @param updateAtHour Update at hour.
     * @param updateAtMin Update at minute.
     * @param updateAtTimes Update times.
     */
    void SetUpdateInfo(const int64_t formId, const bool enableUpdate, const long updateDuration,
    const int updateAtHour, const int updateAtMin, std::vector<std::vector<int>> updateAtTimes);
    /**
     * @brief Clean removed form records.
     * @param bundleName BundleName.
     * @param removedForms The id list of the forms.
     */
    void CleanRemovedFormRecords(const std::string &bundleName, std::set<int64_t> &removedForms);
    /**
     * @brief Clean removed temp form records.
     * @param  bundleName BundleName.
     * @param removedForms The id list of the forms.
     */
    void CleanRemovedTempFormRecords(const std::string &bundleName, const int32_t userId,
        std::set<int64_t> &removedForms);
    /**
     * @brief Get recreate form records.
     * @param reCreateForms The id list of the forms.
     */
    void GetReCreateFormRecordsByBundleName(const std::string &bundleName, std::set<int64_t> &reCreateForms);
    /**
     * @brief Set form isInited = true.
     * @param formId The Id of the form.
     * @param isInited isInited property
     */
    void SetFormCacheInited(const int64_t formId, const bool isInited);
    /**
     * @brief Set versionUpgrade.
     * @param formId The Id of the form.
     * @param versionUpgrade true or false
     */
    void SetVersionUpgrade(const int64_t formId, const bool versionUpgrade);
    /**
     * @brief Update form for host clients.
     * @param formId The Id of the form.
     * @param needRefresh true or false
     */
    void UpdateHostNeedRefresh(const int64_t formId, const bool needRefresh);
    /**
     * @brief Update form for host clients.
     * @param formId The Id of the form.
     * @param formRecord The form info.
     * @return Returns true if form update, false if other.
     */
    bool UpdateHostForm(const int64_t formId, const FormRecord &formRecord);
    /**
     * @brief handle update form flag.
     * @param formIDs The id of the forms.
     * @param callerToken Caller ability token.
     * @param flag form flag.
     * @param isOnlyEnableUpdate form enable update form flag.
     * @param refreshForms Refresh forms
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateHostFormFlag(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                               bool flag, bool isOnlyEnableUpdate, std::vector<int64_t> &refreshForms);
    /**
     * @brief Find matched form id.
     * @param formId The form id.
     * @return Matched form id.
     */
    int64_t FindMatchedFormId(const int64_t formId);
    /**
     * @brief Clear host data by uId.
     * @param uId The caller uId.
     */
    void ClearHostDataByUId(const int uId);
    /**
     * @brief Get no host temp forms.
     * @param uid The caller uid.
     * @param noHostTempFormsMap no host temp forms.
     * @param foundFormsMap Form Id list.
     */
    void GetNoHostTempForms(const int uid, std::map<FormIdKey, std::set<int64_t>> &noHostTempFormsMap,
        std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief delete forms by userId.
     *
     * @param userId user ID.
     * @param removedFormIds removed userId.
     */
    void DeleteFormsByUserId(const int32_t userId, std::vector<int64_t> &removedFormIds);
    /**
    * @brief Clear form records for st limit value test.
    */
    void ClearFormRecords();

    /**
     * @brief handle get no host invalid temp forms.
     * @param userId User ID.
     * @param callingUid The UID of the proxy.
     * @param matchedFormIds The set of the valid forms.
     * @param noHostTempFormsMap The map of the no host forms.
     * @param foundFormsMap The map of the found forms.
     */
    void GetNoHostInvalidTempForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                   std::map<FormIdKey, std::set<int64_t>> &noHostTempFormsMap,
                                   std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief handle delete no host temp forms.
     * @param callingUid The UID of the proxy.
     * @param noHostTempFormsMap The map of the no host forms.
     * @param foundFormsMap The map of the found forms.
     */
    void BatchDeleteNoHostTempForms(int32_t callingUid, std::map<FormIdKey, std::set<int64_t>> &noHostTempFormsMap,
                                    std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief delete invalid temp forms.
     * @param userId User ID.
     * @param callingUid The UID of the proxy.
     * @param matchedFormIds The set of the valid forms.
     * @param removedFormsMap The map of the removed invalid forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t DeleteInvalidTempForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                   std::map<int64_t, bool> &removedFormsMap);

    /**
     * @brief clear host data by invalid forms.
     * @param callingUid The UID of the proxy.
     * @param removedFormsMap The map of the removed invalid forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t ClearHostDataByInvalidForms(int32_t callingUid, std::map<int64_t, bool> &removedFormsMap);

    /**
     * @brief delete publish forms temp data
     * @param userId User ID.
     * @param bundleName BundleName.
     * @param validFormIds The set of the valid forms.
     * @return Returns -
     */
    void DeleteInvalidPublishForms(int32_t userId, std::string bundleName, std::set<int64_t> &validFormIds);

    /**
     * @brief Create form acquire data host record.
     * @param requestCode The request code of this acquire form.
     * @param info The form item info.
     * @param callerToken  Caller ability token.
     * @param callingUid The UID of the proxy.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool CreateFormAcquireDataRecord(int64_t requestCode, const FormItemInfo &info,
                                     const sptr<IRemoteObject> &callerToken, int callingUid);

    /**
     * @brief Create form state host record.
     * @param provider The provider of the form state
     * @param info The form item info.
     * @param callerToken The UID of the proxy.
     * @param callingUid The UID of the proxy.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool CreateFormStateRecord(std::string &provider, const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
                               int callingUid);

    /**
     * @brief acquire form state callback.
     * @param state form state.
     * @param provider provider info.
     * @param want The want of onAcquireFormState.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    ErrCode AcquireFormStateBack(AppExecFwk::FormState state, const std::string &provider, const Want &want);

    /**
     * @brief acquire form data callback.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    ErrCode AcquireFormDataBack(const AAFwk::WantParams &wantParams, int64_t requestCode);

    /**
     * @brief Notify the form is visible or not.
     * @param formIds Indicates the ID of the forms.
     * @param isVisible Visible or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                               const sptr<IRemoteObject> &callerToken);

    /**
     * @brief set form record visible.
     * @param matchedFormId form id.
     * @param isVisible is visible.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    ErrCode SetRecordVisible(int64_t matchedFormId, bool isVisible);

    /**
     * @brief add request publish form info.
     * @param formId The form id of the form to publish.
     * @param want The want of the form to publish.
     * @param formProviderData The form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddRequestPublishFormInfo(int64_t formId, const Want &want,
                                      std::unique_ptr<FormProviderData> &formProviderData);

    /**
     * @brief remove request publish form info.
     * @param formId The form id of the form to publish.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    ErrCode RemoveRequestPublishFormInfo(int64_t formId);

    /**
     * @brief check whether request publish form info.
      * @param formId The form id of the form to publish.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool IsRequestPublishForm(int64_t formId);

    /**
     * @brief get request publish form info.
     * @param formId The form id of the form to publish.
     * @param want The want of the form to publish.
     * @param formProviderData The form data.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    ErrCode GetRequestPublishFormInfo(int64_t formId, Want &want,
                                      std::unique_ptr<FormProviderData> &formProviderData);
    /**
     * @brief Get updated form info.
     * @param record Indicates the form record.
     * @param bundlePackInfo Indicates the BundlePackInfo object.
     * @param abilityFormInfo Indicates the obtained abilityFormInfo object.
     * @return Returns true on success, false on failure.
     */
    bool GetPackageForm(const FormRecord &record, const BundlePackInfo &bundlePackInfo,
        AbilityFormInfo &abilityFormInfo);

    /**
     * @brief Set form free install flag.
     * @param formId Indicates the form ID.
     * @param isNeedFreeInstall Indicates the free install flag is true or false.
     * @return Returns true on success, false on failure.
     */
    bool SetRecordNeedFreeInstall(int64_t formId, bool isNeedFreeInstall);

    /**
     * @brief StopRenderingForm.
     * @param formId The form id.
     */
    void StopRenderingForm(int32_t formId);

    /**
     * @brief update host forms
     * @param updateFormIds
     */
    void UpdateHostForms(const std::vector<int64_t> &updateFormIds);

    /**
     * @brief Checks that the form is valid.
     * @param formId Indicates the form ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CheckInvalidForm(const int64_t formId);

    /**
    * @brief get cast forms count.
    * @param formCount Returns the number of the cast form.
    * @return Return the cast forms number.
    */
    int32_t GetCastFormsCount(int32_t &formCount);

    /**
    * @brief get temp forms count.
    * @return Return the temp forms number.
    */
    int32_t GetTempFormCount() const;

    /**
    * @brief get temp forms count.
    * @param formCount Returns the number of the temp form.
    * @return Return the temp forms number.
    */
    int32_t GetTempFormsCount(int32_t &formCount);

    /**
    * @brief get host forms count.
    * @param bundleName Indicates form host bundleName.
    * @param formCount Returns the number of the host form.
    * @return Return the host forms number.
    */
    int32_t GetHostFormsCount(const std::string &bundleName, int32_t &formCount);

    /**
    * @brief handle form add observer.
    * @param hostBundleName the bundle name of form host.
    * @param formId Indicates the form ID.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode HandleFormAddObserver(const std::string hostBundleName, const int64_t formId);

    /**
    * @brief handle form add observer.
    * @param hostBundleName the bundle name of form host.
    * @param runningFormInfo the running forms' infos of the specify application name.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode HandleFormRemoveObserver(const std::string hostBundleName, const RunningFormInfo runningFormInfo);

    /**
     * @brief Get the running form infos by form id.
     * @param formId Indicates the form ID.
     * @param runningFormInfos Return the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfosByFormId(const int64_t formId, RunningFormInfo &runningFormInfo);

    /**
     * @brief Get all running form infos.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos currently.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos);

    /**
     * @brief Get the running form infos by bundle name.
     * @param bundleName Application name.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos);

    /**
     * @brief Get form instances by filter info.
     * @param formInstancesFilter includes bundleName, moduleName, formName, abilityName to get formInstances.
     * @param formInstances return formInstances
     * @return return ERR_OK on get info success,other on failure.
     */
    ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances);

    /**
     * @brief Get form instance by formId.
     * @param formId formId Indicates the unique id of form.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstances);

    /**
     * @brief Get form instance by formId, include form store in DB.
     * @param formId formId Indicates the unique id of form.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstances);

    /**
     * @brief Set form config map.
     * @param configMap form config map.
     */
    void SetConfigMap(const std::map<std::string, int32_t> &configMap);

    /**
     * @brief Get form config param form map.
     * @param key the param's name.
     * @param value the return value.
     */
    void GetConfigParamFormMap(const std::string &key, int32_t &value) const;

    /**
     * @brief Recycle all recyclable forms.
     */
    void RecycleAllRecyclableForms() const;

    /**
     * @brief Recycle forms.
     * @param formIds Indicates the ID of the forms.
     * @param callingUid The uid of caller.
     * @param want The want of forms to be recycled.
     */
    void RecycleForms(const std::vector<int64_t> &formIds, const int &callingUid, const Want &want) const;

    /**
     * @brief Update the form cloud update duration by bundleName.
     * @param bundleName The specified bundleName.
     * @param duration The form cloud update duration.
     */
    void UpdateFormCloudUpdateDuration(const std::string &bundleName, int duration);

    /**
     * @brief Remove the form cloud update duration by bundleName.
     * @param bundleName The specified bundleName.
     */
    void RemoveFormCloudUpdateDuration(const std::string &bundleName);

    /**
     * @brief Get the form cloud update duration by bundleName.
     * @param bundleName The specified bundleName.
     */
    int GetFormCloudUpdateDuration(const std::string &bundleName) const;

    /**
     * @brief Determine if the form cloud update duration exists by bundleName.
     * @param bundleName The specified bundleName.
     */
    bool HasFormCloudUpdateDuration(const std::string &bundleName) const;

    /**
     * @brief Update form location.
     * @param formId The Id of the form.
     * @param formLocation The form location.
     * @param hostBundleName the bundle name of form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation);

    /**
     * @brief Get the formRecords by refreshType.
     * @param formRefreshType form refresh type.
     * @param visibleFormRecords Return the visible forms' infos need to refresh.
     * @param invisibleFormRecords Return the invisible forms' infos need to refresh.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRecordsByFormType(const int32_t formRefreshType,
        std::vector<FormRecord> &visibleFormRecords, std::vector<FormRecord> &invisibleFormRecords);

    /**
     * @brief Set form lock or dislock.
     * @param formId The Id of the form.
     * @param lock Ture or false.
     */
    ErrCode SetFormLock(const int64_t formId, const bool lock);

    /**
     * @brief Set form lock or dislock.
     * @param formId The Id of the form.
     * @param lock Ture or false.
     */
    ErrCode GetFormLock(const int64_t formId, bool &lock);

    /**
     * @brief Set form protect or disprotect.
     * @param formId The Id of the form.
     * @param protect Ture or false.
     */
    ErrCode SetFormProtect(const int64_t formId, const bool protect);

    /**
     * @brief Set form protect or disprotect.
     * @param formId The Id of the form.
     * @param protect Ture or false.
     */
    ErrCode GetFormProtect(const int64_t formId, bool &protect);

    /**
     * @brief Set form enable or disable.
     * @param formId The Id of the form.
     * @param enable Ture or false.
     */
    ErrCode SetFormEnable(const int64_t formId, const bool enable);

     /**
     * @brief Set form refresh flag or in disable during.
     * @param formId The Id of the form.
     * @param enable Ture or false.
     */
    ErrCode SetRefreshDuringDisableForm(const int64_t formId, const bool enable);

     /**
     * @brief Set form update flag or in disable during.
     * @param formId The Id of the form.
     * @param enable Ture or false.
     */
    ErrCode SetUpdateDuringDisableForm(const int64_t formId, const bool enable);

    /**
     * @brief protect forms style.
     * @param formRecords The Id list of the formRecord.
     * @param protect True is protect form, false is unprotect form.
     */
    void LockForms(const std::vector<FormRecord> &&formRecords, const bool protect);

    /**
     * @brief Enable forms style.
     * @param formRecords The Id list of the formRecord.
     * @param enable True is enable form, false is disable form.
     */
    void EnableForms(const std::vector<FormRecord> &&formRecords, const bool enable);

    /**
     * @brief Check if form is abnormal.
     * @param formIds The list of formId.
     */
    void CheckForms(const std::vector<int64_t> &formIds);

    /**
     * @brief Get all formIds by userId.
     * @param userId User ID.
     * @param formIds The list of formId.
     */
    void GetFormIdsByUserId(int32_t userId, std::vector<int64_t> &formIds);

    /**
     * @brief Recheck whether need clean form host.
     * @param callerToken The client stub of the form host record.
     */
    bool RecheckWhetherNeedCleanFormHost(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Cache the visibility of the card.
     * @param formId form id.
     * @param isVisible is visible.
     */
    void SetFormVisible(int64_t formId, bool isVisible);

    /**
     * @brief Delete Cache of card visibility.
     * @param formId form id.
     */
    void DeleteFormVisible(int64_t formId);

    /**
     * @brief Check if the card can be updated.
     * @param formId form id.
     */
    bool GetFormCanUpdate(int64_t formId);

    /**
     * @brief merge form new want to old want.
     * @param newWant new want info.
     * @param oldWant old want info.
     */
    void MergeFormWant(const Want &newWant, Want &oldWant);

    /**
     * @brief Update form want.
     * @param formId form id.
     * @param want new want.
     * @param record form record info.
     */
    void UpdateFormWant(const int64_t formId, const Want &want, FormRecord &record);

    /**
     * @brief Get all formRecord by userId.
     * @param userId User ID.
     * @param formRecords The list of formRecord.
     */
    void GetFormRecordsByUserId(const int32_t userId, std::vector<FormRecord> &formRecords);

    /**
     * @brief get formRecord by formId
     * @param formId form id.
     * @param formRecord form record.
     * @return Returns true on success, false on failure.
     */
    bool GetFormRecordById(const int64_t formId, FormRecord& formRecord);

    /**
     * @brief make new formRecord by source record
     * @param formRecord form record.
     * @return Returns new formRecord.
     */
    FormRecord GetFormAbilityInfo(const FormRecord &record) const;

    /**
     * @brief Update formRecord isExistRecycleTask.
     * @param formId The id of the forms.
     * @param isExistRecycleTask Whether the form exist recycle task.
     * @return Returns true on success, false on failure.
     */
    bool UpdateFormRecordSetIsExistRecycleTask(const int64_t formId, bool isExistRecycleTask);

    /**
     * @brief Record low memory state.
     * @param isLowMemory is low memory.
     */
    void SetIsLowMemory(bool isLowMemory);

    /**
     * @brief Get low memory state.
     * @return Returns true on low memory state.
     */
    bool IsLowMemory() const;

    /**
     * @brief Set form specification.
     * @param formId The Id of the form.
     * @param specification specification.
     */
    ErrCode SetSpecification(const int64_t formId, const int32_t specification);

    /**
     * @brief Get the visibility of the card.
     * @param formId form id.
     */
    bool GetFormVisible(int64_t formId);

    /**
     * @brief set expect recycled status
     * @param formIds The list of formId.
     * @param isExpectRecycled isExpectRecycled
     */
    void SetExpectRecycledStatus(const std::vector<int64_t> &formIds, bool isExpectRecycled);

    /**
     * @brief set expect recycled status
     * @param formId formId.
     * @param isExpectRecycled isExpectRecycled
     */
    void SetExpectRecycledStatus(int64_t formId, bool isExpectRecycled);

    /**
     * @brief get expect recycled status
     * @param formId form id.
     * @return Returns true if the form should be recycled
     */
    bool IsExpectRecycled(int64_t formId);

    /**
     * @brief Get form record.
     * @param bundleName Bundle name.
     * @param moduleName module name.
     * @param formRecords The form record list.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool GetFormRecord(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormRecord> &formRecords) const;

    /**
     * @brief due control forms style.
     * @param formRecords The Id list of the formRecord.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @param isControl True is control form, false is not control form.
     */
    void DueControlForms(const std::vector<FormRecord> &&formRecords, const bool isDisablePolicy, const bool isControl);

    /**
     * @brief Get transparencyFormCapabilityKey value.
     * @return Returns transparencyFormCapabilityKey value.
     */
    const std::string& GetTransparencyFormCapabilityKey();

    /**
     * @brief Get form upgrade info from formRecord.
     * @return Returns true on success, false on failure.
     */
    bool GetFormUpgradeInfo(const int64_t formId, FormUpgradeInfo& formUpgradeInfo) const;

    /**
     * @brief Update form upgrade info.
     * @param formId The Id of the form.
     * @param FormUpgradeInfo The form upgrade info.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UpdateFormUpgradeInfo(const int64_t formId, const FormUpgradeInfo& formUpgradeInfo);

    /**
     * @brief Set transparent form color form for host clients.
     * @param formId The Id of the form.
     * @param transparencyColor The transparency color.
     */
    void SetHostTransparentFormColor(const int64_t formId, const std::string &transparencyColor);

    /**
     * @brief Delete transparent form color form for host clients.
     * @param formId The Id of the form.
     */
    void DelHostTransparentFormColor(const int64_t formId);

    /**
     * @brief Get addFormFinish and set isNeedUpdateFormOnAddFormFinish flag atomic method.
     * @param formId The Id of the form.
     * @return Returns value of addFormFinish.
     */
    bool GetAddfinishAndSetUpdateFlag(const int64_t formId);

    /**
     * @brief Is needUpdate On addFinish atomic method.
     * @param formId The Id of the form.
     * @param formRecord form record.
     * @return Returns value of IsNeedUpdate.
     */
    bool GetIsNeedUpdateOnAddFinish(const int64_t formId, FormRecord &formRecord);

    /**
    * @brief Merges form data into the provider data.
    * @param formId The Id of the form.
    * @param formProviderData The target FormProviderData to receive the merged data.
    * @return Returns true if this function is successfully called; returns false otherwise.
    */
    bool MergeFormData(const int64_t formId, FormProviderData &formProviderData);
private:
    /**
     * @brief Create form record.
     * @param formInfo The form item info.
     * @param callingUid The UID of the proxy.
     * @param userId User ID.
     * @return Form record.
     */
    FormRecord CreateFormRecord(const FormItemInfo &formInfo, const int callingUid,
        const int32_t userId = Constants::DEFAULT_USER_ID) const;

    /**
     * @brief Create host record.
     * @param info The form item info.
     * @param callerToken The UID of the proxy.
     * @param callingUid The UID of the proxy.
     * @param record The form host record.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool CreateHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const int callingUid, FormHostRecord &record);

    /**
     * @brief Parse update config.
     * @param record The form record.
     * @param info The form item info.
     * @return None.
     */
    void ParseUpdateConfig(FormRecord &record, const FormItemInfo &info) const;

    /**
     * @brief Parse update interval config.
     * @param record The form record.
     * @param configDuration interval duration.
     */
    void ParseIntervalConfig(FormRecord &record, const int configDuration) const;

    /**
     * @brief Parse multi update time config.
     * @param record The form record.
     * @param info form item info.
     */
    void ParseMultiUpdateTimeConfig(FormRecord &record, const FormItemInfo &info) const;

    /**
     * @brief Parse at time config.
     * @param record The form record.
     * @param info form item info.
     */
    void ParseAtTimerConfig(FormRecord &record, const FormItemInfo &info) const;

    /**
     * @brief Get the temp forms from host and delete temp form in cache.
     * @param record The form record.
     * @param recordTempForms the temp forms.
     */
    void HandleHostDiedForTempForms(const FormHostRecord &record, std::vector<int64_t> &recordTempForms);

    /**
     * @brief Check if two forms is same or not.
     * @param record FormRecord.
     * @param formInfo FormInfo.
     * @return Returns true on success, false on failure.
     */
    bool IsSameForm(const FormRecord &record, const FormInfo &formInfo);

    /**
     * @brief Check if two forms is same or not.
     * @param record Indicates the form record.
     * @param abilityFormInfo Indicates the AbilityFormInfo.
     * @return Returns true on success, false on failure.
     */
    bool IsSameForm(const FormRecord &record, const AbilityFormInfo &abilityFormInfo);

    /**
     * @brief check if form cached.
     * @param record The form record.
     * @return Returns ERR_OK on cached, others on not cached.
     */
    bool IsFormCached(const FormRecord record);

    /**
    * @brief handle update form flag.
    * @param formIDs The id of the forms.
    * @param flag form flag.
    * @param isOnlyEnableUpdate form enable update form flag.
    * @param formHostRecord form host record.
    * @param refreshForms Refresh forms
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode HandleUpdateHostFormFlag(const std::vector<int64_t> &formIds, bool flag, bool isOnlyEnableUpdate,
                                     FormHostRecord &formHostRecord, std::vector<int64_t> &refreshForms);

    /**
     * @brief Fill the basic running form info by form record.
     * @param formRecord The form record.
     * @param runningFormInfo Return the running forms' info.
     */
    void FillBasicRunningFormInfoByFormRecord(const FormRecord &formRecord,
                                              RunningFormInfo &runningFormInfo) const;
    /**
    * @brief Get ability form info.
    * @param record Indicates form record.
    * @param abilities Indicates the ModuleAbilityInfo in FA model or ExtensionAbilities in stage model.
    * @param abilityFormInfo Indicates the obtained abilityFormInfo object.
    * @return Returns ERR_OK on success, others on failure.
    */
    template<typename T>
    bool GetAbilityFormInfo(const FormRecord &record, const std::vector<T> &abilities,
        AbilityFormInfo &abilityFormInfo);

    /**
     * @brief post delay RecheckWhetherNeedCleanFormHost task.
     * @param callerUid The calleruid of FormHostRecord of vector<FormHostRecord> clientRecords_.
     * @param remoteObjectOfHost The client stub of the form host record.
     */
    void PostDelayRecheckWhetherNeedCleanFormHostTask(
        const int callerUid, const sptr<IRemoteObject> &remoteObjectOfHost);

    /**
     * @brief Init low memory state.
     */
    void InitLowMemoryStatus();

    /**
     * @brief Init transparencyFormCapbilityKey.
     */
    void InitTransparencyFormCapabilityKey();

private:
    void GetUnusedFormInstancesByFilter(
        const FormInstancesFilter &formInstancesFilter, std::vector<FormInstance> &formInstances);
    ErrCode GetUnusedFormInstanceById(const int64_t formId, FormInstance &formInstance);
    void GetUnusedFormInfos(std::vector<RunningFormInfo> &runningFormInfos);
    void GetUnusedFormInfos(const std::string &bundleName, std::vector<RunningFormInfo> &runningFormInfos);
    void DeleteRecordTempForms(const std::vector<int64_t> &recordTempForms);

    mutable std::mutex formRecordMutex_;
    mutable std::mutex formHostRecordMutex_;
    mutable std::mutex formTempMutex_;
    mutable std::mutex formStateRecordMutex_;
    mutable std::mutex formRequestPublishFormsMutex_;
    mutable std::mutex formAcquireDataRecordMutex_;
    mutable std::mutex formConfigMapMutex_;
    mutable std::mutex formCloudUpdateDurationMapMutex_;
    mutable std::shared_mutex formVisibleMapMutex_;
    std::map<int64_t, FormRecord> formRecords_;
    std::vector<FormHostRecord> clientRecords_;
    std::vector<int64_t> tempForms_;
    std::map<std::string, FormHostRecord> formStateRecord_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formAddObservers_;
    std::map<int32_t, FormHostRecord> formAcquireDataRecord_;
    using FormRequestPublishFormInfo = std::pair<Want, std::unique_ptr<FormProviderData>>;
    std::map<int64_t, FormRequestPublishFormInfo> formRequestPublishForms_;
    int64_t udidHash_ = 0;
    std::vector<sptr<IRemoteObject>> formObservers_;
    std::map<std::string, int32_t> formConfigMap_;
    std::unordered_map<std::string, int> formCloudUpdateDurationMap_;
    std::unordered_map<int64_t, bool> formVisibleMap_;
    std::atomic_bool isLowMemory_ = false;
    std::string transparencyFormCapabilityKey_ = "";
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_FORM_DATA_MGR_H
