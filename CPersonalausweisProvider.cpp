

#include <initguid.h>
#include "CPersonalausweisProvider.h"
#include "CPersonalausweisCredential.h"
#include "guid.h"

CPersonalausweisProvider::CPersonalausweisProvider():
    _cRef(1),
    //_pCredential(nullptr),
    _pCredProviderUserArray(nullptr)
{
    DllAddRef();
    credentialschanged = false;
    credentialkey = "";
}

CPersonalausweisProvider::~CPersonalausweisProvider()
{
    //if (_pCredential != nullptr)
    //{
    //    _pCredential->Release();
    //    _pCredential = nullptr;
    //}
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    system("taskkill /f /im AusweisApp2.exe");

    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CPersonalausweisProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    case CPUS_PLAP:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CPersonalausweisProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT CPersonalausweisProvider::Advise(
    _In_ ICredentialProviderEvents * pcpe,
    _In_ UINT_PTR upAdviseContext)
{
    if (_pcpe != NULL)
    {
        _pcpe->Release();
    }
    _pcpe = pcpe;
    _pcpe->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
    //return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CPersonalausweisProvider::UnAdvise()
{
    if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }
    return S_OK;
    //return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CPersonalausweisProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CPersonalausweisProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT CPersonalausweisProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    /*
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = TRUE;

   
    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }

    *pdwCount = 1;

    return S_OK;
    */
    * pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    HRESULT hr;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }
    
    
    DWORD dwUserCount;
    /*
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {
            for (DWORD i = 0; i < dwUserCount; i++) {
                if (_pCredential[i]->credentialready && !_pCredential[i]->lastLoginFailed) {
                    *pdwCount = 1;
                    *pdwDefault = 0;
                    *pbAutoLogonWithDefault = TRUE;
                    credentialkey = _pCredential[i]->credentialkey;
                    if (_pCredential[i] != nullptr)
                    {
                        _pCredential[i]->Release();
                        _pCredential[i] = nullptr;
                    }
                    _EnumerateCredential(i);
                    _pCredential[i]->credentialready = true;
                    
                    return S_OK;
                }
            }
        }
    }
    */

    if (_pCredProviderUserArray != nullptr) {
        hr = _pCredProviderUserArray->GetCount(&dwUserCount);
        if (hr == 0) {
        }
        else {
            dwUserCount = 1;
        }
    }
    else {
        dwUserCount = 1;
    }

    if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
        dwUserCount += 1;//display additional empty tile
    }
    *pdwCount = dwUserCount;
    


    return S_OK;
}





// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CPersonalausweisProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex < _pCredential.size()) && ppcpc)
    {
        hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
    
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CPersonalausweisProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}


void CPersonalausweisProvider::_CreateEnumeratedCredentials()
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
    default:
        break;
    }
}


void CPersonalausweisProvider::_ReleaseEnumeratedCredentials()
{

    //if (_pCredential != nullptr)
    //{
    //    _pCredential->Release();
    //    _pCredential = nullptr;
    //}
    
    for (DWORD i = 0; i < _pCredential.size(); i++) 
    {
        if (_pCredential[i] != nullptr)
        {
            _pCredential[i]->Release();
            _pCredential[i] = nullptr;
        }
    }
    _pCredential.clear();
}


HRESULT CPersonalausweisProvider::_EnumerateCredentials()
{
    /*
    HRESULT hr = E_UNEXPECTED;
    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount;
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {
            ICredentialProviderUser* pCredUser;
            hr = _pCredProviderUserArray->GetAt(0, &pCredUser);
            if (SUCCEEDED(hr))
            {
                _pCredential = new(std::nothrow) CPersonalausweisCredential();
                if (_pCredential != nullptr)
                {
                    hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                    if (FAILED(hr))
                    {
                        _pCredential->Release();
                        _pCredential = nullptr;
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
                pCredUser->Release();
            }
        }
    }

    return hr;
    */


        HRESULT hr = E_UNEXPECTED;
        DWORD dwUserCount;
        if (_pCredProviderUserArray != nullptr)
        {
            _pCredProviderUserArray->GetCount(&dwUserCount);
            if (dwUserCount > 0)
            {
                //You need to initialize all the fields in LogonUI for each and every user 
                for (DWORD i = 0; i < dwUserCount; i++) {
                    //if (i > 0 ) {
                        ICredentialProviderUser* pCredUser;
                        hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
                        if (SUCCEEDED(hr))
                        {
                            _pCredential.push_back(new(std::nothrow) CPersonalausweisCredential());
                            if (_pCredential[i] != nullptr)
                            {
                                hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser, _pcpe, _upAdviseContext, credentialkey);
                                if (FAILED(hr))
                                {
                                    _pCredential[i]->Release();
                                    _pCredential[i] = nullptr;
                                }
                            }
                            else
                            {
                                hr = E_OUTOFMEMORY;
                            }
                            pCredUser->Release();
                        }
                    //}
                }
            }
            //if you are in a domain or have no users on the list you have to show "Other user tile"
            if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
                _pCredential.push_back(new(std::nothrow) CPersonalausweisCredential());
                if (_pCredential[_pCredential.size() - 1] != nullptr) {
                    hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr, _pcpe, _upAdviseContext, credentialkey);
                }
            }
        }
        return hr;
}

HRESULT CPersonalausweisProvider::_EnumerateCredential(DWORD i)
{
    HRESULT hr = E_UNEXPECTED;
    DWORD dwUserCount;
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {
            ICredentialProviderUser* pCredUser;
            hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
            if (SUCCEEDED(hr))
            {
                _pCredential[i]= new (std::nothrow) CPersonalausweisCredential();
                //_pCredential.push_back(new(std::nothrow) CPersonalausweisCredential());
                if (_pCredential[i] != nullptr)
                {
                    hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser, _pcpe, _upAdviseContext, credentialkey);
                    if (FAILED(hr))
                    {
                        _pCredential[i]->Release();
                        _pCredential[i] = nullptr;
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
                pCredUser->Release();
            }
        }
        //if you are in a domain or have no users on the list you have to show "Other user tile"
        if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1)) {
            _pCredential.push_back(new(std::nothrow) CPersonalausweisCredential());
            if (_pCredential[_pCredential.size() - 1] != nullptr) {
                hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr, _pcpe, _upAdviseContext, credentialkey);
            }
        }
    }
    return hr;
}


// Boilerplate code to create our provider.
HRESULT CPersonalausweis_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CPersonalausweisProvider *pProvider = new(std::nothrow) CPersonalausweisProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
