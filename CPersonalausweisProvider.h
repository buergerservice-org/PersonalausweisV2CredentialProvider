

#include "helpers.h"
#include <windows.h>
#include <strsafe.h>
#include <new>
#include <vector>
#include "CPersonalausweisCredential.h"

class CPersonalausweisProvider : public ICredentialProvider,
                        public ICredentialProviderSetUserArray
{
  public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CPersonalausweisProvider, ICredentialProvider), // IID_ICredentialProvider
            QITABENT(CPersonalausweisProvider, ICredentialProviderSetUserArray), // IID_ICredentialProviderSetUserArray
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(_In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const *pcpcs);

    IFACEMETHODIMP Advise(_In_ ICredentialProviderEvents *pcpe, _In_ UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(_Out_ DWORD *pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd);

    IFACEMETHODIMP GetCredentialCount(_Out_ DWORD *pdwCount,
                                      _Out_ DWORD *pdwDefault,
                                      _Out_ BOOL *pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc);

    IFACEMETHODIMP SetUserArray(_In_ ICredentialProviderUserArray *users);

    friend HRESULT CPersonalausweis_CreateInstance(_In_ REFIID riid, _Outptr_ void** ppv);
    

  protected:
    CPersonalausweisProvider();
    __override ~CPersonalausweisProvider();

  private:
    void _ReleaseEnumeratedCredentials();
    void _CreateEnumeratedCredentials();
    HRESULT _EnumerateEmpty();
    HRESULT _EnumerateCredentials();
    HRESULT _EnumerateCredential(DWORD i);
    HRESULT _EnumerateEmptyTileCredential();
    bool credentialschanged;

private:
    long _cRef;            // Used for reference counting.
    //CPersonalausweisCredential                       _pCredential Vector;    // SampleV2Credential
    std::vector<CPersonalausweisCredential*> _pCredential;
    bool _fRecreateEnumeratedCredentials;
    ICredentialProviderEvents* _pcpe;// Used to tell our owner to re-enumerate credentials.
    UINT_PTR _upAdviseContext;       // Used to tell our owner who we are when asking to 
                                     // re-enumerate credentials.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    ICredentialProviderUserArray            *_pCredProviderUserArray;
    std::string credentialkey;
};
