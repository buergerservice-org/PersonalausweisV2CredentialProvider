

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE         = 0,
    SFI_LABEL             = 1,
    SFI_LARGE_TEXT        = 2,
    SFI_PASSWORD          = 3,
    SFI_SUBMIT_BUTTON     = 4,
    SFI_CERTIFICATE       = 5,
    SFI_PERSONALDATA      = 6,
    SFI_HASHKEY           = 7,
    SFI_INFO_LINK         = 8,
    SFI_FULLNAME_TEXT     = 9,
    SFI_DISPLAYNAME_TEXT  = 10,
    SFI_LOGONSTATUS_TEXT  = 11,
    SFI_CHECKBOX          = 12,
    SFI_EDIT_TEXT         = 13,
    SFI_COMBOBOX          = 14,
    SFI_NUM_FIELDS        = 15,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_LABEL
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_LARGE_TEXT
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_SUBMIT_BUTTON
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_CERTIFICATE
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_PERSONALDATA
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_HASHKEY
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_INFO
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_FULLNAME_TEXT
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_DISPLAYNAME_TEXT
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_LOGONSTATUS_TEXT
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_CHECKBOX
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_EDIT_TEXT
    { CPFS_HIDDEN,   CPFIS_NONE                      },    // SFI_COMBOBOX
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,    L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { SFI_LABEL,             CPFT_SMALL_TEXT,    L"Tooltip",                    CPFG_CREDENTIAL_PROVIDER_LABEL },
    { SFI_LARGE_TEXT,        CPFT_LARGE_TEXT,    L"Sample Credential Provider"                                 },
    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT, L"Password"                                                   },
    { SFI_SUBMIT_BUTTON,     CPFT_SUBMIT_BUTTON, L"Submit"                                                     },
    { SFI_PERSONALDATA,      CPFT_COMMAND_LINK,  L"Erzeuge Personalausweisschl�ssel"                           },
    { SFI_CERTIFICATE,       CPFT_COMMAND_LINK,  L"Zeige Zertifikat"                                           },
    { SFI_HASHKEY,           CPFT_COMMAND_LINK,  L"Zeige Personalausweisschl�ssel"                             },
    { SFI_INFO_LINK,         CPFT_COMMAND_LINK,  L"Info"                                                       },
    { SFI_FULLNAME_TEXT,     CPFT_SMALL_TEXT,    L"Full name: "                                                },
    { SFI_DISPLAYNAME_TEXT,  CPFT_SMALL_TEXT,    L"Display name: "                                             },
    { SFI_LOGONSTATUS_TEXT,  CPFT_SMALL_TEXT,    L"Logon status: "                                             },
    { SFI_CHECKBOX,          CPFT_CHECKBOX,      L"Checkbox"                                                   },
    { SFI_EDIT_TEXT,         CPFT_EDIT_TEXT,     L"Edit Text"                                                  },
    { SFI_COMBOBOX,          CPFT_COMBOBOX,      L"Combobox"                                                   },
};

static const PWSTR s_rgComboBoxStrings[] =
{
    L"First",
    L"Second",
    L"Third",
};
