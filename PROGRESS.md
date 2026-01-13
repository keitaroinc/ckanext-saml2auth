# CKAN 2.11 Migration Progress - ckanext-saml2auth

## Overview

Migrating ckanext-saml2auth from CKAN 2.9/2.10 to CKAN 2.11 (Python 3.10, Flask)

**Initial Test Results**: 13 failed, 28 passed, 2 skipped
**Current Test Results**: 5 failed, 36 passed, 2 skipped
**Progress**: 8 issues fixed ✅

---

## Issue 1: Flask Test Client Site URL Mismatch

**Problem**:
- Tests configured `ckan.site_url = 'http://test.ckan.net'` in multiple places (test.ini, conftest.py, test decorators)
- Flask's test client in CKAN 2.11 defaults to `http://localhost:5000` regardless of configuration
- SAML responses used `destination='http://test.ckan.net/acs'`
- pysaml2 validation failed: `destination 'http://test.ckan.net/acs' not in return addresses '['http://localhost:5000/acs']'`
- Resulted in 12 tests failing with `ValueError: Missing assertion`

**Root Cause**:
In CKAN 2.11, Flask's test client uses its own SERVER_NAME that overrides the configured `ckan.site_url`. The `toolkit.config.get('ckan.site_url')` returns `http://localhost:5000` during test execution, not the configured `http://test.ckan.net`.

**Solution**:
Updated all test fixtures and assertions to use `http://localhost:5000` instead of `http://test.ckan.net`:

**Files Modified**:
- `ckanext/saml2auth/tests/test_blueprint_get_request.py`:
  - `_prepare_unsigned_response()`: Changed destination/recipient URLs
  - `_load_base()`: Changed default destination parameter
  - Updated assertion_consumer_service config
  - Updated 3 redirect location assertions
- `ckanext/saml2auth/tests/test_blueprint.py`:
  - Updated 2 cookie domain assertions from 'test.ckan.net' to 'localhost'

**Result**: ✅ Fixed destination URL validation, "Missing assertion" errors resolved

---

## Issue 2: SAML Response Expired Timestamp

**Problem**:
After fixing Issue 1, tests failed with:
```
ResponseLifetimeExceed: Can't use response, too old
(now=2026-01-13T12:48:42Z + slack=0 > not_on_or_after=2024-01-18T06:21:48Z)
```

**Root Cause**:
The SAML response template `unsigned0.xml` had a hardcoded old timestamp:
```xml
<saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" ... />
```

**Solution**:
Made the timestamp dynamic:

1. Updated `unsigned0.xml`:
   - Changed hardcoded `NotOnOrAfter="2024-01-18T06:21:48Z"` to template variable `NotOnOrAfter="{{ not_on_or_after }}"`

2. Updated `_prepare_unsigned_response()` in `test_blueprint_get_request.py`:
   - Calculate `not_on_or_after` as current time + 5 minutes
   - Pass it to the template context

**Files Modified**:
- `ckanext/saml2auth/tests/responses/unsigned0.xml`
- `ckanext/saml2auth/tests/test_blueprint_get_request.py`

**Result**: ✅ SAML response timestamp validation now passes

---

## Issue 3: NameID Object Not JSON Serializable

**Problem**:
After fixing Issues 1-2, 9 tests failed with:
```
TypeError: Object of type NameID is not JSON serializable
```

**Root Cause**:
In CKAN 2.11 with Flask, session data must be JSON serializable. The `set_saml_session_info()` function stored a `saml_session_info` dict containing a `name_id` key with a NameID object (from pysaml2) directly into the Flask session. Flask's session serialization requires all data to be JSON-compatible.

In CKAN 2.9/2.10 with Pylons, session storage worked differently and could handle non-JSON-serializable objects.

**Solution**:
Updated `cache.py` to serialize/deserialize the NameID object:

1. `set_saml_session_info()`:
   - Copy the session_info dict
   - Use `code()` function (from `saml2.ident`) to encode the NameID object to a string
   - Store the serialized version in the session

2. `get_saml_session_info()`:
   - Retrieve the session_info from session
   - Check if `name_id` is a string (encoded)
   - Use `decode()` function to convert it back to a NameID object
   - Return the deserialized version for pysaml2 compatibility

This matches the pattern already used by `set_subject_id()` / `get_subject_id()`.

**Files Modified**:
- `ckanext/saml2auth/cache.py`

**Result**: ✅ Session serialization now works, 9 tests fixed

---

## Remaining Issues (5 tests failing)

### Issue 4: Plugin Missing 'name' Attribute (4 tests)

**Failing Tests**:
- `test_interface.py::TestInterface::test_after_login_is_called`
- `test_interface.py::TestInterface::test_before_create_is_called`
- `test_interface.py::TestInterface::test_before_update_is_called_on_saml_user`
- `test_interface.py::TestInterface::test_before_update_is_called_on_ckan_user`

**Error**: `AttributeError: 'ExampleISaml2AuthPlugin' object has no attribute 'name'`

**Status**: 🔍 Needs investigation

---

### Issue 5: Cookie Domain Empty String (1 test)

**Failing Test**:
- `test_blueprint.py::TestBlueprint::test_ckan_cookie_cleared_on_slo`

**Error**: `AssertionError: assert '' == 'localhost'`

**Details**: Cookie domain is empty string instead of expected 'localhost'

**Status**: 🔍 Needs investigation

---

## Summary of Changes

### Core Code Changes:
1. `ckanext/saml2auth/cache.py` - NameID serialization for Flask sessions
2. `ckanext/saml2auth/spconfig.py` - Extract acs_url variable (minor refactor)

### Test Changes:
1. `ckanext/saml2auth/tests/test_blueprint_get_request.py` - URL and timestamp fixes
2. `ckanext/saml2auth/tests/test_blueprint.py` - Cookie domain assertions
3. `ckanext/saml2auth/tests/responses/unsigned0.xml` - Dynamic timestamp

### Configuration:
No changes to production configuration needed.

---

## Key CKAN 2.11 Migration Learnings

1. **Flask Test Client URL**: Flask's test client in CKAN 2.11 uses `localhost:5000` by default, ignoring `ckan.site_url` configuration in tests

2. **Session Serialization**: Flask requires all session data to be JSON serializable. pysaml2 objects (NameID, etc.) must be encoded/decoded using `saml2.ident.code()` and `decode()`

3. **Test Configuration**: `@pytest.mark.ckan_config()` decorators don't override Flask test client's default URLs

---

*Migration started: 2026-01-13*
*Last updated: 2026-01-13*
