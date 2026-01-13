# encoding: utf-8
"""
Copyright (c) 2020 Keitaro AB

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import logging

from saml2.ident import code, decode

log = logging.getLogger(__name__)


def set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = code(subject_id)


def get_subject_id(session):
    try:
        return decode(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    # In CKAN 2.11 with Flask, session data must be JSON serializable
    # Convert NameID object to string for JSON compatibility
    serializable_info = saml_session_info.copy()
    if 'name_id' in serializable_info:
        # Use code() to serialize the NameID object
        serializable_info['name_id'] = code(serializable_info['name_id'])
    session['_saml_session_info'] = serializable_info


def get_saml_session_info(session):
    try:
        session_info = session['_saml_session_info']
        # In CKAN 2.11, name_id was encoded for JSON serialization
        # Decode it back to NameID object if it's a string
        if session_info and 'name_id' in session_info:
            if isinstance(session_info['name_id'], str):
                session_info = session_info.copy()
                session_info['name_id'] = decode(session_info['name_id'])
        return session_info
    except KeyError:
        return None
