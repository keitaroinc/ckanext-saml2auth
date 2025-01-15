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
from saml2.saml import NameID

log = logging.getLogger(__name__)


def set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = code(subject_id)


def get_subject_id(session):
    try:
        return decode(session['_saml2_subject_id'])
    except KeyError:
        return None


def set_saml_session_info(session, saml_session_info):
    """Adds information about pysaml2 AuthnResponse to CKAN's session.

    `pysaml2` returns a NameID object in the session_info() call. Since we want
    to serialize the object to write it into the cookie we need to convert it.
    `name_id` is the same as `_saml2_subject_id` so we apply `code` as we do in
    `set_subject_id`.

    We are not sure if it always return an object, so we checking to be sure.
    """
    if isinstance(saml_session_info['name_id'], NameID):
        saml_session_info['name_id'] = code(saml_session_info['name_id'])
    session['_saml_session_info'] = saml_session_info


def get_saml_session_info(session):
    """Returns the saml session info from the session object.

    The session object is serializable but pysaml expect a NameID object as
    name_id, so we are decoding it again as we do in get_subject_id.
    """
    try:
        session_info = session['_saml_session_info']
    except KeyError:
        return None

    if isinstance(session_info['name_id'], str):
        session_info['name_id'] = decode(session_info['name_id'])

    return session_info
