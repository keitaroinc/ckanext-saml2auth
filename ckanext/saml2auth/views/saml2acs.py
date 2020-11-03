# encoding: utf-8
from flask import Blueprint
import ckan.plugins.toolkit as toolkit

saml2acs = Blueprint(u'saml2acs', __name__)


def acs():
    return toolkit.redirect_to('home.index')


saml2acs.add_url_rule(u'/acs', view_func=acs, methods=[u'GET', u'POST'])
