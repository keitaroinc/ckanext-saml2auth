from ckan.plugins.interfaces import Interface


class ISaml2Auth(Interface):
    u'''
    This interface allows plugins to hook into the Saml2 authorization flow
    '''
    def before_saml2_user_update(self, user_dict, saml_attributes):
        u'''
        Called just before updating an existing user

        :param user_dict: User metadata dict that will be passed to user_update
        :param saml_attributes: A dict containing extra SAML attributes returned
            as part of the SAML Response
        '''
        pass

    def before_saml2_user_create(self, user_dict, saml_attributes):
        u'''
        Called just before creating a new user

        :param user_dict: User metadata dict that will be passed to user_create
        :param saml_attributes: A dict containing extra SAML attributes returned
            as part of the SAML Response
        '''
        pass

    def after_saml2_login(self, resp, saml_attributes):
        u'''
        Called once the user has been logged in programatically, just before
        returning the request. The logged in user can be accessed using g.user
        or g.userobj

        :param resp: A Flask response object. Can be used to issue
            redirects, add headers, etc
        :param saml_attributes: A dict containing extra SAML attributes returned
            as part of the SAML Response
        '''
        pass
