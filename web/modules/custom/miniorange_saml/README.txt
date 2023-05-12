CONTENTS OF THIS FILE
---------------------
 * Introduction
 * Requirements/dependencies
 * Installation
 * Configuration
 * Setup Guides


INTRODUCTION
------------
miniOrange SAML 2.0 SSO allows users residing at SAML 2.0 compliant Identity Provider to login to your Drupal. We support all known IdPs - Google Apps, ADFS, Okta, Salesforce, Shibboleth, SimpleSAMLphp, OpenAM, Centrify, Ping, RSA, IBM, Oracle, OneLogin, Bitium, WSO2, NetIQ etc. If you need detailed instructions on setting up these IdPs, we can give you step by step instructions.


REQUIREMENTS/DEPENDENCIES
-------------------------
NONE


INSTALLATION
------------
1.	Uninstall the existing miniorange_saml ( if any ) module.
2.  Delete the existing miniorange_saml folder ( if any ) of the module from the Drupal directory.
3.	Paste this module folder on a same place and install the module from admin console of Drupal site.
4.	Run the Drupal update script using this URL :- <Base URL of Drupal site>/update.php


CONFIGURATION
-------------
 * Configure user permissions in Configuration » People » miniOrange SAML Login Configuration:

   - Setup Customer account with miniOrange (Optional)
     Login/Create account with miniOrange by entering email address, phone number and password.

   - Identity Provider Setup.
     Make note of the Service Provider information from Service Provider Metadata tab. This will be required to configure your IdP.

   - Service Provider Setup
     Configure the Drupal site to act as a Service Provider(SP). Information such as IdP Entity ID, x.509 certificate and SAML Login URL are taken from IdP and stored here.


SETUP GUIDES
------------
We provide details step by step setup guide for various IDPs
Please visit - https://plugins.miniorange.com/configure-drupal-saml-single-sign-on
Note: If you dont find guide for your desired IDP, please contact us at drupalsupport@xecurify.com