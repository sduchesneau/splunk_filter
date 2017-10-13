#!/usr/bin/env python

import ldap
import getopt
import sys, os
from cftools.cf import CF
from cftools.logger import logger
from config import config

SUCCESS     = "--status=success"
FAILED      = "--status=fail"

def userLogin( info ):
    
    found_user = False

    BIND_DN = 'cn=' + info['username'] + ',' + config.ldap.ldap_user_root
    BIND_PASS = info['password']

    logger.info('userLogin - message="User logging in with domain and username"  username="%s"' % ( BIND_DN ))
    logger.info('userLogin - message="LDAP server %s"' % ( config.ldap.ldap_server ))

    try:

        ldap_connection = ldap.initialize(config.ldap.ldap_server)   
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
        ldap.set_option( ldap.OPT_X_TLS_DEMAND, True )
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        
        # Debug Mode, uncomment this to see debug level information on the command line
        #ldap.set_option( ldap.OPT_DEBUG_LEVEL, 255 )

        auth = ldap_connection.simple_bind_s(BIND_DN, BIND_PASS)

        found_user = True

    except Exception, e:
        pass

    if found_user:
        print SUCCESS
        logger.info('message="Login Success" type="login" outcome="success" user="%s" script_return="%s" domain_controller="%s"' % ( BIND_DN, SUCCESS, config.ldap.ldap_server ))

    else:
        print FAILED
        logger.info('message="Login Failure" type="login" outcome="failure" user="%s" script_return="%s" domain_controller="%s"' % ( BIND_DN, FAILED, config.ldap.ldap_server ) )

def getUserInfo( infoIn ):
    
    try:
        cf = CF(config.cloudfoundry.cf_url)
    except Exception, e:
        logger.error('getUserInfo - message="unable to call PCF", curl="%s", exception=%s' % ( config.cloudfoundry.cf_url,e ))
        return
    
    try:
        cf.login(config.cloudfoundry.admin_user, config.cloudfoundry.admin_password)
    except Exception, e:
        logger.error('getUserInfo - message="invalid PCF credentials", curl="%s" - admin_user="%s", exception=%s' % ( config.cloudfoundry.cf_url, config.cloudfoundry.admin_user, e ))
        return

    try:
        usr = cf.search_user(infoIn['username'])
        if usr == None:
            raise Exception("No User Found")
        user_role = 'user'
        if isOrgManager(infoIn['username'], cf):
            logger.debug('Setting %s to power user' % infoIn['username'])
            user_role = 'power'
        outStr = SUCCESS + ' --userInfo=;' + usr['entity']['username'] + ';;' + user_role

        print outStr
    except Exception, e:
        logger.error('getUserInfo - message="Error when searching user", curl="%s" - username="%s", exception=%s' % ( config.cloudfoundry.cf_url, infoIn['username'], e ))
        print FAILED


def isOrgManager(user_name, cf):
    try:
        usr = cf.search_user(user_name)
        if usr == None:
            return False
        managed_orgs = cf._search(usr.get('entity').get('managed_organizations_url'))
        if managed_orgs == None:
            return False
        active_managed_orgs = [org for org in managed_orgs 
                               if org.get('entity').get('status') == u'active']
        if len(active_managed_orgs) > 0:
            return True

        return False
    except Exception, e:
        logger.error(e)
        logger.error('isOrgManager - message="Error when getting managed organizations", curl="%s" - username="%s"' % ( config.cloudfoundry.cf_url, user_name ))
        return False

def getUsers( infoIn ):
        
    print SUCCESS + ' --userInfo=;admin;;admin'

def getSearchFilter(infoIn):
    if not infoIn.has_key('username'):
        logger.error('getSearchFilter - called without username param')
        print FAILED
        return

    try:
        cf = CF(config.cloudfoundry.cf_url)
        cf.login(config.cloudfoundry.admin_user, config.cloudfoundry.admin_password)
    except Exception, e:
        logger.error('getSearchFilter - message="invalid PCF credentials", curl="%s" - admin_user="%s", exception=' % ( config.cloudfoundry.cf_url, config.cloudfoundry.admin_user, e ))
        print FAILED
        return
    
    try:
        usr = cf.search_user(infoIn['username'])
        if usr == None:
            raise Exception
    except:
        logger.error('getSearchFilter - message="Cannot find user in PCF", username="%s"' % infoIn['username'] )
        print FAILED
        return
    
    try:
        orgs = cf.search_orgs(usr['entity']['organizations_url'])

        if len(orgs) >= 1:
            appIndexFilter = 'index='+ config.splunk.app_index_name + ' '
            sysIndexFilter = 'index='+ config.splunk.system_index_name
            
            filter = ''

            sysLogFilter = False

            for org in orgs:
                
                '''
                If user is in Infra-org, add syslogs filter
                ''' 
                if (org['entity']['name'] == 'Infra-org'):
                    sysLogFilter = True

                currentFilter = 'host='  + org['entity']['name'] + '.*'

                if filter != '':
                    filter += ' OR '

                filter+= currentFilter
                
            allFilter = '(' + appIndexFilter + filter + ')'
            if sysLogFilter:
                allFilter += ' OR ' + '(' + sysIndexFilter + ')'

            print SUCCESS + ' --search_filter=' + allFilter
        else:
            logger.error('getSearchFilter - message="no PCF organization found for", username="%s"' % ( infoIn['username'] ))
            print FAILED    
    except:
        
        logger.error('getSearchFilter - message="method being called for an invalid user", username="%s"' % ( infoIn['username'] ))
        print FAILED

def readinputs():
    
   '''
    reads the inputs coming in and put them in a dict for processing.
   '''
   optlist, args = getopt.getopt(sys.stdin.readlines(), '', ['username=', 'password='])

   returnDict = {}
   for name, value in optlist:
      returnDict[name[2:]] = value.strip()

   return returnDict

def checkusername(username):
    
    if not username:
        return ''
            
    if "\\" in username['username']:
        return "domain_user"
    else:
        return ''

if __name__ == "__main__":
    
    logging = logger()
    logger = logging.get_logger('ldap_auth')


    callname = sys.argv[1]

    dictin = readinputs()
    #usertype = checkusername(dictin)

    if callname == "userLogin": 
        userLogin( dictin )
    elif callname == "getUsers":
        getUsers( dictin )
    elif callname == "getUserInfo":
        getUserInfo( dictin )
    elif callname == "getSearchFilter":
        getSearchFilter( dictin )
    else:
        print "ERROR unknown function call: " + callname
