#!/usr/bin/python2.7

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

    BIND_DN = 'cn=' + info['username'] + ',' + config.ldap.LDAP_USER_ROOT
    BIND_PASS = info['password']

    logger.info('userLogin - message="User logging in with domain and username"  username="%s"' % ( BIND_DN ))
    logger.info('userLogin - message="LDAP server %s"' % ( config.ldap.LDAP_SERVER ))

    try:

        ldap_connection = ldap.initialize(config.ldap.LDAP_SERVER)   
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
        logger.info('message="Login Success" type="login" outcome="success" user="%s" script_return="%s" domain_controller="%s"' % ( BIND_DN, SUCCESS, config.ldap.LDAP_SERVER ))

    else:
        print FAILED
        logger.info('message="Login Failure" type="login" outcome="failure" user="%s" script_return="%s" domain_controller="%s"' % ( BIND_DN, FAILED, config.ldap.LDAP_SERVER ) )

def getUserInfo( infoIn ):
    
    try:
        cf = CF(config.cloudfoundry.CF_URL)
    except Exception, e:
        print(e)
        logger.info('getUserInfo - message="unable to call PCF", curl="%s"' % ( config.cloudfoundry.CF_URL ))
    else:
        try:
            cf.login(config.cloudfoundry.admin_user, config.cloudfoundry.admin_password)
        except Exception, e:
            print(e)
            logger.info('getUserInfo - message="invalid PCF credentials", curl="%s" - admin_user="%s"' % ( config.cloudfoundry.CF_URL, config.cloudfoundry.admin_user ))
        else:
    
            try:
                usr = cf.search_user(infoIn['username'])
                outStr = SUCCESS + ' --userInfo=;' + usr['entity']['username'] + ';;user'

                print outStr
            except:
                logger.info('getUserInfo - message="Error when searching user", curl="%s" - username="%s"' % ( config.cloudfoundry.CF_URL, infoIn['username'] ))
                print FAILED

def getUsers( infoIn ):
        
    print SUCCESS + ' --userInfo=;admin;;admin'

def getSearchFilter(infoIn):

    try:
        cf = CF(config.cloudfoundry.CF_URL)
        cf.login(config.cloudfoundry.admin_user, config.cloudfoundry.admin_password)

        usr = cf.search_user(infoIn['username'])
        
    except:
        logger.info('getSearchFilter - message="invalid PCF credentials", curl="%s" - admin_user="%s"' % ( config.cloudfoundry.CF_URL, config.cloudfoundry.admin_user ))
        print FAILED

    else:
        try:
            orgs = cf.search_orgs(usr['entity']['organizations_url'])

            if len(orgs) > 1:
                indexFilter = '--search_filter=index=pcf_syslog ' % config.splunk.index_name
                filter = ''
                for org in orgs:
                   
                    currentFilter = 'host='  + org['entity']['name'] + '.*'

                    if filter != '':
                        filter += ' OR '

                    filter+= currentFilter

                print SUCCESS + ' ' + indexFilter + filter
            else:
                logger.info('getSearchFilter - message="no PCF organization found for", username="%s"' % ( infoIn['username'] ))
                print FAILED    
        except:
            
            logger.info('getSearchFilter - message="method being called for an invalid user", username="%s"' % ( infoIn['username'] ))
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
