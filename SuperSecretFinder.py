#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# The original SecretFinder: Burp Suite Extension to find and search apikeys/tokens from a webpage 
# by m4ll0k
# https://github.com/m4ll0k
# Additional Regex added by: Nullifidian
# https://github.com/Nullifidian/SuperSecretFinder/blob/main/SuperSecretFinder.py

# Code Credits:
# OpenSecurityResearch CustomPassiveScanner: https://github.com/OpenSecurityResearch/CustomPassiveScanner
# PortSwigger example-scanner-checks: https://github.com/PortSwigger/example-scanner-checks
# https://github.com/redhuntlabs/BurpSuite-Asset_Discover/blob/master/Asset_Discover.py

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re
import binascii
import base64
import xml.sax.saxutils as saxutils


class BurpExtender(IBurpExtender, IScannerCheck):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("SecretFinder")
        self._callbacks.registerScannerCheck(self)
        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # add your regex here
    regexs = {
        'google_api' : 'AIza[0-9A-Za-z-_]{35}',
        'google_captcha' : '6L[0-9A-Za-z-_]{38}',
        'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+',
        'amazon_aws_access_key_id' : 'AKIA[0-9A-Z]{16}',
        'amazon_mws_auth_toke' : 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'amazon_aws_url' : 's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
        'facebook_access_token' : 'EAACEdEose0cBA[0-9A-Za-z]+',
        'authorization_basic' : 'basic\s*[a-zA-Z0-9=:_\+\/-]+',
        'authorization_bearer' : 'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
        'authorization_api' : 'api[key|\s*]+[a-zA-Z0-9_\-]+',
        'mailgun_api_key' : 'key-[0-9a-zA-Z]{32}',
        'twilio_api_key' : 'SK[0-9a-fA-F]{32}',
        'twilio_account_sid' : 'AC[a-zA-Z0-9_\-]{32}',
        'twilio_app_sid' : 'AP[a-zA-Z0-9_\-]{32}',
        'paypal_braintree_access_token' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'square_oauth_secret' : 'sq0csp-[ 0-9A-Za-z\-_]{43}',
        'square_access_token' : 'sqOatp-[0-9A-Za-z\-_]{22}',
        'stripe_standard_api' : 'sk_live_[0-9a-zA-Z]{24}',
        'stripe_restricted_api' : 'rk_live_[0-9a-zA-Z]{24}',
        'github_access_token' : '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
        'rsa_private_key' : '-----BEGIN RSA PRIVATE KEY-----',
        'ssh_dsa_private_key' : '-----BEGIN DSA PRIVATE KEY-----',
        'ssh_dc_private_key' : '-----BEGIN EC PRIVATE KEY-----',
        'pgp_private_block' : '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'json_web_token' : 'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*',
        'Major Credit Cards' : '\b(1800|2131|30[0-5]\d|3[4-7]\d{2}|4\d{3}|5[0-5]\d{2}|6011|6[2357]\d{2})[- ]?(\d{4}[- ]?\d{4}[- ]?\d{4}|\d{6}[- ]?\d{5})\b',
        'Austrian Social Security' : '\b\d{4}(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-5])\d{2}\b',
        'Bulgarian Uniform Civil Number' : '\b\d{2}([024][1-9]|[135][0-2])(0[1-9]|[12]\d|3[01])[-+]?\d{4}\b',	
        'Canadian Social Insurance' : '\b[1-9]\d{2}[- ]?\d{3}[- ]?\d{3}\b',
        'Chinese National ID' : '\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{4}\b',
        'Croatian Master Citizen' : '\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(9\d{2}|0[01]\d)\d{6}\b',
        'Danish Civil Registration' : '\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2}[-+]?\d{4}\b',
        'Finnish Social Security' : '\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2}[-+a]\d{3}\w\b',
        'Indian Permanent Account' : '\b[a-z]{3}[abcfghjlpt][a-z]\d{4}[a-z]\b',
        'Indian Vehicle License Plate' : '\b([a-z]{2}[ ]\d{1,2}|dl[ ][1-9]?\d[ ][cprstvy])[ ][a-z]{0,2}[ ]\d{1,4}\b',
        'Italian Fiscal Code' : '\b([bcdfghj-np-tv-z][a-z]{2}){2}\d{2}[a-ehlmprst]([04][1-9]|[1256]\d|[37][01])(\d[a-z]{3}|z\d{3})[a-z]\b',
        'Norwegian Personal Numeric Code' : '\b(0[1-9]|[12]\d|3[01])([04][1-9]|[15][0-2])\d{7}\b',
        'Romanian Personal Numeric Code' : '\b[1-8]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(0[1-9]|[1-4]\d|5[0-2]|99)\d{4}\b',
        'South Korean Resident Registration' : '\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\-[0-49]\d{6}\b',
        'Swedish Personal ID#' : '\b(19\d{2}|20\d{2}|\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-+]?\d{4}\b',
        'Taiwanese National ID#' : '\b[a-z][12]\d{8}\b',
        'United Kingdom National Insurance' : '\b[abceghj-prstw-z][abceghj-nprstw-z][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[a-dfm]?\b',
        'United States Social Security' : '\b(?!000)(?!666)([0-6]\d{2}|7([0-356]\d|7[012]))[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b',
        'Sybase Error' : 'Warning.*?\Wsybase_',
        'Sybase Error' : 'Sybase message',
        'Sybase Error' : 'Sybase.*?Server message',
        'Sybase Error' : 'SybSQLException',
        'Sybase Error' : 'Sybase\.Data\.AseClient',
        'Sybase Error' : 'com\.sybase\.jdbc',
        'SQLite Error' : 'SQLite/JDBCDriver',	
        'SQLite Error' : 'SQLite\.Exception',
        'SQLite Error' : '(Microsoft|System)\.Data\.SQLite\.SQLiteException',
        'SQLite Error' : 'Warning.*?\W(sqlite_|SQLite3::)',
        'SQLite Error' : '\[SQLITE_ERROR\]',
        'SQLite Error' : 'sqlite3.OperationalError:',
        'SQLite Error' : 'SQLite3::SQLException',
        'SQLite Error' : 'org\.sqlite\.JDBC',
        'SQLite Error' : 'Pdo[./_\\]Sqlite',
        'SQLite Error' : 'SQLiteException',
        'SAP_MaxDB_Error' : 'SQL error.*?POS([0-9]+)',
        'SAP_MaxDB_Error' : 'Warning.*?\Wmaxdb_',
        'SAP_MaxDB_Error' : 'DriverSapDB',
        'SAP_MaxDB_Error' : 'com\.sap\.dbtech\.jdbc',
        'PostgreSQL_Error' : 'PostgreSQL.*?ERROR',
        'PostgreSQL_Error' : 'Warning.*?\Wpg_',
        'PostgreSQL_Error' : 'valid PostgreSQL result',
        'PostgreSQL_Error' : 'Npgsql\.',
        'PostgreSQL_Error' : 'PG::SyntaxError:',
        'PostgreSQL_Error' : 'org\.postgresql\.util\.PSQLException',
        'PostgreSQL_Error' : 'ERROR:\s\ssyntax error at or near',
        'PostgreSQL_Error' : 'ERROR: parser: parse error at or near',
        'PostgreSQL_Error' : 'PostgreSQL query failed',
        'PostgreSQL_Error' : 'org\.postgresql\.jdbc',
        'PostgreSQL_Error' : 'Pdo[./_\\]Pgsql',
        'PostgreSQL_Error' : 'PSQLException',
        'Oracle_Error' : '\bORA-\d{5}',
        'Oracle_Error' : 'Oracle error',
        'Oracle_Error' : 'Oracle.*?Driver',
        'Oracle_Error' : 'Warning.*?\W(oci|ora)_',
        'Oracle_Error' : 'quoted string not properly terminated',
        'Oracle_Error' : 'SQL command not properly ended',
        'Oracle_Error' : 'macromedia\.jdbc\.oracle',
        'Oracle_Error' : 'oracle\.jdbc',
        'Oracle_Error' : 'Zend_Db_(Adapter|Statement)_Oracle_Exception',
        'Oracle_Error' : 'Pdo[./_\\](Oracle|OCI)',
        'Oracle_Error' : 'OracleException',
        'MySQL_Error' : 'SQL syntax.*?MySQL',
        'MySQL_Error' : 'Warning.*?\Wmysqli?_',
        'MySQL_Error' : 'MySQLSyntaxErrorException',
        'MySQL_Error' : 'valid MySQL result',
        'MySQL_Error' : 'check the manual that corresponds to your (MySQL|MariaDB) server version',
        'MySQL_Error' : 'MySqlClient\.',
        'MySQL_Error' : 'com\.mysql\.jdbc',
        'MySQL_Error' : 'Zend_Db_(Adapter|Statement)_Mysqli_Exception',
        'MySQL_Error' : 'Pdo[./_\\]Mysql',
        'MySQL_Error' : 'MySqlException',
        'MS_SQL_Server_Error' : 'Driver.*? SQL[\-\_\ ]*Server',
        'MS_SQL_Server_Error' : 'OLE DB.*? SQL Server',
        'MS_SQL_Server_Error' : '\bSQL Server[^&lt;&quot;]+Driver',
        'MS_SQL_Server_Error' : 'Warning.*?\W(mssql|sqlsrv)_',
        'MS_SQL_Server_Error' : '\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}',
        'MS_SQL_Server_Error' : 'System\.Data\.SqlClient\.SqlException',
        'MS_SQL_Server_Error' : '(?s)Exception.*?\bRoadhouse\.Cms\.',
        'MS_SQL_Server_Error' : '\[SQL Server\]',
        'MS_SQL_Server_Error' : 'ODBC SQL Server Driver',
        'MS_SQL_Server_Error' : 'ODBC Driver \d+ for SQL Server',
        'MS_SQL_Server_Error' : 'SQLServer JDBC Driver',
        'MS_SQL_Server_Error' : 'com\.jnetdirect\.jsql',
        'MS_SQL_Server_Error' : 'macromedia\.jdbc\.sqlserver',
        'MS_SQL_Server_Error' : 'Zend_Db_(Adapter|Statement)_Sqlsrv_Exception',
        'MS_SQL_Server_Error' : 'com\.microsoft\.sqlserver\.jdbc',
        'MS_SQL_Server_Error' : 'Pdo[./_\\](Mssql|SqlSrv)',
        'MS_SQL_Server_Error' : 'SQL(Srv|Server)Exception',
        'MS_Access_Error' : 'Microsoft Access (\d+ )?Driver',
        'MS_Access_Error' : 'JET Database Engine',
        'MS_Access_Error' : 'Access Database Engine',
        'MS_Access_Error' : 'ODBC Microsoft Access',
        'MS_Access_Error' : 'Syntax error \(missing operator\) in query expression',
        'Interbase_Firebired_Error' : 'Dynamic SQL Error',
        'Interbase_Firebired_Error' : 'Warning.*?\Wibase_',
        'Interbase_Firebired_Error' : 'org\.firebirdsql\.jdbc',
        'Interbase_Firebired_Error' : 'Pdo[./_\\]Firebird',
        'Ingres_Error' : 'Warning.*?\Wingres_',
        'Ingres_Error' : 'Ingres SQLSTATE',
        'Ingres_Error' : 'Ingres\W.*?Driver',
        'Ingres_Error' : 'com\.ingres\.gcf\.jdbc',
        'Informix_Error' : 'Warning.*?\Wifx_',
        'Informix_Error' : 'Exception.*?Informix',
        'Informix_Error' : 'Informix ODBC Driver',
        'Informix_Error' : 'ODBC Informix driver',
        'Informix_Error' : 'com\.informix\.jdbc',
        'Informix_Error' : 'weblogic\.jdbc\.informix',
        'Informix_Error' : 'Pdo[./_\\]Informix',
        'Informix_Error' : 'IfxException',
        'IBM_DB2_Error' : 'CLI Driver.*?DB2',
        'IBM_DB2_Error' : 'DB2 SQL error',
        'IBM_DB2_Error' : '\bdb2_\w+\(',
        'IBM_DB2_Error' : 'SQLSTATE.+SQLCODE',
        'IBM_DB2_Error' : 'com\.ibm\.db2\.jcc',
        'IBM_DB2_Error' : 'Zend_Db_(Adapter|Statement)_Db2_Exception',
        'IBM_DB2_Error' : 'Pdo[./_\\]Ibm',
        'IBM_DB2_Error' : 'DB2Exception',
        'HSQLDB_Error' : 'Unexpected end of command in statement \["',
        'HSQLDB_Error' : 'Unexpected token.*?in statement \[',
        'HSQLDB_Error' : 'org\.hsqldb\.jdbc',
        'H2_Error' : 'org\.h2\.jdbc',
        'Frontbase_error' : 'Exception (condition )?\d+\. Transaction rollback',
        'Frontbase_error' : 'com\.frontbase\.jdbc',
        'GOOGLE_OAUTH_ID' : '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'MAILCHIMP_API_KEY' : '[0-9a-f]{32}-us[0-9]{1,2}',
        'TWITTER_ACCESS_TOKEN' : '[1-9][0-9]+-[0-9a-zA-Z]{40}',
        'google_captcha' : '6L[0-9A-Za-z-_]{38}',
        'BRAINTREE_ACCESS_TOKEN' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'GOOGLE_API_KEY' : 'AIza[0-9A-Za-z-_]{35}',
        'GOOGLE_API_KEY' : 'AIza[0-9A-Za-z\-_]{35}',
        'AMAZON_AUTH_TOKEN' : 'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'ATOMIST_API_KEY' : '\b[A-F0-9]{64}\b',
        'AMAZON_ACCESS_KEY' : '\bAK[0-9A-Z]{18}\b',
        'FACEBOOK_ACCESS_TOKEN' : 'EAACEdEose0cBA[0-9A-Za-z]+',
        'heroku_api' : '[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
        'URL_PASSWORD' : '((?:ht|f|sm)tps?:\/\/[^:/?#\[\]@""<>{}|\\^``\s]+:)[^:/?#\[\]@""<>{}|\\^``\s]+@',
        'slack_webhook' : 'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'GITHUB_TOKEN' : '(https?:\/\/)(?:v1\.)?[a-f0-9]{40}((?::x-oauth-basic)?@)',
        'MAILGUN_KEY' : 'key-[0-9a-zA-Z]{32}',
        'STRIPE_RESTRICTED_API_KEY' : 'rk_live_[0-9a-zA-Z]{24}',
        'TWILLIO_API_KEY' : 'SK[0-9a-fA-F]{32}',
        'PICATIC_API_KEY' : 'sk_live_[0-9a-z]{32}',
        'STRIPE_REGULAR_API_KEY' : 'sk_live_[0-9a-zA-Z]{24}',
        'SQUARE_OAUTH_TOKEN' : 'sq0atp-[0-9A-Za-z\-_]{22}',
        'SQUARE_OAUTH_SECRET' : 'sq0csp-[ 0-9A-Za-z\-_]{43}',
        'SQUARE_OAUTH_SECRET' : 'sq0csp-[0-9A-Za-z\-_]{43}',
        'SQUARE_OAUTH_SECRET' : 'sqOatp-[0-9A-Za-z\-_]{22}',
        'slack_token' : '(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
        'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+'
    }
    regex = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}](%%regex%%)[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
    issuename = "SecretFinder: %s"
    issuelevel = "Information"
    issuedetail = r"""Potential Secret Find: <b>%%regex%%</b>
    <br><br><b>Note:</b> Please note that some of these issues could be false positives, a manual review is recommended."""

    def doActiveScan(self, baseRequestResponse,pa):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]), 
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])),
                BurpExtender.ssuelevel, 
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        tmp_issues = []

        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)


        for reg in self.regexs.items():
            tmp_issues = self._CustomScans.findRegEx(
                BurpExtender.regex.replace(r'%%regex%%',reg[1]),
                BurpExtender.issuename%(' '.join([x.title() for x in reg[0].split('_')])), 
                BurpExtender.issuelevel,
                BurpExtender.issuedetail
                )
            scan_issues = scan_issues + tmp_issues

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._mime_type = self._helpers.analyzeResponse(self._requestResponse.getResponse()).getStatedMimeType()
        return

    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        print(self._mime_type)
        if '.js' in str(self._requestResponse.getUrl()):
            print(self._mime_type)
            print(self._requestResponse.getUrl())
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        if self._callbacks.isInScope(self._helpers.analyzeRequest(self._requestResponse).getUrl()):
            myre = re.compile(regex, re.VERBOSE)
            encoded_resp=binascii.b2a_base64(self._helpers.bytesToString(response))
            decoded_resp=base64.b64decode(encoded_resp)
            decoded_resp = saxutils.unescape(decoded_resp)

            match_vals = myre.findall(decoded_resp)

            for ref in match_vals:
                url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
                offsets = []
                start = self._helpers.indexOf(response,
                                    ref, True, 0, responseLength)
                offset[0] = start
                offset[1] = start + len(ref)
                offsets.append(offset)

                try:
                    print("%s : %s"%(issuename.split(':')[1],ref))
                    scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                        self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                        [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                        issuename, issuelevel, issuedetail.replace(r"%%regex%%", ref)))
                except:
                    continue
        return (scan_issues)

class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"
