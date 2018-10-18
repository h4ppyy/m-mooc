"""
import cx_Oracle

conn = cx_Oracle.connect('scott', 'tiger', 'localhost:1521/xe')
print (conn.version)

db = conn.cursor()
#db.execute('select * from vw_history_rsum')
db.execute('select count(*) from vw_history_rsum')

for rec in db:
    print (rec)

#print (db.fetchall())

db.close()
conn.close()
"""

# myscript.py

from __future__ import print_function

import cx_Oracle
import os
import uuid

if 1==2:
    q = ". /edx/app/edxapp/edx-platform/lms/djangoapps/branding/insert_member.sh edx mih5@mobis.co.kr mih5nm"
    status = os.system(q)
    print(status)

if 1==1:
    print("Oracle 11g Connect test start...:")

    # Connect as user "hr" with password "welcome" to the "oraclepdb" service running on this computer.
    #connection = cx_Oracle.connect("scott", "tiger", "localhost/xe")
    #connection = cx_Oracle.connect("IMIF_SWA", "Swa$2018", "10.10.163.73:1521/imdb")
    connection = cx_Oracle.connect("SWAUSER", "mbora#SW252", "10.230.22.252:1521/mobispdm")
    print("    Version:", connection.version)
    print("  User Name:", connection.username)
    print("Connect TNS:", connection.tnsentry)

    cursor = connection.cursor()
    #cursor.execute("select count(*) from vw_history_rsum")
    #for cnt in cursor:
    #    print("Values:", cnt)

    #cursor.execute("select USER_ID ,USER_NM ,DUTY_CD ,DUTY_NM_HOME ,DEPT_CD ,DEPT_NM ,USER_GRADE_CODE ,JW_NM_HOME from WFUSER.VW_HISTORY_SWA")
    os.putenv('NLS_LANG', 'UTF8')
    sql = """
                    SELECT
                         USER_ID
                        ,NVL(USER_KN,\'\') USER_KN
                        ,NVL(USER_EN,\'\') USER_EN
                        ,NVL(ORGTX_DIV,\'\') ORGTX_DIV
                        ,NVL(DEPT_NM,\'\') DEPT_NM
                        ,NVL(POSN_NM,\'\') POSN_NM
                    FROM MERP.VW_USER_IM
                    ORDER BY USER_ID ASC
            """
    cursor.execute(sql)

    for dt in cursor:
        print("data:", dt)

    cursor.close()
    connection.close()

if 1==2:
    print("Oracle 11g Connect test start...:")

    # Connect as user "hr" with password "welcome" to the "oraclepdb" service running on this computer.
    #connection = cx_Oracle.connect("scott", "tiger", "localhost/xe")
    connection = cx_Oracle.connect("IMIF_SWA", "Swa$2018", "10.10.163.73:1521/imdb")
    print("    Version:", connection.version)
    print("  User Name:", connection.username)
    print("Connect TNS:", connection.tnsentry)

    cursor = connection.cursor()
    #cursor.execute("select count(*) from vw_history_rsum")
    #for cnt in cursor:
    #    print("Values:", cnt)

    #cursor.execute("select USER_ID ,USER_NM ,DUTY_CD ,DUTY_NM_HOME ,DEPT_CD ,DEPT_NM ,USER_GRADE_CODE ,JW_NM_HOME from WFUSER.VW_HISTORY_SWA")

    sql = """
         SELECT
             USER_ID
            ,NVL(USER_NM,\'\') USER_NM
            ,DUTY_CD
            ,DUTY_NM_HOME
            ,DEPT_CD
            ,NVL(DEPT_NM,\'\') DEPT_NM
            ,USER_GRADE_CODE
            ,NVL(JW_NM_HOME,\'\') JW_NM_HOME
        FROM WFUSER.VW_HISTORY_SWA
       """

    cursor.execute(sql)

    f = open('bat.sh', 'w')
    for dt in cursor:
        print("data:", dt[0], dt[1], dt[0]+"@mobis.co.kr")
        # 32 bytes password
        _uuid = uuid.uuid4().__str__()
        _uuid = _uuid.replace('-', '')

        q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings aws create_user -p {uid} -e {email} -u {username}""".format(uid=_uuid, email=dt[0]+"@mobis.co.kr", username=dt[0])
        f.write(q)
        f.write('\n')

    f.close()

    cursor.close()
    connection.close()

