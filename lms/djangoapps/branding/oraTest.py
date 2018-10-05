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

#cursor.execute("select * from wfuser.vw_history_rsum")
#cursor.execute("select * from WFUSER.VW_HISTORY_SWA")
#cursor.execute("select 1+1  from dual")
#cursor.execute("select * from tab")
#cursor.execute("select * from tab")

cursor.execute("select USER_ID ,USER_NM ,DUTY_CD ,DUTY_NM_HOME ,DEPT_CD ,DEPT_NM ,USER_GRADE_CODE ,JW_NM_HOME from WFUSER.VW_HISTORY_SWA")

for dt in cursor:
    print("data:", dt)

cursor.close()
connection.close()

