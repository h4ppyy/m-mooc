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
connection = cx_Oracle.connect("scott", "tiger", "oracle11g:1521/xe")
print("    Version:", connection.version)
print("  User Name:", connection.username)
print("Connect TNS:", connection.tnsentry)

cursor = connection.cursor()
#cursor.execute("select count(*) from vw_history_rsum")
#for cnt in cursor:
#    print("Values:", cnt)

cursor.execute("select * from vw_history_rsum")

for dt in cursor:
    print("data:", dt)

