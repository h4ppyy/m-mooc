# -*- coding: utf-8 -*- 

import logging
import os
import cx_Oracle
import MySQLdb as mdb
import uuid

buf = {}
cnt_all = 0
cnt_true = 0
cnt_false = 0

def user_ora_human_update(rnn_go):
    #http://localhost:18000/userhumanupdate?rnn_go=1
    mycon = None
    mycur = None
    con = None
    cur = None
    try:
        results = []
        gMobis = True
        if gMobis:
            MOBIS_DB_USR = 'SWAUSER'
            MOBIS_DB_PWD = 'mbora#SW252'
            MOBIS_DB_SID = 'mobispdm'
            MOBIS_DB_IP = '10.230.22.252'
            MOBIS_DB_PORT = '1521'
        else:
            MOBIS_DB_USR = 'scott'
            MOBIS_DB_PWD = 'tiger'
            MOBIS_DB_SID = 'XE'
            MOBIS_DB_IP = 'localhost'
            MOBIS_DB_PORT = '1521'

        con = cx_Oracle.connect("SWAUSER", "mbora#SW252", "10.230.22.252:1521/mobispdm")
        os.putenv('NLS_LANG', 'UTF8')
        cur = con.cursor()

        sql = """select userenv('LANGUAGE') from dual"""
        cur.execute(sql)

        for row in cur.fetchall():
            print row

        query = """
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
        cur.execute(query)

        for row in cur.fetchall():
            results.append(row)

        mycon = None
        mycon = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')
        mycur = mycon.cursor()

        try:
            cnt = 0
            for row in results:
                cnt = cnt + 1
                user_id = row[0]    # USER_ID
                user_nm = row[1]    # USER_KN
                email = user_id+'@mobis.co.kr'    # email
                user_human_update(mycon, mycur, user_nm, user_id, email)
            print 'cnt_all:{0}, cnt_true:{1} cnt_false:{2}', cnt_all,  cnt_true, cnt_false
        except:
            print 'error {0}'.format(e)

        json_return = {}
        json_return['status'] = 'OK'
    except ora.DatabaseError as e:
        logging.info('Oracle SQL: %s', e)
        json_return = {}
        json_return['status'] = 'fail'
        return JsonResponse(json_return)
    finally:
        if mycur is not None:
            mycur.close()
        if mycon is not None:
            mycon.close()
        # cursor and connection close
        if cur is not None:
            cur.close()
        if con is not None:
            con.close()
        return 'OK'

def user_human_update(con, cur, user_nm, username, email):
    try:
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            id = row[0]
            exists_flag = True
            break

        global cnt_all
        global cnt_true
        global cnt_false

        cnt_all = cnt_all + 1
        if exists_flag:
            cnt_true = cnt_true + 1
            sql1 = """
                  update auth_user set username = \'{username}\', last_name = \'{last_name}\' where email = \'{email}\'
                  """.format(username=username, last_name=user_nm, email=email)
            cur.execute(sql1)

            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            con.commit()
        else:
            if 1==2:
                cnt_false = cnt_false + 1
                _uuid = uuid.uuid4().__str__()
                _uuid = _uuid.replace('-', '')

                cmd = 'bash /edx/app/edxapp/edx-platform/add_user_bat.sh {email} {password} {username}'.format(
                    email=email,
                    password=_uuid,
                    username=username)
                result = os.system(cmd)
                user_human_info_update(con, cur, user_nm, email)

    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)
        print 'views.py def index user_human_update MySQL: {0}'.format(e)

def user_human_info_update(con, cur, user_nm, email):
    try:
        user_id = 0
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            id = row[0]
            exists_flag = True
            break

        if exists_flag:
            sql1 = """
                  update auth_user set last_name = \'{last_name}\' where email = {email}
                  """.format(last_name=user_nm, email=email)
            cur.execute(sql1)

            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            con.commit()
        else:
            logging.info("views.py def index user_human_info_update : %s record(s) affected", '0')
            print "views.py def index user_human_info_update : 0 record(s) affected"
    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)
        print 'views.py def index user_human_update MySQL: {0}'.format(e)

gDebug = False
gDebug = True
if gDebug:
    if __name__ == "__main__":
        r = user_ora_human_update(1)
        print r
        r = user_ora_human_update(2)
        print r

