/*************************************************************************
	> File Name: modbus_signal_data.h
	> Author: 
	> Mail: 
	> Created Time: Mon 07 Aug 2017 04:32:27 PM HKT
 ************************************************************************/

#ifndef _MODBUS_SIGNAL_DATA_H
#define _MODBUS_SIGNAL_DATA_H

#include <sqlite3.h>


extern sqlite3 *m_signal_db;


#define MODBUS_DATABASE		"/mnt/KINGSTON/signal.db"

sqlite3 *open_db(const char *db_name);
int close_db(sqlite3 *db);
int exec_sql_cmd(sqlite3 *db, char *sql);
int create_signal_info_dto_table(sqlite3 *db);
int create_signal_data_dto_table(sqlite3 *db);
int insert_signal_data(sqlite3 *db, char *id, char *origval, char *sigval, char *picktime);
int insert_signal_info(sqlite3 *db, char *id, char *name, int valtype, char *maxval, char *minval, int ctrlable, char *opertype);
int create_index_on_singalid(sqlite3 *db);
int create_picktime_index_on_singalid(sqlite3 *db);




#endif
