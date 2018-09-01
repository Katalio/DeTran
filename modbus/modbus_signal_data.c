/*************************************************************************
	> File Name: modbus_signal_data.c
	> Author: 
	> Mail: 
	> Created Time: Mon 07 Aug 2017 04:32:21 PM HKT
 ************************************************************************/

#include <stdio.h>
#include <sqlite3.h>
#include <syslog.h>
#include "modbus_signal_data.h"

sqlite3 *m_signal_db = NULL;

//SQL ---- DEFINE BEGIN ------------------------------------------

#define CREATE_SIGNAL_INFO_TABLE_SQL	\
"CREATE TABLE SIGNAL_INFO_TABLE("  \
	"ID 			TEXT 	 PRIMARY KEY NOT NULL," \
	"NAME			TEXT," \
	"VALTYPE		BOOLEAN," \
	"MAXVAL		TEXT," \
	"MINVAL		TEXT," \
	"CONTROLABLE	BOOLEAN," \
	"OPERTYPE		TEXT);"
	
#define CREATE_SIGNAL_DATA_TABLE_SQL	\
"CREATE TABLE SIGNAL_DATA_TABLE("  \
	"ID 			INTEGER PRIMARY KEY   AUTOINCREMENT," \
	"SIG_ID 		TEXT 	 NOT NULL," \
	"UPLOAD_FLAG 	BOOLEAN," \
	"ORIGVAL		TEXT," \
	"SIGLVAL		TEXT," \
	"PICKTIME		INTEGER	NOT NULL);"

#define INSERT_SIGNAL_DATA_SQL(sql, id, origval, sigval, picktime)		\
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"INSERT INTO SIGNAL_DATA_TABLE(SIG_ID, UPLOAD_FLAG, ORIGVAL, SIGLVAL, PICKTIME) VALUES ('%s', 0, '%s', '%s', strftime('%%s', '%s', 'utc')); ", \
	id, origval, sigval, picktime); \
} while (0);

#define INSERT_SIGNAL_INFO_SQL(sql, id, name, valtype, maxval, minval, ctrlable, opertype)				\
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"INSERT INTO SIGNAL_INFO_TABLE(ID, NAME, VALTYPE, MAXVAL, MINVAL, CONTROLABLE, OPERTYPE) VALUES ('%s', '%s', '%d', '%s', '%s', '%d', '%s'); ", \
	id, name, valtype, maxval, minval, ctrlable, opertype); \
} while (0);

#define UPDATE_SIGNAL_INFO_SQL(sql, id, name, valtype, maxval, minval, ctrlable, opertype)				\
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"UPDATE SIGNAL_INFO_TABLE SET NAME = '%s', VALTYPE = '%d', MAXVAL = '%s', MINVAL = '%s', CONTROLABLE = '%d', OPERTYPE = '%s' WHERE ID = '%s'; ", \
	name, valtype, maxval, minval, ctrlable, opertype, id); \
} while (0);


#define CREATE_INDEX_BY_SIGID_AND_PICKTIME	"CREATE INDEX i_signal_id_index ON SIGNAL_DATA_TABLE (SIG_ID, PICKTIME);"
#define CREATE_INDEX_BY_PICKTIME			"CREATE INDEX i_picktime_index ON SIGNAL_DATA_TABLE (PICKTIME);"

#define UPDATE_UPLOAD_FLAG_IN_TABLE(sql, id, picktime)		\
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"UPDATE SIGNAL_DATA_TABLE SET UPLOAD_FLAG = 1 WHERE SIG_ID = '%s' AND PICKTIME = strftime('%%s', '%s', 'utc'); ", \
	id, picktime); \
} while (0);

#define DELETE_N_DAY_BEFOR_DATA(sql, now, ndaySec) \
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"DELETE FROM SIGNAL_DATA_TABLE WHERE PICKTIME < (strftime('%%s', '%s', 'utc') - %d);", \
	now, ndaySec); \
} while (0);

#define SELECT_DATA_BY_PICKTIME(sql, start_time, end_time) \
do { \
	snprintf(sql, sizeof(sql) - 1, \
	"SELECT SIG_ID, ORIGVAL, SIGLVAL, PICKTIME FROM SIGNAL_DATA_TABLE WHERE picktime BETWEEN strftime('%%s', '%s', 'utc') AND strftime('%%s', '%s', 'utc'); ", \
	start_time, end_time);\
} while (0);
			

//SQL ---- DEFINE END ------------------------------------




/* create or connect database */
sqlite3 *open_db(const char *db_name)
{
	sqlite3 *db = NULL;
	int ret;


	if (db_name == NULL)
	{
		return NULL;	
	}

	
	ret = sqlite3_open(db_name, &db);
	if (ret > 0)
	{
		syslog(LOG_ERR, "Can't open database, %s:%s", db_name, sqlite3_errmsg(db));
		return NULL;
	}
	
	sqlite3_busy_timeout(db, 5 * 1000);
	return db;
}

/* disconnect from database */
int close_db(sqlite3 *db)
{
	if (db == NULL)
	{
		return 0;
	}

	sqlite3_close(db);
	return 0;
}


static int callback(void *data, int argc, char **argv, char **azColName)
{
	int i;
	char line[256] = {0};

	
	if (data != NULL)
	{
		syslog(LOG_INFO, "%s: ", (const char *)data);
		
		memset(line, 0, sizeof(line));
   		for (i = 0; i < argc; i++)
   		{
   			snprintf(line + strlen(line), sizeof(line) - strlen(line), "%s    ", azColName[i]);
      	
   		}
		syslog(LOG_INFO, "%s", line);
	}
	
	memset(line, 0, sizeof(line));
   	for (i = 0; i < argc; i++)
   	{
   		snprintf(line + strlen(line), sizeof(line) - strlen(line), "%s    ", argv[i] ? argv[i] : "NULL");
   	}
   	syslog(LOG_INFO, "%s", line);
   	
   	return 0;
}


/* executed a sql command */
int exec_sql_cmd(sqlite3 *db, char *sql)
{
	int ret;
	char *errMsg = NULL;
	
	if (db == NULL || sql == NULL)
	{
		return -1;
	}

	if (nvram_get_int("modbus_debug_switch") == 1)
	{
		syslog(LOG_INFO, "sql = [%s]", sql);
	}
	
	ret = sqlite3_exec(db, sql, callback, 0, &errMsg);
	if (ret != SQLITE_OK)
	{
		syslog(LOG_ERR, "SQL error: %s\n", errMsg);
		
		if ((ret == SQLITE_ERROR && strstr(errMsg, "no such table") != NULL)
			|| ret == SQLITE_IOERR
			|| ret == SQLITE_CORRUPT
			|| ret == SQLITE_FULL
			|| ret == SQLITE_CANTOPEN
			|| ret == SQLITE_NOTADB
			|| ret == SQLITE_READONLY
			|| ret == SQLITE_TOOBIG)
		{
			sqlite3_free(errMsg);
			return -2;
		}
		
		sqlite3_free(errMsg);
		return -1;
	}

	return 0;
}

/* executed a sql command */
int exec_sql_cmd_no_cb(sqlite3 *db, char *sql)
{
	int ret;
	char *errMsg = NULL;
	
	if (sql == NULL)
	{
		return -1;
	}

	if (nvram_get_int("modbus_debug_switch") == 1)
	{
		syslog(LOG_INFO, "sql = [%s]", sql);
	}
	
	ret = sqlite3_exec(db, sql, NULL, NULL, &errMsg);
	if (ret != SQLITE_OK)
	{
		syslog(LOG_ERR, "SQL error: %s\n", errMsg);
		
		if ((ret == SQLITE_ERROR && strstr(errMsg, "no such table") != NULL)
			|| ret == SQLITE_IOERR
			|| ret == SQLITE_CORRUPT
			|| ret == SQLITE_FULL
			|| ret == SQLITE_CANTOPEN
			|| ret == SQLITE_NOTADB
			|| ret == SQLITE_READONLY
			|| ret == SQLITE_TOOBIG)
		{
			sqlite3_free(errMsg);
			return -2;
		}
		
		sqlite3_free(errMsg);
		return -1;
	}

	return 0;
}



int create_signal_info_dto_table(sqlite3 *db)
{
	//char *sql;
	int ret;

	if (db == NULL)
	{
		return -1;
	}
	#if 0
	sql = "CREATE TABLE SIGNAL_INFO_TABLE("  \
			 "ID 			TEXT 	 PRIMARY KEY NOT NULL," \
			 "NAME			TEXT," \
			 "VALTYPE		BOOLEAN," \
			 "MAXVAL		TEXT," \
			 "MINVAL		TEXT," \
			 "CONTROLABLE	BOOLEAN," \
			 "OPERTYPE		TEXT);";
	#endif
	
	//syslog(LOG_INFO, "sql = [%s]", sql);
	ret = exec_sql_cmd(db, CREATE_SIGNAL_INFO_TABLE_SQL);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}



int create_signal_data_dto_table(sqlite3 *db)
{
	//char *sql;
	int ret;

	if (db == NULL)
	{
		return -1;
	}

	#if 0
	sql = "CREATE TABLE SIGNAL_DATA_TABLE("  \
			 "ID 			INTEGER PRIMARY KEY   AUTOINCREMENT," \
			 "SIG_ID 		TEXT 	 NOT NULL," \
			 "UPLOAD_FLAG 	BOOLEAN," \
			 "ORIGVAL		TEXT," \
			 "SIGLVAL		TEXT," \
			 "PICKTIME		INTEGER	NOT NULL);";
	#endif
	//syslog(LOG_INFO, "sql = [%s]", CREATE_SIGNAL_DATA_TABLE_SQL);
	ret = exec_sql_cmd(db, CREATE_SIGNAL_DATA_TABLE_SQL);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}

int insert_signal_data(sqlite3 *db, char *id, char *origval, char *sigval, char *picktime)
{
	char sql[256] = {0};
	int ret;
	
	if (db == NULL)
	{
		return -1;
	}

	INSERT_SIGNAL_DATA_SQL(sql, id, origval, sigval, picktime);
	#if 0
	snprintf(sql, sizeof(sql) - 1, 
			"INSERT INTO SIGNAL_DATA_TABLE(SIG_ID, UPLOAD_FLAG, ORIGVAL, SIGLVAL, PICKTIME) VALUES ('%s', 0, '%s', '%s', strftime('%%s', '%s', 'utc')); ",
			id, origval, sigval, picktime);
	#endif
	//syslog(LOG_INFO, "sql = [%s]", sql);
	ret = exec_sql_cmd_no_cb(db, sql);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
		return 0;
	}
	else
	{
		return 0;
	}
}

int insert_signal_info(sqlite3 *db, char *id, char *name, int valtype, char *maxval, char *minval, int ctrlable, char *opertype)
{
	char sql[256] = {0};
	int ret;
	
	if (db == NULL)
	{
		return -1;
	}

	INSERT_SIGNAL_INFO_SQL(sql, id, name, valtype, maxval, minval, ctrlable, opertype);
	#if 0
	snprintf(sql, sizeof(sql) - 1, 
			"INSERT INTO SIGNAL_INFO_TABLE(ID, NAME, VALTYPE, MAXVAL, MINVAL, CONTROLABLE, OPERTYPE) VALUES ('%s', '%s', '%d', '%s', '%s', '%d', '%s'); ",
			id, name, valtype, maxval, minval, ctrlable, opertype);
	#endif
	//syslog(LOG_INFO, "sql = [%s]", sql);
	ret = exec_sql_cmd_no_cb(db, sql);
	if (ret == -1)
	{
		//update signal info
		UPDATE_SIGNAL_INFO_SQL(sql, id, name, valtype, maxval, minval, ctrlable, opertype);
		//syslog(LOG_INFO, "sql = [%s]", sql);
		ret = exec_sql_cmd_no_cb(db, sql);
	}


	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}

int create_index_on_singalid(sqlite3 *db)
{
	//char *sql;
	int ret;
	
	if (db == NULL)
	{
		return -1;
	}
	
	//sql = "CREATE INDEX i_signal_id_index ON SIGNAL_DATA_TABLE (SIG_ID, PICKTIME);";
	//syslog(LOG_INFO, "sql = [%s]", CREATE_INDEX_BY_SIGID_AND_PICKTIME);
	ret = exec_sql_cmd_no_cb(db, CREATE_INDEX_BY_SIGID_AND_PICKTIME);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}


int create_picktime_index_on_singalid(sqlite3 *db)
{
	//char *sql;
	int ret;

	if (db == NULL)
	{
		return -1;
	}
	
	//sql = "CREATE INDEX i_picktime_index ON SIGNAL_DATA_TABLE (PICKTIME);";
	//syslog(LOG_INFO, "sql = [%s]", CREATE_INDEX_BY_PICKTIME);
	ret = exec_sql_cmd_no_cb(db, CREATE_INDEX_BY_PICKTIME);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}


int update_signal_data_upload_flag(sqlite3 *db, char *id, char *picktime)
{
	char sql[256] = {0};
	int ret;

	
	if (db == NULL || id == NULL || picktime == NULL)
	{
		return -1;
	}

	UPDATE_UPLOAD_FLAG_IN_TABLE(sql, id, picktime);
	#if 0
	snprintf(sql, sizeof(sql) - 1, 
			"UPDATE SIGNAL_DATA_TABLE SET UPLOAD_FLAG = 1 WHERE SIG_ID = '%s' AND PICKTIME = strftime('%%s', '%s', 'utc'); ",
			id, picktime);
	#endif
	//syslog(LOG_INFO, "sql = [%s]", sql);
	ret = exec_sql_cmd_no_cb(db, sql);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}



int select_time_slice(sqlite3 *db, char *start_time, char *end_time)
{
	char sql[256] = {0};
	int ret;

	
	if (db == NULL || start_time == NULL || end_time == NULL)
	{
		return -1;
	}

	SELECT_DATA_BY_PICKTIME(sql, start_time, end_time);

	ret = exec_sql_cmd_no_cb(db, sql);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}



int delete_sinal_data_N_day_before(sqlite3 *db, int ndaySec)
{
	char sql[256] = {0};
	int ret;
	char cur_time[32] = {0};
	
	if (db == NULL || ndaySec <= 1)
	{
		return -1;
	}
	//DELETE_N_DAY_BEFOR_DATA(sql, ndaySec);
	//ndaySec = nvram_get_int("nDaySec_test");

	getCurTime(cur_time, sizeof(cur_time));
	
	DELETE_N_DAY_BEFOR_DATA(sql, cur_time, ndaySec);
	#if 0
	snprintf(sql, sizeof(sql) - 1, 
			"DELETE FROM SIGNAL_DATA_TABLE WHERE PICKTIME < (strftime('%%s', 'now', 'utc') -  %d);",
			ndaySec);
	#endif
	//syslog(LOG_INFO, "sql = [%s]", sql);
	ret = exec_sql_cmd_no_cb(db, sql);
	if (ret == -2)
	{
		//recreate datebase
		close_db(MODBUS_DATABASE);
		m_signal_db = NULL;
		unlink(MODBUS_DATABASE);
		m_signal_db = open_db(MODBUS_DATABASE);
		create_signal_data_dto_table(m_signal_db);
	    create_signal_info_dto_table(m_signal_db);
	    create_index_on_singalid(m_signal_db);
	    create_picktime_index_on_singalid(m_signal_db);
	    return 0;
	}
	else
	{
		return 0;
	}
}



